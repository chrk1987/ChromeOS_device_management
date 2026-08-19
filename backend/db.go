package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoStore, when non-nil, backs every piece of app state this connector
// keeps of its own (connection status/credentials metadata, the last-synced
// device cache, sync settings, thresholds, device action history, portal
// login sessions, portal demo accounts) with MongoDB, so a backend restart
// no longer loses all of it the way it always has up to this point in the
// project.
//
// Deliberately NOT a rewrite of every store.field access into a database
// call: requests still read/write the existing in-memory Store (and the
// in-memory sessions/demoUsers maps in auth.go) exactly as before - same
// latency, same locking, same behavior - and Mongo is written through
// (fire-and-forget, in a goroutine with its own short timeout) right after
// each of the handful of places that already mutate that state. On startup,
// whatever Mongo has is loaded back into memory once, before the HTTP
// server starts accepting requests. If Mongo is unreachable, everything
// still works exactly as it always has - purely in-memory, reset on
// restart - startup just logs a warning instead of failing, so this never
// turns "no database configured" into "app won't start."
var mongoStore *mongoPersistence

type mongoPersistence struct {
	client        *mongo.Client
	connColl      *mongo.Collection // singleton doc: the Connection
	devicesColl   *mongo.Collection // one doc per Device, _id = device ID
	actionsColl   *mongo.Collection // one doc per DeviceAction, _id = action ID
	settingsColl  *mongo.Collection // singleton doc: sync interval + Thresholds
	directoryColl *mongo.Collection // singleton doc: users/orgUnits/churn/groups cache
	sessionsColl  *mongo.Collection // one doc per login session, _id = token
	usersColl     *mongo.Collection // one doc per portal login account, _id = username
}

const mongoOpTimeout = 5 * time.Second

// connectMongo is called once from main() at startup. MONGODB_URI defaults
// to the local default port so this works out of the box against a mongod
// already running on the same machine (confirmed present in this
// environment); MONGODB_DB defaults to a name scoped to this project so it
// doesn't collide with any other database on a shared Mongo instance.
func connectMongo() *mongoPersistence {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		log.Printf("mongo: connect failed (%v) - continuing with in-memory state only, nothing will survive a restart", err)
		return nil
	}
	if err := client.Ping(ctx, nil); err != nil {
		log.Printf("mongo: ping failed (%v) - continuing with in-memory state only, nothing will survive a restart", err)
		return nil
	}

	dbName := os.Getenv("MONGODB_DB")
	if dbName == "" {
		dbName = "chromeos_connector"
	}
	db := client.Database(dbName)
	log.Printf("mongo: connected to %s (db %q) - app state now persists across restarts", uri, dbName)

	return &mongoPersistence{
		client:        client,
		connColl:      db.Collection("connection"),
		devicesColl:   db.Collection("devices"),
		actionsColl:   db.Collection("actions"),
		settingsColl:  db.Collection("settings"),
		directoryColl: db.Collection("directory_cache"),
		sessionsColl:  db.Collection("sessions"),
		usersColl:     db.Collection("app_users"),
	}
}

// singletonFilter/singletonID are used for the three collections that only
// ever hold exactly one document (connection, settings, directory cache) -
// upserting against a fixed _id is simpler than reasoning about find-one
// semantics for a collection that's conceptually a single row.
const singletonID = "singleton"

var singletonFilter = bson.M{"_id": singletonID}

type connectionDoc struct {
	ID         string `bson:"_id"`
	Connection `bson:",inline"`
}

func (m *mongoPersistence) saveConnection(conn Connection) {
	if m == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		_, err := m.connColl.ReplaceOne(ctx, singletonFilter, connectionDoc{ID: singletonID, Connection: conn}, options.Replace().SetUpsert(true))
		if err != nil {
			log.Printf("mongo: saving connection failed (non-fatal): %v", err)
		}
	}()
}

func (m *mongoPersistence) loadConnection() (Connection, bool) {
	if m == nil {
		return Connection{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	var doc connectionDoc
	if err := m.connColl.FindOne(ctx, singletonFilter).Decode(&doc); err != nil {
		if err != mongo.ErrNoDocuments {
			log.Printf("mongo: loading connection failed (non-fatal, starting disconnected): %v", err)
		}
		return Connection{}, false
	}
	return doc.Connection, true
}

// saveDevices fully replaces the device cache - matches runSync's own
// "fresh := ...; store.devices = fresh" full-replace semantics exactly, so
// a device Google no longer reports also disappears from Mongo, not just
// memory. Devices are stored as individual documents (not one big array
// doc) so a future feature needing to query/paginate them directly against
// Mongo isn't blocked by everything being buried in one blob.
func (m *mongoPersistence) saveDevices(devices map[string]*Device) {
	if m == nil {
		return
	}
	docs := make([]any, 0, len(devices))
	for id, d := range devices {
		docs = append(docs, deviceDoc{ID: id, Device: *d})
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		if _, err := m.devicesColl.DeleteMany(ctx, bson.M{}); err != nil {
			log.Printf("mongo: clearing devices failed (non-fatal): %v", err)
			return
		}
		if len(docs) == 0 {
			return
		}
		if _, err := m.devicesColl.InsertMany(ctx, docs); err != nil {
			log.Printf("mongo: saving devices failed (non-fatal): %v", err)
		}
	}()
}

type deviceDoc struct {
	ID     string `bson:"_id"`
	Device `bson:",inline"`
}

// saveDevice persists a single device's current fields - used for the
// lighter-weight single-device mutations (org unit move, an action's
// after-effects) instead of re-saving the entire fleet for a one-field
// change.
func (m *mongoPersistence) saveDevice(d *Device) {
	if m == nil || d == nil {
		return
	}
	doc := deviceDoc{ID: d.ID, Device: *d}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		if _, err := m.devicesColl.ReplaceOne(ctx, bson.M{"_id": d.ID}, doc, options.Replace().SetUpsert(true)); err != nil {
			log.Printf("mongo: saving device %s failed (non-fatal): %v", d.ID, err)
		}
	}()
}

func (m *mongoPersistence) loadDevices() map[string]*Device {
	out := map[string]*Device{}
	if m == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	cur, err := m.devicesColl.Find(ctx, bson.M{})
	if err != nil {
		log.Printf("mongo: loading devices failed (non-fatal, starting empty): %v", err)
		return out
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var doc deviceDoc
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		d := doc.Device
		out[doc.ID] = &d
	}
	return out
}

type settingsDoc struct {
	ID               string     `bson:"_id"`
	SyncIntervalMins int        `bson:"syncIntervalMins"`
	Thresholds       Thresholds `bson:"thresholds"`
}

func (m *mongoPersistence) saveSettings(syncIntervalMins int, thresholds Thresholds) {
	if m == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		doc := settingsDoc{ID: singletonID, SyncIntervalMins: syncIntervalMins, Thresholds: thresholds}
		if _, err := m.settingsColl.ReplaceOne(ctx, singletonFilter, doc, options.Replace().SetUpsert(true)); err != nil {
			log.Printf("mongo: saving settings failed (non-fatal): %v", err)
		}
	}()
}

func (m *mongoPersistence) loadSettings() (int, Thresholds, bool) {
	if m == nil {
		return 0, Thresholds{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	var doc settingsDoc
	if err := m.settingsColl.FindOne(ctx, singletonFilter).Decode(&doc); err != nil {
		if err != mongo.ErrNoDocuments {
			log.Printf("mongo: loading settings failed (non-fatal, using defaults): %v", err)
		}
		return 0, Thresholds{}, false
	}
	return doc.SyncIntervalMins, doc.Thresholds, true
}

type directoryCacheDoc struct {
	ID       string           `bson:"_id"`
	Users    []*DirectoryUser `bson:"users"`
	OrgUnits []*OrgUnitInfo   `bson:"orgUnits"`
	Churn    []*ChurnRecord   `bson:"churn"`
	Groups   []*GroupInfo     `bson:"groups"`
}

// saveDirectoryCache persists the four lists runSync always refreshes
// together - kept as one document since they're always read and written as
// a unit, never independently.
func (m *mongoPersistence) saveDirectoryCache(users []*DirectoryUser, orgUnits []*OrgUnitInfo, churn []*ChurnRecord, groups []*GroupInfo) {
	if m == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		doc := directoryCacheDoc{ID: singletonID, Users: users, OrgUnits: orgUnits, Churn: churn, Groups: groups}
		if _, err := m.directoryColl.ReplaceOne(ctx, singletonFilter, doc, options.Replace().SetUpsert(true)); err != nil {
			log.Printf("mongo: saving directory cache failed (non-fatal): %v", err)
		}
	}()
}

func (m *mongoPersistence) loadDirectoryCache() ([]*DirectoryUser, []*OrgUnitInfo, []*ChurnRecord, []*GroupInfo) {
	if m == nil {
		return nil, nil, nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	var doc directoryCacheDoc
	if err := m.directoryColl.FindOne(ctx, singletonFilter).Decode(&doc); err != nil {
		if err != mongo.ErrNoDocuments {
			log.Printf("mongo: loading directory cache failed (non-fatal, starting empty): %v", err)
		}
		return nil, nil, nil, nil
	}
	return doc.Users, doc.OrgUnits, doc.Churn, doc.Groups
}

type actionDoc struct {
	ID           string `bson:"_id"`
	DeviceAction `bson:",inline"`
}

// saveAction upserts one action's current state - called both when an
// action is first created (status pending) and again whenever its status
// later changes (complete/error), so action history genuinely survives a
// restart instead of just letting an in-flight one vanish mid-poll.
func (m *mongoPersistence) saveAction(a *DeviceAction) {
	if m == nil || a == nil {
		return
	}
	doc := actionDoc{ID: a.ID, DeviceAction: *a}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		if _, err := m.actionsColl.ReplaceOne(ctx, bson.M{"_id": a.ID}, doc, options.Replace().SetUpsert(true)); err != nil {
			log.Printf("mongo: saving action %s failed (non-fatal): %v", a.ID, err)
		}
	}()
}

func (m *mongoPersistence) loadActions() map[string]*DeviceAction {
	out := map[string]*DeviceAction{}
	if m == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	cur, err := m.actionsColl.Find(ctx, bson.M{})
	if err != nil {
		log.Printf("mongo: loading actions failed (non-fatal, starting empty): %v", err)
		return out
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var doc actionDoc
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		a := doc.DeviceAction
		out[doc.ID] = &a
	}
	return out
}

type sessionDoc struct {
	ID string `bson:"_id"` // the bearer token itself
	session
}

func (m *mongoPersistence) saveSession(token string, s *session) {
	if m == nil || s == nil {
		return
	}
	doc := sessionDoc{ID: token, session: *s}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		if _, err := m.sessionsColl.ReplaceOne(ctx, bson.M{"_id": token}, doc, options.Replace().SetUpsert(true)); err != nil {
			log.Printf("mongo: saving session failed (non-fatal): %v", err)
		}
	}()
}

func (m *mongoPersistence) deleteSession(token string) {
	if m == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
		defer cancel()
		if _, err := m.sessionsColl.DeleteOne(ctx, bson.M{"_id": token}); err != nil {
			log.Printf("mongo: deleting session failed (non-fatal): %v", err)
		}
	}()
}

// loadSessions hydrates the in-memory sessions map at startup - expired
// sessions are dropped (and cleaned up from Mongo) rather than loaded, same
// as getSession already does for ones found expired later at lookup time.
func (m *mongoPersistence) loadSessions() map[string]*session {
	out := map[string]*session{}
	if m == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	cur, err := m.sessionsColl.Find(ctx, bson.M{})
	if err != nil {
		log.Printf("mongo: loading sessions failed (non-fatal, starting with none): %v", err)
		return out
	}
	defer cur.Close(ctx)
	now := time.Now()
	var expired []string
	for cur.Next(ctx) {
		var doc sessionDoc
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		if now.After(doc.session.Expiry) {
			expired = append(expired, doc.ID)
			continue
		}
		s := doc.session
		out[doc.ID] = &s
	}
	if len(expired) > 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
			defer cancel()
			m.sessionsColl.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": expired}})
		}()
	}
	return out
}

type appUserDoc struct {
	ID           string `bson:"_id"` // username
	PasswordHash []byte `bson:"passwordHash"`
	Role         string `bson:"role"`
}

// saveAppUserIfAbsent upserts a demo account only if it doesn't already
// exist in Mongo - seedDemoUsers runs on every startup with the same fixed
// seeds, and this must not clobber a real deployment's actual password
// hash with the hardcoded demo one on every restart.
func (m *mongoPersistence) saveAppUserIfAbsent(u *appUser) {
	if m == nil || u == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	doc := appUserDoc{ID: u.Username, PasswordHash: u.PasswordHash, Role: u.Role}
	_, err := m.usersColl.UpdateOne(ctx,
		bson.M{"_id": u.Username},
		bson.M{"$setOnInsert": doc},
		options.UpdateOne().SetUpsert(true))
	if err != nil {
		log.Printf("mongo: seeding app user %s failed (non-fatal): %v", u.Username, err)
	}
}

// loadAppUsers reads every persisted portal login account - takes priority
// over the hardcoded seeds wherever both exist (seeding uses $setOnInsert,
// so Mongo already wins for anything previously changed there).
func (m *mongoPersistence) loadAppUsers() map[string]*appUser {
	out := map[string]*appUser{}
	if m == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoOpTimeout)
	defer cancel()
	cur, err := m.usersColl.Find(ctx, bson.M{})
	if err != nil {
		log.Printf("mongo: loading app users failed (non-fatal): %v", err)
		return out
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var doc appUserDoc
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		out[doc.ID] = &appUser{Username: doc.ID, PasswordHash: doc.PasswordHash, Role: doc.Role}
	}
	return out
}

// hydrateStoreFromMongo runs once at startup, before the HTTP server starts
// accepting requests, and loads back whatever a previous run persisted. A
// no-op (store keeps its NewStore() defaults) when mongoStore is nil.
//
// Connection is the one deliberate exception to "restore everything
// exactly as it was": its metadata (client ID, customer ID, scopes, last
// known account, timestamps) is restored, but Status is always forced back
// to disconnected. The actual authenticated Google API client
// (store.google) is never persisted here and can't be - it's rebuilt fresh
// every process start from either GOOGLE_MODE env vars or a fresh key
// upload, and there's no way to verify a restored "active" status is still
// backed by a live, working credential without the same real reconnect
// this project has required after every restart all along. Claiming
// "active" for a connection that isn't truly live would be a worse
// regression than just keeping the existing reconnect step - so that one
// piece of existing behavior is deliberately preserved unchanged; sync
// settings, thresholds, the device cache, and action history all now
// genuinely survive a restart.
func hydrateStoreFromMongo() {
	if mongoStore == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	if conn, ok := mongoStore.loadConnection(); ok {
		conn.Status = StatusDisconnected
		store.conn = conn
	}
	store.devices = mongoStore.loadDevices()
	store.actions = mongoStore.loadActions()
	if mins, thresholds, ok := mongoStore.loadSettings(); ok {
		store.syncIntervalMins = mins
		store.thresholds = thresholds
	}
	store.users, store.orgUnits, store.churn, store.groups = mongoStore.loadDirectoryCache()

	log.Printf("mongo: hydrated %d cached device(s), %d action(s), %d cached user(s) from a previous run", len(store.devices), len(store.actions), len(store.users))
}
