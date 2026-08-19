package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// This is app-level RBAC for the connector portal itself - who can click
// Wipe/Disconnect/change Settings in THIS app - and is unrelated to
// AdminRoleAssignment in google.go, which surfaces Google Workspace's own
// admin roles read-only. Two different "roles" concepts, two different
// purposes.

// Role hierarchy: viewer < operator < admin. Every authenticated user can
// read; operator adds Restart + Sync now; admin adds Wipe, Disconnect,
// Settings, and the initial connect wizard.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var roleRank = map[string]int{RoleViewer: 0, RoleOperator: 1, RoleAdmin: 2}

type appUser struct {
	Username     string
	PasswordHash []byte
	Role         string
}

// Seeded in-memory demo accounts - this is a prototype with no user
// database, not a production auth system. Logged at startup so whoever runs
// it can actually log in without reading source.
var demoUsers = map[string]*appUser{}

// seedDemoUsers seeds the three fixed demo accounts into memory (as
// before), and - when mongoStore is available - also persists them via
// saveAppUserIfAbsent, which only writes a seed if that username doesn't
// already exist in Mongo. That means a previous run's demo accounts (and
// their password hashes, if this ever got extended with a password-change
// endpoint) survive a restart unchanged instead of being silently
// overwritten by these hardcoded seeds every time - the whole point of
// persisting them at all. Any account Mongo already has (loaded separately
// in main() before this runs) takes priority in the in-memory map; seeding
// only fills in ones that are still missing.
func seedDemoUsers() {
	seeds := []struct{ username, password, role string }{
		{"admin", "admin123", RoleAdmin},
		{"operator", "operator123", RoleOperator},
		{"viewer", "viewer123", RoleViewer},
	}
	log.Println("seeding demo portal accounts (prototype only - not for production use):")
	for _, s := range seeds {
		if _, exists := demoUsers[s.username]; exists {
			log.Printf("  %s already loaded from Mongo - keeping it, not reseeding", s.username)
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(s.password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash demo password: %v", err)
		}
		u := &appUser{Username: s.username, PasswordHash: hash, Role: s.role}
		demoUsers[s.username] = u
		mongoStore.saveAppUserIfAbsent(u)
		log.Printf("  %s / %s  (role: %s)", s.username, s.password, s.role)
	}
}

type session struct {
	Username string
	Role     string
	Expiry   time.Time
}

const sessionTTL = 12 * time.Hour

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

func newSessionToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the platform RNG is broken - nothing sane to do but stop
	}
	return hex.EncodeToString(b)
}

func createSession(username, role string) string {
	token := newSessionToken()
	s := &session{Username: username, Role: role, Expiry: time.Now().Add(sessionTTL)}
	sessionsMu.Lock()
	sessions[token] = s
	sessionsMu.Unlock()
	mongoStore.saveSession(token, s)
	return token
}

func getSession(token string) (*session, bool) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[token]
	if !ok || time.Now().After(s.Expiry) {
		delete(sessions, token)
		mongoStore.deleteSession(token)
		return nil, false
	}
	return s, true
}

func deleteSession(token string) {
	sessionsMu.Lock()
	delete(sessions, token)
	sessionsMu.Unlock()
	mongoStore.deleteSession(token)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// requireRole wraps a handler so it only runs for a session whose role is at
// least minRole in the viewer < operator < admin hierarchy. Every protected
// route in main.go is wrapped with this - there's no route that trusts the
// caller without a valid, unexpired session token.
func requireRole(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		s, ok := getSession(token)
		if !ok {
			http.Error(w, "session expired or invalid", http.StatusUnauthorized)
			return
		}
		if roleRank[s.Role] < roleRank[minRole] {
			http.Error(w, "insufficient role for this action", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// requireReadOrRole is for GET/POST-combined handlers (sync/settings,
// thresholds) where reading only needs a valid session but writing needs at
// least writeMinRole - splitting them into two routes wasn't worth the
// duplication given how small each handler already is.
func requireReadOrRole(writeMinRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		s, ok := getSession(token)
		if !ok {
			http.Error(w, "session expired or invalid", http.StatusUnauthorized)
			return
		}
		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && roleRank[s.Role] < roleRank[writeMinRole] {
			http.Error(w, "insufficient role for this action", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// sessionFromRequest is for handlers that branch behavior by role internally
// (handleDeviceAction: restart needs operator, wipe needs admin) instead of
// having one fixed minRole for the whole route.
func sessionFromRequest(r *http.Request) (*session, bool) {
	return getSession(bearerToken(r))
}

// POST /api/auth/login {"username":"...","password":"..."}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	user, ok := demoUsers[body.Username]
	if !ok || bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(body.Password)) != nil {
		// Same message either way - don't reveal whether the username exists.
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	token := createSession(user.Username, user.Role)
	writeJSON(w, map[string]string{"token": token, "username": user.Username, "role": user.Role})
}

// POST /api/auth/logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := bearerToken(r); token != "" {
		deleteSession(token)
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// GET /api/auth/me - lets the frontend restore a session after a page
// reload without re-prompting for credentials, as long as the token is
// still valid.
func handleMe(w http.ResponseWriter, r *http.Request) {
	s, ok := sessionFromRequest(r)
	if !ok {
		http.Error(w, "session expired or invalid", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]string{"username": s.Username, "role": s.Role})
}
