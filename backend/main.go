package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- Domain types ----------

type ConnectionStatus string

const (
	StatusDisconnected ConnectionStatus = "disconnected"
	StatusPending      ConnectionStatus = "pending"    // credentials generated, waiting on admin
	StatusAuthorized   ConnectionStatus = "authorized" // admin clicked authorize in Google console
	StatusSyncing      ConnectionStatus = "syncing"
	StatusActive       ConnectionStatus = "active"
	StatusError        ConnectionStatus = "error"
)

type Connection struct {
	Status           ConnectionStatus `json:"status"`
	ClientID         string           `json:"clientId,omitempty"`
	CustomerID       string           `json:"customerId,omitempty"`
	Scopes           []string         `json:"scopes,omitempty"`
	AuthorizationUrl string           `json:"authorizationUrl,omitempty"`
	ConnectedAccount string           `json:"connectedAccount,omitempty"`
	AuthorizedAt     *time.Time       `json:"authorizedAt,omitempty"`
	DeviceCount      int              `json:"deviceCount"`
	LastSync         *time.Time       `json:"lastSync,omitempty"`
	adminEmail       string           // set on upload, used by handleFinish instead of an env var
}

type Device struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	User                    string     `json:"user"`
	OrgUnit                 string     `json:"orgUnit"`
	Status                  string     `json:"status"`                    // active | syncing | offline
	Online                  bool       `json:"online"`                    // computed in handleDevices from LastSeen vs onlineAfterMinutes - a real-time-ish connectivity signal, separate from the longer-horizon Stale flag
	ConnectionState         string     `json:"connectionState,omitempty"` // last-reported network state from Chrome Management Telemetry - a snapshot as of the device's last check-in, not a live ping (see decodeConnectionState)
	ProvisionStatus         string     `json:"provisionStatus,omitempty"` // raw Google status: ACTIVE | DISABLED | DEPROVISIONED
	LastSeen                time.Time  `json:"lastSeen"`
	OsVersion               string     `json:"osVersion,omitempty"`
	AutoUpdateExpiration    *time.Time `json:"autoUpdateExpiration,omitempty"`
	BootMode                string     `json:"bootMode,omitempty"` // Verified | Dev
	Model                   string     `json:"model,omitempty"`
	FirmwareVersion         string     `json:"firmwareVersion,omitempty"`
	DeviceLicenseType       string     `json:"deviceLicenseType,omitempty"`
	ManufactureDate         string     `json:"manufactureDate,omitempty"` // yyyy-mm-dd
	ExtendedSupportEligible bool       `json:"extendedSupportEligible,omitempty"`
	ExtendedSupportEnabled  bool       `json:"extendedSupportEnabled,omitempty"`
	StorageFreeBytes        int64      `json:"storageFreeBytes,omitempty"`
	StorageTotalBytes       int64      `json:"storageTotalBytes,omitempty"`
	RamTotalBytes           int64      `json:"ramTotalBytes,omitempty"`
	RamFreeBytes            int64      `json:"ramFreeBytes,omitempty"`
	LastKnownIP             string     `json:"lastKnownIp,omitempty"`
	ActiveTimeTodayMinutes  int        `json:"activeTimeTodayMinutes,omitempty"`
	RecentUserEmail         string     `json:"recentUserEmail,omitempty"`
	RecentUserCount         int        `json:"recentUserCount,omitempty"`
	CpuTempCelsius          int64      `json:"cpuTempCelsius,omitempty"`
	TpmFamily               string     `json:"tpmFamily,omitempty"`
	DeprovisionReason       string     `json:"deprovisionReason,omitempty"`
	Location                string     `json:"location,omitempty"`
	Notes                   string     `json:"notes,omitempty"`
	OrderNumber             string     `json:"orderNumber,omitempty"`
	MacAddress              string     `json:"macAddress,omitempty"`
	EthernetMacAddress      string     `json:"ethernetMacAddress,omitempty"`
	CpuModel                string     `json:"cpuModel,omitempty"`
	CpuArchitecture         string     `json:"cpuArchitecture,omitempty"`
	CpuMaxClockMhz          int64      `json:"cpuMaxClockMhz,omitempty"`
	SupportEndDate          *time.Time `json:"supportEndDate,omitempty"`
	ChromeOsType            string     `json:"chromeOsType,omitempty"` // chromeOs | chromeOsFlex
	OsUpdateState           string     `json:"osUpdateState,omitempty"`
	OsUpdateTargetVersion   string     `json:"osUpdateTargetVersion,omitempty"`
	FirstEnrollmentTime     *time.Time `json:"firstEnrollmentTime,omitempty"`
	LastEnrollmentTime      *time.Time `json:"lastEnrollmentTime,omitempty"`
	Stale                   bool       `json:"stale"` // computed in handleDevices from LastSeen vs the configured staleAfterDays threshold - not part of the raw Google sync

	// Added for the custom Chrome location tracking extension
	TrackedLocationLat          float64        `json:"trackedLocationLat,omitempty"`
	TrackedLocationLng          float64        `json:"trackedLocationLng,omitempty"`
	TrackedLocationAccuracy     float64        `json:"trackedLocationAccuracy,omitempty"`
	TrackedLocationTime         int64          `json:"trackedLocationTime,omitempty"`
	TrackedLocationPingInterval int            `json:"trackedLocationPingInterval,omitempty"` // stored in minutes
	LocationHistory             []LocationPing `json:"locationHistory,omitempty"`
}

type LocationPing struct {
	Lat       float64 `json:"lat"`
	Lng       float64 `json:"lng"`
	Accuracy  float64 `json:"accuracy"`
	Timestamp int64   `json:"timestamp"`
}

// ChurnRecord is a deprovisioned/retired device - fetched via a separate
// query against the same Chromeosdevices.List endpoint (status:DEPROVISIONED),
// not the default active-device list, so it lives in its own store slice.
type ChurnRecord struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	OrgUnit           string `json:"orgUnit"`
	DeprovisionReason string `json:"deprovisionReason,omitempty"`
}

// DirectoryUser is the subset of Google's Directory Users API we use to
// cross-reference against devices - orphaned-device and login-vs-sync
// detection, using the admin.directory.user.readonly scope that's already
// granted but was previously unused.
type DirectoryUser struct {
	Email         string     `json:"email"`
	Suspended     bool       `json:"suspended"`
	LastLoginTime *time.Time `json:"lastLoginTime,omitempty"`
	OrgUnit       string     `json:"orgUnit"`
}

// OrgUnitInfo is the subset of Google's Directory OrgUnits API we use for
// the org-unit breakdown, using the admin.directory.orgunit.readonly scope
// that's already granted but was previously unused.
type OrgUnitInfo struct {
	ID         string `json:"id,omitempty"` // needed as the target for Chrome Policy resolution
	Path       string `json:"path"`
	Name       string `json:"name"`
	ParentPath string `json:"parentPath,omitempty"`
}

// GroupInfo uses the admin.directory.group.readonly scope - a new scope,
// not part of what this connector originally requested.
type GroupInfo struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Description string `json:"description,omitempty"`
	MemberCount int64  `json:"memberCount"`
}

// MobileDeviceInfo uses the admin.directory.device.mobile.readonly scope -
// a new scope, extending the fleet view beyond ChromeOS to phones/tablets
// enrolled in Workspace MDM.
// DeviceEvent is a Chrome Management Telemetry event - a different feed
// from anything else this app surfaces: not a portal-issued action (see
// DeviceAction), not a periodic snapshot (see the Device struct's telemetry
// fields) but a real push-style occurrence the device itself reported -
// network state changes, USB connect/disconnect, app install/uninstall,
// audio underruns, WiFi signal drops. DeviceName is resolved locally from
// the synced device list since the Telemetry API's event payload only
// carries the device's opaque ID, not its friendly name.
type DeviceEvent struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"deviceId"`
	DeviceName  string    `json:"deviceName,omitempty"`
	EventType   string    `json:"eventType"`
	ReportTime  time.Time `json:"reportTime"`
	UserEmail   string    `json:"userEmail,omitempty"`
	Description string    `json:"description,omitempty"`
}

type MobileDeviceInfo struct {
	ID       string     `json:"id"`
	Name     string     `json:"name,omitempty"`
	Email    string     `json:"email,omitempty"`
	Model    string     `json:"model,omitempty"`
	Os       string     `json:"os,omitempty"`
	Type     string     `json:"type,omitempty"`
	Status   string     `json:"status,omitempty"`
	LastSync *time.Time `json:"lastSync,omitempty"`
}

// AuditEvent is one entry from the Admin SDK Reports API
// (admin.reports.audit.readonly scope) - a different API from the Chrome
// Management reports built earlier.
type AuditEvent struct {
	Time       *time.Time `json:"time,omitempty"`
	ActorEmail string     `json:"actorEmail,omitempty"`
	EventName  string     `json:"eventName,omitempty"`
	EventType  string     `json:"eventType,omitempty"`
}

type AuditLog struct {
	AdminActivity []AuditEvent `json:"adminActivity"`
	LoginActivity []AuditEvent `json:"loginActivity"`
}

// SecurityAlert uses the Alert Center API (apps.alerts scope) - covers DLP
// violations, compromised accounts, phishing, and other security sources.
type SecurityAlert struct {
	ID         string     `json:"id"`
	CreateTime *time.Time `json:"createTime,omitempty"`
	Type       string     `json:"type"`
	Source     string     `json:"source"`
	Severity   string     `json:"severity,omitempty"`
	Status     string     `json:"status,omitempty"`
}

// PolicyValue is one resolved Chrome policy from the Chrome Policy API
// (chrome.management.policy scope, read+write) - the actual enforced value,
// not just whether a device reports compliance.
type PolicyValue struct {
	SchemaName  string `json:"schemaName"`
	DisplayName string `json:"displayName"`
	Category    string `json:"category,omitempty"`
	Value       string `json:"value,omitempty"` // JSON-stringified resolved value; empty means not explicitly set (inherited default), not a fetch failure
}

// PolicySchemaField describes one settable field within a policy schema, as
// Google's own Chrome Policy API schema catalog documents it - the field's
// real JSON name, its description, and (for enum-like fields) the exact
// known values Google accepts, straight from the schema metadata rather
// than guessed.
type PolicySchemaField struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	KnownValues []string `json:"knownValues,omitempty"`
}

// PolicySchemaInfo is one schema found via SearchPolicySchemas - the same
// live catalog Admin console's own policy editor is built on top of. This is
// how app/network/kiosk/print management are reached here: instead of four
// separate hardcoded schema names guessed ahead of time, search finds the
// real schema and its real fields, then SetPolicy/ClearPolicy edit it
// through the same generic mechanism as the curated list.
type PolicySchemaInfo struct {
	SchemaName  string              `json:"schemaName"`
	Description string              `json:"description,omitempty"`
	Category    string              `json:"category,omitempty"`
	Fields      []PolicySchemaField `json:"fields,omitempty"`
}

// DeviceTelemetry comes from the Chrome Management Telemetry API
// (chrome.management.telemetry.readonly), a different API/scope from the
// Directory API fields on Device above. Fetched lazily per-device (only
// when a detail panel is expanded), not on every device list sync - this is
// the same live data Admin console's device detail page shows (storage,
// boot performance, network diagnostics, battery), which the Directory
// API's own DiskVolumeReports doesn't reliably populate.
type DeviceTelemetry struct {
	StorageAvailableBytes       int64         `json:"storageAvailableBytes,omitempty"`
	StorageTotalBytes           int64         `json:"storageTotalBytes,omitempty"`
	BootUpDurationSeconds       float64       `json:"bootUpDurationSeconds,omitempty"`
	LastShutdownTime            *time.Time    `json:"lastShutdownTime,omitempty"`
	LastShutdownDurationSeconds float64       `json:"lastShutdownDurationSeconds,omitempty"`
	LastShutdownReason          string        `json:"lastShutdownReason,omitempty"`
	ConnectionState             string        `json:"connectionState,omitempty"`
	ConnectionType              string        `json:"connectionType,omitempty"`
	LanIpAddress                string        `json:"lanIpAddress,omitempty"`
	GatewayIpAddress            string        `json:"gatewayIpAddress,omitempty"`
	LatencyMs                   float64       `json:"latencyMs,omitempty"`
	LatencyProblem              string        `json:"latencyProblem,omitempty"`
	BatteryHealth               string        `json:"batteryHealth,omitempty"`
	BatteryCycleCount           int64         `json:"batteryCycleCount,omitempty"`
	MemoryAvailableBytes        int64         `json:"memoryAvailableBytes,omitempty"`
	MemoryTotalBytes            int64         `json:"memoryTotalBytes,omitempty"`
	Displays                    []DisplayInfo `json:"displays,omitempty"`
	AudioInputDevice            string        `json:"audioInputDevice,omitempty"`
	AudioOutputDevice           string        `json:"audioOutputDevice,omitempty"`
	AudioOutputVolume           int64         `json:"audioOutputVolume,omitempty"`
	UsbPeripherals              []string      `json:"usbPeripherals,omitempty"`
	AppsUsage                   []AppUsage    `json:"appsUsage,omitempty"`
	// Diagnostic only - how many separate AppReport snapshots Google
	// actually returned for this device, and the oldest one's timestamp.
	// Answers "is Admin console's fuller app list just a longer retention
	// window than this endpoint keeps, or something else" with real numbers
	// instead of a guess.
	AppReportSnapshotCount int        `json:"appReportSnapshotCount,omitempty"`
	AppReportOldestTime    *time.Time `json:"appReportOldestTime,omitempty"`
}

// AppUsage is one entry from AppReport.UsageData - AppId is Google's opaque
// identifier (an extension ID or a chrome:// URL, not a friendly display
// name - there's no app-name catalog available via this API), so it's shown
// as-is rather than invented.
type AppUsage struct {
	AppId                  string  `json:"appId"`
	AppType                string  `json:"appType,omitempty"`
	RunningDurationSeconds float64 `json:"runningDurationSeconds,omitempty"`
}

// DisplayInfo is one entry from GraphicsInfo.DisplayDevices - internal
// (built-in panel) vs external (connected monitor).
type DisplayInfo struct {
	Name     string `json:"name,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// AdminRoleAssignment joins a Directory API role assignment to its role
// name and (for user assignees) email - uses
// admin.directory.rolemanagement.readonly, a new scope, isolated from every
// other token group per the pattern established for the other integrations.
type AdminRoleAssignment struct {
	AssigneeEmail    string `json:"assigneeEmail"`
	AssigneeType     string `json:"assigneeType"` // USER | GROUP
	RoleName         string `json:"roleName"`
	IsSuperAdminRole bool   `json:"isSuperAdminRole"`
	ScopeType        string `json:"scopeType"` // CUSTOMER | ORG_UNIT
	OrgUnitPath      string `json:"orgUnitPath,omitempty"`
}

type DeviceAction struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"deviceId"`
	Action    string    `json:"action"` // restart | wipe | powerwash | screenshot | set_volume | crd | capture_logs | support_packet | disable | enable | deprovision | move
	Status    string    `json:"status"` // pending | complete | error
	Error     string    `json:"error,omitempty"`
	Result    string    `json:"result,omitempty"` // e.g. the CRD session URL - populated only for actions that return one
	CreatedAt time.Time `json:"createdAt"`
}

// actionMinRole gates each device action by the same viewer<operator<admin
// hierarchy used everywhere else. Diagnostic/reversible actions (restart,
// screenshot, remote support session, log/support-packet capture, volume)
// only need operator; anything destructive or account-level (wipe,
// powerwash, disable/enable, deprovision, move between org units) needs
// admin.
var actionMinRole = map[string]string{
	"restart":        RoleOperator,
	"screenshot":     RoleOperator,
	"set_volume":     RoleOperator,
	"crd":            RoleOperator,
	"capture_logs":   RoleOperator,
	"support_packet": RoleOperator,
	"wipe":           RoleAdmin,
	"powerwash":      RoleAdmin,
	"disable":        RoleAdmin,
	"enable":         RoleAdmin,
	"deprovision":    RoleAdmin,
	"move":           RoleAdmin,
}

// The types below come from Google's Chrome Management API
// (chrome.management.reports.readonly scope) - a separate API and scope
// from the Directory API used everywhere else in this connector.

type ChromeVersionCount struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	Count   int64  `json:"count"`
}

type InstalledAppCount struct {
	AppId              string `json:"appId"`
	DisplayName        string `json:"displayName"`
	AppType            string `json:"appType"`
	AppSource          string `json:"appSource,omitempty"`   // CHROME_WEBSTORE | PLAY_STORE
	HomepageUri        string `json:"homepageUri,omitempty"` // used to both link out and, keyed by AppId, resolve the raw IDs device-detail's per-device AppsUsage otherwise shows
	BrowserDeviceCount int64  `json:"browserDeviceCount"`
	OsUserCount        int64  `json:"osUserCount"`
}

type PrinterUsage struct {
	Printer      string `json:"printer"`
	PrinterModel string `json:"printerModel"`
	DeviceCount  int64  `json:"deviceCount"`
	JobCount     int64  `json:"jobCount"`
	UserCount    int64  `json:"userCount"`
}

type CrashEventCount struct {
	BrowserVersion string `json:"browserVersion"`
	Count          int64  `json:"count"`
	Date           string `json:"date,omitempty"` // yyyy-mm-dd
}

type ChromeReports struct {
	ChromeVersions []ChromeVersionCount `json:"chromeVersions"`
	InstalledApps  []InstalledAppCount  `json:"installedApps"`
	AndroidApps    []InstalledAppCount  `json:"androidApps"`
	Printers       []PrinterUsage       `json:"printers"`
	CrashEvents    []CrashEventCount    `json:"crashEvents"`
}

// Thresholds are the user-configurable cutoffs behind several fleet
// insights - exposed via GET/POST /api/chromeos/thresholds so an admin can
// tune them instead of editing source constants.
type Thresholds struct {
	StaleAfterDays     int     `json:"staleAfterDays"`
	OnlineAfterMinutes int     `json:"onlineAfterMinutes"` // separate, finer-grained cousin of StaleAfterDays - drives the Devices table's Online/Offline badge instead of the longer-horizon fleet-hygiene Stale flag
	LowStoragePercent  float64 `json:"lowStoragePercent"`
	LowRamPercent      float64 `json:"lowRamPercent"`
	HotCpuTempCelsius  int     `json:"hotCpuTempCelsius"`
	OutdatedTpmFamily  string  `json:"outdatedTpmFamily"`
}

func defaultThresholds() Thresholds {
	return Thresholds{
		StaleAfterDays:     7,
		OnlineAfterMinutes: 60,
		LowStoragePercent:  10.0,
		LowRamPercent:      15.0,
		HotCpuTempCelsius:  60,
		OutdatedTpmFamily:  "1.2",
	}
}

// ---------- In-memory store (stands in for the credential vault + DB) ----------

type Store struct {
	mu               sync.Mutex
	conn             Connection
	devices          map[string]*Device
	actions          map[string]*DeviceAction
	actionSeq        int
	google           GoogleClient // set in main() - mock or real, see google.go
	syncIntervalMins int
	users            []*DirectoryUser // refreshed alongside devices in runSync
	orgUnits         []*OrgUnitInfo   // refreshed alongside devices in runSync
	churn            []*ChurnRecord   // refreshed alongside devices in runSync
	groups           []*GroupInfo     // refreshed alongside devices in runSync
	thresholds       Thresholds
}

func NewStore() *Store {
	return &Store{
		conn:             Connection{Status: StatusDisconnected},
		devices:          map[string]*Device{},
		actions:          map[string]*DeviceAction{},
		syncIntervalMins: 15,
		thresholds:       defaultThresholds(),
	}
}

var store = NewStore()

// ---------- HTTP handlers ----------
// The mock/real Google client selection lives in google.go. `store.google`
// (set in main()) is a GoogleClient interface - these handlers don't know
// or care which implementation is behind it.

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// POST /api/chromeos/connect/init
// connectorScopes is the full set of domain-wide delegation scopes this
// connector requests, shared by the env-var-driven init flow and the key
// upload flow so both request exactly the same access.
var connectorScopes = []string{
	"https://www.googleapis.com/auth/admin.directory.device.chromeos",
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
	"https://www.googleapis.com/auth/chrome.management.reports.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.readonly",
	"https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
	"https://www.googleapis.com/auth/admin.reports.usage.readonly",
	"https://www.googleapis.com/auth/apps.alerts",
	// chrome.management.policy (not the .readonly variant) - covers both
	// reading and writing policy values. Needed for the Policy compliance
	// tab's edit/clear actions; the readonly scope alone would 403 on
	// SetPolicy/ClearPolicy. Existing connections authorized under the old
	// readonly-only scope list will need domain-wide delegation re-granted
	// with this scope before policy writes will work - see the Connection
	// details panel.
	"https://www.googleapis.com/auth/chrome.management.policy",
	"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
	"https://www.googleapis.com/auth/chrome.management.telemetry.readonly",
}

// domainWideDelegationUrl is Admin console's real "API controls > Domain-wide
// delegation" page - where the admin pastes the client ID + scopes shown
// after upload.
const domainWideDelegationUrl = "https://admin.google.com/ac/owl/domainwidedelegation"

// Generates the OAuth client + scopes the admin needs to paste into Google
// Admin console. This step is fully automated — no human input required.
// Kept as-is for the env-var-driven startup path (GOOGLE_MODE=real with
// GOOGLE_SERVICE_ACCOUNT_KEY etc already set); handleConnectUpload below is
// the browser-driven equivalent that takes the key as a file upload instead.
func handleInit(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()

	clientID := os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	if clientID == "" {
		clientID = "104852073419-8kfj2n5qm1.apps.googleusercontent.com" // mock display value
	}

	store.conn = Connection{
		Status:           StatusPending,
		ClientID:         clientID,
		CustomerID:       os.Getenv("GOOGLE_CUSTOMER_ID"),
		Scopes:           connectorScopes,
		AuthorizationUrl: domainWideDelegationUrl,
	}
	mongoStore.saveConnection(store.conn)
	writeJSON(w, store.conn)
}

// POST /api/chromeos/connect/upload (multipart/form-data: key=<file>,
// adminEmail=<string>, customerId=<string>)
// The browser-driven equivalent of handleInit - the admin uploads the
// service account JSON key and types the admin email + customer ID directly
// in the portal instead of an operator pre-setting GOOGLE_SERVICE_ACCOUNT_KEY/
// GOOGLE_ADMIN_EMAIL/GOOGLE_CUSTOMER_ID env vars before the backend starts.
// The key bytes only ever live in memory for this process - never written to
// local disk. Everything after this (waiting for authorization, finish/sync)
// is the same store.conn-driven flow handleInit already feeds.
func handleConnectUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil { // 1MB is generous for a service account key
		http.Error(w, "invalid upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("key")
	if err != nil {
		http.Error(w, "missing key file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	keyData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "reading key file: "+err.Error(), http.StatusBadRequest)
		return
	}

	adminEmail := r.FormValue("adminEmail")
	customerID := r.FormValue("customerId")
	if adminEmail == "" || customerID == "" {
		http.Error(w, "adminEmail and customerId are required", http.StatusBadRequest)
		return
	}

	var key struct {
		ClientID string `json:"client_id"`
		Type     string `json:"type"`
	}
	if err := json.Unmarshal(keyData, &key); err != nil || key.Type != "service_account" {
		http.Error(w, "not a valid service account JSON key", http.StatusBadRequest)
		return
	}

	client, err := NewRealGoogleClientFromKeyData(r.Context(), keyData, adminEmail, customerID)
	if err != nil {
		http.Error(w, "initializing google client: "+err.Error(), http.StatusBadGateway)
		return
	}

	store.mu.Lock()
	store.google = client
	store.conn = Connection{
		Status:           StatusPending,
		ClientID:         key.ClientID,
		CustomerID:       customerID,
		Scopes:           connectorScopes,
		AuthorizationUrl: domainWideDelegationUrl,
		adminEmail:       adminEmail,
	}
	mongoStore.saveConnection(store.conn)
	store.mu.Unlock()

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.conn)
}

// GET /api/chromeos/connect/status
// The admin has one manual click to make in the real Google Admin console.
// Here we simulate it completing automatically 4 seconds after init, which
// stands in for the backend's polling loop detecting a real consent grant.
func handleConnectStatus(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	pending := store.conn.Status == StatusPending
	store.mu.Unlock()

	if pending {
		// Real mode: this actually calls Google and only advances once
		// the admin has genuinely clicked authorize in Admin console.
		// Mock mode: Probe() always succeeds immediately.
		if err := store.google.Probe(); err == nil {
			store.mu.Lock()
			store.conn.Status = StatusAuthorized
			now := time.Now()
			store.conn.AuthorizedAt = &now
			mongoStore.saveConnection(store.conn)
			store.mu.Unlock()
		} else {
			log.Printf("consent not detected yet: %v", err)
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.conn)
}

// POST /api/chromeos/connect/finish
// Kicks off the sync worker. From here on nothing needs a human.
func handleFinish(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	if store.conn.Status != StatusAuthorized {
		store.mu.Unlock()
		http.Error(w, "not authorized yet", http.StatusConflict)
		return
	}
	store.conn.Status = StatusSyncing
	if store.conn.adminEmail != "" {
		store.conn.ConnectedAccount = store.conn.adminEmail // set by handleConnectUpload
	} else if email := os.Getenv("GOOGLE_ADMIN_EMAIL"); email != "" {
		store.conn.ConnectedAccount = email
	} else {
		store.conn.ConnectedAccount = "admin@acme.com"
	}
	mongoStore.saveConnection(store.conn)
	store.mu.Unlock()

	go runSync()

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.conn)
}

// runSync pulls the current device list from Google (or the mock) and
// replaces the store's device snapshot. Used both for the initial sync
// right after connecting and for every manual/auto sync afterward.
func runSync() {
	devices, err := store.google.ListDevices()
	if err != nil {
		log.Printf("sync failed: %v", err)
		store.mu.Lock()
		store.conn.Status = StatusError
		mongoStore.saveConnection(store.conn)
		store.mu.Unlock()
		return
	}

	fresh := make(map[string]*Device, len(devices))
	store.mu.Lock()
	for _, d := range devices {
		// Preserve custom location tracking data that the extension sent
		// otherwise the Google Directory API sync will wipe it out.
		if old, ok := store.devices[d.ID]; ok {
			d.TrackedLocationLat = old.TrackedLocationLat
			d.TrackedLocationLng = old.TrackedLocationLng
			d.TrackedLocationAccuracy = old.TrackedLocationAccuracy
			d.TrackedLocationTime = old.TrackedLocationTime
			d.TrackedLocationPingInterval = old.TrackedLocationPingInterval
			d.LocationHistory = old.LocationHistory
		}
		fresh[d.ID] = d
	}
	store.mu.Unlock()

	// Users and org units are supplementary context for insights, not the
	// core sync - a failure here shouldn't take down the device sync itself.
	users, err := store.google.ListUsers()
	if err != nil {
		log.Printf("fetching directory users failed (non-fatal): %v", err)
	}
	orgUnits, err := store.google.ListOrgUnits()
	if err != nil {
		log.Printf("fetching org units failed (non-fatal): %v", err)
	}
	churn, err := store.google.ListChurn()
	if err != nil {
		log.Printf("fetching deprovisioned devices failed (non-fatal): %v", err)
	}
	groups, err := store.google.ListGroups()
	if err != nil {
		log.Printf("fetching groups failed (non-fatal, needs admin.directory.group.readonly scope): %v", err)
	}

	store.mu.Lock()
	store.devices = fresh
	store.users = users
	store.orgUnits = orgUnits
	store.churn = churn
	store.groups = groups
	now := time.Now()
	store.conn.Status = StatusActive
	store.conn.DeviceCount = len(devices)
	store.conn.LastSync = &now
	mongoStore.saveConnection(store.conn)
	mongoStore.saveDevices(store.devices)
	mongoStore.saveDirectoryCache(store.users, store.orgUnits, store.churn, store.groups)
	store.mu.Unlock()

	log.Printf("sync complete: %d devices", len(devices))
}

// autoSyncLoop re-runs the sync on a timer whenever the connector is active.
// The interval is re-read from the store each cycle, so a change made via
// POST /api/chromeos/sync/settings takes effect after the current wait ends.
func autoSyncLoop() {
	for {
		store.mu.Lock()
		mins := store.syncIntervalMins
		// Keep retrying through Error too - otherwise one transient failure
		// (e.g. a DNS blip right after the machine wakes from sleep) leaves
		// auto-sync permanently stuck until a manual disconnect/reconnect,
		// instead of self-healing on the next tick like a real MDM agent would.
		retryable := store.conn.Status == StatusActive || store.conn.Status == StatusError
		store.mu.Unlock()

		time.Sleep(time.Duration(mins) * time.Minute)

		if retryable {
			runSync()
		}
	}
}

// POST /api/chromeos/sync
// Triggers an immediate refresh from Google instead of waiting for the
// next auto-sync tick.
func handleSyncNow(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	// Error is a retryable state, not a dead end - a transient failure
	// (confirmed live: a DNS lookup failure right after the machine woke
	// from sleep) shouldn't require a full disconnect/reconnect to recover
	// from. Only block retrying while genuinely mid-setup.
	connected := store.conn.Status == StatusActive || store.conn.Status == StatusError
	store.mu.Unlock()
	if !connected {
		http.Error(w, "not connected", http.StatusConflict)
		return
	}

	runSync()

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.conn)
}

// GET/POST /api/chromeos/sync/settings
// GET returns the current auto-sync interval; POST sets a new one
// (accepts any positive number of minutes, including custom values).
func handleSyncSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		var body struct {
			IntervalMinutes int `json:"intervalMinutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IntervalMinutes <= 0 {
			http.Error(w, "intervalMinutes must be a positive integer", http.StatusBadRequest)
			return
		}
		store.mu.Lock()
		store.syncIntervalMins = body.IntervalMinutes
		mongoStore.saveSettings(store.syncIntervalMins, store.thresholds)
		store.mu.Unlock()
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, map[string]int{"intervalMinutes": store.syncIntervalMins})
}

// GET/POST /api/chromeos/thresholds
// GET returns the current insight thresholds; POST updates any subset of
// them (fields omitted from the body keep their current value).
func handleThresholds(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		store.mu.Lock()
		body := store.thresholds
		store.mu.Unlock()

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.StaleAfterDays <= 0 {
			http.Error(w, "staleAfterDays must be a positive integer", http.StatusBadRequest)
			return
		}
		if body.OnlineAfterMinutes <= 0 {
			http.Error(w, "onlineAfterMinutes must be a positive integer", http.StatusBadRequest)
			return
		}
		if body.LowStoragePercent <= 0 || body.LowStoragePercent > 100 {
			http.Error(w, "lowStoragePercent must be between 0 and 100", http.StatusBadRequest)
			return
		}
		if body.LowRamPercent <= 0 || body.LowRamPercent > 100 {
			http.Error(w, "lowRamPercent must be between 0 and 100", http.StatusBadRequest)
			return
		}
		if body.HotCpuTempCelsius <= 0 {
			http.Error(w, "hotCpuTempCelsius must be a positive integer", http.StatusBadRequest)
			return
		}
		if body.OutdatedTpmFamily == "" {
			http.Error(w, "outdatedTpmFamily must not be empty", http.StatusBadRequest)
			return
		}

		store.mu.Lock()
		store.thresholds = body
		mongoStore.saveSettings(store.syncIntervalMins, store.thresholds)
		store.mu.Unlock()
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.thresholds)
}

// GET /api/chromeos/directory
// Users and org units from the Directory API - refreshed alongside devices
// in runSync, so this just reads the last-fetched snapshot.
func handleDirectory(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, map[string]any{
		"users":    store.users,
		"orgUnits": store.orgUnits,
		"groups":   store.groups,
	})
}

// GET /api/chromeos/mobile-devices
// Live call, not cached - the mobile fleet is viewed occasionally, not
// polled. Requires admin.directory.device.mobile.readonly, a new scope.
func handleMobileDevices(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	devices, err := google.ListMobileDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching mobile devices: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, devices)
}

// GET /api/chromeos/audit-log
// Requires admin.reports.audit.readonly, a new scope - a different API
// (Admin SDK Reports API) from the Chrome Management reports built earlier.
func handleAuditLog(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	auditLog, err := google.ListAuditLog()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching audit log: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, auditLog)
}

// GET /api/chromeos/security-alerts
// Requires apps.alerts, a new scope - the Alert Center API, which covers
// DLP violations, compromised accounts, phishing, and other security
// sources, not just device management.
func handleSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	alerts, err := google.ListSecurityAlerts()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching security alerts: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, alerts)
}

// POST /api/chromeos/security-alerts/action
// body: {"alertId": "...", "action": "delete" | "undelete" | "feedback", "feedbackType": "VERY_USEFUL"}
// Real, live effect on Google's side: delete/undelete change whether the
// alert shows in Admin console's own Alert Center too (soft-delete, not a
// portal-local hide). There's no public API to set an alert's Status or
// Assignee - only delete/undelete/feedback are real write actions here (see
// the GoogleClient interface comment on DeleteAlert for why). Gated at
// RoleAdmin, same tier as the other real-Google-state writes in this app.
func handleSecurityAlertAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AlertID      string `json:"alertId"`
		Action       string `json:"action"`
		FeedbackType string `json:"feedbackType,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AlertID == "" || body.Action == "" {
		http.Error(w, "alertId and action are required", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	var err error
	switch body.Action {
	case "delete":
		err = google.DeleteAlert(body.AlertID)
	case "undelete":
		err = google.UndeleteAlert(body.AlertID)
	case "feedback":
		if body.FeedbackType == "" {
			http.Error(w, "feedbackType is required for the feedback action", http.StatusBadRequest)
			return
		}
		err = google.SubmitAlertFeedback(body.AlertID, body.FeedbackType)
	default:
		http.Error(w, "unsupported action: "+body.Action, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// GET /api/chromeos/policies
// Requires chrome.management.policy (read+write scope, covers reads too) -
// the Chrome Policy API, showing the actual enforced policy value, not just
// whether a device reports itself compliant.
func handlePolicies(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	policies, err := google.ListPolicies()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching policies: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, policies)
}

// GET /api/chromeos/policies/search?q=extension
// Searches the Chrome Policy API's real schema catalog by keyword - how
// app/network/kiosk/print management are reached here instead of four
// separate hardcoded schema names. Read-only (RoleViewer): finding a schema
// isn't itself a change, only SetPolicy/ClearPolicy are.
func handlePolicySearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	results, err := google.SearchPolicySchemas(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("searching policy schemas: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, results)
}

// POST /api/chromeos/policies/set
// body: {"orgUnitPath": "/Engineering", "schemaName": "chrome.devices.GuestMode", "value": {"guestModeEnabled": false}}
// Requires chrome.management.policy - the write half of the scope handlePolicies
// reads with. Real, live effect: this changes what Google enforces on every
// device/user in that org unit, the same as an edit in Admin console. Gated
// at RoleAdmin at the route level (see mux registration below).
func handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrgUnitPath string          `json:"orgUnitPath"`
		SchemaName  string          `json:"schemaName"`
		Value       json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.OrgUnitPath == "" || body.SchemaName == "" || len(body.Value) == 0 {
		http.Error(w, "orgUnitPath, schemaName, and value are required", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	if err := google.SetPolicy(body.OrgUnitPath, body.SchemaName, body.Value); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// POST /api/chromeos/policies/clear
// body: {"orgUnitPath": "/Engineering", "schemaName": "chrome.devices.GuestMode"}
// Removes the explicit override on that org unit so it inherits from its
// parent again - Admin console's "Inherit" toggle. Same real-effect and
// role-gating notes as handleSetPolicy above.
func handleClearPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrgUnitPath string `json:"orgUnitPath"`
		SchemaName  string `json:"schemaName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.OrgUnitPath == "" || body.SchemaName == "" {
		http.Error(w, "orgUnitPath and schemaName are required", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	if err := google.ClearPolicy(body.OrgUnitPath, body.SchemaName); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// GET /api/chromeos/devices/telemetry?id=...
// Requires chrome.management.telemetry.readonly, a new scope - fetched only
// when a device's detail panel is expanded, not as part of the regular
// device sync (this is a per-device call, expensive to run for every
// device on every poll).
func handleDeviceTelemetry(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	t, err := google.GetDeviceTelemetry(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching device telemetry: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, t)
}

// GET /api/chromeos/admin-roles
// Requires admin.directory.rolemanagement.readonly, a new scope - who holds
// which Google Admin role (Super Admin, custom roles, etc), not this app's
// own login roles (see auth.go for that).
func handleAdminRoles(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	roles, err := google.ListAdminRoles()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching admin roles: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, roles)
}

// GET /api/chromeos/chrome-reports
// Calls the Chrome Management API live on every request rather than caching
// in the store - these reports are viewed occasionally from the Reports
// tab, not polled every few seconds like devices. Requires the
// chrome.management.reports.readonly scope, granted separately from the
// Directory API scopes used everywhere else in this connector.
func handleChromeReports(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	google := store.google
	store.mu.Unlock()

	reports, err := google.ListChromeReports()
	if err != nil {
		http.Error(w, fmt.Sprintf("fetching Chrome reports: %v", err), http.StatusBadGateway)
		return
	}
	writeJSON(w, reports)
}

// GET /api/chromeos/status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()
	writeJSON(w, store.conn)
}

// GET /api/chromeos/devices
func handleDevices(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()
	staleAfter := time.Duration(store.thresholds.StaleAfterDays) * 24 * time.Hour
	onlineAfter := time.Duration(store.thresholds.OnlineAfterMinutes) * time.Minute
	now := time.Now()
	list := make([]*Device, 0, len(store.devices))
	for _, d := range store.devices {
		// Google's own Status field is provisioning state (ACTIVE/DISABLED/
		// DEPROVISIONED), not connectivity - a device can be provisioned
		// ACTIVE and still not have synced in months. Stale is computed
		// fresh on every read so it always reflects the current threshold.
		d.Stale = d.Status == "active" && now.Sub(d.LastSeen) > staleAfter
		// Online is a real signal (LastSync, the real thing Google reports),
		// just bucketed on a much shorter window than Stale - there's no
		// "is it connected right now" field anywhere in the Directory or
		// Chrome Management APIs, so this is the closest honest
		// approximation: recently synced = online, otherwise not. It is
		// NOT driven by telemetry's connection_state, which is deliberately
		// excluded here - that field is cached on-device and only uploads
		// once the device reconnects, so it can still read "Online" hours
		// after a device actually went dark.
		d.Online = d.Status == "active" && now.Sub(d.LastSeen) <= onlineAfter
		list = append(list, d)
	}
	writeJSON(w, list)
}

// Non-configurable thresholds - narrower/less commonly tuned than the ones
// exposed via the Settings tab (see Thresholds / defaultThresholds above).
const (
	expiringSoonAfter = 90 * 24 * time.Hour // AUE within this window -> flagged
	staleLoginDays    = 30                  // user hasn't logged in this long but device synced recently -> flagged
	sharedDeviceUsers = 3                   // recent users at/above this count -> flagged as shared
)

const recentActionsLimit = 10

type ExpiringDevice struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	AutoUpdateExpiration time.Time `json:"autoUpdateExpiration"`
	DaysRemaining        int       `json:"daysRemaining"`
}

type DeviceRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ActionCount struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

type StorageWarning struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	FreeGB      float64 `json:"freeGb"`
	TotalGB     float64 `json:"totalGb"`
	PercentFree float64 `json:"percentFree"`
}

type RamWarning struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	FreeMB      float64 `json:"freeMb"`
	TotalMB     float64 `json:"totalMb"`
	PercentFree float64 `json:"percentFree"`
}

// DeviceMetric is a generic device+human-readable-value pair, reused across
// several unrelated insight lists (orphaned devices, login/sync mismatches,
// shared devices, hot CPUs, outdated TPM) instead of one bespoke struct each.
type DeviceMetric struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type OrgUnitStat struct {
	Path    string `json:"path"`
	Total   int    `json:"total"`
	Active  int    `json:"active"`
	Offline int    `json:"offline"`
}

// MonthlyCount is a generic (label, count) pair for time-bucketed insights -
// currently just the enrollment trend, but shaped to be reused.
type MonthlyCount struct {
	Month         string `json:"month"` // yyyy-mm
	Count         int    `json:"count"`
	ChromeOsCount int    `json:"chromeOsCount"`
	FlexCount     int    `json:"flexCount"`
}

// DirectoryHealth surfaces directory-wide hygiene signals that aren't tied
// to any one device - computed from the same Users/Groups data already
// fetched in runSync, no extra Google API calls.
type DirectoryHealth struct {
	SuspendedUsers     int `json:"suspendedUsers"`
	UsersNeverLoggedIn int `json:"usersNeverLoggedIn"`
	EmptyGroups        int `json:"emptyGroups"`
	TotalUsers         int `json:"totalUsers"`
	TotalGroups        int `json:"totalGroups"`
}

type RecentAction struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Action     string    `json:"action"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
}

type FleetInsights struct {
	TotalDevices              int              `json:"totalDevices"`
	ActiveDevices             int              `json:"activeDevices"`
	OfflineDevices            int              `json:"offlineDevices"`
	StaleDevices              int              `json:"staleDevices"`
	StaleAfterDays            int              `json:"staleAfterDays"`
	OsVersions                map[string]int   `json:"osVersions"`
	Models                    map[string]int   `json:"models"`
	FirmwareVersions          map[string]int   `json:"firmwareVersions"`
	LicenseTypes              map[string]int   `json:"licenseTypes"`
	ChromeOsTypes             map[string]int   `json:"chromeOsTypes"`
	Locations                 map[string]int   `json:"locations"`
	DevicesWithoutLocation    int              `json:"devicesWithoutLocation"`
	PendingUpdateDevices      []DeviceMetric   `json:"pendingUpdateDevices"`
	ExpiringSoon              []ExpiringDevice `json:"expiringSoon"`
	DevModeDevices            []DeviceRef      `json:"devModeDevices"`
	ExtendedSupportNeeded     []DeviceRef      `json:"extendedSupportNeeded"`
	AverageFleetAgeYears      float64          `json:"averageFleetAgeYears"`
	DevicesOverThreeYears     int              `json:"devicesOverThreeYears"`
	StorageWarnings           []StorageWarning `json:"storageWarnings"`
	RamWarnings               []RamWarning     `json:"ramWarnings"`
	DevicesWithNetworkInfo    int              `json:"devicesWithNetworkInfo"`
	DevicesWithoutNetworkInfo int              `json:"devicesWithoutNetworkInfo"`
	OrphanedDevices           []DeviceMetric   `json:"orphanedDevices"`
	LoginSyncMismatches       []DeviceMetric   `json:"loginSyncMismatches"`
	SharedDevices             []DeviceMetric   `json:"sharedDevices"`
	HotDevices                []DeviceMetric   `json:"hotDevices"`
	OutdatedTpmDevices        []DeviceMetric   `json:"outdatedTpmDevices"`
	TotalUsageMinutesToday    int              `json:"totalUsageMinutesToday"`
	AverageUsageMinutesToday  float64          `json:"averageUsageMinutesToday"`
	IdleDevices               []DeviceRef      `json:"idleDevices"`
	OrgUnitBreakdown          []OrgUnitStat    `json:"orgUnitBreakdown"`
	ChurnRecords              []ChurnRecord    `json:"churnRecords"`
	ActionCounts              []ActionCount    `json:"actionCounts"`
	RecentActions             []RecentAction   `json:"recentActions"`
	ProvisionStatusCounts     map[string]int   `json:"provisionStatusCounts"`
	BootModeCounts            map[string]int   `json:"bootModeCounts"`
	UpdateStatusCounts        map[string]int   `json:"updateStatusCounts"`
	EnrollmentTrend           []MonthlyCount   `json:"enrollmentTrend"`
	DirectoryHealth           DirectoryHealth  `json:"directoryHealth"`
}

// GET /api/chromeos/insights
// Aggregates fleet health from the devices already pulled by the last sync,
// plus locally tracked action history - no extra Google API calls beyond
// what ListDevices already fetched.
func handleInsights(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()

	now := time.Now()
	thresholds := store.thresholds
	staleAfter := time.Duration(thresholds.StaleAfterDays) * 24 * time.Hour
	onlineAfter := time.Duration(thresholds.OnlineAfterMinutes) * time.Minute
	insights := FleetInsights{
		StaleAfterDays:        thresholds.StaleAfterDays,
		OsVersions:            map[string]int{},
		Models:                map[string]int{},
		FirmwareVersions:      map[string]int{},
		LicenseTypes:          map[string]int{},
		ChromeOsTypes:         map[string]int{},
		Locations:             map[string]int{},
		PendingUpdateDevices:  []DeviceMetric{},
		ExpiringSoon:          []ExpiringDevice{},
		DevModeDevices:        []DeviceRef{},
		ExtendedSupportNeeded: []DeviceRef{},
		StorageWarnings:       []StorageWarning{},
		RamWarnings:           []RamWarning{},
		OrphanedDevices:       []DeviceMetric{},
		LoginSyncMismatches:   []DeviceMetric{},
		SharedDevices:         []DeviceMetric{},
		HotDevices:            []DeviceMetric{},
		OutdatedTpmDevices:    []DeviceMetric{},
		IdleDevices:           []DeviceRef{},
		OrgUnitBreakdown:      []OrgUnitStat{},
		ChurnRecords:          []ChurnRecord{},
		ProvisionStatusCounts: map[string]int{},
		BootModeCounts:        map[string]int{},
		UpdateStatusCounts:    map[string]int{},
		EnrollmentTrend:       []MonthlyCount{},
		ActionCounts:          []ActionCount{},
		RecentActions:         []RecentAction{},
	}

	usersByEmail := make(map[string]*DirectoryUser, len(store.users))
	for _, u := range store.users {
		usersByEmail[u.Email] = u
	}

	var ageYearsSum float64
	var ageCount int
	var usageMinutesSum int
	enrollmentMonths := map[string]int{}
	enrollmentMonthsChromeOs := map[string]int{}
	enrollmentMonthsFlex := map[string]int{}

	for _, d := range store.devices {
		insights.TotalDevices++
		stale := now.Sub(d.LastSeen) > staleAfter
		if stale {
			insights.StaleDevices++
		}
		// This is the SAME signal as the Devices table's Connection column
		// (online-after-minutes), not the days-granularity Stale flag above -
		// they used to be the same computation, which meant this donut and
		// the table's "Sync status" column both claimed to show "Active" for
		// a device that hadn't synced in hours, while the table's separate
		// Connection column already said Offline for it. Using the shorter
		// threshold here instead makes "Active/Offline" mean the same thing
		// everywhere in the app.
		if d.Status == "active" && now.Sub(d.LastSeen) <= onlineAfter {
			insights.ActiveDevices++
		} else {
			insights.OfflineDevices++
		}
		if d.OsVersion != "" {
			insights.OsVersions[d.OsVersion]++
		}
		if d.AutoUpdateExpiration != nil && d.AutoUpdateExpiration.Sub(now) <= expiringSoonAfter {
			insights.ExpiringSoon = append(insights.ExpiringSoon, ExpiringDevice{
				ID:                   d.ID,
				Name:                 d.Name,
				AutoUpdateExpiration: *d.AutoUpdateExpiration,
				DaysRemaining:        int(d.AutoUpdateExpiration.Sub(now).Hours() / 24),
			})
		}
		if d.BootMode == "Dev" {
			insights.DevModeDevices = append(insights.DevModeDevices, DeviceRef{ID: d.ID, Name: d.Name})
		}
		if d.Model != "" {
			insights.Models[d.Model]++
		}
		if d.FirmwareVersion != "" {
			insights.FirmwareVersions[d.FirmwareVersion]++
		}
		if d.DeviceLicenseType != "" {
			insights.LicenseTypes[d.DeviceLicenseType]++
		}
		if d.ChromeOsType != "" {
			insights.ChromeOsTypes[d.ChromeOsType]++
		}
		if d.Location != "" {
			// Location is a free-text admin annotation ("Building A, Floor 2,
			// Desk 14") - grouping on the full string would make every device
			// its own bucket, so this takes just the first comma-separated
			// segment as a building-level grouping.
			building := strings.TrimSpace(strings.SplitN(d.Location, ",", 2)[0])
			insights.Locations[building]++
		} else {
			insights.DevicesWithoutLocation++
		}
		if d.OsUpdateState == "updateStateNeedReboot" || d.OsUpdateState == "updateStateDownloadInProgress" || d.OsUpdateState == "updateStateNotStarted" {
			insights.PendingUpdateDevices = append(insights.PendingUpdateDevices, DeviceMetric{
				ID: d.ID, Name: d.Name, Value: strings.TrimPrefix(d.OsUpdateState, "updateState"),
			})
		}
		if d.ExtendedSupportEligible && !d.ExtendedSupportEnabled {
			insights.ExtendedSupportNeeded = append(insights.ExtendedSupportNeeded, DeviceRef{ID: d.ID, Name: d.Name})
		}
		if d.ManufactureDate != "" {
			if manufactured, err := time.Parse("2006-01-02", d.ManufactureDate); err == nil {
				ageYears := now.Sub(manufactured).Hours() / 24 / 365.25
				ageYearsSum += ageYears
				ageCount++
				if ageYears > 3 {
					insights.DevicesOverThreeYears++
				}
			}
		}
		if d.StorageTotalBytes > 0 {
			percentFree := math.Round(float64(d.StorageFreeBytes) / float64(d.StorageTotalBytes) * 100)
			if percentFree <= thresholds.LowStoragePercent {
				const gb = 1024 * 1024 * 1024
				insights.StorageWarnings = append(insights.StorageWarnings, StorageWarning{
					ID:          d.ID,
					Name:        d.Name,
					FreeGB:      math.Round(float64(d.StorageFreeBytes)/gb*10) / 10,
					TotalGB:     math.Round(float64(d.StorageTotalBytes)/gb*10) / 10,
					PercentFree: math.Round(percentFree*10) / 10,
				})
			}
		}
		if d.RamTotalBytes > 0 {
			percentFree := math.Round(float64(d.RamFreeBytes) / float64(d.RamTotalBytes) * 100)
			if percentFree <= thresholds.LowRamPercent {
				const mb = 1024 * 1024
				insights.RamWarnings = append(insights.RamWarnings, RamWarning{
					ID:          d.ID,
					Name:        d.Name,
					FreeMB:      math.Round(float64(d.RamFreeBytes) / mb),
					TotalMB:     math.Round(float64(d.RamTotalBytes) / mb),
					PercentFree: math.Round(percentFree*10) / 10,
				})
			}
		}
		if d.LastKnownIP != "" {
			insights.DevicesWithNetworkInfo++
		} else {
			insights.DevicesWithoutNetworkInfo++
		}

		usageMinutesSum += d.ActiveTimeTodayMinutes
		// Only flag devices that are online but unused, not offline devices -
		// an offline device trivially has zero usage and is already covered
		// by the staleness signal; a device that checked in today with zero
		// usage is the genuinely odd case (powered on, sitting idle/lost).
		if d.Status == "active" && d.ActiveTimeTodayMinutes == 0 {
			insights.IdleDevices = append(insights.IdleDevices, DeviceRef{ID: d.ID, Name: d.Name})
		}

		if d.RecentUserEmail != "" {
			if u, ok := usersByEmail[d.RecentUserEmail]; ok {
				if u.Suspended {
					insights.OrphanedDevices = append(insights.OrphanedDevices, DeviceMetric{ID: d.ID, Name: d.Name, Value: u.Email})
				}
				if u.LastLoginTime != nil && d.Status == "active" {
					daysSinceLogin := int(now.Sub(*u.LastLoginTime).Hours() / 24)
					if daysSinceLogin > staleLoginDays {
						insights.LoginSyncMismatches = append(insights.LoginSyncMismatches, DeviceMetric{
							ID: d.ID, Name: d.Name, Value: fmt.Sprintf("%dd since %s logged in", daysSinceLogin, u.Email),
						})
					}
				}
			}
		}
		if d.RecentUserCount >= sharedDeviceUsers {
			insights.SharedDevices = append(insights.SharedDevices, DeviceMetric{
				ID: d.ID, Name: d.Name, Value: fmt.Sprintf("%d recent users", d.RecentUserCount),
			})
		}
		if d.CpuTempCelsius >= int64(thresholds.HotCpuTempCelsius) {
			insights.HotDevices = append(insights.HotDevices, DeviceMetric{
				ID: d.ID, Name: d.Name, Value: fmt.Sprintf("%d°C", d.CpuTempCelsius),
			})
		}
		if d.TpmFamily == thresholds.OutdatedTpmFamily {
			insights.OutdatedTpmDevices = append(insights.OutdatedTpmDevices, DeviceMetric{
				ID: d.ID, Name: d.Name, Value: fmt.Sprintf("TPM %s", d.TpmFamily),
			})
		}

		provisionStatus := d.ProvisionStatus
		if provisionStatus == "" {
			provisionStatus = "ACTIVE"
		}
		insights.ProvisionStatusCounts[provisionStatus]++

		bootMode := d.BootMode
		if bootMode == "" {
			bootMode = "Verified"
		}
		insights.BootModeCounts[bootMode]++

		if d.OsUpdateState == "updateStateNeedReboot" || d.OsUpdateState == "updateStateDownloadInProgress" || d.OsUpdateState == "updateStateNotStarted" {
			insights.UpdateStatusCounts["Pending"]++
		} else {
			insights.UpdateStatusCounts["Up to date"]++
		}

		// LastEnrollmentTime, not FirstEnrollmentTime - a device re-enrolled
		// (wiped and re-set-up) this month has a recent LastEnrollmentTime
		// but an old FirstEnrollmentTime, and "recent enrollment activity" is
		// what this trend is meant to show (confirmed live: a device first
		// enrolled 10 months ago but re-enrolled last week showed nothing in
		// this chart until switched to LastEnrollmentTime).
		if d.LastEnrollmentTime != nil {
			month := d.LastEnrollmentTime.Format("2006-01")
			enrollmentMonths[month]++
			if d.ChromeOsType == "chromeOsFlex" {
				enrollmentMonthsFlex[month]++
			} else {
				enrollmentMonthsChromeOs[month]++
			}
		}
	}
	// Deliberately NOT folding store.churn into ProvisionStatusCounts here -
	// churn devices are historical (deprovisioned, no longer in
	// store.devices) and already get their own detailed breakdown via
	// ChurnRecords below (the "Fleet churn" card, with reason/org unit per
	// device). Merging them into this donut's DEPROVISIONED bucket made its
	// total exceed TotalDevices - comparing "devices we currently track" to
	// "devices that left the fleet" isn't the same measurement.

	// Last 6 calendar months, oldest first, including months with zero
	// enrollments so the trend line doesn't silently skip a quiet month.
	for i := 5; i >= 0; i-- {
		month := now.AddDate(0, -i, 0).Format("2006-01")
		insights.EnrollmentTrend = append(insights.EnrollmentTrend, MonthlyCount{
			Month: month, Count: enrollmentMonths[month],
			ChromeOsCount: enrollmentMonthsChromeOs[month], FlexCount: enrollmentMonthsFlex[month],
		})
	}

	insights.DirectoryHealth.TotalUsers = len(store.users)
	for _, u := range store.users {
		if u.Suspended {
			insights.DirectoryHealth.SuspendedUsers++
		}
		if u.LastLoginTime == nil {
			insights.DirectoryHealth.UsersNeverLoggedIn++
		}
	}
	insights.DirectoryHealth.TotalGroups = len(store.groups)
	for _, g := range store.groups {
		if g.MemberCount == 0 {
			insights.DirectoryHealth.EmptyGroups++
		}
	}

	if ageCount > 0 {
		insights.AverageFleetAgeYears = math.Round(ageYearsSum/float64(ageCount)*10) / 10
	}
	insights.TotalUsageMinutesToday = usageMinutesSum
	if insights.TotalDevices > 0 {
		insights.AverageUsageMinutesToday = math.Round(float64(usageMinutesSum)/float64(insights.TotalDevices)*10) / 10
	}

	// Org-unit breakdown starts from every known OU (including ones with zero
	// devices) so empty departments are visible, not just the ones with devices.
	ouStats := make(map[string]*OrgUnitStat, len(store.orgUnits))
	for _, ou := range store.orgUnits {
		ouStats[ou.Path] = &OrgUnitStat{Path: ou.Path}
	}
	for _, d := range store.devices {
		s, ok := ouStats[d.OrgUnit]
		if !ok {
			s = &OrgUnitStat{Path: d.OrgUnit}
			ouStats[d.OrgUnit] = s
		}
		s.Total++
		if d.Status == "active" {
			s.Active++
		} else {
			s.Offline++
		}
	}
	for _, s := range ouStats {
		insights.OrgUnitBreakdown = append(insights.OrgUnitBreakdown, *s)
	}
	sort.Slice(insights.OrgUnitBreakdown, func(i, j int) bool {
		return insights.OrgUnitBreakdown[i].Path < insights.OrgUnitBreakdown[j].Path
	})

	for _, c := range store.churn {
		insights.ChurnRecords = append(insights.ChurnRecords, *c)
	}
	sort.Slice(insights.ChurnRecords, func(i, j int) bool {
		return insights.ChurnRecords[i].Name < insights.ChurnRecords[j].Name
	})

	sort.Slice(insights.PendingUpdateDevices, func(i, j int) bool {
		return insights.PendingUpdateDevices[i].Name < insights.PendingUpdateDevices[j].Name
	})
	sort.Slice(insights.OrphanedDevices, func(i, j int) bool {
		return insights.OrphanedDevices[i].Name < insights.OrphanedDevices[j].Name
	})
	sort.Slice(insights.LoginSyncMismatches, func(i, j int) bool {
		return insights.LoginSyncMismatches[i].Name < insights.LoginSyncMismatches[j].Name
	})
	sort.Slice(insights.SharedDevices, func(i, j int) bool {
		return insights.SharedDevices[i].Name < insights.SharedDevices[j].Name
	})
	sort.Slice(insights.HotDevices, func(i, j int) bool {
		return insights.HotDevices[i].Name < insights.HotDevices[j].Name
	})
	sort.Slice(insights.OutdatedTpmDevices, func(i, j int) bool {
		return insights.OutdatedTpmDevices[i].Name < insights.OutdatedTpmDevices[j].Name
	})
	sort.Slice(insights.IdleDevices, func(i, j int) bool {
		return insights.IdleDevices[i].Name < insights.IdleDevices[j].Name
	})

	sort.Slice(insights.ExpiringSoon, func(i, j int) bool {
		return insights.ExpiringSoon[i].DaysRemaining < insights.ExpiringSoon[j].DaysRemaining
	})
	sort.Slice(insights.DevModeDevices, func(i, j int) bool {
		return insights.DevModeDevices[i].Name < insights.DevModeDevices[j].Name
	})
	sort.Slice(insights.ExtendedSupportNeeded, func(i, j int) bool {
		return insights.ExtendedSupportNeeded[i].Name < insights.ExtendedSupportNeeded[j].Name
	})
	sort.Slice(insights.StorageWarnings, func(i, j int) bool {
		return insights.StorageWarnings[i].PercentFree < insights.StorageWarnings[j].PercentFree
	})
	sort.Slice(insights.RamWarnings, func(i, j int) bool {
		return insights.RamWarnings[i].PercentFree < insights.RamWarnings[j].PercentFree
	})

	actionCounts := map[string]int{}
	allActions := make([]*DeviceAction, 0, len(store.actions))
	for _, a := range store.actions {
		actionCounts[a.Action]++
		allActions = append(allActions, a)
	}
	for action, count := range actionCounts {
		insights.ActionCounts = append(insights.ActionCounts, ActionCount{Action: action, Count: count})
	}
	sort.Slice(insights.ActionCounts, func(i, j int) bool {
		return insights.ActionCounts[i].Action < insights.ActionCounts[j].Action
	})

	sort.Slice(allActions, func(i, j int) bool {
		return allActions[i].CreatedAt.After(allActions[j].CreatedAt)
	})
	if len(allActions) > recentActionsLimit {
		allActions = allActions[:recentActionsLimit]
	}
	for _, a := range allActions {
		deviceName := a.DeviceID
		if d, ok := store.devices[a.DeviceID]; ok {
			deviceName = d.Name
		}
		insights.RecentActions = append(insights.RecentActions, RecentAction{
			ID:         a.ID,
			DeviceID:   a.DeviceID,
			DeviceName: deviceName,
			Action:     a.Action,
			Status:     a.Status,
			CreatedAt:  a.CreatedAt,
		})
	}

	writeJSON(w, insights)
}

// POST /api/chromeos/devices/{id}/action  { "action": "restart" }
// Restart only needs operator; wipe is destructive and needs admin - one
// route serves both, so the role check happens here instead of at the mux
// level, based on which action was actually requested.
func handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	sess, ok := sessionFromRequest(r)
	if !ok {
		http.Error(w, "session expired or invalid", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("id")
	var body struct {
		Action  string `json:"action"`
		Payload string `json:"payload,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	minRole, ok := actionMinRole[body.Action]
	if !ok {
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	if roleRank[sess.Role] < roleRank[minRole] {
		http.Error(w, "insufficient role for this action", http.StatusForbidden)
		return
	}

	store.mu.Lock()
	if _, ok := store.devices[id]; !ok {
		store.mu.Unlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	store.actionSeq++
	action := &DeviceAction{
		ID:        randID("act"),
		DeviceID:  id,
		Action:    body.Action,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	store.actions[action.ID] = action
	mongoStore.saveAction(action)
	store.mu.Unlock()

	// Mock client sleeps 2s then returns nil. Real client actually calls
	// Google's issueCommand API and this is where a real failure (e.g.
	// unsupported command, device offline) would surface.
	go func() {
		result, err := store.google.DoAction(id, body.Action, body.Payload)
		store.mu.Lock()
		if err == nil {
			// Optimistic local update, not a re-sync - confirmed live that
			// Google's Chromeosdevices.List (what runSync uses) lags a real
			// Get() by several seconds after disable/enable/deprovision/move,
			// so re-syncing right away just re-reads the still-stale value.
			// The next scheduled/manual sync will reconcile with whatever
			// Google's List eventually reports.
			if d, ok := store.devices[id]; ok {
				switch body.Action {
				case "disable":
					d.ProvisionStatus, d.Status = "DISABLED", "offline"
					mongoStore.saveDevice(d)
				case "enable":
					d.ProvisionStatus, d.Status = "ACTIVE", "active"
					mongoStore.saveDevice(d)
				case "deprovision":
					delete(store.devices, id) // matches what the next real sync will show - deprovisioned devices aren't in the active list
					mongoStore.saveDevices(store.devices)
				case "move":
					d.OrgUnit = body.Payload
					mongoStore.saveDevice(d)
				}
			}
		}
		if err != nil {
			action.Status = "error"
			action.Error = err.Error()
			log.Printf("action %s on device %s failed: %v", body.Action, id, err)
		} else {
			action.Status = "complete"
			action.Result = result
		}
		mongoStore.saveAction(action)
		store.mu.Unlock()
	}()

	writeJSON(w, action)
}

// GET /api/chromeos/device-events?hours=24&types=NETWORK_STATE_CHANGE,USB_ADDED
// hours defaults to 24 if omitted/invalid; types defaults to
// defaultTelemetryEventTypes (see google.go) if omitted. DeviceName is
// resolved against the currently-synced device list so the frontend never
// has to show a bare opaque device ID.
func handleDeviceEvents(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h > 0 {
		hours = h
	}
	var types []string
	if t := r.URL.Query().Get("types"); t != "" {
		types = strings.Split(t, ",")
	}

	events, err := store.google.ListDeviceEvents(types, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	store.mu.Lock()
	for _, e := range events {
		if d, ok := store.devices[e.DeviceID]; ok {
			e.DeviceName = d.Name
		}
	}
	store.mu.Unlock()

	sort.Slice(events, func(i, j int) bool { return events[i].ReportTime.After(events[j].ReportTime) })
	writeJSON(w, events)
}

// POST /api/chromeos/devices/batch-move {ids: [...], orgUnit: "..."}
// One API call (Chromeosdevices.MoveDevicesToOu) for the whole selection
// instead of looping handleDeviceAction's single-device "move" N times -
// same admin-only gate as the single-device move, since it's the same
// provisioning-affecting action just applied to more than one device.
func handleBatchMove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs     []string `json:"ids"`
		OrgUnit string   `json:"orgUnit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IDs) == 0 || body.OrgUnit == "" {
		http.Error(w, "ids (non-empty) and orgUnit are required", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	for _, id := range body.IDs {
		if _, ok := store.devices[id]; !ok {
			store.mu.Unlock()
			http.Error(w, fmt.Sprintf("device not found: %s", id), http.StatusNotFound)
			return
		}
	}
	store.mu.Unlock()

	if err := store.google.BatchMoveDevices(body.IDs, body.OrgUnit); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Optimistic local update, same reasoning as the single-device move case
	// in handleDeviceAction - Google's List() lags a direct Get() by several
	// seconds, so re-syncing right now would just show the stale org unit.
	store.mu.Lock()
	for _, id := range body.IDs {
		if d, ok := store.devices[id]; ok {
			d.OrgUnit = body.OrgUnit
			mongoStore.saveDevice(d)
		}
	}
	store.mu.Unlock()

	writeJSON(w, map[string]any{"moved": len(body.IDs), "orgUnit": body.OrgUnit})
}

// GET /api/chromeos/actions/{id}
func handleActionStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	store.mu.Lock()
	defer store.mu.Unlock()
	a, ok := store.actions[id]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, a)
}

// POST /api/chromeos/disconnect
func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.conn = Connection{Status: StatusDisconnected}
	store.devices = map[string]*Device{}
	mongoStore.saveConnection(store.conn)
	mongoStore.saveDevices(store.devices)
	writeJSON(w, store.conn)
}

func handleLocationUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		DeviceID string `json:"deviceId"`
		Location struct {
			Lat       float64 `json:"lat"`
			Lng       float64 `json:"lng"`
			Accuracy  float64 `json:"accuracy"`
			Timestamp int64   `json:"timestamp"`
		} `json:"location"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var interval int = 15 // Default 15 minutes

	store.mu.Lock()
	if dev, ok := store.devices[body.DeviceID]; ok {
		dev.TrackedLocationLat = body.Location.Lat
		dev.TrackedLocationLng = body.Location.Lng
		dev.TrackedLocationAccuracy = body.Location.Accuracy
		dev.TrackedLocationTime = body.Location.Timestamp

		// Append to history
		ping := LocationPing{
			Lat:       body.Location.Lat,
			Lng:       body.Location.Lng,
			Accuracy:  body.Location.Accuracy,
			Timestamp: body.Location.Timestamp,
		}
		dev.LocationHistory = append(dev.LocationHistory, ping)
		if len(dev.LocationHistory) > 50 {
			dev.LocationHistory = dev.LocationHistory[1:] // keep last 50
		}

		if dev.TrackedLocationPingInterval > 0 {
			interval = dev.TrackedLocationPingInterval
		}

		log.Printf("Updated tracked location for device %s to %f, %f", dev.Name, dev.TrackedLocationLat, dev.TrackedLocationLng)
	} else {
		log.Printf("Location received for unknown device ID %s: %f, %f", body.DeviceID, body.Location.Lat, body.Location.Lng)
	}
	store.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"intervalMinutes": interval})
}

// handleLocationIntervalUpdate configures how frequently a device should ping its location
func handleLocationIntervalUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DeviceID string `json:"deviceId"`
		Interval int    `json:"intervalMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	dev, ok := store.devices[req.DeviceID]
	if !ok {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	dev.TrackedLocationPingInterval = req.Interval
	log.Printf("Set ping interval for device %s to %d minutes", dev.Name, req.Interval)
	w.WriteHeader(http.StatusOK)
}

func main() {
	mongoStore = connectMongo()
	hydrateStoreFromMongo()
	demoUsers = mongoStore.loadAppUsers()
	sessions = mongoStore.loadSessions()

	store.google = NewGoogleClientFromEnv()
	seedDemoUsers()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", withCORS(handleLogin))
	mux.HandleFunc("/api/auth/logout", withCORS(handleLogout))
	mux.HandleFunc("/api/auth/me", withCORS(handleMe))

	// Admin-only: the initial connect wizard and disconnecting are
	// account-level actions, not everyday operations.
	mux.HandleFunc("/api/chromeos/connect/init", withCORS(requireRole(RoleAdmin, handleInit)))
	mux.HandleFunc("/api/chromeos/connect/upload", withCORS(requireRole(RoleAdmin, handleConnectUpload)))
	mux.HandleFunc("/api/chromeos/connect/status", withCORS(requireRole(RoleAdmin, handleConnectStatus)))
	mux.HandleFunc("/api/chromeos/connect/finish", withCORS(requireRole(RoleAdmin, handleFinish)))
	mux.HandleFunc("/api/chromeos/disconnect", withCORS(requireRole(RoleAdmin, handleDisconnect)))

	// Viewer (any authenticated session) for reads.
	mux.HandleFunc("/api/chromeos/status", withCORS(requireRole(RoleViewer, handleStatus)))
	mux.HandleFunc("/api/chromeos/devices", withCORS(requireRole(RoleViewer, handleDevices)))
	mux.HandleFunc("/api/chromeos/insights", withCORS(requireRole(RoleViewer, handleInsights)))
	mux.HandleFunc("/api/chromeos/actions", withCORS(requireRole(RoleViewer, handleActionStatus)))
	mux.HandleFunc("/api/chromeos/directory", withCORS(requireRole(RoleViewer, handleDirectory)))
	mux.HandleFunc("/api/chromeos/chrome-reports", withCORS(requireRole(RoleViewer, handleChromeReports)))
	mux.HandleFunc("/api/chromeos/mobile-devices", withCORS(requireRole(RoleViewer, handleMobileDevices)))
	mux.HandleFunc("/api/chromeos/audit-log", withCORS(requireRole(RoleViewer, handleAuditLog)))
	mux.HandleFunc("/api/chromeos/security-alerts", withCORS(requireRole(RoleViewer, handleSecurityAlerts)))
	mux.HandleFunc("/api/chromeos/security-alerts/action", withCORS(requireRole(RoleAdmin, handleSecurityAlertAction)))
	mux.HandleFunc("/api/chromeos/policies", withCORS(requireRole(RoleViewer, handlePolicies)))
	mux.HandleFunc("/api/chromeos/policies/search", withCORS(requireRole(RoleViewer, handlePolicySearch)))
	mux.HandleFunc("/api/chromeos/policies/set", withCORS(requireRole(RoleAdmin, handleSetPolicy)))
	mux.HandleFunc("/api/chromeos/policies/clear", withCORS(requireRole(RoleAdmin, handleClearPolicy)))
	mux.HandleFunc("/api/chromeos/admin-roles", withCORS(requireRole(RoleViewer, handleAdminRoles)))
	mux.HandleFunc("/api/chromeos/devices/telemetry", withCORS(requireRole(RoleViewer, handleDeviceTelemetry)))
	mux.HandleFunc("/api/chromeos/device-events", withCORS(requireRole(RoleViewer, handleDeviceEvents)))
	mux.HandleFunc("/api/chromeos/location", withCORS(handleLocationUpdate)) // Open endpoint for extension pings
	mux.HandleFunc("/api/chromeos/location/interval", withCORS(requireRole(RoleAdmin, handleLocationIntervalUpdate)))

	// Operator+ to trigger a sync; device restart/wipe role-checked inside
	// handleDeviceAction since one route serves both actions.
	mux.HandleFunc("/api/chromeos/sync", withCORS(requireRole(RoleOperator, handleSyncNow)))
	mux.HandleFunc("/api/chromeos/devices/action", withCORS(requireRole(RoleOperator, handleDeviceAction)))
	mux.HandleFunc("/api/chromeos/devices/batch-move", withCORS(requireRole(RoleAdmin, handleBatchMove)))

	// Read needs any session; writing needs admin.
	mux.HandleFunc("/api/chromeos/sync/settings", withCORS(requireReadOrRole(RoleAdmin, handleSyncSettings)))
	mux.HandleFunc("/api/chromeos/thresholds", withCORS(requireReadOrRole(RoleAdmin, handleThresholds)))

	go autoSyncLoop()

	addr := ":8080"
	log.Printf("chromeos connector mock backend listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
