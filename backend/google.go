package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	adminreports "google.golang.org/api/admin/reports/v1"
	alertcenter "google.golang.org/api/alertcenter/v1beta1"
	chromemanagement "google.golang.org/api/chromemanagement/v1"
	chromepolicy "google.golang.org/api/chromepolicy/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// decodeTpmFamily converts the TCG TPM family value Google's Directory API
// returns (a hex-encoded ASCII string, e.g. "322e3000") into the human
// version string it actually encodes (e.g. "2.0"). Falls back to the raw
// value if it isn't valid hex or doesn't decode to a printable version
// string, so an unexpected format still shows something rather than nothing.
func decodeTpmFamily(raw string) string {
	if raw == "" {
		return raw
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return raw
	}
	decoded := strings.TrimRight(string(b), "\x00")
	for _, r := range decoded {
		if (r < '0' || r > '9') && r != '.' {
			return raw
		}
	}
	if decoded == "" {
		return raw
	}
	return decoded
}

// shortenGoogleError strips googleapi.Error's pretty-printed JSON Details
// blob (which can run to dozens of lines) down to just the HTTP code and
// message, and collapses oauth2.RetrieveError's raw token-endpoint dump
// (full request URL plus a JSON body) down to just the error code/
// description - both are useful in a terminal but unusable inside a UI card.
func shortenGoogleError(err error) error {
	var gerr *googleapi.Error
	if ok := errors.As(err, &gerr); ok && gerr.Message != "" {
		return fmt.Errorf("HTTP %d: %s", gerr.Code, gerr.Message)
	}

	var rerr *oauth2.RetrieveError
	if ok := errors.As(err, &rerr); ok {
		code := rerr.ErrorCode
		desc := rerr.ErrorDescription
		if code == "" {
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if json.Unmarshal(rerr.Body, &body) == nil {
				code, desc = body.Error, body.Description
			}
		}
		status := http.StatusUnauthorized
		if rerr.Response != nil {
			status = rerr.Response.StatusCode
		}
		if code != "" {
			return fmt.Errorf("HTTP %d: oauth token request rejected (%s): %s", status, code, desc)
		}
		return fmt.Errorf("HTTP %d: oauth token request rejected", status)
	}

	return err
}

// GoogleClient is the seam between your sync/action logic and Google.
// The mock and the real implementation both satisfy this, so main.go
// never has to know which one it's talking to.
type GoogleClient interface {
	// Probe is a cheap call used only to detect whether domain-wide
	// delegation has been authorized yet (the one manual step).
	Probe() error
	ListDevices() ([]*Device, error)
	// DoAction returns an optional result string alongside the error - only
	// populated for actions that produce one (currently "crd", the Chrome
	// Remote Desktop session URL, confirmed live to only be available via a
	// follow-up poll, not the initial issueCommand response).
	DoAction(deviceID, action, payload string) (string, error)
	// BatchMoveDevices uses the Directory API's dedicated bulk endpoint
	// (Chromeosdevices.MoveDevicesToOu) instead of N individual Patch calls -
	// one HTTP request for the whole selection instead of one per device.
	BatchMoveDevices(deviceIDs []string, orgUnit string) error
	// ListDeviceEvents uses the Chrome Management Telemetry API's Events feed
	// (Customers.Telemetry.Events.List) - a genuinely different data source
	// from GetDeviceTelemetry's point-in-time snapshots: this is the actual
	// event stream (network changes, USB, app installs, audio/WiFi issues).
	ListDeviceEvents(eventTypes []string, since time.Time) ([]*DeviceEvent, error)
	// ListUsers and ListOrgUnits use the admin.directory.user.readonly and
	// admin.directory.orgunit.readonly scopes - already part of the
	// connect wizard's requested scopes, just previously unused.
	ListUsers() ([]*DirectoryUser, error)
	ListOrgUnits() ([]*OrgUnitInfo, error)
	// ListChromeReports uses the Chrome Management API
	// (chrome.management.reports.readonly) - a different API and scope from
	// everything else here, which all uses the Directory API.
	ListChromeReports() (*ChromeReports, error)
	// ListChurn fetches deprovisioned/retired devices - same scope and
	// endpoint as ListDevices, just a different status query.
	ListChurn() ([]*ChurnRecord, error)
	// ListGroups and ListMobileDevices use admin.directory.group.readonly and
	// admin.directory.device.mobile.readonly - new scopes, isolated from the
	// original Directory API token so a missing grant here can't break the
	// device/user/orgunit calls that already work.
	ListGroups() ([]*GroupInfo, error)
	ListMobileDevices() ([]*MobileDeviceInfo, error)
	// ListAuditLog uses the Admin SDK Reports API (admin.reports.audit.readonly)
	// - a different API from the Chrome Management reports above.
	ListAuditLog() (*AuditLog, error)
	// ListSecurityAlerts uses the Alert Center API (apps.alerts) - covers DLP
	// violations, compromised accounts, phishing, and other security sources.
	ListSecurityAlerts() ([]*SecurityAlert, error)
	// DeleteAlert soft-deletes an alert (Alert Center's Delete) - it stops
	// showing in List, recoverable via UndeleteAlert for Google's retention
	// window. There is no public API to set an alert's Status/Assignee
	// fields despite AlertMetadata documenting them (confirmed against the
	// full alertcenter/v1beta1 client surface - only Get/List exist for
	// metadata, no update/patch call), so delete/undelete/feedback are the
	// only real write actions available here, not a limitation of this
	// integration.
	DeleteAlert(alertID string) error
	// UndeleteAlert restores an alert DeleteAlert removed.
	UndeleteAlert(alertID string) error
	// SubmitAlertFeedback records how useful this alert was
	// (NOT_USEFUL/SOMEWHAT_USEFUL/VERY_USEFUL) via Alert Center's
	// Feedback.Create - the real "review this alert" action Admin console
	// itself exposes.
	SubmitAlertFeedback(alertID, feedbackType string) error
	// ListPolicies uses the Chrome Policy API (chrome.management.policy.readonly)
	// - the actual enforced policy value, not just device-reported compliance.
	ListPolicies() ([]*PolicyValue, error)
	// SetPolicy uses the Chrome Policy API's write scope
	// (chrome.management.policy) to enforce a new value on a specific org
	// unit - takes effect on devices/users in that OU the same as an Admin
	// console policy edit, next check-in. valueJSON must be a single-field
	// JSON object whose one key is the schema's field name (matches the
	// shape ListPolicies already returns) - that key doubles as the API's
	// required UpdateMask, so there's no separate hardcoded field-name table
	// to keep in sync per schema.
	SetPolicy(orgUnitPath, schemaName string, valueJSON json.RawMessage) error
	// ClearPolicy removes an explicit override on this org unit so it
	// inherits from its parent again - the Chrome Policy API's BatchInherit,
	// equivalent to Admin console's "Inherit" toggle.
	ClearPolicy(orgUnitPath, schemaName string) error
	// SearchPolicySchemas uses the Chrome Policy API's schema catalog
	// (Customers.PolicySchemas.List) to find real policy schemas by keyword -
	// e.g. "extension" surfaces the actual force-install/blocklist schemas,
	// "network" surfaces managed network schemas, "kiosk"/"print" likewise.
	// This is deliberately how app/network/kiosk/print management are
	// reached here instead of hardcoding four separate guessed schema names:
	// every one of those is "just a Chrome policy schema" underneath, and
	// guessing exact schema strings for a write feature risks a wrong
	// literal doing something unintended on a live domain. Searching
	// Google's own live catalog and editing through SetPolicy/ClearPolicy
	// above is the same generic mechanism, applied honestly.
	SearchPolicySchemas(query string) ([]*PolicySchemaInfo, error)
	// ListAdminRoles uses admin.directory.rolemanagement.readonly - a new,
	// isolated scope - to show who holds which Google Admin role.
	ListAdminRoles() ([]*AdminRoleAssignment, error)
	// GetDeviceTelemetry uses the Chrome Management Telemetry API
	// (chrome.management.telemetry.readonly) - a different API from
	// everything else here, and the actual source of the storage/boot
	// performance/network diagnostics data Admin console's device detail
	// page shows (the Directory API's own DiskVolumeReports doesn't
	// reliably populate this). Called per-device, on demand.
	GetDeviceTelemetry(deviceID string) (*DeviceTelemetry, error)
}

// ---------- Mock (default, zero real credentials needed) ----------

type mockGoogleClient struct {
	mu              sync.Mutex
	policyOverrides map[string]json.RawMessage // schemaName -> last value set via SetPolicy, until ClearPolicy
	deletedAlerts   map[string]bool            // alertID -> soft-deleted via DeleteAlert, until UndeleteAlert
	alertFeedback   map[string]string           // alertID -> last feedback type submitted
}

func (m *mockGoogleClient) Probe() error { return nil } // always "authorized" in mock mode

func (m *mockGoogleClient) ListDevices() ([]*Device, error) {
	time.Sleep(1500 * time.Millisecond) // simulate API latency
	return mockDeviceList(), nil
}

func (m *mockGoogleClient) DoAction(deviceID, action, payload string) (string, error) {
	time.Sleep(2 * time.Second) // simulate Google's async action latency
	switch action {
	case "crd":
		return "https://remotedesktop.google.com/support/session/mock-session-id", nil
	case "restart", "wipe", "powerwash", "screenshot", "set_volume", "capture_logs", "support_packet",
		"disable", "enable", "deprovision", "move":
		return "", nil
	default:
		return "", fmt.Errorf("unsupported action: %s", action)
	}
}

func (m *mockGoogleClient) BatchMoveDevices(deviceIDs []string, orgUnit string) error {
	time.Sleep(1 * time.Second) // simulate API latency
	return nil
}

func (m *mockGoogleClient) ListDeviceEvents(eventTypes []string, since time.Time) ([]*DeviceEvent, error) {
	now := time.Now()
	all := []*DeviceEvent{
		{ID: randID("evt"), DeviceID: "mock-dev-1", EventType: "NETWORK_STATE_CHANGE", ReportTime: now.Add(-8 * time.Minute), UserEmail: "alice.chen@example.com", Description: "Network connection state changed to NOT_CONNECTED"},
		{ID: randID("evt"), DeviceID: "mock-dev-2", EventType: "USB_ADDED", ReportTime: now.Add(-25 * time.Minute), UserEmail: "raj.patel@example.com", Description: "USB device connected: SanDisk Ultra USB 3.0"},
		{ID: randID("evt"), DeviceID: "mock-dev-4", EventType: "WIFI_SIGNAL_STRENGTH_LOW", ReportTime: now.Add(-40 * time.Minute), UserEmail: "david.kim@example.com", Description: "WiFi signal strength dropped below -70dBm"},
		{ID: randID("evt"), DeviceID: "mock-dev-1", EventType: "APP_INSTALLED", ReportTime: now.Add(-2 * time.Hour), UserEmail: "alice.chen@example.com", Description: "App installed: Zoom"},
		{ID: randID("evt"), DeviceID: "mock-dev-3", EventType: "AUDIO_SEVERE_UNDERRUN", ReportTime: now.Add(-3 * time.Hour), UserEmail: "maria.lopez@example.com", Description: "Audio buffer underrun for 6.2s"},
		{ID: randID("evt"), DeviceID: "mock-dev-2", EventType: "NETWORK_HTTPS_LATENCY_CHANGE", ReportTime: now.Add(-5 * time.Hour), UserEmail: "raj.patel@example.com", Description: "HTTPS latency problem detected"},
	}
	var out []*DeviceEvent
	typeFilter := map[string]bool{}
	for _, t := range eventTypes {
		typeFilter[t] = true
	}
	for _, e := range all {
		if e.ReportTime.Before(since) {
			continue
		}
		if len(typeFilter) > 0 && !typeFilter[e.EventType] {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *mockGoogleClient) ListUsers() ([]*DirectoryUser, error) {
	now := time.Now()
	recentLogin := now.Add(-2 * time.Hour)
	staleLogin := now.AddDate(0, 0, -45)
	return []*DirectoryUser{
		{Email: "alice.chen@example.com", Suspended: false, LastLoginTime: &recentLogin, OrgUnit: "/Engineering"},
		{Email: "raj.patel@example.com", Suspended: true, LastLoginTime: &staleLogin, OrgUnit: "/Sales"},
		{Email: "maria.lopez@example.com", Suspended: false, LastLoginTime: &recentLogin, OrgUnit: "/HR"},
		{Email: "david.kim@example.com", Suspended: false, LastLoginTime: &staleLogin, OrgUnit: "/Engineering"},
		{Email: "priya.nair@example.com", Suspended: false, LastLoginTime: &recentLogin, OrgUnit: "/Support"},
	}, nil
}

func (m *mockGoogleClient) ListOrgUnits() ([]*OrgUnitInfo, error) {
	return []*OrgUnitInfo{
		{ID: "id:root", Path: "/", Name: "/"},
		{ID: "id:eng", Path: "/Engineering", Name: "Engineering", ParentPath: "/"},
		{ID: "id:sales", Path: "/Sales", Name: "Sales", ParentPath: "/"},
		{ID: "id:hr", Path: "/HR", Name: "HR", ParentPath: "/"},
		{ID: "id:support", Path: "/Support", Name: "Support", ParentPath: "/"},
		{ID: "id:marketing", Path: "/Marketing", Name: "Marketing", ParentPath: "/"}, // no devices yet - exercises the empty-OU case
	}, nil
}

func (m *mockGoogleClient) ListChurn() ([]*ChurnRecord, error) {
	return []*ChurnRecord{
		{ID: randID("dev"), Name: "Chromebook-Eng-051", OrgUnit: "/Engineering", DeprovisionReason: "DEVICE_UPGRADE"},
		{ID: randID("dev"), Name: "Chromebook-Sales-118", OrgUnit: "/Sales", DeprovisionReason: "RETIRING_DEVICE"},
	}, nil
}

func (m *mockGoogleClient) ListGroups() ([]*GroupInfo, error) {
	return []*GroupInfo{
		{Name: "Engineering Team", Email: "engineering@example.com", Description: "All engineering staff", MemberCount: 12},
		{Name: "IT Admins", Email: "it-admins@example.com", Description: "Workspace administrators", MemberCount: 3},
		{Name: "Sales Team", Email: "sales@example.com", MemberCount: 8},
	}, nil
}

func (m *mockGoogleClient) ListMobileDevices() ([]*MobileDeviceInfo, error) {
	sync1 := time.Now().Add(-2 * time.Hour)
	sync2 := time.Now().Add(-30 * time.Minute)
	return []*MobileDeviceInfo{
		{ID: randID("mob"), Name: "Alice Chen", Email: "alice.chen@example.com", Model: "Pixel 8", Os: "Android 14", Type: "ANDROID", Status: "APPROVED", LastSync: &sync1},
		{ID: randID("mob"), Name: "Raj Patel", Email: "raj.patel@example.com", Model: "iPhone 14", Os: "iOS 17.4", Type: "IOS", Status: "APPROVED", LastSync: &sync2},
	}, nil
}

func (m *mockGoogleClient) ListAuditLog() (*AuditLog, error) {
	t1 := time.Now().Add(-1 * time.Hour)
	t2 := time.Now().Add(-3 * time.Hour)
	t3 := time.Now().Add(-20 * time.Minute)
	return &AuditLog{
		AdminActivity: []AuditEvent{
			{Time: &t1, ActorEmail: "admin@acme.com", EventName: "CHANGE_APPLICATION_SETTING", EventType: "APPLICATION_SETTINGS"},
			{Time: &t2, ActorEmail: "admin@acme.com", EventName: "ADD_DEVICE", EventType: "DEVICE_SETTINGS"},
		},
		LoginActivity: []AuditEvent{
			{Time: &t3, ActorEmail: "alice.chen@example.com", EventName: "login_success", EventType: "login"},
		},
	}, nil
}

// mockAlertIDs is fixed (not randID() per call) so DeleteAlert/UndeleteAlert/
// SubmitAlertFeedback have a stable ID to key off across repeated
// ListSecurityAlerts calls - randID() on every call would make it impossible
// to ever act on "the same" mock alert twice.
var mockAlertIDs = []string{"mock-alert-login", "mock-alert-dlp"}

func (m *mockGoogleClient) ListSecurityAlerts() ([]*SecurityAlert, error) {
	t1 := time.Now().Add(-6 * time.Hour)
	t2 := time.Now().Add(-2 * 24 * time.Hour)
	all := []*SecurityAlert{
		{ID: mockAlertIDs[0], CreateTime: &t1, Type: "Suspicious login activity", Source: "Google Identity", Severity: "MEDIUM", Status: "NOT_STARTED"},
		{ID: mockAlertIDs[1], CreateTime: &t2, Type: "DLP rule violation", Source: "Data Loss Prevention", Severity: "HIGH", Status: "IN_PROGRESS"},
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*SecurityAlert
	for _, a := range all {
		if !m.deletedAlerts[a.ID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *mockGoogleClient) DeleteAlert(alertID string) error {
	time.Sleep(300 * time.Millisecond) // simulate API latency
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deletedAlerts == nil {
		m.deletedAlerts = map[string]bool{}
	}
	m.deletedAlerts[alertID] = true
	return nil
}

func (m *mockGoogleClient) UndeleteAlert(alertID string) error {
	time.Sleep(300 * time.Millisecond) // simulate API latency
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deletedAlerts, alertID)
	return nil
}

func (m *mockGoogleClient) SubmitAlertFeedback(alertID, feedbackType string) error {
	time.Sleep(300 * time.Millisecond) // simulate API latency
	valid := map[string]bool{"NOT_USEFUL": true, "SOMEWHAT_USEFUL": true, "VERY_USEFUL": true}
	if !valid[feedbackType] {
		return fmt.Errorf("feedbackType must be one of NOT_USEFUL, SOMEWHAT_USEFUL, VERY_USEFUL")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.alertFeedback == nil {
		m.alertFeedback = map[string]string{}
	}
	m.alertFeedback[alertID] = feedbackType
	return nil
}

// mockPolicyDefaults uses the exact same schema names as curatedPolicySchemas
// below - a prior version of this map used stale names
// ("chrome.devices.DeviceGuestModeEnabled", "chrome.users.DeveloperToolsAvailability")
// that didn't match the real curated list, so those two entries could never
// actually resolve or accept a SetPolicy override in mock mode. Only the
// schemas with a real-world default worth demoing are listed; the rest
// legitimately come back unset, same as the real client's "untouched schema
// returns nothing" behavior.
var mockPolicyDefaults = map[string]string{
	"chrome.users.SafeBrowsingProtectionLevel": `{"safeBrowsingProtectionLevel":"ENHANCED_PROTECTION"}`,
	"chrome.devices.GuestMode":                 `{"guestModeEnabled":false}`,
	"chrome.users.DeveloperTools":               `{"developerToolsAvailability":"DEVELOPER_TOOLS_DISABLED"}`,
	"chrome.users.ManagedBookmarks":             `{"managedBookmarks":[{"name":"Company intranet","url":"https://intranet.example.com"}]}`,
	"chrome.users.AudioCaptureAllowed":          `{"audioCaptureAllowed":true}`,
	"chrome.devices.kiosk.KioskAppSettings":     `{"kioskAppId":"mock-kiosk-app-id"}`,
}

// ListPolicies (mock) mirrors the real client's shape: the security-focused
// curatedPolicySchemas list, plus one entry per curatedCategories keyword -
// found the same way SearchPolicySchemas does (substring match against
// mockPolicySchemaCatalog), not a second hardcoded list to keep in sync.
// Always appends one row per schema, value "" when nothing's set - matches
// the real client's "untouched schema still shows, just unset" behavior.
func (m *mockGoogleClient) ListPolicies() ([]*PolicyValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*PolicyValue
	for _, schema := range curatedPolicySchemas {
		value := mockPolicyDefaults[schema.schema]
		if ov, ok := m.policyOverrides[schema.schema]; ok {
			value = string(ov)
		}
		out = append(out, &PolicyValue{SchemaName: schema.schema, DisplayName: schema.displayName, Category: "Security", Value: value})
	}
	for _, cat := range curatedCategories {
		matches := mockSearchPolicySchemas(cat.keyword)
		if len(matches) == 0 {
			continue
		}
		match := matches[0]
		value := mockPolicyDefaults[match.SchemaName]
		if ov, ok := m.policyOverrides[match.SchemaName]; ok {
			value = string(ov)
		}
		out = append(out, &PolicyValue{SchemaName: match.SchemaName, DisplayName: shortSchemaName(match.SchemaName), Category: cat.displayName, Value: value})
	}
	return out, nil
}

// SetPolicy (mock) just records the value in memory, keyed by schema name
// only - the mock's ListPolicies always resolves against the root OU
// anyway, so there's nothing more granular to fake here. Still validates
// the single-field-object shape the real client requires, so a bad request
// fails the same way in both modes.
func (m *mockGoogleClient) SetPolicy(orgUnitPath, schemaName string, valueJSON json.RawMessage) error {
	time.Sleep(500 * time.Millisecond) // simulate API latency
	if _, err := policyUpdateMask(valueJSON); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policyOverrides == nil {
		m.policyOverrides = map[string]json.RawMessage{}
	}
	m.policyOverrides[schemaName] = valueJSON
	return nil
}

func (m *mockGoogleClient) ClearPolicy(orgUnitPath, schemaName string) error {
	time.Sleep(300 * time.Millisecond) // simulate API latency
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policyOverrides, schemaName)
	return nil
}

// mockPolicySchemaCatalog is a small illustrative set standing in for
// Google's real, much larger schema catalog (hundreds of schemas) - same
// role as the rest of this file's mock data (plausible demo shape, not a
// verified real-world value). The real client below hits the actual live
// catalog instead of anything hardcoded here.
var mockPolicySchemaCatalog = []*PolicySchemaInfo{
	{
		SchemaName: "chrome.users.apps.ExtensionInstallForcelist", Category: "Apps and extensions",
		Description: "Extensions and apps automatically installed and enforced, users cannot remove them.",
		Fields: []PolicySchemaField{{Name: "extensionInstallForcelist", Description: "List of extension IDs (optionally with an update URL) to force-install."}},
	},
	{
		SchemaName: "chrome.users.apps.ExtensionInstallBlocklist", Category: "Apps and extensions",
		Description: "Extensions and apps that are blocked from installation, or '*' to block all except allowlisted ones.",
		Fields: []PolicySchemaField{{Name: "extensionInstallBlocklist", Description: "List of blocked extension IDs, or [\"*\"] for all."}},
	},
	{
		SchemaName: "chrome.devices.NetworkConfiguration", Category: "Network",
		Description: "Managed network configuration (WiFi/VPN/certificates) pushed to devices in this org unit.",
		Fields:      []PolicySchemaField{{Name: "networkConfiguration", Description: "ONC-formatted network configuration JSON."}},
	},
	{
		SchemaName: "chrome.devices.kiosk.KioskAppSettings", Category: "Kiosk",
		Description: "Kiosk app assigned to devices set up as single-app kiosks.",
		Fields:      []PolicySchemaField{{Name: "kioskAppId", Description: "The Chrome Web Store app ID to auto-launch in kiosk mode."}},
	},
	{
		SchemaName: "chrome.printers.PrintersBulkConfiguration", Category: "Printing",
		Description: "Bulk-provisioned printers pushed to devices in this org unit.",
		Fields:      []PolicySchemaField{{Name: "printersConfiguration", Description: "URL or inline JSON describing the printer(s) to provision."}},
	},
	{
		SchemaName: "chrome.users.ManagedBookmarks", Category: "Bookmarks",
		Description: "Bookmarks pushed to the bookmark bar, managed by the admin and not removable by the user.",
		Fields:      []PolicySchemaField{{Name: "managedBookmarks", Description: "List of {name, url} bookmark entries, optionally nested into folders."}},
	},
	{
		SchemaName: "chrome.devices.PowerManagementIdleSettings", Category: "Power",
		Description: "What happens on idle and on power button press - sleep, lock screen, log out, shut down, or do nothing.",
		Fields:      []PolicySchemaField{{Name: "idleAction", Description: "Action to take after the idle delay."}, {Name: "powerButtonAction", Description: "Action to take when the power button is pressed.", KnownValues: []string{"SUSPEND", "LOCK", "SHUT_DOWN", "DO_NOTHING"}}},
	},
	{
		SchemaName: "chrome.users.VideoCaptureAllowed", Category: "Camera",
		Description: "Whether sites and apps are allowed to access the camera at all.",
		Fields:      []PolicySchemaField{{Name: "videoCaptureAllowed", Description: "Allow camera access."}},
	},
	{
		SchemaName: "chrome.users.AudioCaptureAllowed", Category: "Microphone",
		Description: "Whether sites and apps are allowed to access the microphone at all.",
		Fields:      []PolicySchemaField{{Name: "audioCaptureAllowed", Description: "Allow microphone access."}},
	},
	{
		SchemaName: "chrome.devices.UsbDetachableAllowlist", Category: "USB",
		Description: "Which USB devices are allowed to be used when attached to a device in this org unit.",
		Fields:      []PolicySchemaField{{Name: "usbDetachableAllowlist", Description: "List of allowed USB vendor/product ID pairs."}},
	},
	{
		SchemaName: "chrome.devices.WallpaperImage", Category: "Wallpaper",
		Description: "Wallpaper image enforced on the sign-in and lock screen for devices in this org unit.",
		Fields:      []PolicySchemaField{{Name: "wallpaperImageUrl", Description: "URL of the image to enforce as wallpaper."}},
	},
	{
		SchemaName: "chrome.devices.DeviceRestrictionSchedule", Category: "Time-based policies",
		Description: "A schedule during which the device is automatically logged out or restricted, by day and time.",
		Fields:      []PolicySchemaField{{Name: "deviceRestrictionSchedule", Description: "List of {dayOfWeek, startTime, endTime} restriction windows."}},
	},
	{
		SchemaName: "chrome.users.apps.ArcPolicy", Category: "App deployments",
		Description: "Android (ARC++) apps automatically installed for users in this org unit via a managed Google Play configuration.",
		Fields:      []PolicySchemaField{{Name: "arcPolicy", Description: "JSON-encoded managed Google Play app configuration."}},
	},
	{
		SchemaName: "chrome.users.apps.WebAppInstallForceList", Category: "PWA deployments",
		Description: "Progressive web apps (webapp) automatically installed and enforced for users in this org unit.",
		Fields:      []PolicySchemaField{{Name: "webAppInstallForceList", Description: "List of {url, defaultLaunchContainer} PWA entries to force-install."}},
	},
	{
		SchemaName: "chrome.users.apps.AppControlBlockedApps", Category: "App control",
		Description: "Apps blocked from running by publisher, category, or specific app ID, independent of install source.",
		Fields:      []PolicySchemaField{{Name: "appControlBlockedApps", Description: "List of blocked app identifiers or publisher names."}},
	},
}

func (m *mockGoogleClient) SearchPolicySchemas(query string) ([]*PolicySchemaInfo, error) {
	time.Sleep(400 * time.Millisecond) // simulate API latency
	return mockSearchPolicySchemas(query), nil
}

// mockSearchPolicySchemas is the plain (no simulated latency, no error)
// filter both SearchPolicySchemas and ListPolicies use - ListPolicies calls
// it directly per curatedCategories entry rather than through
// SearchPolicySchemas so it isn't paying that method's simulated latency
// once per category on every Policy compliance load.
func mockSearchPolicySchemas(query string) []*PolicySchemaInfo {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return mockPolicySchemaCatalog
	}
	var out []*PolicySchemaInfo
	for _, s := range mockPolicySchemaCatalog {
		if strings.Contains(strings.ToLower(s.SchemaName), q) ||
			strings.Contains(strings.ToLower(s.Description), q) ||
			strings.Contains(strings.ToLower(s.Category), q) {
			out = append(out, s)
		}
	}
	return out
}

func (m *mockGoogleClient) ListAdminRoles() ([]*AdminRoleAssignment, error) {
	return []*AdminRoleAssignment{
		{AssigneeEmail: "admin@example.com", AssigneeType: "USER", RoleName: "Super Admin", IsSuperAdminRole: true, ScopeType: "CUSTOMER"},
		{AssigneeEmail: "priya.nair@example.com", AssigneeType: "USER", RoleName: "Help Desk Admin", ScopeType: "ORG_UNIT", OrgUnitPath: "/Support"},
		{AssigneeEmail: "it-admins@example.com", AssigneeType: "GROUP", RoleName: "User Management Admin", ScopeType: "CUSTOMER"},
	}, nil
}

func (m *mockGoogleClient) GetDeviceTelemetry(deviceID string) (*DeviceTelemetry, error) {
	shutdown := time.Now().Add(-18 * time.Hour)
	return &DeviceTelemetry{
		StorageAvailableBytes:       44_150_000_000,
		StorageTotalBytes:           64_000_000_000,
		BootUpDurationSeconds:       7,
		LastShutdownTime:            &shutdown,
		LastShutdownDurationSeconds: 2,
		LastShutdownReason:          "USER_REQUEST",
		ConnectionState:             "ONLINE",
		ConnectionType:              "WIFI",
		LanIpAddress:                "10.0.1.15",
		GatewayIpAddress:            "10.0.1.1",
		LatencyMs:                   120,
		BatteryHealth:               "BATTERY_HEALTH_NORMAL",
		BatteryCycleCount:           145,
		MemoryAvailableBytes:        2_400_000_000,
		MemoryTotalBytes:            4_000_000_000,
		Displays:                    []DisplayInfo{{Name: "Built-in Display", Internal: true}},
		AudioInputDevice:            "Internal Microphone",
		AudioOutputDevice:           "Internal Speaker",
		AudioOutputVolume:           75,
		UsbPeripherals:              []string{"Logitech USB Receiver"},
		AppsUsage: []AppUsage{
			{AppId: "Chrome", AppType: "APPLICATION_TYPE_CHROME_APP", RunningDurationSeconds: 5520},
			{AppId: "chrome://os-settings/", AppType: "APPLICATION_TYPE_WEB", RunningDurationSeconds: 1140},
			{AppId: "Gmail", AppType: "APPLICATION_TYPE_WEB", RunningDurationSeconds: 15},
		},
	}, nil
}

func (m *mockGoogleClient) ListChromeReports() (*ChromeReports, error) {
	return &ChromeReports{
		ChromeVersions: []ChromeVersionCount{
			{Version: "128.0.6613.138", Channel: "STABLE", Count: 3},
			{Version: "126.0.6478.263", Channel: "STABLE", Count: 1},
			{Version: "124.0.6367.257", Channel: "BETA", Count: 1},
		},
		InstalledApps: []InstalledAppCount{
			{AppId: "ehoadneljpdggcbbknedodolkkjodefl", DisplayName: "Google Docs Offline", AppType: "EXTENSION", AppSource: "CHROME_WEBSTORE", BrowserDeviceCount: 5, OsUserCount: 5},
			{AppId: "gighmmpiobklfepjocnamgkkbiglidom", DisplayName: "AdBlock", AppType: "EXTENSION", AppSource: "CHROME_WEBSTORE", BrowserDeviceCount: 3, OsUserCount: 3},
			{AppId: "aohghmighlieiainnegkcijnfilokake", DisplayName: "Google Docs", AppType: "APP", AppSource: "CHROME_WEBSTORE", BrowserDeviceCount: 5, OsUserCount: 5},
		},
		AndroidApps: []InstalledAppCount{
			{AppId: "com.evernote", DisplayName: "Evernote", AppType: "ANDROID_APP", AppSource: "PLAY_STORE", BrowserDeviceCount: 2, OsUserCount: 2},
			{AppId: "com.spotify.music", DisplayName: "Spotify", AppType: "ANDROID_APP", AppSource: "PLAY_STORE", BrowserDeviceCount: 1, OsUserCount: 1},
		},
		Printers: []PrinterUsage{
			{Printer: "3rd Floor LaserJet", PrinterModel: "HP LaserJet Pro M404dn", DeviceCount: 4, JobCount: 37, UserCount: 4},
			{Printer: "Reception Color Printer", PrinterModel: "Canon imageCLASS MF743Cdw", DeviceCount: 2, JobCount: 12, UserCount: 2},
		},
		CrashEvents: []CrashEventCount{
			{BrowserVersion: "128.0.6613.138", Count: 2, Date: time.Now().AddDate(0, 0, -3).Format("2006-01-02")},
			{BrowserVersion: "124.0.6367.257", Count: 1, Date: time.Now().AddDate(0, 0, -10).Format("2006-01-02")},
		},
	}, nil
}

type mockDeviceSpec struct {
	name, user, ou, osVersion, bootMode   string
	model, firmwareVersion, licenseType   string
	aueInDays                             int // days from now until auto-update expiration
	ageYears                              int
	extSupportEligible, extSupportEnabled bool
	storageFreeGB, storageTotalGB         float64
	ramFreeMB, ramTotalMB                 float64
	lastIP                                string
	activeTimeTodayMinutes                int
	recentUserEmail                       string
	recentUserCount                       int
	cpuTempC                              int64
	tpmFamily                             string
	location, notes, orderNumber          string
	macAddress, ethernetMacAddress        string
	cpuModel, cpuArchitecture             string
	cpuMaxClockMhz                        int64
	supportEndInDays                      int
	chromeOsType                          string // chromeOs | chromeOsFlex
	osUpdateState                         string
	osUpdateTargetVersion                 string
	enrolledYearsAgo                      int
}

func mockDeviceList() []*Device {
	const gb = 1024 * 1024 * 1024
	const mb = 1024 * 1024

	specs := []mockDeviceSpec{
		{
			name: "Chromebook-Eng-014", user: "Alice Chen", ou: "/Engineering", osVersion: "128.0.6613.138", bootMode: "Verified",
			model: "HP Chromebook 14", firmwareVersion: "Google_Coral.10068.111.0", licenseType: "enterprise",
			aueInDays: 620, ageYears: 2, extSupportEligible: false, extSupportEnabled: false,
			storageFreeGB: 45, storageTotalGB: 64, ramFreeMB: 3200, ramTotalMB: 4096, lastIP: "10.0.1.15",
			activeTimeTodayMinutes: 320, recentUserEmail: "alice.chen@example.com", recentUserCount: 1,
			cpuTempC: 45, tpmFamily: "2.0",
			location: "Building A, Floor 2, Desk 14", notes: "Assigned to new hire onboarding kit",
			orderNumber: "GSTORE-88213", macAddress: "AC1F09A1B2C3", ethernetMacAddress: "AC1F09A1B2C4",
			cpuModel: "Intel Celeron N4500", cpuArchitecture: "x86_64", cpuMaxClockMhz: 2800, supportEndInDays: 700,
			chromeOsType: "chromeOs", enrolledYearsAgo: 2,
		},
		{
			// Suspended in the directory (see mockGoogleClient.ListUsers) - exercises the orphaned-device insight.
			name: "Chromebook-Sales-221", user: "Raj Patel", ou: "/Sales", osVersion: "126.0.6478.263", bootMode: "Verified",
			model: "Acer Chromebook 311", firmwareVersion: "Google_Kefka.4519.60.0", licenseType: "enterpriseUpgrade",
			aueInDays: 45, ageYears: 4, extSupportEligible: true, extSupportEnabled: false,
			storageFreeGB: 3, storageTotalGB: 32, ramFreeMB: 500, ramTotalMB: 4096, lastIP: "10.0.1.22",
			activeTimeTodayMinutes: 180, recentUserEmail: "raj.patel@example.com", recentUserCount: 1,
			cpuTempC: 52, tpmFamily: "2.0",
			location: "Building B, Floor 1, Desk 22", notes: "",
			orderNumber: "GSTORE-77410", macAddress: "3C2AF4B5C6D7", ethernetMacAddress: "",
			cpuModel: "MediaTek MT8183", cpuArchitecture: "aarch64", cpuMaxClockMhz: 2000, supportEndInDays: 45,
			chromeOsType: "chromeOs", osUpdateState: "updateStateNeedReboot", osUpdateTargetVersion: "126.0.6478.300", enrolledYearsAgo: 4,
		},
		{
			// Many recent users - exercises the shared-device insight.
			name: "Chromebook-HR-003", user: "Maria Lopez", ou: "/HR", osVersion: "128.0.6613.138", bootMode: "Verified",
			model: "HP Chromebook 14", firmwareVersion: "Google_Coral.10068.111.0", licenseType: "enterprise",
			aueInDays: 900, ageYears: 1, extSupportEligible: false, extSupportEnabled: false,
			storageFreeGB: 50, storageTotalGB: 64, ramFreeMB: 3500, ramTotalMB: 4096, lastIP: "",
			activeTimeTodayMinutes: 410, recentUserEmail: "maria.lopez@example.com", recentUserCount: 4,
			cpuTempC: 48, tpmFamily: "2.0",
			location: "Building A, Floor 1, HR Kiosk", notes: "Shared kiosk device - do not reassign",
			orderNumber: "GSTORE-88213", macAddress: "AC1F09A1B2C9", ethernetMacAddress: "AC1F09A1B2CA",
			cpuModel: "Intel Celeron N4500", cpuArchitecture: "x86_64", cpuMaxClockMhz: 2800, supportEndInDays: 900,
			// Repurposed old hardware running ChromeOS Flex, not a native Chromebook.
			chromeOsType: "chromeOsFlex", enrolledYearsAgo: 1,
		},
		{
			// Offline, Dev mode, hot CPU, outdated TPM - the fleet's problem child.
			name: "Chromebook-Eng-098", user: "David Kim", ou: "/Engineering", osVersion: "124.0.6367.257", bootMode: "Dev",
			model: "Lenovo 100e Chromebook", firmwareVersion: "Google_Trogdor.13606.459.0", licenseType: "educationUpgrade",
			aueInDays: -30, ageYears: 5, extSupportEligible: true, extSupportEnabled: true,
			storageFreeGB: 1, storageTotalGB: 32, ramFreeMB: 300, ramTotalMB: 4096, lastIP: "10.0.1.44",
			activeTimeTodayMinutes: 0, recentUserEmail: "david.kim@example.com", recentUserCount: 1,
			cpuTempC: 68, tpmFamily: "1.2",
			location: "Building A, Floor 2, Desk 98", notes: "Repeated overheating reports - flagged for RMA",
			orderNumber: "GSTORE-65310", macAddress: "5D3EB6C7D8E9", ethernetMacAddress: "5D3EB6C7D8EA",
			cpuModel: "Qualcomm Snapdragon 7c", cpuArchitecture: "aarch64", cpuMaxClockMhz: 2400, supportEndInDays: -30,
			chromeOsType: "chromeOs", osUpdateState: "updateStateDownloadInProgress", osUpdateTargetVersion: "125.0.6422.100", enrolledYearsAgo: 5,
		},
		{
			name: "Chromebook-Support-042", user: "Priya Nair", ou: "/Support", osVersion: "128.0.6613.138", bootMode: "Verified",
			model: "HP Chromebook 14", firmwareVersion: "Google_Coral.10068.111.0", licenseType: "enterprise",
			aueInDays: 15, ageYears: 4, extSupportEligible: true, extSupportEnabled: false,
			storageFreeGB: 20, storageTotalGB: 32, ramFreeMB: 2000, ramTotalMB: 4096, lastIP: "10.0.1.9",
			activeTimeTodayMinutes: 250, recentUserEmail: "priya.nair@example.com", recentUserCount: 2,
			cpuTempC: 50, tpmFamily: "2.0",
			location: "Building C, Support Desk", notes: "",
			orderNumber: "GSTORE-77410", macAddress: "3C2AF4B5C6E1", ethernetMacAddress: "",
			cpuModel: "MediaTek MT8183", cpuArchitecture: "aarch64", cpuMaxClockMhz: 2000, supportEndInDays: 15,
			chromeOsType: "chromeOs", enrolledYearsAgo: 4,
		},
	}
	out := make([]*Device, 0, len(specs))
	for i, n := range specs {
		status := "active"
		provisionStatus := "ACTIVE"
		if i == 3 {
			// Admin-disabled, not just offline - demonstrates the distinction
			// between "device access revoked" and "hasn't synced in a while".
			status = "offline"
			provisionStatus = "DISABLED"
		}
		// Staggered LastSeen values, not all "a few minutes ago" - device 2
		// (index 2) sits well past a typical online-after threshold so the
		// Online/Offline badge has a real example to show without needing
		// the disabled device to carry both meanings at once.
		lastSeenAgo := []time.Duration{2 * time.Minute, 8 * time.Minute, 5 * time.Hour, 3 * time.Minute, 45 * time.Minute}[i]
		connectionState := []string{"ONLINE", "ONLINE", "NOT_CONNECTED", "NOT_CONNECTED", "CONNECTED"}[i]
		aue := time.Now().AddDate(0, 0, n.aueInDays)
		manufactureDate := time.Now().AddDate(-n.ageYears, 0, 0).Format("2006-01-02")
		supportEnd := time.Now().AddDate(0, 0, n.supportEndInDays)
		enrolled := time.Now().AddDate(-n.enrolledYearsAgo, 0, 0)
		out = append(out, &Device{
			ID:                      randID("dev"),
			Name:                    n.name,
			User:                    n.user,
			OrgUnit:                 n.ou,
			Status:                  status,
			ProvisionStatus:         provisionStatus,
			LastSeen:                time.Now().Add(-lastSeenAgo),
			ConnectionState:         decodeConnectionState(connectionState),
			OsVersion:               n.osVersion,
			AutoUpdateExpiration:    &aue,
			BootMode:                n.bootMode,
			Model:                   n.model,
			FirmwareVersion:         n.firmwareVersion,
			DeviceLicenseType:       n.licenseType,
			ManufactureDate:         manufactureDate,
			ExtendedSupportEligible: n.extSupportEligible,
			ExtendedSupportEnabled:  n.extSupportEnabled,
			StorageFreeBytes:        int64(n.storageFreeGB * gb),
			StorageTotalBytes:       int64(n.storageTotalGB * gb),
			RamFreeBytes:            int64(n.ramFreeMB * mb),
			RamTotalBytes:           int64(n.ramTotalMB * mb),
			LastKnownIP:             n.lastIP,
			ActiveTimeTodayMinutes:  n.activeTimeTodayMinutes,
			RecentUserEmail:         n.recentUserEmail,
			RecentUserCount:         n.recentUserCount,
			CpuTempCelsius:          n.cpuTempC,
			TpmFamily:               n.tpmFamily,
			Location:                n.location,
			Notes:                   n.notes,
			OrderNumber:             n.orderNumber,
			MacAddress:              n.macAddress,
			EthernetMacAddress:      n.ethernetMacAddress,
			CpuModel:                n.cpuModel,
			CpuArchitecture:         n.cpuArchitecture,
			CpuMaxClockMhz:          n.cpuMaxClockMhz,
			SupportEndDate:          &supportEnd,
			ChromeOsType:            n.chromeOsType,
			OsUpdateState:           n.osUpdateState,
			OsUpdateTargetVersion:   n.osUpdateTargetVersion,
			FirstEnrollmentTime:     &enrolled,
			LastEnrollmentTime:      &enrolled,
		})
	}
	return out
}

func randID(prefix string) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return prefix + "_" + string(b)
}

// ---------- Real Google Admin SDK client ----------
//
// Built and verified against a live Google Workspace domain. If `go build`
// ever complains about a missing method or field name after a dependency
// bump, run:
//
//   go doc google.golang.org/api/admin/directory/v1 admin.Service
//
// the package surface occasionally shifts between versions.

type realGoogleClient struct {
	svc         *admin.Service // Directory API: original 3 scopes (devices, users, orgunits)
	svcExtended *admin.Service // Directory API: groups + mobile devices, isolated new scopes
	svcRoles    *admin.Service // Directory API: role management, isolated new scope
	cm          *chromemanagement.Service
	telemetry   *chromemanagement.Service // same package as cm, isolated scope/token
	cp          *chromepolicy.Service
	reports     *adminreports.Service
	alerts      *alertcenter.Service
	customerID  string
}

// NewRealGoogleClient builds a client authenticated as a service account
// with domain-wide delegation, impersonating adminEmail (Directory API
// calls always act as a specific admin user, never as the bare service
// account).
// httpClientForScopes builds a JWT-authenticated, impersonating httpClient
// for exactly the given scopes. Every scope GROUP below gets its own call to
// this function - deliberately NOT one shared token source with all scopes
// appended. Google's domain-wide delegation rejects the entire token
// request if any one requested scope isn't authorized for the client ID:
// sharing a token source would mean one not-yet-authorized new scope breaks
// every already-working call sharing it, not just its own. Confirmed against
// a live 401 the first time Chrome Management's scope was appended to the
// Directory API's token request.
func httpClientForScopes(ctx context.Context, keyData []byte, adminEmail string, scopes []string) (*http.Client, error) {
	conf, err := google.JWTConfigFromJSON(keyData, scopes...)
	if err != nil {
		return nil, fmt.Errorf("parsing service account key: %w", err)
	}
	conf.Subject = adminEmail // impersonation - required for domain-wide delegation
	return conf.Client(ctx), nil
}

func NewRealGoogleClient(ctx context.Context, keyPath, adminEmail, customerID string) (*realGoogleClient, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading service account key: %w", err)
	}
	return NewRealGoogleClientFromKeyData(ctx, keyData, adminEmail, customerID)
}

// NewRealGoogleClientFromKeyData is the same construction as
// NewRealGoogleClient but takes the service account key's raw bytes
// directly - used by the connect wizard's key upload, which receives the
// file over HTTP and never writes it to local disk.
func NewRealGoogleClientFromKeyData(ctx context.Context, keyData []byte, adminEmail, customerID string) (*realGoogleClient, error) {
	directoryClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/admin.directory.device.chromeos",
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
	})
	if err != nil {
		return nil, err
	}
	svc, err := admin.NewService(ctx, option.WithHTTPClient(directoryClient))
	if err != nil {
		return nil, fmt.Errorf("creating admin service: %w", err)
	}

	// Groups + mobile devices are new scopes on the same Directory API
	// package - isolated from svc above so an unauthorized grant here can't
	// break the device/user/orgunit calls that already work.
	directoryExtendedClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
	})
	if err != nil {
		return nil, err
	}
	svcExtended, err := admin.NewService(ctx, option.WithHTTPClient(directoryExtendedClient))
	if err != nil {
		return nil, fmt.Errorf("creating extended admin service: %w", err)
	}

	chromeMgmtClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/chrome.management.reports.readonly",
	})
	if err != nil {
		return nil, err
	}
	cm, err := chromemanagement.NewService(ctx, option.WithHTTPClient(chromeMgmtClient))
	if err != nil {
		return nil, fmt.Errorf("creating chrome management service: %w", err)
	}

	// Full read+write scope, not .readonly - required for SetPolicy/
	// ClearPolicy's BatchModify/BatchInherit calls. Isolated in its own
	// token request (see httpClientForScopes above), so this is the ONLY
	// scope that needs re-granting in Admin console's domain-wide
	// delegation for an existing connection upgrading from a
	// readonly-only-scoped grant - every other API/service here is
	// unaffected.
	chromePolicyClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/chrome.management.policy",
	})
	if err != nil {
		return nil, err
	}
	cp, err := chromepolicy.NewService(ctx, option.WithHTTPClient(chromePolicyClient))
	if err != nil {
		return nil, fmt.Errorf("creating chrome policy service: %w", err)
	}

	reportsClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/admin.reports.audit.readonly",
		"https://www.googleapis.com/auth/admin.reports.usage.readonly",
	})
	if err != nil {
		return nil, err
	}
	reports, err := adminreports.NewService(ctx, option.WithHTTPClient(reportsClient))
	if err != nil {
		return nil, fmt.Errorf("creating admin reports service: %w", err)
	}

	alertsClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/apps.alerts",
	})
	if err != nil {
		return nil, err
	}
	alerts, err := alertcenter.NewService(ctx, option.WithHTTPClient(alertsClient))
	if err != nil {
		return nil, fmt.Errorf("creating alert center service: %w", err)
	}

	rolesClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
	})
	if err != nil {
		return nil, err
	}
	svcRoles, err := admin.NewService(ctx, option.WithHTTPClient(rolesClient))
	if err != nil {
		return nil, fmt.Errorf("creating roles admin service: %w", err)
	}

	telemetryClient, err := httpClientForScopes(ctx, keyData, adminEmail, []string{
		"https://www.googleapis.com/auth/chrome.management.telemetry.readonly",
	})
	if err != nil {
		return nil, err
	}
	telemetry, err := chromemanagement.NewService(ctx, option.WithHTTPClient(telemetryClient))
	if err != nil {
		return nil, fmt.Errorf("creating chrome telemetry service: %w", err)
	}

	return &realGoogleClient{
		svc:         svc,
		svcExtended: svcExtended,
		svcRoles:    svcRoles,
		cm:          cm,
		telemetry:   telemetry,
		cp:          cp,
		reports:     reports,
		alerts:      alerts,
		customerID:  customerID,
	}, nil
}

// Probe makes the cheapest possible real call to detect whether the
// domain-wide delegation grant is live yet. Before the admin authorizes
// it, this fails with a 401/403 - that failure is what keeps the connect
// wizard in "pending" instead of advancing.
func (g *realGoogleClient) Probe() error {
	_, err := g.svc.Chromeosdevices.List(g.customerID).MaxResults(1).Do()
	return err
}

func (g *realGoogleClient) ListDevices() ([]*Device, error) {
	resp, err := g.svc.Chromeosdevices.List(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing chromeos devices: %w", err)
	}

	out := make([]*Device, 0, len(resp.Chromeosdevices))
	for _, d := range resp.Chromeosdevices {
		status := "offline"
		if d.Status == "ACTIVE" {
			status = "active"
		}

		lastSeen := time.Now()
		if d.LastSync != "" {
			if t, err := time.Parse(time.RFC3339, d.LastSync); err == nil {
				lastSeen = t
			}
		}

		user := d.AnnotatedUser
		if user == "" {
			user = "-"
		}

		name := d.AnnotatedAssetId
		if name == "" {
			name = d.SerialNumber
		}

		// AutoUpdateExpiration is deprecated by Google in favor of
		// AutoUpdateThrough - prefer the latter, fall back to the former
		// for Workspace domains that haven't backfilled it yet.
		var aue *time.Time
		if d.AutoUpdateThrough != "" {
			if t, err := time.Parse(time.RFC3339, d.AutoUpdateThrough); err == nil {
				aue = &t
			}
		}
		if aue == nil && d.AutoUpdateExpiration > 0 {
			t := time.UnixMilli(d.AutoUpdateExpiration)
			aue = &t
		}
		if aue == nil && d.SupportEndDate != "" {
			if t, err := time.Parse(time.RFC3339, d.SupportEndDate); err == nil {
				aue = &t
			}
		}

		var supportEndDate *time.Time
		if d.SupportEndDate != "" {
			if t, err := time.Parse(time.RFC3339, d.SupportEndDate); err == nil {
				supportEndDate = &t
			}
		}

		var storageFree, storageTotal int64
		if len(d.DiskVolumeReports) > 0 {
			last := d.DiskVolumeReports[len(d.DiskVolumeReports)-1]
			for _, v := range last.VolumeInfo {
				storageFree += v.StorageFree
				storageTotal += v.StorageTotal
			}
			// Some ChromeOS devices report a placeholder/overflow value instead of
			// real disk stats (seen: ~2.3 exabytes). No real Chromebook has more
			// than a few TB of local storage, so treat anything past that as
			// "not actually reported" rather than showing a nonsense number.
			const maxPlausibleBytes = 10 * 1024 * 1024 * 1024 * 1024 // 10 TB
			if storageTotal > maxPlausibleBytes {
				storageFree, storageTotal = 0, 0
			}
		}
		// One extra Telemetry.Devices.Get per device, every sync - the cost is
		// deliberate: it's the only real source for connection_state (there's
		// no "is this device online right now" field anywhere in the
		// Directory API, and the Directory API's own DiskVolumeReports comes
		// back empty for plenty of real devices even though the device
		// itself is fine), so the Fleet insights "Low disk space" card and
		// the Devices table's connection state both need it at sync time,
		// not just lazily when a detail panel is expanded.
		var connectionState string
		if tele, err := g.fetchSyncTelemetry(d.DeviceId); err == nil {
			connectionState = decodeConnectionState(tele.connectionState)
			if tele.storageTotal > 0 {
				storageFree, storageTotal = tele.storageFree, tele.storageTotal
			}
		}

		var ramFree int64
		if len(d.SystemRamFreeReports) > 0 {
			lastReport := d.SystemRamFreeReports[len(d.SystemRamFreeReports)-1]
			if len(lastReport.SystemRamFreeInfo) > 0 {
				ramFree = int64(lastReport.SystemRamFreeInfo[len(lastReport.SystemRamFreeInfo)-1])
			}
		}

		var lastIP string
		if len(d.LastKnownNetwork) > 0 {
			lastIP = d.LastKnownNetwork[0].IpAddress
		}

		var activeTimeTodayMs int64
		if len(d.ActiveTimeRanges) > 0 {
			activeTimeTodayMs = d.ActiveTimeRanges[len(d.ActiveTimeRanges)-1].ActiveTime
		}

		var recentUserEmail string
		if len(d.RecentUsers) > 0 {
			recentUserEmail = d.RecentUsers[0].Email
		}

		var cpuTempC int64
		if len(d.CpuStatusReports) > 0 {
			last := d.CpuStatusReports[len(d.CpuStatusReports)-1]
			if len(last.CpuTemperatureInfo) > 0 {
				var sum int64
				for _, t := range last.CpuTemperatureInfo {
					sum += t.Temperature
				}
				cpuTempC = sum / int64(len(last.CpuTemperatureInfo))
			}
		}

		var tpmFamily string
		if d.TpmVersionInfo != nil {
			tpmFamily = decodeTpmFamily(d.TpmVersionInfo.Family)
		}

		var cpuModel, cpuArch string
		var cpuMaxClockMhz int64
		if len(d.CpuInfo) > 0 {
			cpuModel = d.CpuInfo[0].Model
			cpuArch = d.CpuInfo[0].Architecture
			cpuMaxClockMhz = d.CpuInfo[0].MaxClockSpeedKhz / 1000
		}

		var osUpdateState, osUpdateTarget string
		if d.OsUpdateStatus != nil {
			osUpdateState = d.OsUpdateStatus.State
			osUpdateTarget = d.OsUpdateStatus.TargetOsVersion
		}

		var firstEnrolled, lastEnrolled *time.Time
		if d.FirstEnrollmentTime != "" {
			if t, err := time.Parse(time.RFC3339, d.FirstEnrollmentTime); err == nil {
				firstEnrolled = &t
			}
		}
		if d.LastEnrollmentTime != "" {
			if t, err := time.Parse(time.RFC3339, d.LastEnrollmentTime); err == nil {
				lastEnrolled = &t
			}
		}

		out = append(out, &Device{
			ID:                      d.DeviceId,
			Name:                    name,
			User:                    user,
			OrgUnit:                 d.OrgUnitPath,
			Status:                  status,
			ProvisionStatus:         d.Status,
			OsVersion:               d.OsVersion,
			AutoUpdateExpiration:    aue,
			BootMode:                d.BootMode,
			LastSeen:                lastSeen,
			Model:                   d.Model,
			FirmwareVersion:         d.FirmwareVersion,
			DeviceLicenseType:       d.DeviceLicenseType,
			ManufactureDate:         d.ManufactureDate,
			ExtendedSupportEligible: d.ExtendedSupportEligible,
			ExtendedSupportEnabled:  d.ExtendedSupportEnabled,
			StorageFreeBytes:        storageFree,
			StorageTotalBytes:       storageTotal,
			RamTotalBytes:           d.SystemRamTotal,
			RamFreeBytes:            ramFree,
			LastKnownIP:             lastIP,
			ActiveTimeTodayMinutes:  int(activeTimeTodayMs / 1000 / 60),
			RecentUserEmail:         recentUserEmail,
			RecentUserCount:         len(d.RecentUsers),
			CpuTempCelsius:          cpuTempC,
			TpmFamily:               tpmFamily,
			DeprovisionReason:       d.DeprovisionReason,
			Location:                d.AnnotatedLocation,
			Notes:                   d.Notes,
			OrderNumber:             d.OrderNumber,
			MacAddress:              d.MacAddress,
			EthernetMacAddress:      d.EthernetMacAddress,
			CpuModel:                cpuModel,
			CpuArchitecture:         cpuArch,
			CpuMaxClockMhz:          cpuMaxClockMhz,
			SupportEndDate:          supportEndDate,
			ChromeOsType:            d.ChromeOsType,
			OsUpdateState:           osUpdateState,
			OsUpdateTargetVersion:   osUpdateTarget,
			FirstEnrollmentTime:     firstEnrolled,
			LastEnrollmentTime:      lastEnrolled,
			ConnectionState:         connectionState,
		})
	}
	return out, nil
}

// ListChurn fetches deprovisioned/retired devices - same endpoint and scope
// as ListDevices, just filtered to status:DEPROVISIONED instead of the
// default active-device list. Verified against a live Workspace domain.
func (g *realGoogleClient) ListChurn() ([]*ChurnRecord, error) {
	resp, err := g.svc.Chromeosdevices.List(g.customerID).Query("status:DEPROVISIONED").Do()
	if err != nil {
		return nil, fmt.Errorf("listing deprovisioned devices: %w", err)
	}

	out := make([]*ChurnRecord, 0, len(resp.Chromeosdevices))
	for _, d := range resp.Chromeosdevices {
		name := d.AnnotatedAssetId
		if name == "" {
			name = d.SerialNumber
		}
		out = append(out, &ChurnRecord{
			ID:                d.DeviceId,
			Name:              name,
			OrgUnit:           d.OrgUnitPath,
			DeprovisionReason: d.DeprovisionReason,
		})
	}
	return out, nil
}

func (g *realGoogleClient) ListGroups() ([]*GroupInfo, error) {
	resp, err := g.svcExtended.Groups.List().Customer(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing groups: %w", shortenGoogleError(err))
	}

	out := make([]*GroupInfo, 0, len(resp.Groups))
	for _, gr := range resp.Groups {
		out = append(out, &GroupInfo{
			Name:        gr.Name,
			Email:       gr.Email,
			Description: gr.Description,
			MemberCount: gr.DirectMembersCount,
		})
	}
	return out, nil
}

func (g *realGoogleClient) ListMobileDevices() ([]*MobileDeviceInfo, error) {
	resp, err := g.svcExtended.Mobiledevices.List(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing mobile devices: %w", shortenGoogleError(err))
	}

	out := make([]*MobileDeviceInfo, 0, len(resp.Mobiledevices))
	for _, d := range resp.Mobiledevices {
		var name, email string
		if len(d.Name) > 0 {
			name = d.Name[0]
		}
		if len(d.Email) > 0 {
			email = d.Email[0]
		}
		var lastSync *time.Time
		if d.LastSync != "" {
			if t, err := time.Parse(time.RFC3339, d.LastSync); err == nil {
				lastSync = &t
			}
		}
		out = append(out, &MobileDeviceInfo{
			ID:       d.DeviceId,
			Name:     name,
			Email:    email,
			Model:    d.Model,
			Os:       d.Os,
			Type:     d.Type,
			Status:   d.Status,
			LastSync: lastSync,
		})
	}
	return out, nil
}

func activityToAuditEvent(a *adminreports.Activity) AuditEvent {
	var t *time.Time
	if a.Id != nil && a.Id.Time != "" {
		if parsed, err := time.Parse(time.RFC3339, a.Id.Time); err == nil {
			t = &parsed
		}
	}
	var actorEmail string
	if a.Actor != nil {
		actorEmail = a.Actor.Email
	}
	var eventName, eventType string
	if len(a.Events) > 0 {
		eventName = a.Events[0].Name
		eventType = a.Events[0].Type
	}
	return AuditEvent{Time: t, ActorEmail: actorEmail, EventName: eventName, EventType: eventType}
}

// ListAuditLog calls the Admin SDK Reports API twice - "admin" for changes
// made in Admin console, "login" for sign-in activity.
func (g *realGoogleClient) ListAuditLog() (*AuditLog, error) {
	out := &AuditLog{}

	adminResp, err := g.reports.Activities.List("all", "admin").MaxResults(20).Do()
	if err != nil {
		return nil, fmt.Errorf("listing admin activity: %w", shortenGoogleError(err))
	}
	for _, a := range adminResp.Items {
		out.AdminActivity = append(out.AdminActivity, activityToAuditEvent(a))
	}

	loginResp, err := g.reports.Activities.List("all", "login").MaxResults(20).Do()
	if err != nil {
		return nil, fmt.Errorf("listing login activity: %w", shortenGoogleError(err))
	}
	for _, a := range loginResp.Items {
		out.LoginActivity = append(out.LoginActivity, activityToAuditEvent(a))
	}

	return out, nil
}

// ListSecurityAlerts calls the Alert Center API. Supported sources include
// Data Loss Prevention, Gmail phishing, compromised accounts, and more -
// not exclusively device-related.
func (g *realGoogleClient) ListSecurityAlerts() ([]*SecurityAlert, error) {
	// customerId, if passed, must have the leading "C" stripped from the
	// Directory-API-style ID (confirmed live - the "C..." form got a 400
	// "invalid argument"); easiest is to omit it and let it infer from the
	// caller's identity, since we're already impersonating the admin.
	resp, err := g.alerts.Alerts.List().PageSize(20).Do()
	if err != nil {
		return nil, fmt.Errorf("listing security alerts: %w", shortenGoogleError(err))
	}

	out := make([]*SecurityAlert, 0, len(resp.Alerts))
	for _, a := range resp.Alerts {
		var created *time.Time
		if a.CreateTime != "" {
			if t, err := time.Parse(time.RFC3339, a.CreateTime); err == nil {
				created = &t
			}
		}
		var severity, status string
		if a.Metadata != nil {
			severity = a.Metadata.Severity
			status = a.Metadata.Status
		}
		out = append(out, &SecurityAlert{
			ID:         a.AlertId,
			CreateTime: created,
			Type:       a.Type,
			Source:     a.Source,
			Severity:   severity,
			Status:     status,
		})
	}
	return out, nil
}

// DeleteAlert soft-deletes via Alert Center's Delete - CustomerId is left
// unset deliberately, same reasoning as ListSecurityAlerts above (inferred
// from the impersonated admin's identity; passing the Directory-API "C..."
// form 400s).
func (g *realGoogleClient) DeleteAlert(alertID string) error {
	if _, err := g.alerts.Alerts.Delete(alertID).Do(); err != nil {
		return fmt.Errorf("deleting alert %s: %w", alertID, shortenGoogleError(err))
	}
	return nil
}

// UndeleteAlert restores an alert DeleteAlert removed, within whatever
// retention window Google keeps deleted alerts for.
func (g *realGoogleClient) UndeleteAlert(alertID string) error {
	req := &alertcenter.UndeleteAlertRequest{}
	if _, err := g.alerts.Alerts.Undelete(alertID, req).Do(); err != nil {
		return fmt.Errorf("undeleting alert %s: %w", alertID, shortenGoogleError(err))
	}
	return nil
}

// SubmitAlertFeedback records usefulness feedback via Alert Center's
// Feedback.Create - the real, public-API "review this alert" action (there
// is no public way to set AlertMetadata.Status/Assignee despite those
// fields existing in the schema; see the GoogleClient interface comment).
func (g *realGoogleClient) SubmitAlertFeedback(alertID, feedbackType string) error {
	feedback := &alertcenter.AlertFeedback{Type: feedbackType}
	if _, err := g.alerts.Alerts.Feedback.Create(alertID, feedback).Do(); err != nil {
		return fmt.Errorf("submitting feedback for alert %s: %w", alertID, shortenGoogleError(err))
	}
	return nil
}

// curatedPolicySchemas is a deliberately small, security-relevant subset of
// the dozens of Chrome policy schemas Google exposes - resolving "all of
// them" isn't a real request shape (PolicySchemaFilter takes one schema/
// wildcard per call), so this is a starting set, not the full catalog.
var curatedPolicySchemas = []struct {
	schema      string
	displayName string
}{
	{"chrome.users.SafeBrowsingProtectionLevel", "Safe Browsing protection level"},
	{"chrome.devices.GuestMode", "Guest mode enabled"},
	{"chrome.users.DeveloperTools", "Developer tools availability"},
	{"chrome.users.LockScreen", "Screen lock"},
	{"chrome.devices.DevicePowerwashAllowed", "Device powerwash allowed"},
	{"chrome.devices.ForcedReenrollment", "Forced re-enrollment mode"},
	{"chrome.users.UrlBlocking", "Blocked URLs"},
}

// curatedCategories are settings areas requested for the Policy compliance
// tab beyond the original security-focused curatedPolicySchemas list above.
// Unlike that list, these don't hardcode a specific schema name each - after
// getting burned once already in this codebase by guessed schema names that
// turned out stale (see the mock schema-name-mismatch fix elsewhere in this
// file), each category is resolved by searching Google's real schema
// catalog by keyword (SearchPolicySchemas) and using whatever real schema
// comes back, the same mechanism "Browse policies" already uses. This is
// slower (a search + resolve per category on every Policy compliance load)
// but never shows a schema name that doesn't actually exist on this
// customer's Chrome Policy API.
var curatedCategories = []struct {
	keyword     string
	displayName string
}{
	{"bookmark", "Bookmarks"},
	{"power", "Power button options"},
	{"camera", "Camera"},
	{"microphone", "Microphone"},
	{"usb", "USB"},
	{"wallpaper", "Wallpaper"},
	{"time", "Time-based policies"},
	{"deployment", "App deployments"},
	{"kiosk", "Kiosk mode"},
	{"extension", "Extensions"},
	{"webapp", "PWA deployments"},
	{"app control", "App control"},
}

// Resolve only returns a schema if it has an explicitly configured value
// somewhere in the org unit hierarchy (confirmed live - untouched schemas
// come back with zero ResolvedPolicies, not a schema default), so some
// curated entries legitimately show nothing on domains that never touched
// that particular policy - that's correct behavior, not a fetch failure.

// resolveOrgUnitID looks up an org unit's ID by its path - shared by
// ListPolicies (always against root) and SetPolicy/ClearPolicy (against
// whatever OU the caller targets). Orgunits.List defaults to "children"
// (confirmed live - every entry it returns has a non-"/" path, excluding
// the root itself); "allIncludingParent" is needed to get the root org
// unit's own ID back, so it's used unconditionally here even for non-root
// lookups.
func (g *realGoogleClient) resolveOrgUnitID(orgUnitPath string) (string, error) {
	resp, err := g.svc.Orgunits.List(g.customerID).Type("allIncludingParent").Do()
	if err != nil {
		return "", fmt.Errorf("resolving org unit %q: %w", orgUnitPath, shortenGoogleError(err))
	}
	for _, ou := range resp.OrganizationUnits {
		if ou.OrgUnitPath == orgUnitPath {
			// Chrome Policy API rejects the "id:" prefix Directory API's
			// OrgUnitId carries (confirmed live - "Invalid Org Unit ID: id:..."
			// echoed the exact prefixed value back), so it has to be stripped.
			return strings.TrimPrefix(ou.OrgUnitId, "id:"), nil
		}
	}
	return "", fmt.Errorf("org unit not found: %s", orgUnitPath)
}

// ListPolicies resolves each curated schema against the root org unit via
// the Chrome Policy API - the actual enforced value, not just whether a
// device reports itself compliant.
//
// Every one of these resolves/searches is independent of the others, so
// they run concurrently instead of one after another - sequentially this
// was up to 19 real Chrome Policy API round trips end to end (7 curated
// resolves + 12 categories, each category itself a paginated search plus a
// resolve), confirmed live to be exactly why this tab could sit on
// "Loading..." for a long time on a real domain. A small semaphore caps how
// many run at once so this doesn't burst the customer's API quota. Output
// content and order are unchanged from the old sequential version (results
// are written into fixed slots by original index, not append-as-completed)
// - only how the work is scheduled changed, not what's shown.
func (g *realGoogleClient) ListPolicies() ([]*PolicyValue, error) {
	targetID, err := g.resolveOrgUnitID("/")
	if err != nil {
		return nil, err
	}
	customer := "customers/" + g.customerID

	const maxConcurrentPolicyLookups = 6
	sem := make(chan struct{}, maxConcurrentPolicyLookups)
	var wg sync.WaitGroup
	curatedResults := make([]*PolicyValue, len(curatedPolicySchemas))
	categoryResults := make([]*PolicyValue, len(curatedCategories))
	errCh := make(chan error, len(curatedPolicySchemas)+len(curatedCategories))

	for i, schema := range curatedPolicySchemas {
		i, schema := i, schema // capture per-iteration, not the shared loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			value, err := g.resolveSchemaValue(customer, targetID, schema.schema)
			if err != nil {
				errCh <- err
				return
			}
			curatedResults[i] = &PolicyValue{SchemaName: schema.schema, DisplayName: schema.displayName, Category: "Security", Value: value}
		}()
	}

	for i, cat := range curatedCategories {
		i, cat := i, cat // capture per-iteration, not the shared loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			matches, err := g.searchPolicySchemasPaged(cat.keyword, 1)
			if err != nil {
				errCh <- fmt.Errorf("finding a schema for %s: %w", cat.displayName, err)
				return
			}
			if len(matches) == 0 {
				return // no real schema found for this keyword on this customer - nothing to show, not a fetch failure
			}
			match := matches[0]
			value, err := g.resolveSchemaValue(customer, targetID, match.SchemaName)
			if err != nil {
				errCh <- err
				return
			}
			categoryResults[i] = &PolicyValue{SchemaName: match.SchemaName, DisplayName: shortSchemaName(match.SchemaName), Category: cat.displayName, Value: value}
		}()
	}

	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return nil, err
	}

	var out []*PolicyValue
	for _, r := range curatedResults {
		if r != nil {
			out = append(out, r)
		}
	}
	for _, r := range categoryResults {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// resolveSchemaValue is the single-schema Resolve call shared by
// ListPolicies' curated and keyword-discovered entries - returns "" (not an
// error) when the schema has no explicit value anywhere in the org unit
// hierarchy, since that's Resolve's own confirmed-live behavior for an
// untouched schema, not a failure.
func (g *realGoogleClient) resolveSchemaValue(customer, targetID, schemaName string) (string, error) {
	req := &chromepolicy.GoogleChromePolicyVersionsV1ResolveRequest{
		PolicySchemaFilter: schemaName,
		PolicyTargetKey: &chromepolicy.GoogleChromePolicyVersionsV1PolicyTargetKey{
			TargetResource: "orgunits/" + targetID,
		},
	}
	resp, err := g.cp.Customers.Policies.Resolve(customer, req).Do()
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", schemaName, shortenGoogleError(err))
	}
	if len(resp.ResolvedPolicies) > 0 && resp.ResolvedPolicies[0].Value != nil {
		return string(resp.ResolvedPolicies[0].Value.Value), nil
	}
	return "", nil
}

// shortSchemaName strips the "chrome.users."/"chrome.devices." namespace
// prefix for display - the full name is still shown alongside it in the UI
// for anyone who wants to cross-reference Browse policies or Google's docs.
func shortSchemaName(schemaName string) string {
	if i := strings.LastIndex(schemaName, "."); i >= 0 {
		return schemaName[i+1:]
	}
	return schemaName
}

// policyUpdateMask builds the Chrome Policy API's required UpdateMask from
// valueJSON's own top-level keys - confirmed live this has to be EVERY field
// being set, comma-separated, not just one: a schema like
// chrome.users.UrlBlocking resolves to a two-field object
// ({"urlBlocklist":[...],"chromeInternalUrlsBlocked":false}), and passing
// only one of those two names as the mask left the request rejected. An
// earlier version of this assumed every schema had exactly one field, which
// happened to hold for the first several curated schemas tried and masked
// this until a genuinely multi-field schema was edited.
func policyUpdateMask(valueJSON json.RawMessage) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(valueJSON, &fields); err != nil || len(fields) == 0 {
		return "", fmt.Errorf("value must be a JSON object matching the policy schema, e.g. {\"fieldName\":true}")
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic order - not load-bearing, just avoids a flaky-looking mask across calls
	return strings.Join(names, ","), nil
}

// SetPolicy enforces a new value on orgUnitPath via the Chrome Policy API's
// write scope (chrome.management.policy) - BatchModify takes effect on
// devices/users in that OU the same as an Admin console policy edit, next
// check-in.
func (g *realGoogleClient) SetPolicy(orgUnitPath, schemaName string, valueJSON json.RawMessage) error {
	updateMask, err := policyUpdateMask(valueJSON)
	if err != nil {
		return err
	}

	targetID, err := g.resolveOrgUnitID(orgUnitPath)
	if err != nil {
		return err
	}

	customer := "customers/" + g.customerID
	req := &chromepolicy.GoogleChromePolicyVersionsV1BatchModifyOrgUnitPoliciesRequest{
		Requests: []*chromepolicy.GoogleChromePolicyVersionsV1ModifyOrgUnitPolicyRequest{
			{
				PolicyTargetKey: &chromepolicy.GoogleChromePolicyVersionsV1PolicyTargetKey{
					TargetResource: "orgunits/" + targetID,
				},
				PolicyValue: &chromepolicy.GoogleChromePolicyVersionsV1PolicyValue{
					PolicySchema: schemaName,
					Value:        googleapi.RawMessage(valueJSON),
				},
				UpdateMask: updateMask,
			},
		},
	}
	if _, err := g.cp.Customers.Policies.Orgunits.BatchModify(customer, req).Do(); err != nil {
		return fmt.Errorf("setting %s on %s: %w", schemaName, orgUnitPath, shortenGoogleError(err))
	}
	return nil
}

// ClearPolicy removes an explicit override on orgUnitPath so it inherits
// from its parent again - the Chrome Policy API's BatchInherit, equivalent
// to Admin console's "Inherit" toggle.
func (g *realGoogleClient) ClearPolicy(orgUnitPath, schemaName string) error {
	targetID, err := g.resolveOrgUnitID(orgUnitPath)
	if err != nil {
		return err
	}

	customer := "customers/" + g.customerID
	req := &chromepolicy.GoogleChromePolicyVersionsV1BatchInheritOrgUnitPoliciesRequest{
		Requests: []*chromepolicy.GoogleChromePolicyVersionsV1InheritOrgUnitPolicyRequest{
			{
				PolicySchema: schemaName,
				PolicyTargetKey: &chromepolicy.GoogleChromePolicyVersionsV1PolicyTargetKey{
					TargetResource: "orgunits/" + targetID,
				},
			},
		},
	}
	if _, err := g.cp.Customers.Policies.Orgunits.BatchInherit(customer, req).Do(); err != nil {
		return fmt.Errorf("clearing %s on %s: %w", schemaName, orgUnitPath, shortenGoogleError(err))
	}
	return nil
}

// maxPolicySchemaResults caps how many matches SearchPolicySchemas returns -
// Google's full catalog runs into the hundreds, and this is a live keyword
// search meant to help an admin find one real schema, not a bulk export.
const maxPolicySchemaResults = 25

// SearchPolicySchemas pages through the Chrome Policy API's real schema
// catalog (Customers.PolicySchemas.List - the same catalog Admin console's
// own policy editor is built on) and keeps whatever matches query as a
// case-insensitive substring of the schema's name, description, or
// category. There's no server-side keyword filter for this documented with
// confidence, so filtering is done here instead of risking a Filter()
// expression that silently returns nothing on a live domain.
func (g *realGoogleClient) SearchPolicySchemas(query string) ([]*PolicySchemaInfo, error) {
	return g.searchPolicySchemasPaged(query, maxPolicySchemaResults)
}

// searchPolicySchemasPaged is the shared paginated-search implementation -
// stops as soon as it has `limit` matches, not always at
// maxPolicySchemaResults. ListPolicies' category lookups only ever use
// matches[0], so they call this with limit=1: for a keyword with few real
// matches deep in a large catalog, the old code (always capped at 25) had
// to page through the ENTIRE catalog to confirm there weren't 25 matches
// before returning just the 1 it needed - confirmed live as a big chunk of
// why Policy compliance was slow. Search's own public behavior (up to 25
// results) is unchanged.
func (g *realGoogleClient) searchPolicySchemasPaged(query string, limit int) ([]*PolicySchemaInfo, error) {
	customer := "customers/" + g.customerID
	q := strings.ToLower(strings.TrimSpace(query))

	var out []*PolicySchemaInfo
	pageToken := ""
	for {
		call := g.cp.Customers.PolicySchemas.List(customer).PageSize(100)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("searching policy schemas: %w", shortenGoogleError(err))
		}
		for _, s := range resp.PolicySchemas {
			if q != "" &&
				!strings.Contains(strings.ToLower(s.SchemaName), q) &&
				!strings.Contains(strings.ToLower(s.PolicyDescription), q) &&
				!strings.Contains(strings.ToLower(s.CategoryTitle), q) {
				continue
			}
			info := &PolicySchemaInfo{SchemaName: s.SchemaName, Description: s.PolicyDescription, Category: s.CategoryTitle}
			for _, fd := range s.FieldDescriptions {
				field := PolicySchemaField{Name: fd.Field, Description: fd.FieldDescription}
				for _, kv := range fd.KnownValueDescriptions {
					field.KnownValues = append(field.KnownValues, kv.Value)
				}
				info.Fields = append(info.Fields, field)
			}
			out = append(out, info)
			if len(out) >= limit {
				return out, nil
			}
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return out, nil
}

// ListAdminRoles joins Roles.List and RoleAssignments.List - the
// RoleAssignment resource only carries the assignee's opaque directory ID
// (a user_id or group_id, never an email), so each assignment needs one
// follow-up Users.Get or Groups.Get to resolve a human-readable identity.
// Org-unit-scoped assignments similarly carry only an OrgUnitId, resolved
// against the org unit list already used by ListPolicies.
// fetchStorageBytes is a narrow-read_mask telemetry lookup used only as a
// fallback for devices ListDevices found no DiskVolumeReports for - fetches
// just storage_info instead of GetDeviceTelemetry's full mask, since this
// runs once per such device on every sync rather than on-demand.
// decodeConnectionState maps Google's raw enum to a short human label.
// Documented caveat worth keeping in mind: if the device is currently
// offline, this value is whatever it last reported BEFORE going offline
// (the report itself only uploads once the device reconnects) - it is not
// a live ping. That's exactly why the Devices table's Online/Offline badge
// is driven by lastSync recency, not this field; this is only the
// supplementary "what did it last say about its network" detail.
func decodeConnectionState(raw string) string {
	switch raw {
	case "ONLINE":
		return "Online"
	case "CONNECTED":
		return "Connected (no internet)"
	case "PORTAL":
		return "Captive portal"
	case "CONNECTING":
		return "Connecting"
	case "NOT_CONNECTED":
		return "Not connected"
	default:
		return ""
	}
}

type syncTelemetry struct {
	storageFree, storageTotal int64
	connectionState           string // Google's raw enum, e.g. NETWORK_CONNECTION_STATE_ONLINE - decoded before it reaches the frontend
}

// fetchSyncTelemetry is a narrow-read_mask telemetry lookup folded into every
// device sync - one extra Telemetry.Devices.Get per device that's missing
// DiskVolumeReports, covering both the storage fallback (see ListDevices)
// and connection_state in a single call rather than two, since both are
// needed at sync time now and a second full-mask GetDeviceTelemetry call
// per device per sync would double the added API cost for no reason.
func (g *realGoogleClient) fetchSyncTelemetry(deviceID string) (syncTelemetry, error) {
	name := "customers/" + g.customerID + "/telemetry/devices/" + deviceID
	resp, err := g.telemetry.Customers.Telemetry.Devices.Get(name).ReadMask("storage_info,network_status_report").Do()
	if err != nil {
		return syncTelemetry{}, shortenGoogleError(err)
	}
	var out syncTelemetry
	if resp.StorageInfo != nil {
		out.storageFree = resp.StorageInfo.AvailableDiskBytes
		out.storageTotal = resp.StorageInfo.TotalDiskBytes
	}
	if len(resp.NetworkStatusReport) > 0 {
		out.connectionState = resp.NetworkStatusReport[0].ConnectionState
	}
	return out, nil
}

// GetDeviceTelemetry calls the Chrome Management Telemetry API's
// Customers.Telemetry.Devices.Get, resource name "customers/{id}/telemetry/
// devices/{deviceId}" - same customer resource-name convention as the
// Chrome Management reports endpoints. Most report fields are current-STATE
// snapshots (network/battery/boot) where the most-recent-first entry [0] is
// genuinely the only one that matters. AppReport is different - confirmed
// live it's a history of separate usage snapshots over time, each with its
// own apps, not layered duplicates of the same data - so it's the one field
// here that has to be walked in full and aggregated, not read as [0]. If a
// future field turns out to be usage-history-shaped rather than
// current-state-shaped, it needs the same treatment.
func (g *realGoogleClient) GetDeviceTelemetry(deviceID string) (*DeviceTelemetry, error) {
	name := "customers/" + g.customerID + "/telemetry/devices/" + deviceID
	// read_mask is required (confirmed live - a bare Get() 400s with
	// "read_mask is required") - list every report this method maps below,
	// not just a couple, so adding a new mapped field later doesn't also
	// require remembering to widen this mask.
	readMask := strings.Join([]string{
		"storage_info", "boot_performance_report", "network_status_report",
		"network_diagnostics_report", "battery_status_report", "memory_info",
		"memory_status_report", "graphics_info", "audio_status_report",
		"peripherals_report", "app_report",
	}, ",")
	resp, err := g.telemetry.Customers.Telemetry.Devices.Get(name).ReadMask(readMask).Do()
	if err != nil {
		return nil, fmt.Errorf("getting device telemetry: %w", shortenGoogleError(err))
	}

	out := &DeviceTelemetry{}

	if resp.StorageInfo != nil {
		out.StorageAvailableBytes = resp.StorageInfo.AvailableDiskBytes
		out.StorageTotalBytes = resp.StorageInfo.TotalDiskBytes
	}

	if len(resp.BootPerformanceReport) > 0 {
		bp := resp.BootPerformanceReport[0]
		if d, err := time.ParseDuration(bp.BootUpDuration); err == nil {
			out.BootUpDurationSeconds = d.Seconds()
		}
		if d, err := time.ParseDuration(bp.ShutdownDuration); err == nil {
			out.LastShutdownDurationSeconds = d.Seconds()
		}
		out.LastShutdownReason = bp.ShutdownReason
		if bp.ShutdownTime != "" {
			if t, err := time.Parse(time.RFC3339, bp.ShutdownTime); err == nil {
				out.LastShutdownTime = &t
			}
		}
	}

	if len(resp.NetworkStatusReport) > 0 {
		ns := resp.NetworkStatusReport[0]
		out.ConnectionState = ns.ConnectionState
		out.ConnectionType = ns.ConnectionType
		out.LanIpAddress = ns.LanIpAddress
		out.GatewayIpAddress = ns.GatewayIpAddress
	}

	if len(resp.NetworkDiagnosticsReport) > 0 && resp.NetworkDiagnosticsReport[0].HttpsLatencyData != nil {
		lat := resp.NetworkDiagnosticsReport[0].HttpsLatencyData
		out.LatencyProblem = lat.Problem
		if d, err := time.ParseDuration(lat.Latency); err == nil {
			out.LatencyMs = float64(d.Microseconds()) / 1000
		}
	}

	if len(resp.BatteryStatusReport) > 0 {
		bs := resp.BatteryStatusReport[0]
		out.BatteryHealth = bs.BatteryHealth
		out.BatteryCycleCount = bs.CycleCount
	}

	if resp.MemoryInfo != nil {
		out.MemoryAvailableBytes = resp.MemoryInfo.AvailableRamBytes
		out.MemoryTotalBytes = resp.MemoryInfo.TotalRamBytes
	}
	// MemoryInfo.AvailableRamBytes comes and goes between polls (confirmed
	// live - Google's own docs flag the equivalent status-report field as
	// "unreliable due to Garbage Collection"), so fall back to the sampled
	// status report rather than flip between a real number and "not
	// reported" every time the info snapshot happens to omit it.
	if out.MemoryAvailableBytes == 0 && len(resp.MemoryStatusReport) > 0 {
		out.MemoryAvailableBytes = resp.MemoryStatusReport[0].SystemRamFreeBytes
	}

	if resp.GraphicsInfo != nil {
		for _, dd := range resp.GraphicsInfo.DisplayDevices {
			out.Displays = append(out.Displays, DisplayInfo{Name: dd.DisplayName, Internal: dd.Internal})
		}
	}

	if len(resp.AudioStatusReport) > 0 {
		ar := resp.AudioStatusReport[0]
		out.AudioInputDevice = ar.InputDevice
		out.AudioOutputDevice = ar.OutputDevice
		out.AudioOutputVolume = ar.OutputVolume
	}

	if len(resp.PeripheralsReport) > 0 {
		for _, usb := range resp.PeripheralsReport[0].UsbPeripheralReport {
			if usb.Name != "" {
				out.UsbPeripherals = append(out.UsbPeripherals, usb.Name)
			}
		}
	}

	if len(resp.AppReport) > 0 {
		// Two things were wrong here, confirmed live against a real device
		// whose Admin console "Apps installed" view showed 9 apps while this
		// showed 2 (one of them literally repeated):
		//   1. AppReport is a list of separate report SNAPSHOTS (each its own
		//      ReportTime), not one report with everything in it - reading
		//      only AppReport[0] meant every app that only showed up in a
		//      different snapshot was silently invisible.
		//   2. Within a single snapshot, UsageData can carry more than one
		//      entry for the SAME AppId - AppInstanceId is unique per
		//      window/instance, so two windows of the same app produce two
		//      rows Google never merges for you. That's exactly why the same
		//      app id appeared twice with two small durations instead of once
		//      with their sum.
		// Fix: walk every snapshot, and sum durations per AppId instead of
		// appending one row per instance.
		totals := map[string]float64{}
		types := map[string]string{}
		out.AppReportSnapshotCount = len(resp.AppReport)
		for _, report := range resp.AppReport {
			if t, err := time.Parse(time.RFC3339, report.ReportTime); err == nil {
				if out.AppReportOldestTime == nil || t.Before(*out.AppReportOldestTime) {
					out.AppReportOldestTime = &t
				}
			}
			for _, u := range report.UsageData {
				var seconds float64
				if d, err := time.ParseDuration(u.RunningDuration); err == nil {
					seconds = d.Seconds()
				}
				totals[u.AppId] += seconds
				types[u.AppId] = u.AppType
			}
		}
		for appID, seconds := range totals {
			out.AppsUsage = append(out.AppsUsage, AppUsage{
				AppId: appID, AppType: types[appID], RunningDurationSeconds: seconds,
			})
		}
		sort.Slice(out.AppsUsage, func(i, j int) bool {
			return out.AppsUsage[i].RunningDurationSeconds > out.AppsUsage[j].RunningDurationSeconds
		})
		const maxAppsShown = 15
		if len(out.AppsUsage) > maxAppsShown {
			out.AppsUsage = out.AppsUsage[:maxAppsShown]
		}
	}

	return out, nil
}

func (g *realGoogleClient) ListAdminRoles() ([]*AdminRoleAssignment, error) {
	rolesResp, err := g.svcRoles.Roles.List(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", shortenGoogleError(err))
	}
	roleNames := make(map[int64]string, len(rolesResp.Items))
	superAdminRoles := make(map[int64]bool, len(rolesResp.Items))
	for _, role := range rolesResp.Items {
		roleNames[role.RoleId] = role.RoleName
		superAdminRoles[role.RoleId] = role.IsSuperAdminRole
	}

	assignmentsResp, err := g.svcRoles.RoleAssignments.List(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing role assignments: %w", shortenGoogleError(err))
	}

	orgUnitPaths := map[string]string{} // OrgUnitId -> path, populated lazily
	if ous, err := g.ListOrgUnits(); err == nil {
		for _, ou := range ous {
			orgUnitPaths[strings.TrimPrefix(ou.ID, "id:")] = ou.Path
		}
	}

	out := make([]*AdminRoleAssignment, 0, len(assignmentsResp.Items))
	for _, a := range assignmentsResp.Items {
		var email string
		if a.AssigneeType == "group" {
			if grp, err := g.svcExtended.Groups.Get(a.AssignedTo).Do(); err == nil {
				email = grp.Email
			}
		} else {
			if user, err := g.svc.Users.Get(a.AssignedTo).Do(); err == nil {
				email = user.PrimaryEmail
			}
		}
		if email == "" {
			email = a.AssignedTo // fall back to the opaque ID rather than hiding the row
		}
		out = append(out, &AdminRoleAssignment{
			AssigneeEmail:    email,
			AssigneeType:     strings.ToUpper(a.AssigneeType),
			RoleName:         roleNames[a.RoleId],
			IsSuperAdminRole: superAdminRoles[a.RoleId],
			ScopeType:        a.ScopeType,
			OrgUnitPath:      orgUnitPaths[strings.TrimPrefix(a.OrgUnitId, "id:")],
		})
	}
	return out, nil
}

// ListChromeReports calls four Chrome Management API report endpoints.
// Unlike the Directory API, these take a full resource name
// ("customers/{id}"), not the bare customer ID - confirmed against a live
// 404 that showed the malformed path before this prefix was added. The
// complete_time filter value must be a quoted, date-only string
// ("YYYY-MM-DD") - confirmed against a live 400 after full RFC3339
// timestamps (with or without fractional seconds/offset) were all rejected
// as "Invalid date/time string".
func (g *realGoogleClient) ListChromeReports() (*ChromeReports, error) {
	out := &ChromeReports{}
	customer := "customers/" + g.customerID

	// Paginated, same as CountInstalledApps below - one .Do() with no
	// PageToken loop only returns page 1.
	versionsPageToken := ""
	for {
		// PageSize capped at 100 by the real API (confirmed live - 200 got
		// "Page size must be between 0 and 100: found 200" back), same cap
		// applies to the other two paginated reports below.
		call := g.cm.Customers.Reports.CountChromeVersions(customer).PageSize(100)
		if versionsPageToken != "" {
			call = call.PageToken(versionsPageToken)
		}
		versionsResp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("counting chrome versions: %w", shortenGoogleError(err))
		}
		for _, v := range versionsResp.BrowserVersions {
			out.ChromeVersions = append(out.ChromeVersions, ChromeVersionCount{
				Version: v.Version, Channel: v.Channel, Count: v.Count,
			})
		}
		if versionsResp.NextPageToken == "" {
			break
		}
		versionsPageToken = versionsResp.NextPageToken
	}

	// Paginated - a single .Do() with no PageToken loop only ever returns
	// page 1 (confirmed live: a real domain's installed-apps list ran past
	// one page, so apps genuinely installed and reported in a device's own
	// telemetry weren't in this catalog at all, purely because they were on
	// page 2+ that this never fetched - not because they were missing from
	// Google's data).
	pageToken := ""
	for {
		call := g.cm.Customers.Reports.CountInstalledApps(customer).PageSize(100)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		appsResp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("counting installed apps: %w", shortenGoogleError(err))
		}
		for _, a := range appsResp.InstalledApps {
			item := InstalledAppCount{
				AppId: a.AppId, DisplayName: a.DisplayName, AppType: a.AppType,
				AppSource: a.AppSource, HomepageUri: a.HomepageUri,
				BrowserDeviceCount: a.BrowserDeviceCount, OsUserCount: a.OsUserCount,
			}
			if a.AppType == "ANDROID_APP" {
				out.AndroidApps = append(out.AndroidApps, item)
			} else {
				out.InstalledApps = append(out.InstalledApps, item)
			}
		}
		if appsResp.NextPageToken == "" {
			break
		}
		pageToken = appsResp.NextPageToken
	}

	// Paginated too - same gap as CountInstalledApps/CountChromeVersions above.
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02")
	printersPageToken := ""
	for {
		call := g.cm.Customers.Reports.CountPrintJobsByPrinter(customer).
			Filter(fmt.Sprintf(`complete_time>="%s"`, thirtyDaysAgo)).PageSize(100)
		if printersPageToken != "" {
			call = call.PageToken(printersPageToken)
		}
		printersResp, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("counting print jobs: %w", shortenGoogleError(err))
		}
		for _, p := range printersResp.PrinterReports {
			out.Printers = append(out.Printers, PrinterUsage{
				Printer: p.Printer, PrinterModel: p.PrinterModel,
				DeviceCount: p.DeviceCount, JobCount: p.JobCount, UserCount: p.UserCount,
			})
		}
		if printersResp.NextPageToken == "" {
			break
		}
		printersPageToken = printersResp.NextPageToken
	}

	crashResp, err := g.cm.Customers.Reports.CountChromeCrashEvents(customer).
		Filter("past_number_days = '30'").Do()
	if err != nil {
		return nil, fmt.Errorf("counting crash events: %w", shortenGoogleError(err))
	}
	for _, c := range crashResp.CrashEventCounts {
		var date string
		if c.Date != nil {
			date = fmt.Sprintf("%04d-%02d-%02d", c.Date.Year, c.Date.Month, c.Date.Day)
		}
		out.CrashEvents = append(out.CrashEvents, CrashEventCount{
			BrowserVersion: c.BrowserVersion, Count: c.Count, Date: date,
		})
	}

	return out, nil
}

func (g *realGoogleClient) ListUsers() ([]*DirectoryUser, error) {
	resp, err := g.svc.Users.List().Customer(g.customerID).Do()
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}

	out := make([]*DirectoryUser, 0, len(resp.Users))
	for _, u := range resp.Users {
		// Google returns a 1970-01-01 epoch sentinel (not an empty string) for
		// users who have never completed their first login - treat that as
		// "no login recorded" rather than a real, very stale login date.
		var lastLogin *time.Time
		if u.LastLoginTime != "" {
			if t, err := time.Parse(time.RFC3339, u.LastLoginTime); err == nil && t.Year() > 1970 {
				lastLogin = &t
			}
		}
		out = append(out, &DirectoryUser{
			Email:         u.PrimaryEmail,
			Suspended:     u.Suspended,
			LastLoginTime: lastLogin,
			OrgUnit:       u.OrgUnitPath,
		})
	}
	return out, nil
}

func (g *realGoogleClient) ListOrgUnits() ([]*OrgUnitInfo, error) {
	resp, err := g.svc.Orgunits.List(g.customerID).Type("all").Do()
	if err != nil {
		return nil, fmt.Errorf("listing org units: %w", err)
	}

	out := make([]*OrgUnitInfo, 0, len(resp.OrganizationUnits))
	for _, ou := range resp.OrganizationUnits {
		out = append(out, &OrgUnitInfo{
			ID:         ou.OrgUnitId,
			Path:       ou.OrgUnitPath,
			Name:       ou.Name,
			ParentPath: ou.ParentOrgUnitPath,
		})
	}
	return out, nil
}

// DoAction maps our simplified "restart" / "wipe" verbs onto Google's
// issueCommand API. Command type names are documented here:
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/customer.devices.chromeos/issueCommand
// Double check these enum values against that page before relying on them -
// Google has added new command types over time and I can't verify the
// current full list from here.
// commandActions maps our action names to Google's issueCommand CommandType
// enum. This is the complete list the Directory API exposes as of this
// client version - there is no "reload policies" or bare "reset" command;
// REMOTE_POWERWASH (our "powerwash") is the closest real equivalent to a
// factory reset. TAKE_A_SCREENSHOT/SET_VOLUME/REBOOT/CAPTURE_LOGS are
// documented by Google as Kiosk/managed-guest-session only, so they'll
// return a real (not fabricated) error on an ordinary user-session device -
// confirmed live rather than assumed.
var commandActions = map[string]string{
	"restart":         "REBOOT",
	"wipe":             "WIPE_USERS",
	"powerwash":        "REMOTE_POWERWASH",
	"screenshot":       "TAKE_A_SCREENSHOT",
	"set_volume":       "SET_VOLUME",
	"crd":              "DEVICE_START_CRD_SESSION",
	"capture_logs":     "CAPTURE_LOGS",
	"support_packet":   "FETCH_SUPPORT_PACKET",
}

// batchStatusActions maps our action names to the modern
// BatchChangeChromeOsDeviceStatus enum - confirmed live that the older,
// simpler Chromeosdevices.Patch(Status: "DISABLED") call returns 200 OK but
// silently does NOT change the device's real status (a re-sync right after
// still showed ACTIVE). Patch's "status" field is apparently not actually
// wired up server-side for this transition, despite no error being
// returned - BatchChangeStatus is Google's dedicated, non-deprecated
// endpoint for exactly this (disable/re-enable/deprovision), and returns a
// real per-device error if the transition doesn't succeed.
var batchStatusActions = map[string]string{
	"disable":     "CHANGE_CHROME_OS_DEVICE_STATUS_ACTION_DISABLE",
	"enable":      "CHANGE_CHROME_OS_DEVICE_STATUS_ACTION_REENABLE",
	"deprovision": "CHANGE_CHROME_OS_DEVICE_STATUS_ACTION_DEPROVISION",
}

func (g *realGoogleClient) DoAction(deviceID, action, payload string) (string, error) {
	if commandType, ok := commandActions[action]; ok {
		req := &admin.DirectoryChromeosdevicesIssueCommandRequest{CommandType: commandType}
		switch action {
		case "set_volume":
			req.Payload = fmt.Sprintf(`{"volume":%s}`, payload)
		case "crd":
			req.Payload = `{"ackedUserPresence":true}`
		}
		resp, err := g.svc.Customer.Devices.Chromeos.IssueCommand(g.customerID, deviceID, req).Do()
		if err != nil {
			return "", fmt.Errorf("issuing %s command: %w", commandType, shortenGoogleError(err))
		}
		if action != "crd" {
			return "", nil
		}
		// DEVICE_START_CRD_SESSION's session URL isn't in the issueCommand
		// response - it only shows up later on the command's own result,
		// once the device has picked it up. Poll briefly rather than
		// reporting "Done" with no way to actually connect.
		return g.pollCommandResult(deviceID, resp.CommandId)
	}

	if statusAction, ok := batchStatusActions[action]; ok {
		req := &admin.BatchChangeChromeOsDeviceStatusRequest{
			ChangeChromeOsDeviceStatusAction: statusAction,
			DeviceIds:                        []string{deviceID},
		}
		if action == "deprovision" {
			req.DeprovisionReason = payload
			if req.DeprovisionReason == "" {
				req.DeprovisionReason = "DEPROVISION_REASON_RETIRING_DEVICE"
			}
		}
		resp, err := g.svc.Customer.Devices.Chromeos.BatchChangeStatus(g.customerID, req).Do()
		if err != nil {
			return "", fmt.Errorf("changing device status to %s: %w", statusAction, shortenGoogleError(err))
		}
		for _, r := range resp.ChangeChromeOsDeviceStatusResults {
			if r.Error != nil {
				return "", fmt.Errorf("changing device status to %s: %s", statusAction, r.Error.Message)
			}
		}
		return "", nil
	}

	if action == "move" {
		if payload == "" {
			return "", fmt.Errorf("move requires a target org unit path")
		}
		_, err := g.svc.Chromeosdevices.Patch(g.customerID, deviceID, &admin.ChromeOsDevice{OrgUnitPath: payload}).Do()
		if err != nil {
			return "", fmt.Errorf("moving device: %w", shortenGoogleError(err))
		}
		return "", nil
	}

	return "", fmt.Errorf("unsupported action: %s", action)
}

// BatchMoveDevices moves many devices to the same org unit in one API call
// via Chromeosdevices.MoveDevicesToOu, instead of the N individual Patch
// calls a loop over DoAction("move", ...) would make - one HTTP round trip
// (and one place for Google to reject the whole batch) regardless of
// selection size.
func (g *realGoogleClient) BatchMoveDevices(deviceIDs []string, orgUnit string) error {
	if orgUnit == "" {
		return fmt.Errorf("batch move requires a target org unit path")
	}
	req := &admin.ChromeOsMoveDevicesToOu{DeviceIds: deviceIDs}
	if err := g.svc.Chromeosdevices.MoveDevicesToOu(g.customerID, orgUnit, req).Do(); err != nil {
		return fmt.Errorf("moving %d devices: %w", len(deviceIDs), shortenGoogleError(err))
	}
	return nil
}

// defaultTelemetryEventTypes is used when the caller doesn't ask for
// specific ones - the API requires at least one event_type in the filter
// (a bare List() 400s without it, per Google's own doc note that this
// parameter "will be required" even though currently optional), so there's
// no such thing as "give me everything" the way ListDevices has no filter.
var defaultTelemetryEventTypes = []string{
	"NETWORK_STATE_CHANGE", "USB_ADDED", "USB_REMOVED", "NETWORK_HTTPS_LATENCY_CHANGE",
	"WIFI_SIGNAL_STRENGTH_LOW", "WIFI_SIGNAL_STRENGTH_RECOVERED", "VPN_CONNECTION_STATE_CHANGE",
	"APP_INSTALLED", "APP_UNINSTALLED", "AUDIO_SEVERE_UNDERRUN",
}

// ListDeviceEvents calls the Chrome Management Telemetry API's Events feed -
// a genuinely different data source from GetDeviceTelemetry's point-in-time
// snapshots: this is the actual event stream Google pushes as things
// happen on the device (network changes, USB, app installs, audio/WiFi
// issues), not a periodic poll result.
func (g *realGoogleClient) ListDeviceEvents(eventTypes []string, since time.Time) ([]*DeviceEvent, error) {
	if len(eventTypes) == 0 {
		eventTypes = defaultTelemetryEventTypes
	}

	// read_mask is required (same quirk already confirmed live on
	// GetDeviceTelemetry - a bare List() 400s with "read_mask is required")
	// - list every field this method reads below, so a new field added
	// later doesn't also require remembering to widen this mask.
	readMask := strings.Join([]string{
		"device", "user", "event_type", "report_time",
		"network_state_change_event", "vpn_connection_state_change_event",
		"usb_peripherals_event", "https_latency_change_event", "wifi_signal_strength_event",
		"app_install_event", "app_uninstall_event", "app_launch_event", "audio_severe_underrun_event",
	}, ",")
	sinceStr := since.UTC().Format("2006-01-02T15:04:05.000000000Z")

	// Confirmed live: the filter has to be a flat AND-only list of
	// restrictions - no OR, no parentheses ("Filter should be a flat list
	// 'AND'-separated restrictions"). So there's no single query for
	// "any of these event types" - one List call per event type, merged
	// here, instead of the one-call-with-OR this originally tried.
	out := []*DeviceEvent{}
	for _, eventType := range eventTypes {
		filter := fmt.Sprintf(`timestamp > "%s" AND event_type=%s`, sinceStr, eventType)
		resp, err := g.telemetry.Customers.Telemetry.Events.List("customers/"+g.customerID).Filter(filter).PageSize(50).ReadMask(readMask).Do()
		if err != nil {
			return nil, fmt.Errorf("listing %s telemetry events: %w", eventType, shortenGoogleError(err))
		}
		for _, e := range resp.TelemetryEvents {
			reportTime, _ := time.Parse(time.RFC3339, e.ReportTime)
			ev := &DeviceEvent{
				ID:         e.Name,
				EventType:  e.EventType,
				ReportTime: reportTime,
			}
			if e.Device != nil {
				ev.DeviceID = e.Device.DeviceId
			}
			if e.User != nil {
				ev.UserEmail = e.User.Email
			}
			ev.Description = describeTelemetryEvent(e)
			out = append(out, ev)
		}
	}
	return out, nil
}

// describeTelemetryEvent builds a one-line human summary from whichever
// type-specific payload is populated - the API only fills in the one field
// matching EventType, so this is a straight switch, not a guess.
func describeTelemetryEvent(e *chromemanagement.GoogleChromeManagementV1TelemetryEvent) string {
	switch e.EventType {
	case "NETWORK_STATE_CHANGE":
		if e.NetworkStateChangeEvent != nil {
			return "Network connection state changed to " + e.NetworkStateChangeEvent.ConnectionState
		}
	case "VPN_CONNECTION_STATE_CHANGE":
		if e.VpnConnectionStateChangeEvent != nil {
			return "VPN connection state changed to " + e.VpnConnectionStateChangeEvent.ConnectionState
		}
	case "USB_ADDED", "USB_REMOVED":
		if e.UsbPeripheralsEvent != nil && len(e.UsbPeripheralsEvent.UsbPeripheralReport) > 0 {
			names := make([]string, len(e.UsbPeripheralsEvent.UsbPeripheralReport))
			for i, p := range e.UsbPeripheralsEvent.UsbPeripheralReport {
				if p.Name != "" {
					names[i] = p.Name
				} else {
					names[i] = p.Vendor
				}
			}
			verb := "connected"
			if e.EventType == "USB_REMOVED" {
				verb = "disconnected"
			}
			return "USB device " + verb + ": " + strings.Join(names, ", ")
		}
	case "NETWORK_HTTPS_LATENCY_CHANGE":
		if e.HttpsLatencyChangeEvent != nil {
			return "HTTPS latency state: " + e.HttpsLatencyChangeEvent.HttpsLatencyState
		}
	case "WIFI_SIGNAL_STRENGTH_LOW", "WIFI_SIGNAL_STRENGTH_RECOVERED":
		if e.WifiSignalStrengthEvent != nil {
			return fmt.Sprintf("WiFi signal strength: %d dBm", e.WifiSignalStrengthEvent.SignalStrengthDbm)
		}
	case "APP_INSTALLED":
		if e.AppInstallEvent != nil {
			return "App installed: " + e.AppInstallEvent.AppId
		}
	case "APP_UNINSTALLED":
		if e.AppUninstallEvent != nil {
			return "App uninstalled: " + e.AppUninstallEvent.AppId
		}
	case "APP_LAUNCHED":
		if e.AppLaunchEvent != nil {
			return "App launched: " + e.AppLaunchEvent.AppId
		}
	case "AUDIO_SEVERE_UNDERRUN":
		return "Audio buffer underrun (severe)"
	}
	return ""
}

// pollCommandResult retries Commands.Get a few times, since the device has
// to actually pick up the command before a result (success/failure/payload)
// exists - immediately after issueCommand returns, there's usually nothing
// there yet.
func (g *realGoogleClient) pollCommandResult(deviceID string, commandID int64) (string, error) {
	// Confirmed live: a real device commonly takes longer than a few seconds
	// to notice a new CRD request (it depends on the device's own
	// policy-check interval, and on CRD specifically, on a user actually
	// being present to accept it) - 12 tries at 5s gives it a full minute
	// before giving up, still bounded since this runs in a background
	// goroutine, not blocking the HTTP response.
	for i := 0; i < 12; i++ {
		time.Sleep(5 * time.Second)
		cmd, err := g.svc.Customer.Devices.Chromeos.Commands.Get(g.customerID, deviceID, commandID).Do()
		if err != nil {
			continue // transient - the command may not be queryable yet
		}
		if cmd.CommandResult == nil {
			continue
		}
		switch cmd.CommandResult.Result {
		case "SUCCESS":
			var payload struct {
				Url string `json:"url"`
			}
			if json.Unmarshal([]byte(cmd.CommandResult.CommandResultPayload), &payload) == nil && payload.Url != "" {
				return payload.Url, nil
			}
			return "", nil
		case "FAILURE":
			return "", fmt.Errorf("device reported command failure: %s", cmd.CommandResult.ErrorMessage)
		case "IGNORED":
			return "", fmt.Errorf("device ignored the command as obsolete")
		}
	}
	return "", fmt.Errorf("device hasn't picked up the command yet - it may be offline or asleep; check again shortly")
}

// ---------- Factory ----------

// NewGoogleClientFromEnv picks mock or real based on GOOGLE_MODE.
// Defaults to mock so the project keeps working out of the box.
func NewGoogleClientFromEnv() GoogleClient {
	mode := os.Getenv("GOOGLE_MODE")
	if mode != "real" {
		return &mockGoogleClient{}
	}

	keyPath := os.Getenv("GOOGLE_SERVICE_ACCOUNT_KEY")
	adminEmail := os.Getenv("GOOGLE_ADMIN_EMAIL")
	customerID := os.Getenv("GOOGLE_CUSTOMER_ID")
	if customerID == "" {
		customerID = "my_customer"
	}

	if keyPath == "" || adminEmail == "" {
		fmt.Println("GOOGLE_MODE=real but GOOGLE_SERVICE_ACCOUNT_KEY or GOOGLE_ADMIN_EMAIL is missing - falling back to mock")
		return &mockGoogleClient{}
	}

	client, err := NewRealGoogleClient(context.Background(), keyPath, adminEmail, customerID)
	if err != nil {
		fmt.Printf("failed to init real google client, falling back to mock: %v\n", err)
		return &mockGoogleClient{}
	}
	return client
}
