# ChromeOS connector prototype

A working prototype of the ChromeOS-connector automation flow: a Go backend
with a mock Google Admin SDK client (so it runs with zero real Google
credentials), and a React frontend (no build step) that drives the real
connect wizard and device dashboard against that backend.

This mirrors exactly what was designed in conversation:
- `POST /connect/init` - generates client ID + scopes (automated)
- the one manual step - authorizing in Google Admin console (mocked here as
  an auto-approval after the first status poll)
- `POST /connect/finish` - starts the sync worker (automated)
- `GET /status`, `GET /devices` - drive the dashboard
- `POST /devices/action` - async remote actions (restart/wipe), same pattern
  Google's real `chromeosdevices.action` API uses

## First-time setup (required once, even for mock mode)

`google.go` now imports two real Google-published packages. Fetch them once -
this needs your machine's normal internet access, not anything special:

```bash
cd backend
go mod tidy
```

This downloads `golang.org/x/oauth2` and `google.golang.org/api` and writes a
`go.sum`. You only need to do this once.

## Run the backend (mock mode - default, no Google credentials needed)

```bash
cd backend
go run .
```

You should see:
```
chromeos connector mock backend listening on :8080
```

Leave this running in its own terminal.

## Run the backend (real mode - talks to your actual Google Workspace)

Set these environment variables first (PowerShell shown, adjust for your
shell):

```powershell
$env:GOOGLE_MODE = "real"
$env:GOOGLE_SERVICE_ACCOUNT_KEY = "C:\Users\Work PC.DESKTOP-3L7JM27\Downloads\chrome-os-testing-668b94269512.json"
$env:GOOGLE_ADMIN_EMAIL = "testuser1@tectoro.com"
$env:GOOGLE_CUSTOMER_ID = "my_customer"
$env:GOOGLE_OAUTH_CLIENT_ID = "115543639239444614288"
go run .
```

If `GOOGLE_MODE=real` but the key path or admin email is missing, or the key
fails to load, the server logs a warning and falls back to mock mode rather
than crashing - check the startup log to confirm which mode actually took
effect.

**Important - what I could and couldn't verify:** I wrote `google.go` against
the documented Admin SDK Directory API shape (verified via web search while
building it), but I have no network path to `proxy.golang.org` or
`googleapis.com` from my own environment, so I could not compile or run this
against a real Google Workspace myself. Mock mode is fully tested end-to-end;
real mode is not. If `go build` fails on a method or field name in
`google.go`, run:

```bash
go doc google.golang.org/api/admin/directory/v1 admin.Service
```

and share the output with me - the package surface occasionally differs
slightly by version and I'd rather fix it against your real error than guess.

## Run the frontend

No npm install needed - it loads React from a CDN and has no build step.
Just open the file directly, or serve it so `fetch` calls behave normally:

```bash
cd frontend
python3 -m http.server 3000
```

Then open **http://localhost:3000** in a browser.

## Test it manually via curl (no frontend needed)

```bash
# 1. generate credentials
curl -X POST http://localhost:8080/api/chromeos/connect/init

# 2. check consent status (auto-authorizes in this mock)
curl http://localhost:8080/api/chromeos/connect/status

# 3. finish - starts the background sync
curl -X POST http://localhost:8080/api/chromeos/connect/finish

# 4. after ~2s, check status and device list
curl http://localhost:8080/api/chromeos/status
curl http://localhost:8080/api/chromeos/devices

# 5. try a remote action (use a real device id from step 4)
curl -X POST "http://localhost:8080/api/chromeos/devices/action?id=<device_id>" \
  -H "Content-Type: application/json" \
  -d '{"action":"restart"}'

# 6. reset back to disconnected
curl -X POST http://localhost:8080/api/chromeos/disconnect
```

## What's mocked vs. what's real-shaped

| Piece | In this prototype | In production |
|---|---|---|
| Client ID / scopes | Hardcoded string | Generated via Google Cloud IAM API |
| Admin authorization | Auto-approved on first poll | Real click in Google Admin console (the one unavoidable manual step) |
| Device list | 5 fake ChromeOS devices | `admin.googleapis.com` `chromeosdevices.list` |
| Remote actions | Fake 2s delay then "complete" | Real `chromeosdevices.action` call, polled for real completion |
| Credential storage | In-memory, lost on restart | Encrypted vault (e.g. KMS-wrapped row in Postgres) |
| Sync trigger | One-time on finish | Recurring worker (cron/queue) + Admin SDK push webhook |

Swapping the mock Google client for the real one is a matter of implementing
the same interface shape against `admin.googleapis.com` with real OAuth2
service-account credentials - the API surface, state machine, and frontend
don't need to change.

## Next steps to make this production-shaped

1. Swap in-memory `Store` for Postgres (or your existing DB)
2. Replace `mockDeviceList()` with a real `admin.googleapis.com` client using
   a service account + domain-wide delegation
3. Move the sync trigger from "once on finish" to a recurring job (cron or a
   durable queue like River/Asynq) plus a webhook receiver for push updates
4. Encrypt stored credentials (KMS or similar) rather than keeping them in
   plain memory
5. Add auth to the API itself - right now anyone hitting `:8080` can call it
