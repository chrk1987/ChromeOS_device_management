import { API_URL, AUTH_URL, AUTH_LOGIN_URL, USE_COLLECTOR_API, TENANT_ID } from './config.js';

let cachedToken = null;
let cachedRefreshToken = null;

// pendingLocationPings holds points that were captured on-device but
// couldn't be published (no internet, server unreachable, etc) instead of
// being silently discarded. flushQueue() retries them, oldest first, the
// next time pingLocation() runs. MAX_QUEUE_SIZE bounds local storage if a
// device stays offline for a long stretch - past that, the oldest points
// are dropped rather than the newest.
const QUEUE_KEY = "pendingLocationPings";
const MAX_QUEUE_SIZE = 50;

// --- On-device diagnostic log ---------------------------------------------
// chrome://extensions' "service worker" inspect link and
// chrome://serviceworker-internals aren't reliably reachable on every real
// managed device (policy-installed extensions, restricted DevTools, etc).
// This keeps a rolling trace of every pipeline checkpoint in
// chrome.storage.local instead, viewable from options.html - a normal
// extension page reachable via "Extension options" on the card, no
// DevTools/Developer Mode required.
const DIAG_KEY = "diagnosticLog";
const MAX_DIAG_ENTRIES = 200;

// Chained onto the previous write so overlapping calls (e.g. the alarm
// listener's own log call racing with pingLocation's very next logDiag call,
// neither of which awaits the other) can't both read the array before
// either write lands and silently clobber one another - confirmed happening
// in practice: "alarm fired" entries were consistently missing from real
// device logs even though the code logs one on every single alarm.
let diagWriteQueue = Promise.resolve();

async function logDiag(stage, detail) {
  diagWriteQueue = diagWriteQueue.then(async () => {
    try {
      const data = await chrome.storage.local.get(DIAG_KEY);
      const log = data[DIAG_KEY] || [];
      log.push({ ts: Date.now(), stage, detail: String(detail ?? "") });
      const trimmed = log.length > MAX_DIAG_ENTRIES ? log.slice(log.length - MAX_DIAG_ENTRIES) : log;
      await chrome.storage.local.set({ [DIAG_KEY]: trimmed });
    } catch (e) {
      // Best-effort only - a logging failure must never break the real ping flow.
    }
  });
  return diagWriteQueue;
}

// Helper to decode JWT payload without an external library
function decodeJwtPayload(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error("Failed to decode JWT payload:", e);
    return null;
  }
}

// When the extension is installed or updated, set up an alarm to ping location
chrome.runtime.onInstalled.addListener(() => {
  logDiag("lifecycle", "onInstalled fired - creating alarm and running initial ping");
  // Ping every 15 minutes
  chrome.alarms.create("location-ping", { periodInMinutes: 15 });
  // Also do an initial ping right away
  pingLocation();
});

// onInstalled only fires on install/update, not on every normal boot - so
// without this, after a shutdown/restart the device would sit silent for
// up to a full 15-minute cycle before reporting anything again, for no
// real reason.
chrome.runtime.onStartup.addListener(() => {
  logDiag("lifecycle", "onStartup fired - device/browser just booted");
  pingLocation();
});

// Listen for the alarm to trigger
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "location-ping") {
    logDiag("lifecycle", "alarm fired: location-ping");
    pingLocation();
  }
});

// Lets the diagnostics options page (or anything else in this extension)
// trigger an immediate ping without waiting for the next 15-minute alarm.
// sendMessage itself wakes an idle service worker, so this works even if
// nothing else has run in a while. pingLocation() already catches and logs
// its own errors internally (never rejects), so this always resolves - the
// diagnostics log is the actual source of truth for what happened, this
// response just confirms the run completed.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'force-sync') {
    logDiag("lifecycle", "manual force-sync triggered from diagnostics page");
    pingLocation().then(() => sendResponse({ ok: true }));
    return true; // async response
  }
});

// Fires the moment this module is evaluated - if this entry never shows up
// in the diagnostic log, the service worker never even started (a bad
// import, a missing packaged file, etc), which is a different failure mode
// entirely from anything below actually running and failing partway.
logDiag("lifecycle", "background.js module evaluated - service worker starting");

async function getAuthToken(deviceId) {
  if (!USE_COLLECTOR_API) return null; // Local testing doesn't need auth
  // We temporarily disable cachedToken return here so we can repeatedly test Step 1 & 2.
  // if (cachedToken) {
  //   console.debug("getAuthToken: Using cached JWT token");
  //   return cachedToken;
  // }

  try {
    const authEndpoint = AUTH_URL.replace("{deviceId}", deviceId);

    console.log(`getAuthToken [Step 1]: Requesting device feedback code from ${authEndpoint}`);

    // MOCK RESPONSE FOR TESTING:
    // Because the real dev server returns "404 page not found" for this device ID,
    // we are mocking the fetch response here so you can verify the integration logs!
    const mockResponse = {
      ok: true,
      json: async () => ({
        "data": "df90225c1d71befe83b252535968695b::dc0f446269e985f21deecd8665c82a2b::1f832fb464f5c43e9960b28357c0bf1cd51cc938f165bd38cc50a173cf935b54afd5a69a35b40c522c5c441314cc7ce79b8f8a331803b15d439d15a2ae8dfa1817a7fcfe06ee0ab1312046fd581c954e32dbc012cc2a019564591ccfbf8c85125de338aaa060c2074e71117a3e52e8fa4976ddeb822a0d70a876676ff4d1b12f44b10af9ebe82b4413b89c87ec99ee3f",
        "status": "success"
      })
    };

    // In production, uncomment the real fetch below:
    // GET, not POST - confirmed by hitting this URL directly in a browser
    // (always a GET) returning 200 success, while a POST 404s.
    // const response = await fetch(authEndpoint, { method: 'GET', headers: { 'Accept': 'application/json' } });
    const response = mockResponse; // USING MOCK

    if (response.ok) {
      const result = await response.json();
      console.log("getAuthToken [Step 1]: Successfully retrieved feedback response!");

      if (result.status === "success" && result.data) {
        console.log("getAuthToken [Step 1]: Extracted data code:", result.data);

        // --- STEP 2 ---
        console.log(`getAuthToken [Step 2]: Exchanging code for JWT token at ${AUTH_LOGIN_URL}`);
        const loginResponse = await fetch(AUTH_LOGIN_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            code: result.data,
            app: "Launcher"
          })
        });

        if (loginResponse.ok) {
          const loginData = await loginResponse.json();
          console.log("getAuthToken [Step 2]: Successfully retrieved final JWT token!");
          console.log("Raw Login Response:", loginData);

          cachedToken = loginData.token || loginData.jwt || loginData.access_token || (loginData.data && loginData.data.token) || loginData.data;
          cachedRefreshToken = loginData.refresh_token || loginData.refreshToken || (loginData.data && (loginData.data.refresh_token || loginData.data.refreshToken));

          await logDiag("auth_ok", "JWT obtained via device feedback code exchange");
          return cachedToken;
        } else {
          const loginError = await loginResponse.text();
          console.error(`getAuthToken [Step 2]: Failed. Status: ${loginResponse.status} ${loginResponse.statusText}`);
          console.error(`getAuthToken [Step 2]: Error Response Body:`, loginError);
          await logDiag("auth_step2_fail", `HTTP ${loginResponse.status} ${loginResponse.statusText}: ${loginError}`);
        }
      } else {
        console.error("getAuthToken [Step 1]: Response did not contain success status or data field.", result);
        await logDiag("auth_step1_fail", `unexpected response shape: ${JSON.stringify(result)}`);
      }
    } else {
      const errorText = await response.text();
      console.error(`getAuthToken [Step 1]: Failed. Status: ${response.status} ${response.statusText}`);
      console.error(`getAuthToken [Step 1]: Error Response Body:`, errorText);
      await logDiag("auth_step1_fail", `HTTP ${response.status} ${response.statusText}: ${errorText}`);
    }
  } catch (err) {
    console.error("getAuthToken: Error making API call:", err);
    await logDiag("auth_error", err.message);
  }
  return null;
}

// Helper to reverse geocode lat/lng to an actual address. Returns null on
// any failure (including no internet) rather than throwing - callers treat
// a null result as "queue the raw coordinates without an address" instead
// of losing the point entirely.
async function reverseGeocode(lat, lng) {
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`;
    const response = await fetch(url, {
      headers: {
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Agent': 'ChromeOS-Location-Tracker-Extension/1.0'
      }
    });
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.error("Failed to reverse geocode:", error);
  }
  return null;
}

// --- Offline queue -------------------------------------------------------

async function getQueue() {
  const data = await chrome.storage.local.get(QUEUE_KEY);
  return data[QUEUE_KEY] || [];
}

async function setQueue(queue) {
  await chrome.storage.local.set({ [QUEUE_KEY]: queue });
}

async function enqueuePoint(point) {
  const queue = await getQueue();
  queue.push(point);
  // Drop the oldest points once over the cap - keeps the most recent
  // history, not an ever-growing backlog, if a device is offline for days.
  const trimmed = queue.length > MAX_QUEUE_SIZE ? queue.slice(queue.length - MAX_QUEUE_SIZE) : queue;
  await setQueue(trimmed);
  console.log(`enqueuePoint: queued 1 point, ${trimmed.length} pending in local history`);
}

// Applies the server's requested ping interval, if it sent one - shared by
// both the live-publish path and the queue-flush path since either one
// might be the one that actually reaches the server first.
async function applyServerInterval(data) {
  const newInterval = (data && data.intervalMinutes) || 15;
  const alarm = await chrome.alarms.get("location-ping");
  if (!alarm || alarm.periodInMinutes !== newInterval) {
    console.log(`applyServerInterval: Updating ping interval to ${newInterval} minutes`);
    chrome.alarms.create("location-ping", { periodInMinutes: newInterval });
  }
}

// Builds and sends the actual HTTP request for one point (queued or fresh)
// - factored out of pingLocation so the live path and the retry-from-queue
// path share identical request-building logic. Throws on any failure
// (network error or non-2xx) so callers can tell "published" apart from
// "still failing."
async function publishPoint(point) {
  let payload;
  let headers = { 'Content-Type': 'application/json' };
  let token = null;
  let haloFortDeviceId = point.deviceId;
  // TENANT_ID (from config.js/flavours.json) is only a last-resort fallback -
  // the feedback/login API's JWT is the actual source of truth for which
  // tenant a device belongs to, same as it already is for the device ID.
  let haloFortTenantId = TENANT_ID;

  if (USE_COLLECTOR_API) {
    token = await getAuthToken(point.deviceId);

    if (token) {
      const decodedPayload = decodeJwtPayload(token);
      if (decodedPayload && decodedPayload.device) {
        haloFortDeviceId = decodedPayload.device;
        console.log(`publishPoint: Extracted HaloFort Device ID from JWT: ${haloFortDeviceId}`);
      } else {
        console.warn("publishPoint: Could not extract 'device' field from JWT payload. Using Workspace Device ID as fallback.");
      }
      const jwtTenantId = decodedPayload && (decodedPayload.tenant || decodedPayload.tenantId || decodedPayload.tenant_id || decodedPayload.tn);
      if (jwtTenantId) {
        haloFortTenantId = jwtTenantId;
        console.log(`publishPoint: Extracted HaloFort Tenant ID from JWT: ${haloFortTenantId}`);
        await logDiag("tenant_id_ok", haloFortTenantId);
      } else {
        console.warn("publishPoint: Could not extract a tenant field from JWT payload. Using configured TENANT_ID as fallback.");
        await logDiag("tenant_id_fallback", `no tenant claim in JWT - using configured TENANT_ID "${TENANT_ID}"`);
      }
    } else {
      console.warn("publishPoint: No valid JWT token returned. Will proceed without it (using Workspace Device ID and configured TENANT_ID).");
    }

    payload = {
      "_et": "location_v1",
      "_ed": Math.floor(point.timestamp / 1000),
      "_tn": haloFortTenantId,
      "_d": haloFortDeviceId,
      "_p": {
        "ge": `${point.lat},${point.lng}`,
        "a1": point.displayName || "",
        "a2": point.address.county || point.address.state_district || "",
        "a3": point.address.suburb || point.address.neighbourhood || point.address.residential || point.address.road || "",
        "ci": point.address.city || point.address.town || point.address.village || point.address.municipality || "",
        "st": point.address.state || "",
        "co": point.address.country || ""
      }
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    console.log("publishPoint: Sending payload to HaloFort collector:", payload);
  } else {
    payload = {
      deviceId: point.deviceId,
      location: {
        lat: point.lat,
        lng: point.lng,
        accuracy: point.accuracy,
        timestamp: point.timestamp
      }
    };

    console.log("publishPoint: Sending payload to local backend:", payload);
  }

  await logDiag("publish_attempt", API_URL);

  const response = await fetch(API_URL, {
    method: 'POST',
    headers: headers,
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorText = await response.text();
    if (response.status === 401 && USE_COLLECTOR_API) {
      console.warn("publishPoint: Received 401 Unauthorized, clearing cached JWT token.");
      cachedToken = null;
    }
    await logDiag("publish_fail", `HTTP ${response.status} ${response.statusText}: ${errorText}`);
    const err = new Error(`HTTP ${response.status} ${response.statusText}: ${errorText}`);
    // A 4xx (other than 401, which just needs a fresh token next attempt -
    // handled above) means the server actively rejected this exact payload;
    // retrying the identical point will never succeed. Marking it
    // non-retryable lets flushQueue drop it instead of retrying it forever
    // and blocking every point queued behind it. 5xx and network-level
    // failures (fetch() itself throwing, with no .retryable set at all)
    // stay retryable, since those are transient.
    err.retryable = !(response.status >= 400 && response.status < 500 && response.status !== 401);
    throw err;
  }
  await logDiag("publish_ok", `HTTP ${response.status}`);

  const responseText = await response.text();
  let data = {};
  if (responseText) {
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      console.warn("publishPoint: Server returned non-JSON response:", responseText);
    }
  }
  return data;
}

// Retries every queued point, oldest first, stopping at the first failure
// (rather than skipping ahead) so history publishes in the order it
// happened and we don't hammer the network with several failing requests
// in a row when clearly still offline.
async function flushQueue() {
  let remaining = await getQueue();
  if (remaining.length === 0) return;

  console.log(`flushQueue: attempting to publish ${remaining.length} queued point(s)...`);
  await logDiag("flush_start", `${remaining.length} point(s) queued`);
  while (remaining.length > 0) {
    const point = remaining[0];
    try {
      const data = await publishPoint(point);
      remaining = remaining.slice(1);
      await setQueue(remaining);
      console.log(`flushQueue: published a point captured at ${new Date(point.timestamp).toLocaleString()} - ${remaining.length} still pending.`);
      await applyServerInterval(data);
    } catch (err) {
      if (err.retryable === false) {
        // Permanently invalid payload (a 4xx the server actively rejected,
        // not a transient/network failure) - retrying the exact same point
        // will never succeed, so drop it and move on to the next queued
        // point instead of blocking the whole queue on it forever.
        console.error(`flushQueue: dropping a permanently-invalid point captured at ${new Date(point.timestamp).toLocaleString()} (${err.message}) - will not retry.`);
        await logDiag("publish_dropped", `non-retryable (${err.message}) - point captured at ${new Date(point.timestamp).toLocaleString()} dropped, not retried`);
        remaining = remaining.slice(1);
        await setQueue(remaining);
        continue;
      }
      console.warn(`flushQueue: still failing to publish (${err.message}) - ${remaining.length} point(s) remain queued for next attempt.`);
      break;
    }
  }
}

async function pingLocation() {
  console.log("pingLocation: Starting location ping sequence...");
  await logDiag("ping_start", "pingLocation invoked");

  // Publish anything left over from a previous offline stretch before
  // capturing a new point, so history goes out in the order it happened.
  await flushQueue();

  try {
    // 1. Get the exact Google Workspace Device ID dynamically
    let deviceId = "3421537a-01b4-4013-9654-de1c6a2cf3b9"; // Fallback for local testing
    if (chrome.enterprise && chrome.enterprise.deviceAttributes) {
      deviceId = await new Promise((resolve) => {
        chrome.enterprise.deviceAttributes.getDirectoryDeviceId(resolve);
      });
      console.log(`pingLocation: Fetched real device ID: ${deviceId}`);
      await logDiag("device_id_ok", deviceId);
    } else {
      console.warn("pingLocation: chrome.enterprise.deviceAttributes API not available. Using fallback device ID.");
      await logDiag("device_id_fallback", `enterprise.deviceAttributes unavailable - using fallback ID ${deviceId}`);
    }
    await chrome.storage.local.set({ lastKnownDeviceId: deviceId });

    // 2. Setup offscreen document for geolocation (required in Manifest V3)
    await setupOffscreenDocument('offscreen.html');

    // 3. Request geolocation from the offscreen document
    console.log("pingLocation: Requesting geolocation from offscreen document...");
    const location = await chrome.runtime.sendMessage({
      target: 'offscreen',
      type: 'get-geolocation'
    });

    if (location.error) {
      // Nothing was actually captured - commonly because there's no
      // network path to resolve WiFi-based position at all (ChromeOS
      // devices have no GPS chip), so there's nothing honest to queue for
      // this cycle. This is different from "captured but couldn't upload."
      console.error("pingLocation: Failed to get location:", location.error);
      await logDiag("geolocation_error", location.error);
      return;
    }

    console.log(`pingLocation: Received location: Lat ${location.lat}, Lng ${location.lng}`);
    await logDiag("geolocation_ok", `${location.lat}, ${location.lng} (accuracy ~${location.accuracy}m)`);

    // Best-effort reverse geocode - reverseGeocode() already returns null
    // instead of throwing on failure, so a lack of internet here still
    // lets the raw coordinates get queued below, just without an address.
    console.log("pingLocation: Fetching real address details via Reverse Geocoding...");
    const geoData = await reverseGeocode(location.lat, location.lng);
    await logDiag("reverse_geocode", geoData ? "resolved an address" : "failed/skipped (non-fatal, raw coordinates still queued)");

    const point = {
      deviceId,
      lat: location.lat,
      lng: location.lng,
      accuracy: location.accuracy,
      timestamp: location.timestamp || Date.now(),
      address: (geoData && geoData.address) ? geoData.address : {},
      displayName: geoData ? geoData.display_name : "",
    };

    await enqueuePoint(point);

    // Try to publish immediately - the common online case behaves exactly
    // as before this change (capture, then send right away). If this
    // fails, the point simply stays queued for the next flushQueue() call
    // instead of being lost.
    await flushQueue();
  } catch (error) {
    console.error("pingLocation: Error during ping sequence:", error);
    await logDiag("ping_error", error.message);
  }
}

// Helper function to manage the offscreen document lifecycle
async function setupOffscreenDocument(path) {
  // Check if the offscreen document already exists
  const hasDocument = await chrome.offscreen.hasDocument();
  if (hasDocument) return;

  // If not, create it
  await chrome.offscreen.createDocument({
    url: path,
    reasons: [chrome.offscreen.Reason.GEOLOCATION || 'GEOLOCATION'],
    justification: 'Required to get accurate device location for the IT admin portal'
  });
}
