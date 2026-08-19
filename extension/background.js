import { API_URL, AUTH_URL, USE_COLLECTOR_API, TENANT_ID } from './config.js';

let cachedToken = null;

// When the extension is installed or updated, set up an alarm to ping location
chrome.runtime.onInstalled.addListener(() => {
  // Ping every 15 minutes
  chrome.alarms.create("location-ping", { periodInMinutes: 15 });
  // Also do an initial ping right away
  pingLocation();
});

// Listen for the alarm to trigger
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "location-ping") {
    pingLocation();
  }
});

async function getAuthToken(deviceId) {
  if (!USE_COLLECTOR_API) return null; // Local testing doesn't need auth
  if (cachedToken) {
    console.debug("getAuthToken: Using cached JWT token");
    return cachedToken;
  }
  try {
    const extensionId = chrome.runtime.id;
    const authEndpoint = AUTH_URL.replace("{deviceId}", deviceId).replace("{extensionId}", extensionId);
    
    console.log(`getAuthToken: Requesting JWT from ${authEndpoint}`);
    
    // As per user instructions, this endpoint is a GET request with deviceId and extensionId in URL
    const response = await fetch(authEndpoint, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    if (response.ok) {
      const data = await response.json();
      cachedToken = data.token || data.jwt || data.access_token; // Support common JSON fields for token
      console.log("getAuthToken: Successfully retrieved JWT token.");
      return cachedToken;
    }
    console.error(`getAuthToken: Failed to get auth token. Status: ${response.status} ${response.statusText}`);
  } catch (err) {
    console.error("getAuthToken: Error fetching auth token:", err);
  }
  return null;
}

async function pingLocation() {
  console.log("pingLocation: Starting location ping sequence...");
  try {
    // 1. Get the exact Google Workspace Device ID dynamically
    let deviceId = "3421537a-01b4-4013-9654-de1c6a2cf3b9"; // Fallback for local testing
    if (chrome.enterprise && chrome.enterprise.deviceAttributes) {
      deviceId = await new Promise((resolve) => {
        chrome.enterprise.deviceAttributes.getDirectoryDeviceId(resolve);
      });
      console.log(`pingLocation: Fetched real device ID: ${deviceId}`);
    } else {
      console.warn("pingLocation: chrome.enterprise.deviceAttributes API not available. Using fallback device ID.");
    }

    // 2. Fetch Auth Token (only applies to production environments)
    let token = null;
    if (USE_COLLECTOR_API) {
      token = await getAuthToken(deviceId);
      if (!token) {
        console.error("pingLocation: Cannot ping location without valid JWT token for production collector.");
        return;
      }
    }

    // 3. Setup offscreen document for geolocation (required in Manifest V3)
    await setupOffscreenDocument('offscreen.html');

    // 4. Request geolocation from the offscreen document
    console.log("pingLocation: Requesting geolocation from offscreen document...");
    const location = await chrome.runtime.sendMessage({
      target: 'offscreen',
      type: 'get-geolocation'
    });

    if (location.error) {
      console.error("pingLocation: Failed to get location:", location.error);
      return;
    }
    
    console.log(`pingLocation: Received location: Lat ${location.lat}, Lng ${location.lng}`);

    // 5. Build the Payload
    let payload;
    let headers = { 'Content-Type': 'application/json' };

    if (USE_COLLECTOR_API) {
      // Production format for HaloFort collector
      payload = {
        "_et": "location_v1",
        "_ed": location.timestamp || Date.now(),
        "_tn": TENANT_ID,
        "_d": deviceId,
        "_p": {
          "ge": `${location.lat},${location.lng}`,
          "a1": "", "a2": "", "a3": "", "ci": "", "st": "", "co": ""
        }
      };
      headers['Authorization'] = `Bearer ${token}`;
      console.log("pingLocation: Sending payload to HaloFort collector:", payload);
    } else {
      // Local format for the Go backend
      payload = {
        deviceId: deviceId,
        location: {
          lat: location.lat,
          lng: location.lng,
          accuracy: location.accuracy,
          timestamp: location.timestamp
        }
      };
      console.log("pingLocation: Sending payload to local backend:", payload);
    }

    // 6. Send it to the API
    console.log(`pingLocation: Posting to API_URL: ${API_URL}`);
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      console.log("pingLocation: Successfully reported location to server.");
      const data = await response.json();
      
      // Update ping interval if the server responds with one
      const newInterval = data.intervalMinutes || 15;
      const alarm = await chrome.alarms.get("location-ping");
      if (!alarm || alarm.periodInMinutes !== newInterval) {
        console.log(`pingLocation: Updating ping interval to ${newInterval} minutes`);
        chrome.alarms.create("location-ping", { periodInMinutes: newInterval });
      }
    } else {
      console.error(`pingLocation: Failed to send location to server. Status: ${response.status} ${response.statusText}`);
      if (response.status === 401 && USE_COLLECTOR_API) {
        // Token might be expired, clear it
        console.warn("pingLocation: Received 401 Unauthorized, clearing cached JWT token.");
        cachedToken = null;
      }
    }
  } catch (error) {
    console.error("pingLocation: Error during ping sequence:", error);
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
