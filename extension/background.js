import { API_URL, AUTH_URL, AUTH_LOGIN_URL, USE_COLLECTOR_API, TENANT_ID } from './config.js';

let cachedToken = null;
let cachedRefreshToken = null;

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
    // const response = await fetch(authEndpoint, { method: 'POST', headers: { 'Accept': 'application/json' } });
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
          
          return cachedToken;
        } else {
          const loginError = await loginResponse.text();
          console.error(`getAuthToken [Step 2]: Failed. Status: ${loginResponse.status} ${loginResponse.statusText}`);
          console.error(`getAuthToken [Step 2]: Error Response Body:`, loginError);
        }
      } else {
        console.error("getAuthToken [Step 1]: Response did not contain success status or data field.", result);
      }
    } else {
      const errorText = await response.text();
      console.error(`getAuthToken [Step 1]: Failed. Status: ${response.status} ${response.statusText}`);
      console.error(`getAuthToken [Step 1]: Error Response Body:`, errorText);
    }
  } catch (err) {
    console.error("getAuthToken: Error making API call:", err);
  }
  return null;
}

// Helper to reverse geocode lat/lng to an actual address
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
    let haloFortDeviceId = deviceId; // Default to workspace ID
    
    if (USE_COLLECTOR_API) {
      token = await getAuthToken(deviceId);
      
      if (token) {
        // Decode the JWT token to extract the internal HaloFort device ID
        const decodedPayload = decodeJwtPayload(token);
        if (decodedPayload && decodedPayload.device) {
          haloFortDeviceId = decodedPayload.device;
          console.log(`pingLocation: Extracted HaloFort Device ID from JWT: ${haloFortDeviceId}`);
        } else {
          console.warn("pingLocation: Could not extract 'device' field from JWT payload. Using Workspace Device ID as fallback.");
        }
      } else {
        console.warn("pingLocation: No valid JWT token returned from Step 2. Will proceed without it (using Workspace Device ID).");
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

    // Fetch actual address details (Reverse Geocoding)
    console.log("pingLocation: Fetching real address details via Reverse Geocoding...");
    const geoData = await reverseGeocode(location.lat, location.lng);
    let address = geoData && geoData.address ? geoData.address : {};
    
    // 5. Build the Payload
    let payload;
    let headers = { 'Content-Type': 'application/json' };

    if (USE_COLLECTOR_API) {
      // Production format for HaloFort collector
      payload = {
        "_et": "location_v1",
        "_ed": Math.floor((location.timestamp || Date.now()) / 1000),
        "_tn": TENANT_ID,
        "_d": haloFortDeviceId, // Uses the decoded ID from the JWT
        "_p": {
          "ge": `${location.lat},${location.lng}`,
          "a1": geoData ? geoData.display_name : "", // Full display address
          "a2": address.county || address.state_district || "", // Area/County
          "a3": address.suburb || address.neighbourhood || address.residential || address.road || "", // Local street/village
          "ci": address.city || address.town || address.village || address.municipality || "", // City
          "st": address.state || "", // State
          "co": address.country || ""  // Country
        }
      };
      
      // If we successfully fetched a token, we MUST send it, otherwise the server returns 403 Forbidden.
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
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
      const responseText = await response.text();
      let data = {};
      if (responseText) {
        try {
          data = JSON.parse(responseText);
        } catch (e) {
          console.warn("pingLocation: Server returned non-JSON response:", responseText);
        }
      }
      
      console.log("pingLocation: Successfully reported location to server!");
      console.log("pingLocation: Server Response:", data || responseText);
      
      // Update ping interval if the server responds with one
      const newInterval = data.intervalMinutes || 15;
      const alarm = await chrome.alarms.get("location-ping");
      if (!alarm || alarm.periodInMinutes !== newInterval) {
        console.log(`pingLocation: Updating ping interval to ${newInterval} minutes`);
        chrome.alarms.create("location-ping", { periodInMinutes: newInterval });
      }
    } else {
      const errorText = await response.text();
      console.error(`pingLocation: Failed to send location to server. Status: ${response.status} ${response.statusText}`);
      console.error(`pingLocation: Error Response Body:`, errorText);
      
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
