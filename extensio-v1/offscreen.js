// Listen for messages from the background service worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.target === 'offscreen' && msg.type === 'get-geolocation') {
    getGeolocation().then(sendResponse);
    // Return true to indicate we will send a response asynchronously
    return true;
  }
});

async function getGeolocation() {
  return new Promise((resolve) => {
    if (!navigator.geolocation) {
      resolve({ error: "Geolocation is not supported by this browser." });
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          lat: position.coords.latitude,
          lng: position.coords.longitude,
          accuracy: position.coords.accuracy,
          timestamp: position.timestamp
        });
      },
      (error) => {
        resolve({ error: error.message });
      },
      {
        enableHighAccuracy: true,
        // ChromeOS has no GPS chip - position comes from WiFi-based
        // geolocation, which routinely takes longer than 10s to resolve
        // indoors. 10s was timing out a large fraction of real ping cycles
        // (confirmed via the diagnostics log) with nothing captured at all;
        // 30s gives it a realistic window without hanging a cycle forever.
        timeout: 30000,
        maximumAge: 0
      }
    );
  });
}
