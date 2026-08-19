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
        timeout: 10000,
        maximumAge: 0
      }
    );
  });
}
