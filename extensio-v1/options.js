const DIAG_KEY = "diagnosticLog";
const ERROR_STAGES = new Set([
  "geolocation_error", "auth_step1_fail", "auth_step2_fail",
  "auth_error", "publish_fail", "ping_error", "publish_dropped",
]);
const OK_STAGES = new Set([
  "device_id_ok", "geolocation_ok", "auth_ok", "publish_ok", "tenant_id_ok",
]);

function fmtTime(ts) {
  return new Date(ts).toLocaleString();
}

async function render() {
  const data = await chrome.storage.local.get([DIAG_KEY, "lastKnownDeviceId", "pendingLocationPings"]);
  const log = data[DIAG_KEY] || [];
  const queue = data.pendingLocationPings || [];

  document.getElementById("deviceId").textContent = data.lastKnownDeviceId || "(not resolved yet)";
  document.getElementById("queueCount").textContent = String(queue.length);
  document.getElementById("entryCount").textContent = String(log.length);

  const body = document.getElementById("logBody");
  body.innerHTML = "";
  document.getElementById("empty").style.display = log.length === 0 ? "block" : "none";

  // Newest first
  for (const entry of log.slice().reverse()) {
    const tr = document.createElement("tr");
    if (ERROR_STAGES.has(entry.stage)) tr.className = "err";
    else if (OK_STAGES.has(entry.stage)) tr.className = "ok";

    const tdTime = document.createElement("td");
    tdTime.textContent = fmtTime(entry.ts);
    const tdStage = document.createElement("td");
    tdStage.className = "stage";
    tdStage.textContent = entry.stage;
    const tdDetail = document.createElement("td");
    tdDetail.className = "detail";
    tdDetail.textContent = entry.detail;

    tr.appendChild(tdTime);
    tr.appendChild(tdStage);
    tr.appendChild(tdDetail);
    body.appendChild(tr);
  }
}

document.getElementById("refresh").addEventListener("click", render);
document.getElementById("clear").addEventListener("click", async () => {
  await chrome.storage.local.set({ [DIAG_KEY]: [] });
  render();
});

document.getElementById("forceSync").addEventListener("click", async () => {
  const btn = document.getElementById("forceSync");
  const originalLabel = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Syncing...";
  try {
    // sendMessage wakes an idle service worker on its own, so this works
    // even if nothing has run in a while. pingLocation() never rejects (it
    // catches and logs its own errors), so this always resolves - the log
    // table below is the real source of truth for what actually happened.
    await chrome.runtime.sendMessage({ type: "force-sync" });
  } catch (e) {
    // Only reachable if the service worker couldn't be reached at all.
  }
  await render();
  btn.disabled = false;
  btn.textContent = originalLabel;
});

render();
setInterval(render, 3000);
