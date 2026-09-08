# Chrome Web Store Listing — Halo Agent

## Store Listing Tab

### Title from package
Halo Agent

### Summary (from manifest description — 132 char limit)
Reports device data to your organization's management system.

### Description (long form — paste into the "Description" field, 16,000 char limit)
Halo Agent is a lightweight extension for managed ChromeOS devices that keeps your organization's device management platform informed and up to date.

Once installed by your IT administrator, Halo Agent runs quietly in the background and periodically reports device information back to your organization's management console. This helps IT teams keep an accurate, current view of the managed devices in their fleet — supporting tasks such as device tracking, inventory, compliance checks, and troubleshooting.

Halo Agent is designed to be extended over time: today it reports device location, and future updates may add additional device-health and status reporting — all without requiring end users to take any action.

**Key points:**
- Runs automatically once installed — no setup required by the end user.
- Reports only to your organization's own management system; no data is shared with third parties.
- Intended for deployment on organization-managed ChromeOS devices via Google Admin console (force-install), not for general public installation.
- Continues reporting queued data once connectivity is restored if the device was temporarily offline.
- Includes a local diagnostics page (accessible via "Extension options" on the extension's card in `chrome://extensions`) so IT administrators can confirm the extension is running correctly on a given device — it shows on-device status only and does not transmit anything anywhere.

This extension is intended for use only on devices managed by an organization that has deployed it. It is not intended for use on personal, unmanaged devices.

### Category
Productivity

### Language
English (United States)

### Store icon
128x128 px — use `images/icon-128.png` (already updated in the extension package — same file referenced in `manifest.json`).

### Screenshots (at least 1 required, up to 5, 1280x800 or 640x400)
**Not yet provided** — needs at least one screenshot before this listing can be submitted. Suggested shots:
- The `chrome://extensions` page showing Halo Agent installed and enabled.
- A screenshot of the connector/admin dashboard showing a device's reported location or status.

### Small promo tile (440x280) / Marquee promo tile (1400x560)
Optional — not yet provided.

### Additional fields
| Field | Value |
|---|---|
| Official URL | None |
| Homepage URL | TBD |
| Support URL | TBD |
| Mature content | Off |

### Notes
- The manifest description was shortened to 63 characters to satisfy the Chrome Web Store's 132-character limit on the manifest `description` field; the longer explanatory text above belongs in the Store listing "Description" box, not the manifest.
- Screenshots are the only field above that still needs an asset from you — the Store form requires at least one before it will accept submission.

---

## Privacy Practices Tab

The Developer Dashboard has a separate "Privacy practices" tab (required before publishing) that is distinct from "Store listing." It covers single purpose, permission justification, and data usage. Content for each field is below.

### Single purpose description
Halo Agent reports device information (currently device location) from organization-managed ChromeOS devices to the organization's own device management system, so IT administrators can track and manage their device fleet.

### Permission justifications

**`enterprise.deviceAttributes`**
Used to read the device's directory ID (`getDirectoryDeviceId`) so reported data can be matched to the correct device record in the organization's Google Admin directory. Only available to, and only used on, organization-managed devices where this extension has been force-installed by the admin.

**`geolocation`**
Used to read the device's current position so it can be reported to the organization's management system as part of the device's status. This is the extension's core function; it is only requested on managed devices where the admin has installed the extension and enabled the corresponding device policy.

**`offscreen`**
Required because a Manifest V3 service worker cannot call `navigator.geolocation` directly. The extension creates a hidden offscreen document solely to obtain the geolocation reading, then closes it.

**`alarms`**
Used to schedule the periodic reporting interval (e.g. every 15 minutes, or a custom interval set by the admin) instead of polling continuously, which reduces battery/CPU/network impact.

**`storage`**
Used to persist a small local queue of not-yet-published reports (`pendingLocationPings`) so that data captured while the device is offline is retried once connectivity returns, instead of being lost. Also stores the configured reporting interval and a local, on-device diagnostic log (visible only via the extension's own Options page — see below) used to troubleshoot reporting issues; this log never leaves the device. All data is device-local; nothing is shared with third parties through this permission.

**`storage.managed_schema` (`managed_schema.json`)**
Not an additional permission — this uses the same `storage` permission above, via Chrome's built-in enterprise policy mechanism (`chrome.storage.managed`). It lets an IT administrator optionally configure, per organizational unit through Google Admin console (Policy for extensions), which backend base URL and reporting mode (production collector vs. this connector's own portal) the extension should use, without needing a separate build per environment. If no policy is set, the extension falls back to the values built into the package. No end-user data is involved — these are administrator-supplied configuration values only.

**`options_ui` (Options page)**
Provides a local, read-only diagnostics view (see the Description section above) so an administrator can confirm the extension is running correctly on a given device, including a manual "Force Sync Now" action to trigger an immediate report instead of waiting for the periodic schedule. Everything shown is read from local device storage only; nothing is transmitted anywhere as a result of viewing or using this page.

**Host permission `https://*.halofort.com/*`**
Required to authenticate the device and submit its reported data to the organization's own management backend (Halofort-hosted collector and auth endpoints).

**Host permission `https://*.tectoro.com/*`**
Same purpose as above, for organizations/environments hosted under the tectoro.com domain instead of halofort.com.

**Host permission `https://nominatim.openstreetmap.org/*`**
Used to convert a raw latitude/longitude reading into a human-readable address for display in the management dashboard, via the public OpenStreetMap Nominatim reverse-geocoding service. No account or personal identifier is sent — only the coordinate being resolved.

### Are you using remote code?
No.

### Data usage disclosure
This item collects or uses the following data, and it is required to be disclosed under the Chrome Web Store's data usage policy:
- **Location** — device's approximate/precise geographic location.
- **Personally identifiable information** — the device's directory/device ID (not tied to an individual end user's personal identity; used only to identify the managed device record).

For each collected data type, the form will ask you to confirm the following (answers below):
- Is this data being sold to third parties? — **No.**
- Is this data being used for purposes unrelated to the item's core functionality? — **No** — it is used only to report device status/location to the organization's own management system, which is the extension's core (and only) function.
- Is this data being used to determine creditworthiness or for lending purposes? — **No.**

### Privacy policy URL
**TBD** — the Chrome Web Store requires a published privacy policy URL whenever location or device-identifying data is collected. This must be a real, reachable page describing what is collected (device location, device ID), why (organizational device management), and that it is only shared with the deploying organization's own backend. Host this on an org-owned domain (e.g. a halofort.com or tectoro.com page) before submitting — the listing cannot be published without it.

---

## Distribution Settings

### Visibility

**Private**, restricted to a Google Group you own/manage containing your organization's admins/testers — not Public, not Unlisted.

Reasoning: Halo Agent is not a general-audience extension — it depends on `enterprise.deviceAttributes` and org-managed device policy, so it is meaningless (and non-functional) outside your own managed fleet. Keeping it Private means it never appears in Web Store search or browsing, while still being installable: your Google Admin console force-installs extensions by ID regardless of Store visibility, and members of the linked Google Group can access the listing directly for review/testing purposes.

If your org would rather skip the Google Group restriction and just have a non-discoverable link to hand to reviewers, use **Unlisted** instead — the tradeoff is that Google notes an unlisted item "may still appear in web search engine results," which Private avoids.

### Test instructions

**Username for testing the extension:** None
**Password:** None

**Additional instructions** (paste into that field):
> Halo Agent has no sign-in screen and no popup/options UI — there is nothing to log into. It is a background-only Manifest V3 service worker that activates automatically once installed.
>
> Its core permission, `chrome.enterprise.deviceAttributes`, only returns a value on a ChromeOS device that is enrolled and managed by a Google Workspace/Admin domain, with this extension force-installed via that Admin console's extension policy. It cannot be exercised on an unmanaged/personal Chrome profile — the API call resolves to undefined outside that context.
>
> To verify functionality:
>
> 1. Load the extension on an enrolled, managed ChromeOS test device (or force-install it to a test OU via Google Admin console).
> 2. Open `chrome://extensions`, enable Developer Mode, and click "service worker" under the Halo Agent card to open its console.
> 3. Confirm log output showing a fetched device ID and a successful location report on its periodic interval (default 15 minutes, or immediately on browser startup).
>
> Reach out to [contact/email TBD] if a temporary test device or managed test domain needs to be provisioned for review.
