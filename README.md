# Yes, I'm Lazy !!!!

### So I built VulnWatch.

**Because copying a JavaScript version into another search tab for the 47th time is apparently called “a workflow.”**

Find the technology. Find the version. Look up the advisories. Forget which tab had the evidence. Repeat.

I wanted the browser to handle the repetitive part.

**VulnWatch is a passive Chrome extension that identifies exposed web technologies, checks supported package versions against known advisories, and shows the evidence behind its results.**

You browse. It observes. Strong matches get a badge. Everything else waits quietly in the inspector.

*Lazy about repetitive work. Particular about evidence.*

**v0.2.0 · Developer preview · Chrome 123+ · Manifest V3**

[Install](#install-before-your-coffee-gets-cold) · [Features](#what-it-actually-does) · [API keys](#bring-your-own-keys-or-dont) · [Privacy](#your-browsing-is-your-business) · [Limitations](#the-fine-print-except-its-readable)

---

## What it actually does

| Feature | The useful part |
| --- | --- |
| **Technology detection** | CMSs, exposed WordPress plugins and themes, JavaScript libraries, frameworks, and selected server/language signals. |
| **Version evidence** | Shows the runtime value, generator tag, asset path, or header behind a result. |
| **OSV advisory checks** | Checks supported npm package/version pairs without an API key. |
| **ProjectDiscovery context · new** | Read public CVE-linked template metadata, CVSS/EPSS when available, and existing cloud findings for the current hostname. |
| **Quiet alerts** | Badges for strong, complete affected-version matches. Optional desktop notifications. |
| **Three ways to inspect** | Popup, side panel, or a popup with a panel shortcut. |
| **Light / Dark / Auto** | For daylight, late nights, and people who let their operating system decide. |
| **Automatic observation** | Opt in for selected websites or all permitted websites. Exclude origins whenever you want. |
| **Advisory refresh** | Daily, weekly, or manual refresh of cached OSV lookups. |
| **Research exports** | Copy observations or export JSON with evidence and advisory references. |
| **Noise controls** | Mute a particular advisory on a particular origin. Keep the evidence. Lose the interruption. |

The side panel can follow the active tab or stay pinned to one tab while you look something up elsewhere.

No account is required for the core extension. No build step is required to install it.

## New in v0.2.0

ProjectDiscovery joins the provider list. Add your own key, look up CVE context from an advisory, or review existing cloud findings for the current host. Optional workspace selection, short-lived caches, manual refresh, and rate-limit handling are included. No scans are launched.

All key-based providers now have a **Get API key** link in Settings.

See the [changelog](CHANGELOG.md) for release details.

## It has a face, too

<img src="screenshots/overview-dark.png" alt="VulnWatch dark appearance showing technology evidence and an advisory match" width="380">

[Prefer the light version?](screenshots/overview-light.png) · [ProjectDiscovery preview](screenshots/projectdiscovery.png)

*Screenshots use a local fixture and mocked advisory responses. They do not show a vulnerability discovered on a real website.*

## Install before your coffee gets cold

1. Download this repository using **Code → Download ZIP**, or clone it.
2. Extract it into a folder you intend to keep.
3. Open `chrome://extensions` in Chrome.
4. Enable **Developer mode**.
5. Click **Load unpacked**.
6. Select the **`extension`** folder - the one containing `manifest.json`.
7. Pin **VulnWatch**, open a website, and click the extension icon.

That's it. You may now return to having too many tabs open.

**Automatic observation:** open **Settings → Observation & privacy**, choose **Allow this site** or **Allow all websites**, accept Chrome's permission prompt, and reload the website.

On-click inspection is the default. OSV checks are enabled by default and can be switched off for local detection without remote advisory lookups.

### Updating an existing unpacked installation

Copy the new `extension/` contents over the installed `extension/` folder **at the same path**, then click **Reload** on VulnWatch in `chrome://extensions`. Close and reopen the popup or side panel. Confirm version **0.2.0**. Keeping the installation path preserves the extension identity and its stored settings; session keys may need to be entered again.

## Bring your own keys. Or don't.

**No API key is required to install VulnWatch, detect technologies, or use OSV advisory checks.** Every other provider is optional. “Required” below means required only for that provider's feature.

| Provider | Used for | Is a key needed? | Create an account / get a key |
| --- | --- | --- | --- |
| **OSV** | Automatic supported npm package/version checks and badge matches | **No** | No signup or key. [API documentation](https://google.github.io/osv.dev/api/) |
| **ProjectDiscovery** | Public CVE-linked template metadata and your existing cloud findings | **Yes, for this optional integration** | [Free account signup / sign in](https://cloud.projectdiscovery.io) → [Settings → API Key](https://cloud.projectdiscovery.io/settings/api-key) |
| **WPScan** | On-demand WordPress core, plugin, and theme intelligence | **Yes, for this optional integration**; suitable plan required | [Register](https://wpscan.com/register/) → copy the API token from your profile. [API access and terms](https://wpscan.com/api/) |
| **GitHub Advisories** | On-demand secondary package/version checks | **Optional** for public advisories | [Create a fine-grained token](https://github.com/settings/personal-access-tokens/new) · [Manage tokens](https://github.com/settings/personal-access-tokens) |
| **NVD** | On-demand CVE descriptions and CVSS context | **Optional** | [Request an API key](https://nvd.nist.gov/developers/request-an-api-key) |

**ProjectDiscovery offers free account signup and API-key access.** A free key does not imply unlimited requests or access to every cloud feature. Your plan, workspace permissions, and available scan history determine what can be returned. VulnWatch displays access errors and rate limits rather than treating them as a clean result.

**GitHub:** choose an expiration and minimum access. The public global-advisory endpoint requires no additional fine-grained token permissions. VulnWatch does not need access to your private repositories. [GitHub endpoint documentation](https://docs.github.com/en/rest/security-advisories/global-advisories#list-global-security-advisories).

### Add a key

1. Open **Settings → API keys · optional**.
2. Select a provider. Use **Get API key** to open its official setup page.
3. Paste the key and choose **This browser session only** or **On this device**.
4. Click **Save key** and allow access to that provider when Chrome asks.
5. Click **Test**. You can replace or remove the key from the same panel.

New keys are masked while entering them; saved keys are not displayed again. Requests go directly from the extension's service worker to the selected provider. There is no VulnWatch backend in the middle. Each user supplies their own key; none is bundled in this repository.

### ProjectDiscovery: the useful bits

After saving a ProjectDiscovery key:

- **Advisory context:** inspect a page, open **Advisories**, then click **ProjectDiscovery context** on a CVE-bearing advisory. The lookup uses that CVE and displays public template metadata associated with it. CVSS, EPSS, and CWE values appear only when provided. This is descriptive metadata; template code is not displayed or executed.
- **Existing findings:** expand **ProjectDiscovery · existing cloud findings** and click **Load existing cloud findings**. This sends the displayed hostname to ProjectDiscovery and reads existing records from your account. Results are filtered locally to the exact hostname, excluding sibling/subdomains. Records may concern different paths or ports on that host and are historical, with provider status and dates shown.
- **Workspace:** leave **Workspace ID** empty for the default workspace. For a team, copy its ID from [Settings → Team](https://cloud.projectdiscovery.io/settings/team), paste it, and click **Save workspace**. This selects the workspace for both key testing and lookups.
- **Connection test:** Test verifies public-template access. It does **not** prove that your account can read cloud findings. A findings lookup can still fail because of plan or workspace permissions.

Both lookups are manual and bounded to the first **50 provider candidates**. Pagination or unknown totals are marked incomplete; zero exact matches in an incomplete result is not an exhaustive search. Use the cloud dashboard to review the full history.

ProjectDiscovery metadata is cached only in worker memory, at most **50 entries**. Cached results are reused for up to **one hour for CVE context** and **five minutes for findings**; Refresh requests new data. Closing/suspending the worker may discard it sooner. Use the respective **Refresh** button to bypass cached results. HTTP 429 responses pause further ProjectDiscovery requests using `Retry-After` where available, with at least a one-minute delay.

Changing/removing the key, changing workspace, revoking permissions, or clearing data invalidates these caches. Raw cloud request/response bodies, extracted evidence, and template bodies are discarded before results reach the UI. ProjectDiscovery results do not enter observation exports, badge counts, or desktop alerts.

This integration reads existing information. It does not create scans, retest findings, upload assets, or generate/execute templates.

**WPScan detail:** core lookups use the detected core version. Plugin and theme lookups return a component advisory list; v0.2 does not determine whether the installed version is affected. Those results are labelled accordingly, remain temporary, and do not generate badges or appear in exports.

GitHub and NVD secondary results are also temporary and do not change OSV badge counts.

Provider access and integration terms still apply. WPScan restricts caching/storage and specifies Enterprise accounts for company integrations; supplying your own key does not waive those terms. See [WPScan's API terms](https://wpscan.com/api/).

## A version match is a lead. Bring your brain.

VulnWatch separates what it observed from what it can conclude:

| Result | Meaning |
| --- | --- |
| **Reported** | A direct version claim was exposed. It can still be inaccurate or spoofed. |
| **Corroborated** | More than one strong signal agrees on the version. |
| **Inferred** | A filename or asset parameter suggests the version. No automatic alert. |
| **Unknown** | No acceptable version was exposed. |
| **Affected-version match** | An advisory includes the identified package/version. Exploitability is unverified. |
| **Related template metadata** | A public template is associated with the CVE. Its existence does not establish applicability. |
| **Previous cloud finding** | A historical record from your selected ProjectDiscovery workspace. The displayed status and date matter; current exploitability is unverified. |
| **Unavailable / incomplete** | The lookup failed or coverage is incomplete. |

The extension does not establish whether an affected function is used, whether a patch was backported, or whether an issue qualifies for a bounty.

An empty advisory list means no matching records were returned by the completed checks. It does not mean “this website is secure.”

Your report still needs your research. Tragic, I know.

## Your browsing is your business

- Detection runs locally.
- OSV receives package names, ecosystems, and versions - **not visited URLs or page contents**. Providers still see your IP address.
- No VulnWatch telemetry, account, or Chrome sync. Optional providers use their own accounts.
- ProjectDiscovery context lookups send a CVE identifier. Existing-findings lookups send the displayed hostname, never the visited URL path, query, or page contents. The selected workspace ID is sent when configured.
- ProjectDiscovery summaries are temporarily cached in worker memory; raw scan evidence is not retained. These summaries are separate from saved page observations.
- No cookie or Authorization-header collection.
- No guessed target paths, exploit probes, or extra target requests.
- Resource evidence excludes query strings and fragments.
- Page observations stay in the browser session and are removed when their tabs close or navigate.
- Preferences, explicit mutes/exclusions, and a bounded OSV cache persist locally. API keys persist only if you choose device storage.
- **Local key storage is not an encrypted vault.** Session-only storage is available, and keys never use Chrome sync.

Permissions support current-tab inspection, tab following, selected response-header observation, storage, the side panel, and refresh scheduling. Website access and desktop notifications are requested when you enable those features.

Use **Settings → Data & about** to clear observations, cache, and mutes while keeping your settings and keys.

## The fine print, except it's readable

This is a development preview. Its coverage is deliberately explicit:

- **Top-level document only.** Child frames are not inspected.
- **Visible signals only.** Hidden server dependencies and libraries buried inside bundles may be missed.
- **Selected detection rules.** This is not an exhaustive inventory of the web.
- **Header access depends on permissions.** Reload after granting site access.
- **Late-loaded components may need Re-inspect.** Arbitrary DOM changes are not continuously monitored.
- **Server versions are inventory.** v0.2 does not perform CPE-based server vulnerability matching.
- **Chrome first.** There is no Firefox adapter in this release.

Mapped libraries include jQuery, Lodash, Underscore, Bootstrap, Moment.js, AngularJS, Angular, Vue, React, React DOM, Axios, D3, Handlebars, DOMPurify, Chart.js, Highlight.js, Backbone, SweetAlert2, and Marked.

Additional technology signals include WordPress, Drupal, Joomla, Ghost, Hugo, Wix, Squarespace, Shopify, Webflow, Next.js, Nuxt, PHP, nginx, Apache, IIS, Cloudflare, Express, and ASP.NET. Detection depends on what the page exposes.

## Updates, without the mystery

OSV responses are cached for 24 hours. Scheduled or manual refresh updates up to 20 oldest cached package/version lookups per run. **Re-inspect** requests fresh checks for the current page and updates its displayed observation.

Detection rules and executable code ship with the extension. **This unpacked release does not auto-install software updates:** download the next release and reload the updated extension in Chrome. A Store-distributed build would use browser-managed software updates.

ProjectDiscovery lookups refresh only when requested and use their separate short-lived caches. The scheduled advisory refresh applies to OSV.

No remotely downloaded JavaScript. No imaginary update server.

## Tested. With the boundaries written down.

**39 automated tests passed**, covering detection, uncertainty, advisory handling, alert filtering, key lifetime, message boundaries, navigation during an inspection, exact-host cloud filtering, CVE association, ProjectDiscovery request privacy, workspace/key cache isolation, and rate-limit handling.

Browser UI checks exercised themes, evidence, muting, API key controls, ProjectDiscovery context/findings/workspace controls, cache reuse, permissions, export, and responsive layouts using simulated Chrome APIs and mocked provider responses.

**Still unverified in the build environment:** installing the package in regular Chrome, native popup/side-panel behavior, and live provider connectivity with real credentials.

See [validation details](docs/VALIDATION.md) and [test output](docs/test-results.txt).

Run `npm test` from the project root to execute the dependency-free logic tests with Node.js 20+.

The [local demo](examples/demo.html) exposes synthetic version signals without loading a vulnerable library. Serve the project folder locally to inspect it over HTTP.

## Found something wrong?

Open an issue with:

- Your Chrome and extension versions.
- What you expected and what happened.
- Minimal reproduction steps or a sanitized fixture.
- The relevant detection evidence, if it is safe to share.

Please leave API keys, cookies, private URLs, and other people's data out of the issue. They were not invited.

Useful contributions include better detection rules with fixtures, fewer false positives, clearer evidence, accessibility improvements, and documentation fixes.

---

**Built by [TrffnSec](https://github.com/TrffnSec).**

*Less tab archaeology. More actual research.*
