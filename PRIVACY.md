# VulnWatch Privacy Policy

**Effective date:** September 23, 2026
**Last updated:** September 23, 2026

VulnWatch is a browser extension developed by **TrffnSec** for passive technology detection and vulnerability intelligence lookups.

This Privacy Policy explains what information VulnWatch processes, what information may be sent to third-party services, how information is stored, and the choices available to users.

VulnWatch is designed to minimize data collection. It does not operate a VulnWatch analytics or telemetry backend.

---

## 1. What VulnWatch Does

VulnWatch analyzes technical information exposed by the webpage you are viewing in order to identify technologies such as:

* Content management systems
* JavaScript libraries and frameworks
* WordPress plugins and themes
* Selected server and language indicators
* Exposed software versions

When a supported software package and version are identified, VulnWatch may query vulnerability intelligence providers to find known security advisories associated with that package or version.

VulnWatch does not automatically exploit, scan, attack, or modify websites.

---

## 2. Information Processed Locally

VulnWatch may process information from the webpage currently being inspected, including:

* Page URL and origin
* HTML and DOM elements needed for technology detection
* Script and resource filenames or paths
* Publicly exposed software version information
* Generator metadata
* Runtime JavaScript values used for technology identification
* Selected HTTP response headers
* Technology detection evidence

Selected response headers may include:

* `Server`
* `X-Powered-By`
* `X-Generator`
* `X-Drupal-Cache`
* `X-AspNet-Version`

This information is used to identify technologies and versions.

VulnWatch does not intentionally collect cookies, website passwords, form contents, authentication headers, or private messages.

Resource evidence is designed to exclude URL query strings and fragments where they are not needed for detection.

---

## 3. Website Access

By default, VulnWatch can inspect the active tab when the user explicitly interacts with the extension.

Users may optionally grant VulnWatch access to:

* A specific website
* Multiple websites
* All HTTP and HTTPS websites

Persistent website access is used only for features such as automatic technology observation and response-header detection.

Users can revoke website permissions at any time through VulnWatch settings or Chrome's extension permission controls.

---

## 4. Vulnerability Intelligence Providers

Some VulnWatch features communicate with third-party vulnerability intelligence services.

The exact information sent depends on the provider and the feature the user chooses to use.

### OSV

VulnWatch uses the OSV vulnerability database for supported package/version checks.

Information sent to OSV may include:

* Package name
* Package ecosystem
* Detected package version

VulnWatch does not send the visited webpage URL or webpage contents to OSV as part of these lookups.

---

### ProjectDiscovery

ProjectDiscovery integration is optional and requires the user's own API key.

Depending on the feature used, VulnWatch may send:

* A CVE identifier when requesting vulnerability/template context
* The hostname of the currently inspected website when the user requests existing ProjectDiscovery cloud findings
* An optional ProjectDiscovery workspace or team identifier

For existing cloud findings, VulnWatch sends the hostname rather than the complete visited URL path, query string, or page contents.

ProjectDiscovery requests are initiated only when the user uses the corresponding feature.

VulnWatch does not use ProjectDiscovery to automatically start scans, execute templates, upload targets, or retest findings.

---

### GitHub

GitHub Security Advisories may be used as an optional secondary vulnerability intelligence source.

Information sent may include:

* Package ecosystem
* Package name
* Package version

If the user provides a GitHub API token, the token is sent directly to GitHub when making the requested API call.

VulnWatch does not require or request access to private GitHub repositories for this feature.

---

### WPScan

WPScan integration is optional and requires the user's own WPScan API token.

Depending on the detected component, VulnWatch may send identifiers related to:

* WordPress core versions
* WordPress plugin names
* WordPress theme names

The user's WPScan API token is sent directly to WPScan when the feature is used.

---

### NVD

The National Vulnerability Database may be queried for additional CVE information.

Information sent may include:

* A CVE identifier

If the user provides an NVD API key, that key is sent directly to NVD as part of the requested API call.

---

## 5. Third-Party Services

Third-party providers process information according to their own privacy policies, security practices, account terms, and API terms.

VulnWatch currently integrates with services including:

* OSV
* ProjectDiscovery
* GitHub
* WPScan
* NVD

These providers may receive technical network information normally associated with an internet request, such as the user's IP address.

TrffnSec does not control how these independent third-party services process information after receiving a request.

Users should review the privacy policies and terms of any optional provider they choose to use.

---

## 6. API Keys

VulnWatch does not include shared or developer-owned API keys.

Users provide their own credentials for optional integrations.

Depending on the option selected by the user, API keys may be stored:

### Browser session only

The credential is stored using Chrome's session storage and is intended to remain available only for the current browser session.

### On this device

If the user explicitly chooses persistent storage, the credential may be stored using Chrome extension local storage on the device.

Persistently stored API keys are **not an encrypted password vault**.

Users handling sensitive credentials should consider using session-only storage.

API keys:

* Are not sent to a VulnWatch server
* Are not synchronized through VulnWatch
* Are sent only to the provider for which they were supplied
* Are not included in VulnWatch observation exports
* Can be removed through VulnWatch settings

Users should use API keys with the minimum permissions necessary for the selected provider.

---

## 7. Information Stored by VulnWatch

VulnWatch may store limited data using Chrome extension storage.

This can include:

* Extension preferences
* Theme settings
* Website permission preferences
* Website exclusions
* Muted advisory selections
* Cached OSV vulnerability responses
* Advisory refresh information
* Optional API credentials
* Temporary inspection results

Page inspection results are primarily kept in browser session storage and may be removed when tabs close, pages change, the browser session ends, or the extension clears the information.

OSV advisory information may be cached locally to reduce unnecessary network requests.

ProjectDiscovery result summaries may be temporarily cached in extension worker memory. They are not intended to become permanent browsing-history records.

---

## 8. Data Retention

VulnWatch minimizes retention where practical.

Examples include:

* Page observations are generally temporary and session-based.
* ProjectDiscovery metadata uses short-lived in-memory caching.
* OSV advisory responses may be cached locally for performance.
* User preferences and explicit exclusions or mutes remain until changed or cleared.
* Persistently stored API keys remain until the user removes them or clears the extension's storage.

Users can clear observations, advisory caches, and muted entries through VulnWatch settings.

Users can also remove VulnWatch entirely through Chrome, which removes extension-controlled local storage according to Chrome's extension behavior.

---

## 9. Telemetry and Analytics

VulnWatch does not currently operate its own telemetry, behavioral analytics, advertising, tracking, or profiling system.

VulnWatch does not send browsing history to a TrffnSec analytics server.

There is no VulnWatch account required for the core extension.

Optional third-party providers may maintain their own request logs or account activity records according to their respective policies.

---

## 10. Selling or Sharing Personal Information

TrffnSec does not sell personal information collected through VulnWatch.

VulnWatch does not provide user browsing information to advertising networks or data brokers.

Information is transmitted to third-party vulnerability intelligence providers only when necessary for the corresponding feature, as described in this policy.

---

## 11. Advertising

VulnWatch does not contain advertising.

VulnWatch does not use browsing information for targeted advertising.

---

## 12. Remote Code

VulnWatch does not intentionally download and execute remote JavaScript or other remotely hosted executable code.

Executable extension code is packaged with the extension.

Remote services are used for data lookups, such as vulnerability advisory information.

---

## 13. Security

Reasonable technical measures are used to reduce unnecessary exposure of information.

Examples include:

* HTTPS communication with supported API providers
* Restricted Content Security Policy for extension pages
* Avoiding collection of cookies and authorization headers
* Removing unnecessary URL query strings and fragments from detection evidence
* Limiting provider response sizes
* Applying network request timeouts
* Keeping optional provider access user-controlled
* Separating temporary provider results from automatic vulnerability alerts where appropriate

However, no browser extension, storage system, or network service can guarantee absolute security.

Users should avoid storing highly sensitive API credentials persistently when session-only storage is sufficient.

---

## 14. User Controls

Users can control VulnWatch through its Settings interface.

Available controls may include:

* Enabling or disabling vulnerability intelligence lookups
* Granting or revoking website access
* Granting or revoking provider access
* Enabling or disabling automatic website observation
* Adding website exclusions
* Enabling or disabling notifications
* Adding or removing API credentials
* Selecting session-only or local API-key storage
* Clearing observations and cached advisory information
* Muting individual advisory notifications

Chrome's own extension settings can also be used to control site access or uninstall VulnWatch.

---

## 15. Chrome Permissions

VulnWatch may request Chrome permissions including:

* `activeTab`
* `scripting`
* `storage`
* `sidePanel`
* `alarms`
* `webRequest`
* `tabs`

Optional permissions may include:

* `notifications`
* Website access to HTTP and HTTPS pages
* Access to optional vulnerability intelligence provider APIs

These permissions are used only to provide VulnWatch functionality, such as page inspection, technology detection, tab tracking, response-header observation, local settings, side-panel functionality, scheduled advisory refreshes, and optional notifications.

---

## 16. Children's Privacy

VulnWatch is a technical security and developer tool and is not specifically directed toward children.

TrffnSec does not knowingly use VulnWatch to collect personal information from children.

---

## 17. Changes to This Privacy Policy

This Privacy Policy may be updated when VulnWatch features, integrations, data handling, or legal requirements change.

Material changes will be reflected by updating the "Last updated" date.

The latest version should be made available through the VulnWatch project or associated website.

---

## 18. Open Source

VulnWatch source code is publicly available for inspection.

Project repository:

https://github.com/TrffnSec/VulnWatch

Users and researchers can review the implementation and report privacy or security concerns through the project repository.

---

## 19. Contact

For privacy questions, security concerns, or requests relating to VulnWatch, contact the developer through:

**TrffnSec**

Website:
https://trffnsec.com/

GitHub:
https://github.com/TrffnSec

VulnWatch issues:
https://github.com/TrffnSec/VulnWatch/issues

Please do not include API keys, authentication tokens, private URLs, cookies, or other sensitive information in public GitHub issues.

---

## Summary

VulnWatch is designed around a simple privacy principle:

**Inspect locally where possible, send only the minimum information required for requested vulnerability lookups, and give the user control over optional access and credentials.**

VulnWatch does not operate its own advertising, telemetry, analytics, or browsing-history collection service.
