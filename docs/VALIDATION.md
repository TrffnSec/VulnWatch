# v0.2.0 validation

## Automated checks

39 Node tests passed. ProjectDiscovery tests cover exact CVE association, exact-host filtering (including sibling and credential-URL rejection), metadata-only normalization, invalid scores, unknown/truncated coverage, workspace IDs, key permissions, key/workspace cache invalidation, stale-result rejection, no badge mutation, minimal outbound fields, and HTTP 429 cooldown.

- Node tests exercise detection confidence, multiple-version preservation, CDN package identity, query-string redaction, incomplete and failed provider responses, withdrawn records, alias deduplication, alert filtering, and settings validation.
- Service-worker integration tests use Chrome API adapters and controlled provider responses. They cover scan-to-badge behavior, rejecting messages from webpages, session/local key movement, excluding keys from state responses, clearing observations, navigation during an in-flight lookup, origin exclusions, key deletion, and recovery of interrupted scans on worker restart.
- Browser UI checks ran in Chromium 153 headless with Chrome extension API adapters and mocked provider responses. The real packaged UI and service-worker modules were used, and the capture functions ran against the local fixture DOM/runtime.
- Verified Light, Dark, and Auto controls; advisory details; mute/unmute; key save/test/remove; site permission settings; update settings; secret-free JSON export; and no horizontal overflow at widths 320, 430, and 700 pixels.
- ProjectDiscovery UI controls exercised with mocked template and cloud responses: save/test/remove key, workspace selection, CVE context, existing findings, cache reuse, clearing displayed results on key removal, and exclusion of ProjectDiscovery records/keys from exports.
- Dark/light and ProjectDiscovery screenshots were inspected. They show a synthetic local fixture, not a real website finding.
- Manifest resource references, JavaScript syntax, and ZIP integrity checked before packaging.

## Not verified here

The available headless Chromium build does not load extensions. A regular Chrome **Load unpacked** installation, native toolbar popup/side-panel opening, Chrome's actual permission prompts, and real service-worker suspension were not exercised end to end.

OSV, WPScan, GitHub, NVD, and ProjectDiscovery responses were mocked during automated testing. No real API credentials were supplied. Live API connectivity, plan-specific WPScan behavior, ProjectDiscovery free-plan endpoint access, team-account behavior, actual provider quotas, and current provider response variations remain to be checked by the user. The UI surfaces network and authentication failures instead of treating them as clean checks.

No performance benchmark across a production website corpus or cross-browser compatibility certification is claimed. This is a developer preview, not a store-ready release.

## Reproduce logic tests

From the project folder, run `npm test` with a modern Node.js installation (Node 20+). The logic tests have no external dependencies.

## Optional browser UI test

The script `tests/browser-ui-check.cjs` requires Playwright and a Chromium binary. Install Playwright for development, install its Chromium browser, then run `node tests/browser-ui-check.cjs` from the project folder. `VULNWATCH_CHROMIUM_EXECUTABLE` can select an existing Chromium executable. This test intentionally uses Chrome API adapters; it does not replace a regular Chrome installation test.

## First local Chrome check

1. Follow the installation steps in README.
2. Confirm the extension has no error banner in `chrome://extensions`.
3. Serve `examples/demo.html` locally, open it, and inspect it.
4. Confirm jQuery 3.4.1 and WordPress 6.4.1 are detected.
5. With OSV enabled and working internet, inspect the returned advisories and evidence.
6. Switch to side-panel mode and verify following/pinning tabs.
7. Enable site observation, reload the fixture, and verify automatic inspection.
8. Switch themes and reopen the UI to confirm preferences persist.
9. Add a provider key only if you have a suitable account; use Test to verify connectivity.

To report an issue, share the error text, Chrome version, and reproduction steps. Do not include API keys, cookies, or private page content.

## ProjectDiscovery manual acceptance

After loading v0.2.0 in regular Chrome, add your own key and use Test. Confirm the message explicitly tests template access. On a page with a CVE-bearing OSV advisory, request ProjectDiscovery context. On an asset with existing cloud findings in your account, compare hostname, status, and dates with the dashboard. Verify an empty/denied response is not labelled secure. Test the optional workspace ID if you use teams. Check that navigating to another page, changing the key/workspace, or clearing data does not show prior-account results. These real-account checks were not performed in this build environment.
