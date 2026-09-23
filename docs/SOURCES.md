# Implementation references

Official sources consulted for v0.1 and v0.2 (links checked 2026-09-23):

- Chrome scripting: https://developer.chrome.com/docs/extensions/reference/api/scripting
- Chrome storage: https://developer.chrome.com/docs/extensions/reference/api/storage
- Chrome side panel: https://developer.chrome.com/docs/extensions/reference/api/sidePanel
- Chrome update lifecycle: https://developer.chrome.com/docs/extensions/develop/concepts/extensions-update-lifecycle
- OSV version query: https://google.github.io/osv.dev/post-v1-query/
- OSV API: https://google.github.io/osv.dev/api/
- WPScan API endpoints: https://wpscan.com/docs/api/v3/
- WPScan terms: https://wpscan.com/api/
- GitHub public advisories API: https://docs.github.com/en/rest/security-advisories/global-advisories
- NVD API: https://nvd.nist.gov/developers/vulnerabilities

Provider responses are untrusted data rendered as text; external links are restricted to HTTPS. Advisory matching provides affected-version signals, not exploitability confirmation.

ProjectDiscovery and API-key setup references:

- Authentication and key settings: https://docs.projectdiscovery.io/api-reference/introduction
- Public template metadata search: https://docs.projectdiscovery.io/api-reference/templatev2/search-templates
- Existing cloud findings: https://docs.projectdiscovery.io/api-reference/results/get-all-results
- Free signup: https://docs.projectdiscovery.io/quickstart/index
- Account/workspace administration: https://docs.projectdiscovery.io/cloud/admin
- ProjectDiscovery key settings: https://cloud.projectdiscovery.io/settings/api-key
- GitHub token creation: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- NVD key request: https://nvd.nist.gov/developers/request-an-api-key
- WPScan registration: https://wpscan.com/register/

Free signup is not a promise of unrestricted access to all provider endpoints. This release uses only read-only ProjectDiscovery metadata and historical findings retrieval.
