# Skill scan browser regression

`skill_process_diagram.cjs` exercises the source-linked diagram UI with a
synthetic report, including keyboard use, narrow layouts, literal hostile labels,
exports, new separate playground drafts, saved/unsaved map preservation and
stale-citation invalidation after map replacement.

`skill_process_api.cjs` uploads authored synthetic ZIP bytes through a running
local FastAPI candidate, then opens the generated diagram as a new playground
map and calls the real planning API. Set `INJECTICIDE_TEST_URL` (default
`http://127.0.0.1:8241`) and start the candidate with `RESEARCH_MCP_URL` and
`SKILL_SANDBOX_URL` unset. It uses cached browser libraries, contacts no model,
and does not execute uploaded code. These checks are local acceptance evidence,
not authenticated production or original customer-package acceptance.

`skill_scan_lifecycle.cjs` runs the current scan UI in an isolated headless browser with synthetic endpoint responses. It does not contact Injecticide or scan real skill files. It checks file release, consecutive scans, cancellation, stale responses, pagination, complete detailed export, timeout, unmount cleanup, and bounded DOM/heap growth across 12 large reports.

`scanner_evidence_0_7.cjs` checks separate evidence states, creator mitigation
versus partial coverage, scoped official validator results, sanitized request
diagnostics, keyboard use and 390px/1440px layouts. Failed requests keep the
selected local File for explicit retry; no automatic retransmission occurs.
Success, replacement and explicit clearing release it. Both harnesses use
synthetic responses and are separate from the authenticated production smoke test.

Prerequisites: Node.js, the `playwright` package available on Node's module search path, and Microsoft Edge installed. Set `INJECTICIDE_TEST_BROWSER=chrome` to use Chrome instead.

Download the same pinned browser libraries used by `webapp/static/index.html` into `tmp/scan-resource-regression/` from the repository root:

```powershell
New-Item -ItemType Directory -Force tmp/scan-resource-regression
Invoke-WebRequest https://unpkg.com/react@18.3.1/umd/react.production.min.js -OutFile tmp/scan-resource-regression/react.js
Invoke-WebRequest https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js -OutFile tmp/scan-resource-regression/react-dom.js
Invoke-WebRequest https://unpkg.com/@babel/standalone@7.28.5/babel.min.js -OutFile tmp/scan-resource-regression/babel.js
node tests/browser/skill_scan_lifecycle.cjs
node tests/browser/scanner_evidence_0_7.cjs
```

When using a shared Playwright installation, set `NODE_PATH` to its containing `node_modules` directory first. The test shortens only the scan timeout inside its isolated browser fixture. Heap measurements are JavaScript heap after forced garbage collection, not total browser or system memory.

Optionally set `INJECTICIDE_APP_SOURCE` to a different app.js file to check a baseline. The previous implementation fails the uploaded-file-release assertion.
