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

Prerequisites: Node.js, the project's reviewed `playwright` package installed in
`working/cache/browser/node_modules/`, and Microsoft Edge installed. Provision
that excluded dependency cache through the checked launcher's `run` mode; do not
install or download anything into the retired `tmp/` tree. Set
`INJECTICIDE_TEST_BROWSER=chrome` for the harnesses that support Chrome.

Run from this checkout's root using the owner-required launcher:

```powershell
$launcher = 'C:/Users/DavidFarris/.codex/tools/working_area.py'
$checkout = (Get-Location).Path
python $launcher check --root $checkout
python $launcher run --root $checkout -- node tests/browser/skill_scan_lifecycle.cjs
python $launcher run --root $checkout -- node tests/browser/scanner_evidence_0_7.cjs
```

The launcher prints the run directory. Screenshots, evidence, downloads and traces
are written to `working/runs/<run-id>/reports/browser/<harness-name>/`; automatic
browser profiles and subprocess temporary files inherit that run's temporary
paths. A harness refuses to run without the managed run directory. These checks
are operating controls, not an OS sandbox.

Pinned browser libraries must match `webapp/static/index.html`. The active cache
is `working/cache/browser/scan-resource-regression/`, containing:

| File | Existing pinned source |
| --- | --- |
| `react.js` | `https://unpkg.com/react@18.3.1/umd/react.production.min.js` |
| `react-dom.js` | `https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js` |
| `babel.js` | `https://unpkg.com/@babel/standalone@7.28.5/babel.min.js` |

If the active cache is incomplete, the harnesses can read the complete retained
cache at `working/relocated/2026-11-02/tmp/scan-resource-regression/`. That fallback
is read-only; new libraries belong in the active cache. Do not run historical
scripts from the relocated tree. Obtain missing dependencies only through an
explicitly chosen command inside the launcher's `run` mode. The harnesses resolve
Playwright directly from the local working cache, rather than an external
`NODE_PATH` installation.

For `skill_scan_lifecycle.cjs`, an optional `INJECTICIDE_TEST_SCREENSHOT` is relative
to that harness's output directory, or an absolute path inside the same current
managed run. Outside destinations are rejected. The harness shortens only the
scan timeout inside its isolated browser fixture. Heap measurements are JavaScript
heap after forced garbage collection, not total browser or system memory.

Optionally set `INJECTICIDE_APP_SOURCE` to a different app.js file to check a baseline. The previous implementation fails the uploaded-file-release assertion.
