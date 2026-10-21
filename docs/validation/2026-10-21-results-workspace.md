# Shared testing results workspace — 0.5.1

David requested use of the empty main workspace for package scans and other
tests, with production as the acceptance environment. This release changes
presentation only; request contracts, analyzers and endpoint handling remain
unchanged.

## Behavior

- Package scan and Prompt tests select matching controls and a wide results pane.
- Both panels remain mounted, retaining completed results, filters, report depth
  and pagination when switching views.
- Launching either test brings its results workspace into view.
- Controls and export actions wrap; the layout stacks on smaller screens.

## Verification before release

- Python suite: **312 passed**.
- Existing `tests/browser/skill_scan_lifecycle.cjs`: **PASS**, including 12 repeated
  reports with 200 files / 8,000 findings, bounded DOM and heap, cancellation,
  stale response rejection, pagination, complete export, timeout and unmount.
- Edge browser against the running application: a real benign SKILL.md upload
  completed; report was outside the controls column. At 1920px viewport, controls
  measured 380px and results 1008px. At 390px, controls and results stacked with
  document width exactly 390px.
- Keyboard activation of view buttons, retained filters and detail selection,
  and a downloaded detailed report passed.
- A synthetic prompt session (intercepted HTTP plus a browser WebSocket fixture,
  no provider call or real API key) completed and retained its result across view
  switches. Prompt controls/results also fitted the 390px viewport.
- No browser page errors. Screenshots and the browser probe are retained locally
  under `tmp/scan-results-layout/`.
- Independent QA/accessibility code review found no blocking defect; final
  browser evidence supplements that static review.

## Production release checks

Use the existing PR validation and master deployment pipeline, including its
environment checkpoint. Confirm the deployed Git marker, application version,
healthy services and production-origin benign scan after deployment. Stop on a
failed health check; the existing deployment wrapper supports returning to the
previous production revision `1903d31224f4f88bb8632e5455c0ec6b806599cd`.

Browser prompt testing verifies presentation using synthetic responses; it does
not establish provider availability or test paid LLM endpoints.
