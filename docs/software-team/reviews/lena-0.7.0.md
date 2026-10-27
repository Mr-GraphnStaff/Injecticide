# Lena independent QA review: scanner evidence 0.7.0

- Date: 2026-10-27 (America/Chicago).
- Project: Injecticide; branch `codex/scanner-evidence-0-7`, working candidate
  based on `7af759dd44e16c2e494e1bc61b478b84c84d4a78`.
- Runtime: local Windows Python 3.12 and headless Microsoft Edge; source on the
  Pi SMB share. This is not production/Pi-container validation.
- Reviewer: Lena, separate assurance agent reporting to Avery.
- Independence: reviewed Ishan's marker/coverage/governance implementation,
  Avery's official-validator/API implementation, and Mara's UI. Lena authored
  the evaluation corpus/tool/tests/docs and does **not** independently approve
  those artifacts here. They require another reviewer.
- Method: static source inspection, synthetic direct reproductions, targeted
  Python tests, two independently executed browser harnesses, and mobile
  screenshot inspection. No corporate skill or personal information was used.

## Findings and retests

| ID | Severity | Evidence | Expected / observed before correction | Owner / retest |
| --- | --- | --- | --- | --- |
| LENA-01 | Medium | `inspection_evidence._outside_fences`; synthetic unclosed Python fence containing a line ` ```python` followed by REVIEW TAG and EOF comments | An info-bearing line cannot close an executable Markdown fence. Before correction the metadata was falsely verified. | Ishan corrected closing-fence recognition. Independently repeated the exact synthetic input: `status=absent`, `start_marker_found=false`; marker claims inside the still-open fence are ignored. |
| LENA-02 | Low | `creator_mitigation('demo.json', '{"examples":{"_review_tag":"large-file read in chunks","_end_of_file":true}}')` | A nested example is not a top-level creator convention. Before correction it produced an invalid claim and review finding. | Ishan corrected top-level recognition. Independent exact reproduction now returns absent with no start claim. |

These are synthetic local regression cases, not claims of observed exploitation.
Verified creator tags still cannot authorize execution, suppress other findings,
prove model runtime reading or establish exhaustive detector coverage.

## Verification actually executed

`python -m pytest tests/test_inspection_evidence.py tests/test_official_validators.py tests/test_scan_diagnostics.py tests/test_vendor_requirements.py tests/test_package_analysis.py -q`

- Final result: **126 passed, 2 skipped in 32.59 seconds**.
- The two skips are local `pytest.importorskip('mcp')` transport checks in
  `test_vendor_requirements.py`. The installed local environment lacks that SDK;
  this run therefore does not establish live MCP transport behavior.
- Tests cover creator marker verification versus detector limits, malformed/
  fenced/duplicate-key inputs, scoped metadata validation, validator tamper
  rejection, non-execution of uploaded bodies, stale vendor evidence, isolated
  compatibility outcomes and request-ID/error handling.

`node tests/browser/scanner_evidence_0_7.cjs`

- **PASS**, executed independently with the bundled Playwright module path and
  headless Microsoft Edge.
- Verified keyboard submission and disclosure, double-submit protection,
  manual retry without reselecting the local file, no automatic retransmission,
  success releasing the file, timeout/clear/replacement recovery, stale-response
  isolation, structured/legacy/invalid responses, request correlation, separate
  evidence axes, scoped format-validator failure, and legacy report handling.
- Checked horizontal overflow at 390 px and 1440 px and inspected the generated
  mobile screenshot. Detailed export contains evidence fields and request ID,
  without the synthetic upload body.
- The harness uses synthetic endpoint responses. It does not test Cloudflare,
  client-certificate selection, the external production route or real upload
  latency. A mocked `Failed to fetch` recovery does not diagnose the historical
  user failure.

`node tests/browser/skill_scan_lifecycle.cjs`

- **PASS**, independently executed existing regression harness.
- Twelve repeated synthetic reports, each with 200 files and 8,000 findings:
  at most 10 file cards and 100 findings visible; post-GC DOM nodes remained
  2,589 across all twelve runs; post-GC JavaScript heap ranged 10.67–10.75 MiB.
- These are controlled JavaScript heap/DOM observations, not total system-memory
  measurements or production capacity claims.

`git diff --check`: passed; Git reported line-ending conversion notices, not
whitespace failures.

## Scope limits and verdict

The inspected UI has named report regions, a native keyboard-operable disclosure,
an alert for failures, and keyboard/responsive behavior demonstrated above.
Manual screen-reader use, comprehensive contrast evaluation, browser diversity
and a full WCAG conformance audit were not performed.

**QA review: complete with stated limitations; both reported findings corrected
and independently retested.** No unresolved blocker was observed within this
scope. This is not independent approval of Lena's own evaluation tooling, full
release approval, confirmation of vendor upload acceptance, or evidence that
every detector inspects every character. Full CI, container and authenticated
production verification remain the release owner's next steps.
