# Injecticide skill inspection milestone — 0.8.0 candidate

- Lead: David Farris. October 27, 2026: authorized implementation of the skill
  scanning vision and subsequent "whatever it takes" local work; any cost needs
  his prior approval. No paid calls, accounts, installations or service activation
  are authorized by existing credentials. A separate $5 synthetic provider
  benchmark budget/account question is pending; silence is not approval.
- Current outcome: provider-independent skill/package inspection that improves
  actual detection and content understanding. Skills first; plugins and projects
  remain the future direction, not accepted as implemented by this milestone.
- Coordinator/integration: Avery Chen on Windows, checkout on the Pi network
  share. Branch `codex/skill-inspection-0-8`. Preserve the unrelated dirty
  research PLAN/VALIDATION, existing architecture files, validation and tmp data.
- Implementers: Ishan (assets, nested archives, optional scanner MCP); Elena
  (relationship graph, Python data flow); Avery (integration, decoded projections,
  CLI, reporting). Lena independently authored the package evaluation and QA;
  Elena reviewed decoding/assets/evaluation; Morgan independently reviews the
  combined security boundary and Lena's evaluation. Names are role identities;
  actual executions and findings are recorded separately.
- Acceptance: every inventory item has a measured inspection state; structural
  assets are inspected where supported, metadata is scanned, links/container
  provenance remain correct, hidden/reference/script scenarios are tested against
  paired benign controls, unsafe inputs retain bounded resource use and no
  uploaded code executes in static scans. MCP must actually invoke the scanner,
  not merely supply research documents. Existing regressions must pass.
- Release: candidate only, prepared for a draft PR. Major release requires human
  PR acceptance under AGENTS.md. No workflows/auth/secrets changed. Container
  COPY changes package the new engine modules; production is not deployed by
  this implementation assignment. Final revision/verification is in the release
  handoff and validation record.
- Evidence/limits: `skill-milestone-evaluation.md` preserves the initial misses
  and threshold definition. Synthetic regression accuracy is not representative
  market accuracy. Original customer ZIP bytes were not supplied to this chat;
  exported Markdown is not a new artifact scan. OCR/rendering, font programs,
  interprocedural/arbitrary-language analysis, customer workflow execution and
  direct provider performance remain unverified. The existing operator-managed
  isolated-runner interface has not become runtime proof through static analysis.

## Verification ledger

- New independent QA package benchmark: six authored hostile cases detected,
  four benign controls without actionable high/block security alarms; two
  coverage challenges tracked separately. Original labels unchanged; detection
  threshold expansion to governance-counted high findings explicitly documented.
- Independent reviews exposed malformed URL handling, nested archive identity
  boundaries, iTXt metadata omissions, multiline fence regressions, misleading
  suffix bypasses, document-contained Python dataflow and control-heavy UTF-8
  decoding. Fixes require independent retesting, not author self-approval.
- Both browser harnesses passed, including independent keyboard/responsive,
  escaping, export, lifecycle and repeated-scan checks. The optional scanner MCP
  passed 24 SDK tests, including actual separate-process stdio calls. Full
  final-source suite results are recorded in the validation record.
- Independently inspected four whole commit-pinned public skill directories
  (81 files), without executing fetched code. Real-package probes exposed and
  verified correction of a false password-disclosure block and filename-case
  graph omissions. These unlabeled observations do not establish accuracy.

# Previous assignment: scanner evidence release 0.7.0

- Team lead: David Farris. On October 27, 2026 explicitly authorized the whole
  agreed scanner update, push and production deployment subject to team processes.
- Source: Injecticide, branch `codex/scanner-evidence-0-7`, based on production
  `7af759dd44e16c2e494e1bc61b478b84c84d4a78`. Actual coordinator runtime is Windows,
  with the checkout on the Raspberry Pi network share; production is the Pi.
- Coordinator: Avery Chen. Core: Ishan. Reporting/UX: Mara. Local evaluation and
  comparison: Lena. Integration, official validators, diagnostics/release: Avery.
  Independent security review: Morgan. Independent QA/accessibility review was performed by Lena on others' work;
  Morgan independently reviewed Lena's evaluation slice and the security changes.
  Authors do not independently approve their own work. Personnel histories are fictional; delivery records below are factual.
- Scope: additive evidence contracts, creator mitigation recognition, scoped
  compatibility authority, contact observations, official reference validators,
  local evaluation/report comparison, recoverable uploads and scan diagnostics.
- Non-goals: removing resource limits, certifying safe execution, fabricating
  vendor requirements, changing the company's private auditor skill, running
  customer code, or claiming synthetic-corpus market accuracy.
- Constraints: deterministic Python scanner; isolated sandbox; no hot execution
  of fetched research. Preserve unrelated dirty research/docs and temporary files.
  No workflow/auth/gate configuration changes. Reuse Azure CI and the protected Pi
  full-stack rebuild with rollback. No new paid services or LLM usage.

## Requirements and evidence

| ID | Acceptance behavior | Owner | Status/evidence |
| --- | --- | --- | --- |
| R1 | Static vendor compatibility cannot hard-fail from unverified authority; structural parser errors remain measurable | Ishan | Implemented; core tests and Morgan/Lena reviews |
| R2 | Per-detector/file limits are visible; creator tags and true EOF verification are separate from inspection completeness | Ishan | Implemented; core tests and Morgan/Lena reviews |
| R3 | Contacts, code capability, policy and harmful behavior remain separate; no blanket author/domain trust | Ishan/Mara | Implemented; behavioral and UI tests/review |
| R4 | Reviewed pinned official validators run locally, integrity checked; results are format-only and unavailable is explicit | Avery | Implemented; official/API tests and independent review |
| R5 | Authored local corpus and hash-bound report comparison expose detection, review burden and unknown coverage without inflated accuracy claims | Lena | Implemented; 61 comparison/evaluation tests and Morgan review |
| R6 | Failed uploads retain explicit retry; API diagnostics use request ID/stage without payload logging; external authenticated scan path verified | Mara/Avery | Local tests/review passed; public production upload pending |
| R7 | Independent security, QA and accessibility reviews; passing complete tests and builds; all containers rebuilt and live target checks | Avery/reviewers | Reviews passed; clean CI/build/deployment pending |

## Current evidence and limitations

The corporate `.skill` and both full auditor reports are not available in this
checkout; their particular missed email finding is unverified. Comparison support
is not retrospective proof about those artifacts. Evaluation fixtures are authored
synthetic examples, not a representative independently labeled production corpus.

## Work ledger

Candidate-time status: implementation and independent reviews complete; not yet
deployed. Local full suite: 463 passed, four optional MCP-SDK skips. Both browser
harnesses passed, including independently executed keyboard/responsive and
lifecycle checks. Authored evaluation: 14 cases, zero contract mismatches, one
explicitly incomplete case. See reviews/lena-0.7.0.md and reviews/morgan-0.7.0.md.

Next release gates: clean Azure CI (including MCP SDK), three image builds,
merge under the lead's explicit release authorization, protected full Pi rebuild,
and live authenticated public upload/coverage/redaction/request-ID smoke checks.
This source record describes candidate-time evidence; deployment runs record
actual publication and target verification separately.
