# Contextual detection and source policy: 0.15.0 local qualification

Date: October 29, 2026. Coordinator/integration: Avery Chen. Implementation:
Ishan and Avery. Independent QA/accessibility: Lena. Independent security and
coordinator evidence review: Morgan Hale. These are separate agent assignments,
not independent human PR acceptance.

## Outcome and source identity

Local implementation and verification are **complete with stated limitations**.
The candidate is **not published**. No commit, push, CI run, merge or deployment
was performed by this assignment. Commit permission for the scanner-image
packaging change and human PR acceptance remain required by AGENTS.md.

- Version: `0.15.0` candidate.
- Branch: `codex/scanner-context-correction`.
- Base: `f6873958e15e2116db430f51b997ef7009753052`, matching the supplied report's
  `0.14.1 (f687395)` build. Qualification applies to the working diff, not base alone.
- Scanner engine SHA-256:
  `641640dc906db7ea912e5ece73f4b868f0dabd580efb810d6cefc0c985482dec`.
- Runtime host: local Windows; original dirty network checkout was preserved.
  The isolated worktree registration failed, so every execution used its explicit
  workspace path. Recovery does not depend on an app attachment.

## Implemented contract

The seven existing high-blocking prose detectors retain candidate text, source,
speech act, imperative evidence, target and syntax evidence strength. Policy
separately evaluates these facts with adapter-supplied source channel. Example
framing does not remove detection. Metadata, filenames, directories, quoted
authority and HTTP form fields cannot upgrade source trust.

High-confidence model-directed requests from untrusted/unknown sources block;
user-turn requests receive review. Described risks are logged, examples flagged,
and unresolved intent or reference resolution reviewed. Example activation is
source-linked, including structured JSON cases. Recognized test inputs retain
their legacy exposure-review presentation without becoming governance blocks.
Code-flow/effect detectors retain independent evidence and policy contracts.

Original positives remain intact. The autonomous-authoritative-write fixture
blocks from its actual conditional model-directed workflow at lines 14-17;
metadata alone remains uncertain. Structural groups stop at unrelated paragraphs
and have explicit item, character and physical-line limits.

Report corrections also include folded YAML purpose parsing, invocation versus
boundary-escape distinctions, source-linked block reasons, declaration versus EOF
counts, bounded database samples/totals, source versus projection completeness,
linked workflow steps and optional version consistency observations.

## Executed verification

| Check | Observed result |
| --- | --- |
| Entire Python suite with optional pinned MCP SDK in isolated test environment | **1,478 passed; zero failed; zero skipped**, 123.74 seconds |
| Independent final security selection, including original skill fixtures | **494 passed**, exact engine fingerprint above |
| Independent final QA selection | **373 passed**, including **272** new matrix/guard/provenance cases |
| Final coordinator positive/projection/redaction selection | **375 passed** |
| Edge contextual report harness | Passed facts/policy/source/target/confidence presentation, literal hostile labels, keyboard disclosures, sampling, complete exports and 390px/1440px reflow |
| Edge report-scope harness | Passed six scopes, roving keyboard, retained evidence, exports, hostile strings, reflow, reset and legacy data |
| Isolated scanner packaging | Reconstructed Docker COPY inventory imports and scans both operative and illustrative inputs in flat module mode |
| Diff and recovery | Whitespace check passed; reverse application check of recovery patch passed |

The full suite used the existing production dependencies plus the already-pinned
optional MCP SDK installed only in a temporary test environment. Production
dependency declarations were not expanded. Browser tests use synthetic endpoint
responses; they are not live production or screen-reader acceptance.

Local raw evidence: `tmp/full-0.15.0-qualified.xml`,
`tmp/speech-act-0.15.0-qualified.json`,
`tmp/final-positive-preservation-verified.xml`, reviewer receipts and browser
screenshots. Private package reports remain local and are not public fixtures.

## Separated regression measurements

These are finite authored/source-reviewed regression cases, not population
accuracy estimates. Metrics are intentionally not combined into one score.

- Core benign security discussion: **0 false blocks / 20 contexts**.
- Core untrusted operative requests: **60/60 matching facts and expected blocks**.
- Core direct user requests: **15/15 review-policy matches**.
- Core illustrative examples: **20/20 candidates retained and flagged**.
- Encoded English requests: **5/5 retained projection and correct source policy**.
- Four enterprise contexts: request, described risk, example and activated example
  each **20/20 retained candidates and correct policy**, separately reported.
- Six conditional workflow contexts: each **5/5 correct facts/policy**.
- Own repository documentation/payload contexts: **20** source-pinned unit/channel
  contexts; **0 false blocks / 14 nonoperative contexts**, **8/8 writeup candidates
  retained and flagged**, **6/6 same-payload operative policy matches**.
- One non-English intent case is explicitly **unassessed**, excluded from negative
  counts. Detection of supplied bytes is not complete semantic understanding.

Source units retain original revision, file/unit hashes and line ranges. Matching
current canonical blobs support shallow CI; differing source requires the pinned
historical object. No repository path is treated as evidence of benign intent.

## Original package and resource evidence

The supplied `infosec-memory-core-3.0.2.skill` SHA-256 is
`5a77b63ac1fe9fdd47af560fa64868e587e28bba82dfe7c575cff4926fd1ca52`.
Final local scan: **190 files, 35 review findings, 131 informational findings,
sandboxed, zero blocking finding references**, partial coverage. Database
sampling remains 50 of 27,081 directory records, not an exhaustive database scan.
Package scripts and embedded operating instructions were never executed.

The supplied detailed production report names a different `3_0_0.skill` artifact.
Exact member hashes bind its cited disclosure/SDK examples to the available
archive; this is not whole-artifact or live-runtime parity. Review counts across
those different artifacts are not presented as an accuracy improvement metric.

Independent Windows dense-input measurements reproduced approximately 339 MiB
and 76 seconds before correction; the corrected actor-dense case used about
109 MiB and 10 seconds while retaining the final request. Inside-budget framed
action-dense cases retained/flagged examples and blocked an outside request at
about 91-92 MiB. These are host process measurements, not an executed Linux
container limit or guaranteed latency benchmark.

## Review closure and publication limits

See [QA review](../software-team/reviews/lena-contextual-accuracy.md),
[final security review](../software-team/reviews/morgan-speech-act-policy.md) and
[acceptance matrix](../software-team/speech-act-acceptance-matrix.md).

Earlier interrupted/failed runs remain recorded. They exposed false blocks,
missed passive/conditional requests, JSON wrapping/activation regressions,
decoded-context redaction, flat imports, an original positive regression and
resource inflation. They are not counted as passing qualification.

Remaining limits: bounded English/static syntax, bounded single-layer base64,
unverified runtime source provenance and approval enforcement, incomplete binary
and sampled-data coverage, unavailable original 3.0.0 archive, no live deployment,
no real screen-reader acceptance and no general accuracy certification. These
limits do not change the research-grade product requirement.
