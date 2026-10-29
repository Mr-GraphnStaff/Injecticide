# Independent QA review: contextual accuracy correction

The first section below records the earlier 0.14.2 correction phase. The final
0.15.0 speech-act/source-policy review and evidence are recorded at the end;
the earlier scoped verdict is not a verdict on the later architecture.

- Reviewer: Lena, separate QA subagent. Production authors: Ishan (contextual classification) and Avery (reporting/integration).
- Date: October 29, 2026.
- Source: isolated Windows checkout based on `f687395`, candidate version `0.14.2`; working diff inspected before the final runs below.
- Verdict: **complete with stated limitations** for the assigned local QA review. No unresolved blocking defect observed within the exercised scope. This is not release authorization or live deployment acceptance.

## Requirements and observed evidence

| Requirement | Observed result |
| --- | --- |
| Ordinary status, risk, and defensive reference prose must not establish an active credential-disclosure request | Passed synthetic cases in active and reference paths; exact matching SSO and application-standard members no longer block. |
| Documentation headings, paths, and benign surrounding text must not immunize operative requests | Passed paired requests beneath detection/attack/trusted-document headings, in both active and reference paths. |
| Preserve direct, passive, multiline, conditional, indirect, and activated-quote disclosure requests | Passed, including passive printed/sent/revealed forms, an executed quoted instruction, an explicitly followed unsafe example, and system/developer-prompt controls. |
| SDK questions must not be called a tool escape; actual execution must retain controls | SDK/document prose cases pass. Actual interpreter/shell instructions retain actionable capability review, approval, sandbox, and code-execution controls. |
| A block must point to its finding, source, and classification context | Reporting checks pass; UI and detailed export preserve the blocking source and line/context evidence. |
| Correct source-vs-projection completeness and report counts | Sampled SQLite text is not marked complete; measured table sampling and total counts are exposed. Creator summary retains verified, declared, unresolved claim, absent, and unassessable categories separately. |
| Follow linked documented startup sequences without claiming execution | Source-linked plaintext companion steps and substep labels pass; unrelated files are excluded in the reporting fixture. Runtime remains unverified. |
| Optional version conventions are maintenance evidence | Drift observation test passes without creating a format failure or security block. |

## Commands actually run on the final candidate

1. `python -m pytest tests/test_contextual_accuracy_acceptance.py -q --tb=short --junitxml=tmp/qa-context-final.xml` — **45 passed**.
2. `python -m pytest tests/test_reporting_accuracy.py tests/test_contextual_classification_impl.py tests/test_contextual_evidence.py tests/test_scanner_protective_context.py tests/test_contextual_rules.py tests/test_scan_cli.py -q --tb=short --junitxml=tmp/qa-report-final.xml` — **93 passed**.
3. `node tests/browser/contextual_report_accuracy.cjs` with the bundled Playwright dependency directory on `NODE_PATH` — **passed** in headless Microsoft Edge.
4. `git diff --check` — **clean**.

An earlier expanded relevant regression run covered 130 tests successfully. The initial 38-case independent contextual baseline failed 15 cases and passed 23 before the implementation changes. Additional cases were added during review; the 45-case final suite must not be represented as having an identical recorded baseline. The original baseline JUnit file was overwritten during a rerun; its actual result remains in the tool transcript, while the current/final JUnit files are explicitly named as such.

## Exact source-member verification

The available archive differs from the package named in the pasted production report. The prior comparison established matching member hashes for the three reported disclosure findings and the Cloudflare reference. QA re-scanned those exact bytes in minimal synthetic packages, without executing package code. All three former disclosure blocks are absent from the candidate's `blocking_findings`; the attack reference retains a review-level observation where intent is ambiguous. The Cloudflare SDK false tool-escape finding is absent, while its other capability controls remain.

QA also checked the identification/authentication-policy member from the supplied archive after the noun-coordinate topic fix. It produces no blocking findings. This fifth member is not asserted to match a separately supplied production artifact.

Local evidence, containing hashes and finding metadata rather than private source records:

- `tmp/qa-context-before.json`
- `tmp/qa-context-after.json`
- `tmp/qa-context-final-members.json`
- `tmp/qa-context-final.xml`
- `tmp/qa-report-final.xml`

## UI and accessibility review

The independent browser fixture verifies native `details`/`summary` Enter/Space operation, first-child summary semantics, no nested interactive controls in that summary, literal rendering of hostile source/table labels, no HTML execution, accurate creator-category counts, database sample/total rows, evidence retained by detailed export, no page errors, and no horizontal overflow at 390px and 1440px.

The screenshot at `tmp/contextual-report-accuracy.png` was visually inspected. It shows the new sampling text and literal table label in the expanded evidence panel. The isolated fixture uses local cached browser libraries and shell CSS; its missing static logos and incomplete utility styling do not constitute production visual acceptance. Actual screen-reader operation was not tested.

## Review boundaries

QA inspected Ishan's contextual matching, passive/quote handling, catalog context, strongest-evidence retention, execution-capability separation, finding descriptions and dispositions. QA separately inspected Avery's purpose parsing, credential-capability recommendation, blocking references, database projection metadata, source completeness, linked process extraction, version evidence, and UI/export rendering. Neither author independently closed their own change through this review.

The tests are authored regression and acceptance cases, not a representative independently labeled production benchmark. No runtime execution of uploaded scripts, endpoint attack, billable model evaluation, live 3.0.0-package scan, screen-reader acceptance, deployment, or broad industry-certification assessment was performed by this reviewer. Morgan's independent security review and the coordinator's integrated suite remain separate evidence.

## Final phase: 0.15.0 detector facts and source-aware policy

The lead expanded acceptance to retain detector evidence inside examples and
evaluate speech act, instruction actor, source channel, and policy separately.
QA independently authored `tests/test_speech_act_policy.py`, the source-pinned
fixture manifest `tests/fixtures/speech_act_owned_units.json`, the reusable
`tools/speech_act_policy_evaluation.py`, and the acceptance matrix in
`docs/software-team/speech-act-acceptance-matrix.md`.

The target contract was explicitly clarified during review: it denotes the
instruction addressee, not the resource's owner. A command to the assistant to
extract another application's key remains model-directed. Unknown source is
treated as untrusted for high-confidence model-directed requests; unspecified
intent/target still requires review. Direct user requests receive review rather
than automatic authority to disclose secrets.

### Defects independently exposed and retested

- Narrative/example classifications initially lost some original candidates or
  misclassified explicit third-party dialogue. Cases now retain speech-act facts.
- Same-line quoted activation, operational fences, bare blockquotes, independent
  live instructions after fiction, exception/encouragement negation idioms, and
  “now do the example above” were exercised as distinct minimal pairs.
- Twelve early examples initially displaced a later operative request in all
  three instruction detectors. The bounded result now retains the late request
  and its actual final-line source evidence, while examples alone remain flagged.
- Flat Docker-style module import failed during real prompt-override scanning,
  despite package-mode tests passing. QA reproduced the relative-import failure;
  after correction the same flat-mode scan returned `blocked` successfully.
- The repository's existing short base64 payload initially produced no candidate.
  After decoder correction its explicit writeup still lost outer example
  context. Both the candidate miss and the framing failure were retested after
  correction; operative and illustrative presentations now differ correctly.
- An original source-pinned review paragraph containing a literal payload caused
  a system-disclosure block. It now retains and flags the illustrative candidate.
  No source filename or repository path was used as an exemption.

### Final observed checks

- New speech-act, source-policy, own-document, provenance, saturation, encoding,
  and negation suite: **157 passed** (`tmp/qa-speech-act-final.xml`). This includes
  a shallow-CI regression: matching current source canonicalized to LF must
  verify the pinned full-file and unit hashes without requiring an old Git
  object. Historical content is used only if current bytes differ and the pinned
  object is actually available; otherwise provenance verification fails.
- Existing contextual/reporting/protective regressions plus the earlier
  independent acceptance suite: **163 passed**
  (`tmp/qa-semantic-regression-final.xml`).
- Expanded independent Edge harness: **passed**. Both “Blocking evidence” and
  “Instruction evidence and policy” disclosures preserve source/class/target/
  confidence, support native keyboard use, escape untrusted text, retain detailed
  exports, and reflow at 390px/1440px. No browser page errors were observed.
- `git diff --check`: clean; Git emitted an existing line-ending conversion
  warning for project context, not a whitespace-error failure.

### Separate evaluation measures

The versioned evaluator records per-unit expected and observed facts/actions.
Final executed evidence is `tmp/qa-speech-act-owned-final.json` (the later `v2`
snapshot uses the source-neutral group label `operative_request`). On these
authored contexts only:

- Benign security discussion: **20/20 candidates retained**, **0/20 false blocks**.
- Operative requests from untrusted sources: **60/60 matching-fact policy blocks**.
- Direct user requests: **15/15 review-policy matches**.
- Illustrative examples: **20/20 candidates retained and flagged**.
- Encoded English requests: **5/5 projection/policy matches**.
- Source-pinned existing documentation/writeups: **20 source/channel contexts**;
  **0 false blocks in 14 nonoperative contexts**, **8/8 writeup candidates
  retained/flagged**, and **6/6 same-payload operative-policy matches**.
- Synthetic Spanish: **one explicitly unassessed coverage case**, excluded from
  true-negative and recall denominators.

Earlier failure snapshots (`tmp/qa-owned-units-before.json` and
`tmp/qa-owned-units-real-doc-before.json`) preserve the missed encoded candidate
and misclassified own-document contexts. They are not replaced by relabeled
successful negatives.

### Final review verdict and limits

**Complete with stated limitations** for independent local QA. No unresolved
blocking defect was observed in the exercised requirements. QA reviewed Ishan's
fact classification, original/decoded framing, bounded activation resolution,
strongest-evidence selection, and flat import handling separately from Avery's
trusted adapter context, policy evaluation, source references, evidence export,
and presentation changes. This does not self-approve either author's work or
replace Morgan's security review.

The source recognizers remain bounded English/static syntax. Activation tests
model later instructions within the supplied input; they do not authenticate a
live chat's cross-turn identity or prove runtime policy enforcement. Some
observation lines identify the beginning of a contextual unit rather than the
exact token's physical line; pinned fixture manifests therefore retain the full
original unit range and hashes. Actual live deployment, the original 3.0.0
artifact, arbitrary language/encoding coverage, and real screen-reader operation
were not verified by this reviewer. The finite metrics do not establish general
industry accuracy or certification.

## Final addendum: all seven high-blocking prose rules

Security review exposed that the four enterprise prose detectors still coupled
their class directly to blocking. QA extended the independent matrix across
`autonomous_authoritative_write`, `bulk_enterprise_modification`,
`workflow_manipulation`, and `cross_system_automation`. Each detector has request,
described-risk, illustrative-example, and activated-example units under all five
channels: **80 additional cases**, with separate enterprise metrics. This does
not change source-code/data-flow effect policy.

The first enterprise run failed all 80 cases because the observations lacked
the new facts. After integration, broader regressions exposed a real duplicate
JSON-key instruction downgrade; it was corrected and independently tested under
all five source channels. Structured evaluation inputs retain their existing
review presentation, while the independent policy response is `flag` and they
do not count for blocking. The former path-dependent configuration expectation
was deliberately replaced with a same-structure/path-invariance assertion,
following the lead's explicit requirement that paths not grant trust. Separate
operative JSON fields and malformed/duplicate-key instructions still block for
untrusted channels.

Final observed evidence for this expanded scope:

- The independent speech-act suite: **242 passed** (237-case run plus five new
  duplicate-JSON source-channel controls).
- Combined independent matrix, existing contextual evidence, Python security,
  package-effect, effect-review, and effect-integration run: **333 passed** in
  `tmp/qa-all-instruction-policy-final.xml`.
- Reusable evaluator: exit **0**, recorded in
  `tmp/qa-seven-rule-policy-final.json`. Each enterprise context group has
  **20/20 retained candidates and matching facts/policy**, with **zero unexpected
  blocks**. Original credential/system/override and own-source metrics remain
  separately recorded and unchanged.
- Expanded Edge policy/evidence UI harness: **passed** after these changes.
- `git diff --check`: clean apart from the informational pre-existing line-ending
  conversion warning noted above.

QA inspected the seven-rule policy list, enterprise fact classification and
retained unit context, fixture-review compatibility, path-invariance test change,
and duplicate-JSON regression correction. **Complete with stated limitations**
for local QA; no unresolved blocking defect observed in this tested scope.
Code-effect behavior remains independently verified by the existing effect
tests, not reclassified through prose-example labels. All earlier deployment,
language, runtime-provenance, screen-reader, contextual-line, and finite-corpus
limitations still apply.

## Final conditional-workflow recall check

The integrated suite then exposed a real positive-fixture regression:
`test_skill_fixtures.py`'s autonomous-authoritative-write fixture retained only
its ambiguous metadata candidate and lost the explicit “When triggered, Claude
will:” operation list. Its original expected blocking outcome was preserved.

QA added 30 independent source-channel cases covering exact metadata-only
ambiguity, the operative condition/list, that same list under a mere
“Demonstration” heading, a historical third-party description, a clearly framed
illustrative workflow, and activation of that example. The metadata-only row
uses the actual original fixture's capability-description wording; a generic
heading is not accepted as an example exemption.

QA inspected the bounded structural grouping: an explicit conditional current-
model header governs its own contiguous list, with source start/end evidence,
eight-item/16-line/4096-character limits, and explicit limit reporting. It does
not join arbitrary neighboring prose or promote general capability metadata to
an active instruction. The existing detectors still inspect individual content.

Final observed runs:

- Independent matrix plus existing skill fixtures: **282 passed**, including all
  272 new matrix/guard/provenance tests and the original autonomous-write block
  assertion (`tmp/qa-conditional-workflow-final.xml`).
- Combined matrix, original skill fixtures, contextual evidence, Python
  security, and package-effect suites: **373 passed**
  (`tmp/qa-final-conditional-regressions.xml`).
- Reusable evaluator: exit **0** (`tmp/qa-conditional-policy-final.json`). Each
  new conditional context records **5/5 retained candidates and matching facts/
  policy**, with no unexpected blocks. Prior metric groups remain separate.
- `git diff --check`: no whitespace errors.

**Complete with stated limitations** for this final independent local QA scope.
The positive fixture's expected block was not weakened to obtain a pass. The
previously recorded runtime, deployment, language, source-location, and finite-
corpus limitations remain in effect.
