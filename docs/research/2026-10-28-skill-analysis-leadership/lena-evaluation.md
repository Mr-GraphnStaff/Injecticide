# Lena: evidence for skill-analysis leadership

**Current result:** external evaluation protocol and local runner implemented;
21 authored runner-contract tests pass. External payload bodies remain unacquired
pending an engine/runner freeze. There is no measured superiority claim and no
executed external comparator result yet.

Lena is the independent assurance role reporting to Avery for this assignment.
Runtime is Windows with the project checkout on a Pi network share. The runner
is Lena-authored work and requires another reviewer; the role name does not make
its implementation independently reviewed.

## What credible evaluation needs to answer

Can a fixed scanner identify harmful instructions and dangerous source-to-action
relationships while letting legitimate skills remain useful? Measure separate
security-block and security-review operating points. Do not substitute format
conformance, contact presence or package capability for an upstream malicious
label. Preserve misses, false alarms, abstentions, errors and label uncertainty.
Compare the same artifact bytes under named versions and reviewed threshold
mappings. Whole packages, source-native text and normalized text are different
evaluation inputs and must not be pooled silently.

## Primary-source research

| Source | What it contributes | Label/license boundary | Decision |
| --- | --- | --- | --- |
| [MaliciousSkillBench](https://github.com/protectskills/MaliciousSkillBench/tree/893afd609be22a2dfac5a2b94bbebb4eeb99515e) | Consolidated public benchmark with frozen random, malicious-structural-disjoint and source-disjoint manifests; package provenance and partial taxonomy | [LICENSE-DATA](https://github.com/protectskills/MaliciousSkillBench/blob/893afd609be22a2dfac5a2b94bbebb4eeb99515e/LICENSE-DATA) licenses benchmark metadata CC-BY-4.0; [third-party notice](https://github.com/protectskills/MaliciousSkillBench/blob/893afd609be22a2dfac5a2b94bbebb4eeb99515e/THIRD_PARTY_NOTICE.md) explicitly preserves original artifact terms | Audit source licenses and retain the official frozen manifests. Do not blanket-relicense skill text or call normalized text a complete package. |
| [SkillFortifyBench](https://github.com/qualixar/skillfortifybench/tree/eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39) | 540 externally generated labeled artifacts across Claude/MCP/OpenClaw; all 180 Claude Markdown entries are selected before reading their bodies | [MIT license](https://github.com/qualixar/skillfortifybench/blob/eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39/LICENSE); upstream explicitly says synthetic-only and no hard-negative tier | Useful bounded external diagnostic after freeze. Not representative real-world accuracy. No generator execution needed. |
| [Anthropic example skills](https://github.com/anthropics/skills/tree/dbd4588f9e1033efb41dad4bef2f7947c8993d44) | Full real published skill trees, including scripts and referenced material, expose nuisance alarms that single-file examples miss | README distinguishes Apache examples from source-available document skills. Individually verified Apache-2.0 LICENSE.txt in brand-guidelines, mcp-builder and webapp-testing | Select those three full trees. Label origin is `publisher_benign_assumption_not_independent_ground_truth`; diagnostic burden only, no certified benign FPR. |
| [Skill-Inject](https://github.com/aisa-group/skill-inject/tree/182f3d9d9836e81cdae213e9b9cec1d9be96eea3) | Research benchmark distinguishes contextual dual-use injections, obvious injections, clean skills and runtime task outcomes | Repository declares MIT, but LICENSE attribution says Bootstrap Authors; clean-skill upstream provenance needs additional verification before copying | Candidate only. Do not turn contextual task-dependent cases into unconditional malicious labels. No payload bodies acquired. |
| [Cisco evaluation documentation](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1/evals) | Demonstrates rigorous denominator/error accounting, exact finding identity matching and explicit dataset roles | Apache-2.0 applies to Cisco-authored code/fixtures; external sources retain their own terms. Its golden corpus is not independent of its own scanner development | Treat as comparator protocol evidence and a candidate reviewed tool, not neutral ground truth or proof of our relative performance. |

The [MaliciousSkillBench primary project page](https://protectskills.github.io/MaliciousSkillBench/)
distinguishes 9,740 represented identities from 9,735 exact frozen text records
and five sanitized public representations. That distinction must survive ingestion.
Its [official protocol](https://github.com/protectskills/MaliciousSkillBench/blob/893afd609be22a2dfac5a2b94bbebb4eeb99515e/benchmark/protocols.md)
holds out SRC009, SRC011 and SRC012 in its source-disjoint test. SkillFortifyBench
is **SRC012**. Reading/tuning on its samples would invalidate a later claim that
this source was unseen by our implementation team. We caught that conflict from
metadata before fetching sample bodies and retained the freeze requirement.

The current public [skillscan.io dataset policy](https://skillscan.io/data/)
explicitly identifies its verdicts as scanner output, not ground truth. Such
signals are useful for disagreement mining and human-review sampling, not an
independent malicious/benign accuracy denominator.

## Implemented contract

New `tools/skill_eval.py` reuses the existing `tools/scanner_evaluation.py`
bounded JSON parser and reproducible archive builder. It adds an external corpus
contract rather than replacing the authored regression suite.

- Every case has its source, label origin, split, native input view and original
  file digests. Duplicate identities, unsafe paths and input substitutions fail
  explicitly. Whole-package ZIPs preserve the complete selected tree.
- Two fixed profiles are declared before running: actionable governance-counted
  security findings at block tier, and at review-or-block tier. PII, format and
  non-governance capability observations remain separate.
- A detected signal is recorded even if another part of the scan is incomplete.
  No signal with known incomplete coverage becomes an abstention, not a successful
  negative. Scanner errors and missing/integrity-failed inputs stay in the class
  denominator. Error text does not echo payloads or private literals.
- Recall and negative-signal-rate bounds account for unresolved cases. Category
  strata, labeled population sizes and unknown-label populations stay visible.
  These are diagnostics conditional on upstream labels, not prevalence estimates
  or proof of exploitability.
- A comparison requires the same full population, source-label authority,
  artifact view and exact input hash. External mappings declare both thresholds
  and actual scanner/version contexts. Neither scanner becomes ground truth.
- Holdout runs require a caller-declared freeze ID and mark exposure in output.
  This is a transparent procedural marker, not authentication or proof a language
  model never encountered public benchmark content during training.

Python API: `evaluate(manifest_path, split=..., freeze_id=..., scanner=..., artifacts=...)`
and `compare_runs(left, right)`. CLI and interpretation are documented in
`evals/skill_scanner/README.md`. No local Cisco scanner distribution was found;
no comparator installation or execution has been performed.

## Executed checks and remaining work

`python -m pytest -q tests/test_skill_eval.py`: **21 passed**. These use only
small locally authored fixtures to test runner behavior, never external holdout
bodies. They challenge class denominators, abstentions, scanner failures,
credential-bearing exception suppression, PII/capability separation, path escapes,
source/native packaging identity, holdout opt-in and cross-tool substitutions.

Elena's separate code review found that the initial category allowlist omitted
the credential-to-network-flow detector and accepted missing actionability/
governance fields. Both were corrected before external exposure: sensitive-data
flows are included, PII/PHI prefixes remain excluded, and eligibility requires
explicit booleans. Potentially qualifying findings with missing policy metadata
now cause an abstention for the affected profile unless a separate eligible
finding already establishes a positive signal. Known informational or explicitly
ineligible findings do not manufacture ambiguity.

Elena's final independent review reported no remaining actionable runner finding;
her five additional profile/abstention tests and these 21 runner tests passed.
The runner is author-frozen at SHA-256
`14e8663721480ffb71a79b7e8d6d950b4aaa13be17654a277b0eba20d81855df`.
The coordinator subsequently froze 33 engine source files and the runner before
authorizing acquisition. The acquired 199 files comprise all 180 selected native
Markdown inputs, 18 files in the three complete publisher packages, and the
SkillFortify MIT notice (258,317 bytes). Original SkillFortify SHA-256 values and
publisher Git blob SHA-1 values/sizes were verified before scanning. Artifact
bodies remain outside source staging in the release scratch directory.

### Executed external diagnostic and disclosed scoring amendment

Separate Python processes ran published 0.10.0 and candidate 0.11.0 against the
same hash-bound inputs. The first frozen runner conservatively abstained on
every no-signal case: it incorrectly expected the fixture enum `complete` while
the owning `coverage_report` emits `complete_supported_content`. These initial
receipts are preserved. This was a scoring adapter defect, not a detector fix.

The coordinator explicitly authorized a post-exposure protocol amendment. The
corrected adapter accepts only that exact top-level owning enum, rejects mixed
coverage policies in comparisons, and records policy version 2. Locally authored
actual-scan/enum/bounds tests and independent peer tests passed: **41 tests**.
Elena independently verified runner SHA-256
`7615d8d22f973570302de05ba5f8ef859bb8875461b150d57fb3b0b9bef1d822`.
All 33 frozen engine source hashes remained unchanged. Both engines were then
run again using the same reviewed adapter, input bytes, labels and thresholds;
the adapter correction and corpus exposure are recorded separately rather than
silently replacing the first receipts.

The corrected 180-case comparison found **zero changed decisions** between
0.10.0 and 0.11.0. Relative to upstream's 90 synthetic malicious labels:

| Predetermined signal profile | Positive | Negative | Abstain | Signal-recall bounds |
| --- | ---: | ---: | ---: | --- |
| Block | 3 | 84 | 3 | 3.33–6.67% |
| Review or block | 8 | 79 | 3 | 8.89–12.22% |

For the 90 upstream synthetic benign labels, both profiles recorded zero
positives, 18 negatives and 72 abstentions. Consequently the negative-class
signal-rate bound is **0–80%**, not proof of a 0% false-positive rate. Top-level
coverage was `complete_supported_content` for 105 inputs and `partial` for 75.
The conservative global-coverage requirement includes format limitations; these
native Markdown inputs must not be relabeled complete Agent Skills packages to
improve the denominator. Observed review signals were five credential-to-network
flow cases and three dynamic-execution cases.

All three publisher packages also had identical old/new decisions. The
brand-guidelines package had no selected signal with supported-content coverage;
mcp-builder and webapp-testing abstained with partial coverage. Their labels
remain **unknown**, and none enters a certified benign accuracy denominator.

The complete aggregate metrics, category strata, actual version contexts,
manifest digests and v1/v2 receipt hashes are in
`lena-evaluation-results.json`. Raw acquisition, freeze, exposure, amendment and
run receipts remain under `tmp/skill-leadership-0-11/`. No external comparator
was installed or run. These results expose a substantial missed-signal problem
on this externally authored synthetic population; they provide no measured
improvement, market-leadership or general real-world accuracy claim. The corpus
is now exposed. Future detector changes informed by these results require a new
independent holdout or an explicitly disclosed repeated evaluation.

The next detection work should target the substantial external Markdown gap as
a separate research cycle: select missed categories by these aggregate results,
obtain source-reviewed positive and nearby benign cases, and evaluate on a new
held-out source. The new code-analysis mechanisms are supported by paired local
regressions and bounded static evidence; this external text benchmark did not
demonstrate a detection improvement for them. A mechanism-and-UX milestone is
supportable; an industry-leadership claim is not.

No package runtime execution, paid provider calls, real secret output, deployment
or external outreach was part of this assignment.

## Separate scoped-report UI assurance

The coordinator authored the six-scope navigation, token presentation and
improvement-plan formatter. Independent browser checks in
`tests/browser/skill_report_scopes.cjs` passed against the actual client source
with explicitly synthetic API fixtures: all six scopes remain reachable, one
roving tab stop follows arrow/Home/End navigation, every scope reflows at 390 px,
fresh scans reset selection, and legacy reports retain honest unknown states.
Both full-report Markdown modes retain cross-scope evidence. The separate plan
download preserves all four item dispositions, source locations, actions,
validation, artifact identity and priority interpretation. Hostile HTML and
triple-backtick text round-trip as literal JSON without executing or breaking
the export's fenced structure. The fixture's raw upload text is absent.

The adapted standards and evidence regression harnesses passed. The existing
diagram harness exposed a coordinator regression that lost the active scope and
keyboard focus after returning from its separate playground map. After the
coordinator moved the selected scope to its parent state, the original return
and focus checks passed without adding a compensating scope click to the test.

These are local interaction checks, not production visual acceptance, scanner
accuracy evidence, tokenizer accuracy or independent approval of the earlier
diagram/standards components authored by this agent. Actual candidate-API
integration also passed when the coordinator executed the adapted actual-API
harness after restart: real synthetic upload, source-bound plan download matching
the returned API items, token view, separate playground map, planning API and
return scope/focus. This execution is reported as coordinator-run integration,
distinct from this agent's independent fixture-based interaction checks.
