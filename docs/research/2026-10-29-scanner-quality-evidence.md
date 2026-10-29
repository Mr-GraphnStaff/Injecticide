# Scanner quality: evidence and next experiments

Date: 2026-10-29. Research and independent assurance role: Lena, reporting to Avery; David remains team lead. This document records source inspection and a proposed evaluation protocol, not a completed comparative benchmark or release approval. No new external service was activated, private skill uploaded, downloaded sample executed, or paid provider called.

## Conclusions supported now

The best immediate improvements are fewer misleading alerts, stronger instruction-to-effect evidence, explicit incomplete coverage, and readable evidence navigation. None alone establishes industry leadership. The current generic refusal/chunk declaration/map fixes require independent review of their final implementation; this research does not certify their intended behavior.

The existing external evaluation is a diagnostic warning. `evals/skill_scanner/README.md` explicitly records exposure of the 180 SkillFortify Claude Markdown inputs. `docs/research/2026-10-28-skill-analysis-leadership/lena-evaluation.md` records identical selected decisions for 0.10.0 and 0.11.0: review-or-block positives on 8/90 upstream synthetic malicious labels, 79 negatives and 3 abstentions. Upstream synthetic benign labels produced zero positives but 72/90 abstentions. This cannot support a 0% false-positive claim. The source is now exposed; future runs are regression/diagnostic evidence, never a fresh holdout. Publisher examples carry an assumption about legitimate purpose, not independently established benign labels.

## Primary-source practices worth incorporating

| Source inspected | Practice and application | Boundary |
| --- | --- | --- |
| [Cisco recommended settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings) | Separate a medium review queue from a high blocking gate; contextual capability observations stay visible at lower severity. Publish exact settings, model, population, confidence intervals and confusion counts. | The vendor reports approximately 8% held-out recall for deterministic rules alone and higher recall with its LLM judge. Those are its measurements, with its model/data/configuration; they are not Injecticide results or proof an LLM judge is required here. Its recommended configurations all enable the judge. |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector#suppressing-false-positives-baseline) and [resource bounds](https://github.com/NVIDIA/SkillSpector/blob/main/docs/ANALYSIS_RESOURCE_BOUNDS.md) | Evidence-bound suppressions reactivate when source/version changes. Caller exclusions remain visible and incomplete; author-controlled files should not silently exclude inspection. Resource ceilings must yield partial analysis rather than cleanliness. | Do not introduce broad content-triggered exemptions or turn incomplete scope into a safe verdict. A reviewed suppression needs its own evidence and lifecycle. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Compact discovery with expandable detail; versioned result semantics; inspect configured agent/MCP relationships as a separate scope. | Current analysis requires an account token/API, and scanning MCP configuration may contact remote endpoints or execute stdio commands with consent. It is not an assumed offline/no-cost comparator. No such scan was run here. |
| [Agent Skills evaluation guide](https://agentskills.io/skill-creation/evaluating-skills) | Compare the same realistic tasks with/without a skill or against a frozen previous version; preserve outputs, observable assertions, timing/tokens and human review. | Output-quality/runtime evaluation is a separate outcome from static format and security inspection. It may require model calls; static findings cannot certify successful execution. |
| [Agent Skills specification](https://agentskills.io/specification) | Trace mandatory frontmatter constraints, optional metadata, progressive disclosure, scripts and references separately. | `metadata.version` is an optional string example; the specification does not prescribe SemVer or require CHANGELOG.md. Markdown body content has no format restrictions. A local policy restricting version placement must be labeled as local policy rather than attributed to the standard. |

Documentation discovery used the official [complete page index](https://agentskills.io/llms.txt); its creation, description optimization, scripting, client implementation and evaluation sections are separate concerns. Reading this selected comparison set is not a claim that every linked external document was ingested. Existing `docs/research/2026-10-28-skill-analysis-leadership/` research remains a source for prior traceability, not current implementation proof.

## Prioritized experiments

1. **Context calibration with paired abuse controls.** Distinguish mentioning/refusing credential or PHI disclosure from instructing disclosure; preserve direct sensitive-data matches and separate malicious clauses. Recognize a plain chunked-reference declaration without inventing a whole-file EOF claim. A declaration must not bypass actual bounded scan coverage, malformed explicit EOF claims, trailing content or forged evidence. Test findings, dispositions, governance decisions and exported text together.
2. **Evidence-first map.** Node selection should emphasize every incident edge, dim unrelated edges without deleting data, support keyboard/Escape and explicit clearing, and preserve normal editing and test-plan highlighting. Explain source identity, inferred static relationships and runtime uncertainty independently. Validate dense graphs and mobile layouts; unknown runtime trust must not disappear for cosmetic reasons.
3. **Instruction-to-effect witnesses.** Extend measured support for literal CLI arguments bound to known script parameters, exact source-to-sink paths and cross-file evidence. Use close benign controls where the same script uploads a public report. Existing authored mechanism tests are regression evidence; measure held-out improvement separately.
4. **Coverage and review burden.** Track unsupported syntax, unresolved references, truncated input and suppressed findings in machine-readable evidence and the UI. Report review frequency and reviewer effort on a natural sample without calling unlabelled flag frequency a false-positive rate.
5. **Review lifecycle.** Consider artifact-and-rule-version-bound suppressions with reason, issuer and expiry. Never let a skill's own safety label or example marker grant trust. This is a candidate feature, not implemented or approved by this report.

## Credible no-new-cost comparison protocol

- Freeze scanner source, bundled rules, runner, adapter, threshold mappings, dependency versions and input-view definitions before acquiring new holdout bodies. Record hashes, timestamps and who saw which material. A caller-declared freeze ID is not independent proof of secrecy.
- Keep the already-exposed 180-case set as diagnostics. Select a new source/structural holdout using metadata only, check source overlap/deduplication and licensing, and have labels independently reviewed where feasible. Freeze disputed labels as unknown; never recycle scanner verdicts as ground truth.
- Preserve complete packages separately from native single-file and normalized-text views. Never pool them silently or wrap raw Markdown as a fully conformant package just to improve coverage.
- First compare Injecticide's released baseline and candidate offline using `tools/skill_eval.py`. The existing runner preserves hashes, label origin, selected security block/review profiles and abstention bounds; inspect adapters and exact bytes. This alone is useful zero-provider-cost evidence.
- For external tools, review and pin releases/dependencies first. Use static/local modes only in a disposable isolated environment, with telemetry/network/model lookups disabled and no execution of scanned content. Record unavailable features explicitly. If safe offline isolation or installation is unavailable, mark the comparator not run; do not invent a result.
- Treat Snyk remote analysis and any paid/local-GPU judge as a separate proposed experiment. Before activation, present provider/account, upload scope, expected volume/tokens, monetary estimate and a hard cap to David. An open-source license does not mean zero operating cost. No new infrastructure is required for the first baseline/candidate comparison.
- Predeclare two security operating points and separate conformance/context findings. Record all cases, errors, abstentions, incomplete coverage, elapsed time, peak resource use and per-category counts. Report review burden, recall and false-positive uncertainty with original denominators. Compare paired case decisions and confidence intervals; publish raw safe receipts and scoring amendments.
- Keep runtime task success, safety of execution, static detection and usability separate. Human acceptance remains distinct from CI passing. Claims must name the measured population/version; no universal accuracy, perfect-safety or industry-leadership claim follows from this protocol alone.

## Checks actually performed for this report

Read repository AGENTS.md, the software-team persona/assurance playbook, external eval README, prior research/evaluation report, and relevant runner source. Read official web sources linked above, including NVIDIA resource-bound/suppression documentation and Cisco measurement caveats. No comparator was installed or run. No scanner accuracy or final UI acceptance test was performed as part of writing this report; those results must be recorded after final implementation review.

## Independent final change review

Reviewed the candidate working-tree diff after both authors declared their code frozen, based on released 0.12.0 commit `bf10a4bb45ccc1152eb3ae2e52498ae21bb93d1c`. Review scope: scanner disclosure/definition/quote and protective context, governance disclosure indicator, chunk claims, process summary/uncertainty, inline and playground map focus/state/CSS, and their tests. This reviewer authored the research report only, not production changes or the submitted test files.

Three concrete review findings were reproduced and returned to owners: unrelated definition language could downgrade disclosure; an unrelated completed quote and a secret-values-in-report request could inherit benign context; adding/replacing maps and preserved test-path edges needed consistent focus/count state. Authors fixed these, and independent retests passed. No unresolved release-blocking defect was observed in this scoped review. This is a reviewer recommendation, not David's PR acceptance or a release/deployment confirmation.

Actual independent checks against the final candidate:

- `python -m pytest tests/test_scanner_protective_context.py tests/test_skill_scanner_corpus.py tests/test_contextual_rules.py tests/test_contextual_evidence.py tests/test_inspection_evidence.py tests/test_process_diagram.py -q`: **127 passed**, 9.30 seconds. The authored corpus threshold was not relaxed.
- Twelve additional whole-scan string probes passed with matching governance indicators: direct/protective/mixed actions, backward target/action order, negative refusal, unrelated definition/quote and literal secret values versus a true evidence-summary topic. Four direct system-target scope/backward/guard probes passed.
- Seven independent chunk-evidence strings: plain/quoted declarations remained informational without EOF/completeness verification; wrong filename, trailing data, fenced EOF and explicit missing EOF remained review; valid matching true EOF verified.
- `tests/browser/skill_process_diagram.cjs` and `tests/browser/map_connection_focus.cjs` independently executed under Edge headless with the cached local Playwright runtime: **both passed**. They exercised actual React client code against synthetic API fixtures, including 40 components/105 connections, incident highlights, dim/filter/clear, Enter/Space/Escape, retained test paths, movement/invalidation, 390/1440 reflow, complete JSON export, literal hostile labels, separate saved drafts and report return. The dense playground screenshot was visually inspected.
- `git diff --check`: passed; Git emitted line-ending conversion notices only.

Reviewed source SHA-256 identities (reporting before release commit):

| File | SHA-256 |
| --- | --- |
| `skill_sandbox/scan_rules.py` | `20e63e4a7e71c0f441e387653fa54c3c304f3cbc998a384341e79bddd53b60da` |
| `skill_sandbox/contextual_rules.py` | `eb2b79b3352b45663243b952fa4eb41b88a871ca545a9abc59518f08419cbe35` |
| `skill_sandbox/inspection_evidence.py` | `ab5d094705c5e2e02f3de5b6881c92232f2bbcd8e826e0b233783c7536144630` |
| `skill_sandbox/process_diagram.py` | `182576f232374cff970a09e8359f12829fff3ce5ddc1cdd5556cc6c2c7c2a507` |
| `webapp/static/app.js` | `57ecfe2f953c31696b1e35c53fef28043c99e03e7f20c8daf4d46f8b81616c6a` |
| `webapp/static/pages/ArchitectureCanvas.jsx` | `7ca63f443be1051effec26c7b0f27e34447c56fc81dd409881f34af1901c2c96` |

Residual limits: bounded deterministic syntax does not prove arbitrary natural-language intent; source declarations are not runtime enforcement. Dense routes can still cross and require scrolling; connection focus is not an automatic layout optimizer. Browser fixtures do not establish live deployed behavior, screen-reader/manual UAT or universal vendor compatibility. This reviewer did not run the full repository suite or the actual local API harness; coordinator evidence for those must be recorded separately. No external comparator or new independent held-out accuracy evaluation was executed, so this change supports a scoped correctness/usability improvement, not demonstrated general superiority.


## User direction: Obsession MCP

David proposed the name **Obsession MCP** for a focused skill/plugin research
service feeding the existing update process. He clarified that discovery and
analysis should run in the background, independently of scanning. This is design
direction, not an implemented or activated service in 0.13.0.

A background cycle can discover, capture, compare, analyze and propose evidence
updates. Validation and review produce a versioned snapshot for subsequent scans;
an in-flight scan retains its original rules/reference versions. Scanner gaps and
review disagreements feed new research questions. Retrieved content remains
untrusted evidence and cannot directly activate detectors, policy or executable
content. Costed search/model/infrastructure activation requires advance notice,
account/upload details, an estimate and a cap before approval.

Proposed initial cadence: once every 24 hours, checking source revisions before
analysis. Retain the last validated snapshot on failure; notify on meaningful
findings or failures. This cadence is recorded but no scheduler was activated.
