# Independent security review: contextual accuracy correction

**Superseded acceptance scope:** The review below records the initial correction. The lead subsequently required explicit speech-act facts, adapter source-channel context, target classification and separate governance policy. The expanded independent review is recorded in [morgan-speech-act-policy.md](morgan-speech-act-policy.md); this initial record does not approve that expanded implementation.

- Reviewer: Morgan Hale, independently delegated security reviewer; authors were Ishan and Avery.
- Date: October 29, 2026.
- Source: working candidate 0.14.2 based on `f6873958e15e2116db430f51b997ef7009753052`.
- Reviewed scanner engine fingerprint: `292198f6299f0391ae3b5a7d9e0dfec173248f93ad5b52c198a60fea60e39069`.
- Verdict: **complete with stated limitations** for this security review. No unresolved security blocker remains in the inspected correction. This is not production deployment approval or evidence of general detection accuracy.

## Requirements and observed results

The scanner must distinguish operative disclosure instructions from grammatical descriptions, protective guidance and documented adversary behavior. Ambiguous syntax remains reviewable; an uploaded path, author, heading or claim cannot establish trust. Invocation capability is separate from boundary escape. Blocking decisions must retain source and contextual evidence.

Independent baseline probes reproduced false blocks for status predicates, causal risk descriptions, third-person attacker descriptions and system-prompt risk prose, together with missed passive disclosure directives. Existing security tests passed while these defects remained; their previous pass was not evidence that contextual accuracy was established.

The final source corrects those reproductions. In 23 independently authored end-to-end probes, the seven original contract mismatches are resolved. Direct, conditional, multiline, passive, contrast-after-prohibition, refusal-reversal and assistant-directed requests remain blocking. An explicit benign/educational label does not exempt a later operative request. This is a small regression set, not a representative accuracy estimate.

Further review discovered and required correction of three issues beyond the initial examples:

- Nonaddressed `agent` in a vulnerability description was incorrectly treated as the instruction's actor. The corrected example is informational.
- A spoofed attack/control catalog could hide extraction followed by saving, pasting, uploading or a named output file. All four independently reproduced output-effect variants now remain actionable and block in the final source.
- Mixed descriptive and ambiguous observations retained `action_state=requested` without operative evidence. Final enrichment reports `intent_unverified`; an imperative observation still wins and preserves the requested/block classification.

The three disputed source members and Cloudflare reference were checked again directly from the supplied archive. Their bytes match the members identified in the pasted report. In the final candidate the application-status phrase produces no disclosure finding, the design-risk text is informational, the attack reference retains review with explicitly unverified intent, and the SDK question is not a tool-escape finding. The full supplied archive was also independently rescanned before the final enrichment-only correction: no governance-counted block, sandbox and approval controls retained, 35 review findings and 129 informational findings. The final member-level retest verifies the subsequent enrichment correction. The pasted report's entire 3_0_0 artifact was not available; the supplied 3.0.2 archive is a different artifact.

## Boundaries and reporting

Static inspection of the complete diff confirms no uploaded-code execution, URL fetch, dependency installation, authentication change, workflow edit or deployment change was added. Code-flow detectors remain separate from prose classification. Governance now includes blocking finding references with source path, detector and observation locations; capability evidence alone does not independently assert credential misuse. Plain tool invocation has its own capability observation, distinct from an explicit boundary-bypass instruction.

SQLite extraction remains read-only with trusted schema disabled. Optional row totals use one cumulative operation budget separate from the projection budget. A synthetic FTS5 database with 12,000 documents and a tail table returned measured totals normally. Independently accelerating only count-query progress callbacks exhausted that optional budget: totals became unavailable while the same successful 7,948-character projection, including the tail data, remained intact. No per-table budget reset or loss of successful content projection was observed.

The source-backed process view follows only resolved packaged document links and retains source/step limits, runtime uncertainty and explicit text-block scope. It does not execute the documented sequence or fetch external links. Version observations are maintenance evidence with no governance effect; the helper is in the already-packaged evidence module. Token measurements distinguish a complete extracted projection from incomplete source extraction. React renders the added evidence as text; the UI security review here is static, not independent browser acceptance.

## Executed verification

- Final focused suite: **194 passed in 7.48 seconds** across contextual rules/evidence, code security, package effects/review, calibration review, implementation and independent acceptance suites, reporting accuracy and evidence redaction.
- Reporting helper relocation was separately retested: **5 passed in 1.70 seconds**.
- `git diff --check` passed; a line-ending conversion notice on project context was informational.
- Context parser performance after the quadratic-scan correction: 1 MiB repeated text in 0.432 seconds; 989,001 characters across two sentence-rich lines in 0.193 seconds; 1 MiB single-line input in 0.189 seconds. Full static scan of the repeated 1 MiB input completed in 6.326 seconds, with zero findings and partial coverage disclosed.
- Local raw evidence: `tmp/morgan-security-baseline.json`, `tmp/morgan-security-after.json`, `tmp/morgan-context-performance.json`, `tmp/morgan-full-scan-performance.json`, `tmp/morgan-final-package-summary.json`, and `tmp/morgan-final-member-review.json`. These temporary records are not public fixtures and are not an independently labeled production corpus.

## Coordinator execution review and remaining limits

Avery selected current release source matching the pasted report, isolated implementation from the pre-existing dirty checkout, supplied raw requirements to independent reviewers, accepted reproducible findings and retained failed-run history. Source inspection confirms no release or workflow change was silently substituted for the correction. I did not observe a commit, push or deployment. The original dirty checkout was not edited by this reviewer.

The first full-suite attempt was interrupted after a newly introduced quadratic contextual pass was found; it must not be reported as passing. The coordinator owns the final whole-suite and browser evidence. This review does not independently establish live deployment, runtime skill behavior, complete malicious-code coverage, acceptance of the private package, or industry-wide accuracy. These remaining evidence limits do not lower the requirement to make contextual decisions correctly.
