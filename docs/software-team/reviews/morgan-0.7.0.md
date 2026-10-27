# Morgan independent security review — scanner evidence 0.7.0

Reviewer: Morgan Hale, Security Architect, reporting to Avery Chen. Review date:
October 27, 2026. Runtime: Windows against the Raspberry Pi network checkout.
Scope: independent read-only source review and local synthetic negative checks;
Morgan did not author the application changes or implementation tests. This
review record is the only file authored by the reviewer.

Candidate: branch `codex/scanner-evidence-0-7`, working changes based on
`7af759dd44e16c2e494e1bc61b478b84c84d4a78`. New/untracked source and tests were
included in inspection. The final implementation owners declared source
quiescent before the final independent reproduction/test pass.

## Verdict

**Security review complete with stated limitations. Ready within the reviewed
0.7.0 evidence-contract scope; no unresolved high/medium finding from this
review.** This is not production-deployment completion, a general safety or
accuracy certification, or independent verification of the company's package.
Avery must still finish R7 CI/container builds, release controls and the actual
public authenticated upload checks before declaring the release deployed.

## Resolved review findings

| Finding | Severity at discovery | Evidence and independent closure |
| --- | --- | --- |
| False EOF verification inside malformed or container-prefixed code fences | Medium | Original `creator_mitigation` verified EOF after an invalid closing fence such as three backticks followed by `python` or trailing prose, and inside blockquote/list fences. `inspection_evidence.py:18` now requires a proper closing fence, and container-prefixed/nested contexts are explicitly unverifiable at `:105`. Reproduced original simple and mixed nested examples after the fix: none verify. A proper top-level closed fence with an actual EOF comment still verifies. |
| Convention-A prefix and nonstandard-JSON acceptance | Medium correctness | Original A recognition accepted `chunked-reference-NOT-A-CONVENTION` and `/disabled`; JSON NaN/Infinity/-Infinity could verify. Exact scalar recognition at `inspection_evidence.py:90` and strict JSON constant rejection now prevent these false verifications. Canonical positives still verify; duplicates and trailing content remain unverified. |
| Caller-controlled analysis diagnostics and pre-handler validation reflection | Medium | Original analysis `ValueError` was returned verbatim. Framework 422 responses exposed invalid form `input` and lacked correlation. `webapp/api.py:115` adds scan-only correlation/sanitized pre-handler 422; `:568` onward preserves endpoint-owned stages and fixed error messages. Independent tests confirm arbitrary analysis sentinels and invalid-file-field sentinels are absent, request IDs match headers, and sandbox 422 retains its sandbox stage. |
| Credential-bearing URL and authorization values reflected into report evidence | Medium | A synthetic `mcp.json` containing URL userinfo, api_key query, access_token fragment and Authorization bearer value appeared in findings/behavior/instruction evidence before the fix. `evidence_redaction.py:92` now sanitizes evidence after detection and decisions. The synthetic secret no longer appears anywhere in the serialized report; network findings remain and an ordinary directory email remains visible. This is bounded report hygiene, not exhaustive secret detection. |
| Redaction could mutate trusted report identities, hashes and decisions | High | An intermediate global-replacement implementation let password values `a`, `prompt_override`, `blocked`, `high`, `bad` or `block_by_default` rewrite hash strings, rule IDs and computed policy/risk fields. The final implementation uses explicit evidence-bearing fields with computed values preserved by default (`evidence_redaction.py:31,149`). Independently reran all six cases: artifact hashes equal original upload SHA-256, finding IDs and blocked tier remain intact, and high/bad/block_by_default risk decisions remain unchanged. |
| Redaction work budget could be swallowed or permit an excessive regex | Medium | The URL collector previously caught the same ValueError used for a literal-count budget, and aggregate retained literal characters were not capped. A dedicated propagated `RedactionBudgetExceeded`, 128-value/32-KiB aggregate literal limits and bounded source/tree traversal now apply (`evidence_redaction.py:39-65`). Independently lowered limits for deterministic negative tests: both URL count and aggregate-character limits fail closed. |
| Comparison accepted contradictory coverage and failed on malformed nested inputs | Medium correctness | Original comparison raised AttributeError for null coverage, non-object inventory or mitigation, and could label missing detection `not_detected` despite known truncation/arbitrary complete fields. `tools/scanner_evaluation.py:106,141,242` now validates consumed nested structures and treats partial/error/not_performed evidence across matching file/inventory records conservatively. Original malformed examples now give safe ValueError; truncated/contradictory inventory coverage gives unknown; non-boolean skipped is rejected. Unsupported stages or unknown rules cannot establish absence. |
| Engine identity did not distinguish the changed scanner | Medium audit integrity | Metadata originally retained engine 0.2.1 / October 19 adapter identity. `package_evidence.py:113-139` now reports engine 0.3.0, October 27 adapter revision and a source fingerprint over local scanner modules plus the pinned validator manifest. Comparison retains this context. Independent scan checks confirm the version and 64-hex fingerprint are present; upload data does not choose the fingerprint source. |

## Other reviewed boundaries

- R1: portable format semantics are an explicit local contract only when the
  portable target is selected. Unverified vendor semantics are advisory; local
  parser safety remains distinct. The final targeted tests cover both paths.
- R2: creator mitigation, extraction, detector input/limits and result-display
  coverage remain separate. A verified tag does not suppress security findings,
  increase detector coverage or prove a target LLM read the whole file.
- R3: email/phone presence remains an observation and no longer automatically
  establishes regulated-data handling or a disclosure attempt. Identifier/clinical
  and genuine instruction signals remain separately testable. No company/domain
  blanket trust or suppression was introduced.
- R4: bundled OpenAI/Anthropic scripts are pinned administrator-supplied source,
  hash checked before import, invoked on a fixed temporary SKILL.md containing
  only bounded, uniquely parsed, anchor-free complete frontmatter. Uploaded
  modules are not imported or run. Results explicitly have no execution-policy
  effect and do not establish runtime acceptance. Products without a reviewed
  executable validator are unavailable, not passed. No hot research execution.
- R5: comparison rejects missing/different artifact hash claims; matching claims
  do not authenticate an author or appoint either report ground truth. Synthetic
  corpus labels are explicitly authored, not held out or independently human
  adjudicated. No broad accuracy or comparative superiority claim was found.
- R6: no payload/filename/full exception is logged by the new unexpected-failure
  path; only request ID, stage and exception class are logged. Returned known
  failures use fixed diagnostics. Framework and endpoint stage ownership were
  independently exercised.

## Executed verification

Final independent command after source quiescence:

```text
python -m pytest tests/test_inspection_evidence.py tests/test_official_validators.py tests/test_scan_diagnostics.py tests/test_scanner_evaluation.py -q
121 passed in 24.49s
```

Also executed separate direct synthetic reproductions of the original false EOF,
strict-JSON, exact-A-value, credential reflection, schema/decision redaction,
work-budget and API diagnostic cases described above. All final assertions
passed. An earlier independent R5-only rerun passed 61 tests. These are local
observations, not production checks. `git diff --check` had no whitespace errors.

## Limits and skipped checks

- The company's original `.skill`, both full auditor reports and its private
  auditor implementation were not available; their exact discrepancies remain
  unverified. No source change was made to the private skill.
- This reviewer did not independently run paid LLM evaluation, a vendor upload,
  customer code, live abuse traffic, deployment, browser accessibility checks,
  complete CI or production mTLS upload. Those are separate team/integration
  evidence where applicable, not implied by this verdict.
- Static review and authored synthetic regression cases do not establish absence
  of undiscovered vulnerabilities, real-world false-positive/negative rates,
  non-English attack detection, complete binary analysis or runtime safety.
- Unsupported Markdown container contexts, parser/resource limits and unknown
  compatibility are intentionally explicit abstentions. Report-secret discovery
  is bounded and not guaranteed complete; evidence must retain its source-data
  handling protections.
