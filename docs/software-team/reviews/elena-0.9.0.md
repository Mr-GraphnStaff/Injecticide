# Elena independent calibration and integration review — 2026-10-28

Reviewer: Elena Voss, AI Security Architect reporting to Morgan Hale. Avery
coordinates; David Farris is team lead. Actual execution host: Windows, checkout
`Y:/projects/Injecticide`, branch `codex/skill-process-diagrams-0-9`.

## Independence and scope

This agent implemented `process_diagram.py` earlier and does **not** approve that
module or its own diagram tests. This review independently examines Ishan's
scanner calibration and Avery's report integration, citation offsets, redaction
ordering, release notes and assignment context. Morgan's separate review covers
the authored diagram module and UI. Role identities are fictional; the tool runs
and findings below are actual local evidence.

On-the-spot peer coverage on October 28: Ishan's calibration and Avery's
integration/reporting. Quarterly personnel review was not performed or scheduled
by this technical review. No production changes, customer-code execution, paid
calls or external messaging occurred.

## Findings and verified corrections

1. **Personal-data approval inconsistency — corrected.** Initial synthetic
   `jira-references/people.md` with a named email and labeled UUID produced
   `require_approval` findings but governance `approval_required=false` and
   brokered `allow`. `governance.py:72` now recognizes actionable personal contact
   review; both execution routes receive the relevant finding identities at
   lines 132 and 139. Personal-only output describes disclosure review instead
   of inventing execution side effects. These are scanner recommendations, not
   proof of an enforced external approval gate.
2. **Early benign mentions suppressed a later active call — corrected.** Three
   prose API mentions consumed the observation cap and hid a later fenced
   `eval(input())`, yielding `no_static_findings`. `app.py:528` now prioritizes
   higher-risk observations across units, and `scan_rules.py` retains the
   strongest observations within a unit. Independent paired tests require the
   active call at its physical line to remain under review.
3. **Claimed fix-note exemption too broad — removed.** An interim expansion
   downgraded imperative calls following claimed false-positive context. Probes
   using `run`, `execute`, `use` and `apply` reproduced this. The final contract
   retains only the original empty API-name prose calibration. Raw nonempty calls
   remain reviewable; documentation cannot promise general prose understanding.
4. **Quadratic line accounting in expanded scans — corrected.** Scanning all
   email observations initially rescanned the entire text prefix per match.
   Direct detector timings for 1,000 / 10,000 / 30,000 repeated synthetic aliases
   were 0.039 / 0.593 / 5.394 seconds. Incremental line accounting yielded
   0.005 / 0.029 / 0.086 seconds in a subsequent local run. The corresponding
   dynamic matcher took 0.002 / 0.024 / 0.060 seconds and retained the last active
   call at lines 1,001 / 10,001 / 30,001. These are local diagnostic samples,
   not production throughput guarantees.
5. **Assignment-context escape corruption — corrected.** Form-feed/tab/newline
   corruption in the newly prepended source hash, test directory and review
   receipt path was reported to Avery and verified corrected by rereading the
   context. Changelog and scanner documentation now describe the narrower
   empty-API-name boundary.

## Additional inspected behavior

- Reference/template roles cannot waive `pii_`/`phi_` dispositions
  (`disposition.py:91`). Named/unknown addresses remain review findings; role-style
  aliases retain presence evidence and unknown public availability. Labeled
  UUID-shaped account identifiers are distinguished from unlabeled build UUIDs.
- Native HTML script capability is informational, while an active dynamic call
  remains a separate review finding. Disguised source behind a document suffix
  remains reviewable without claiming a proven upload-policy bypass
  (`package_threats.py:240`). Inert JSON script blocks/comments were checked by
  the calibration regressions. This is not comprehensive HTML execution analysis.
- Markdown source layout is retained for dynamic-call citations. Embedded
  observations and formatted samples are offset back to their physical document
  lines (`package_analysis.py:70`). Independent package probes verified both.
- Process extraction occurs before the existing report redactor, then the new
  diagram/export surfaces derive from sanitized evidence
  (`package_analysis.py:162`). A synthetic credential in a documented step did
  not appear anywhere in serialized output, including Mermaid/map exports.
- Inspected `docs/skill-scanner.md`, `CHANGELOG.md` and the assignment context for
  claims consistent with the tested implementation and explicit runtime limits.

## Verification

Independent authored probes are retained in `tests/test_calibration_review.py`.
The successful final-scope command is:

```text
python -m pytest -q tests/test_calibration_review.py tests/test_scanner_calibration.py tests/test_evidence_redaction.py tests/test_contextual_rules.py tests/test_skill_scanner.py
```

Final result: **79 passed in 43.13 seconds**, after the performance correction.
Earlier invocations with
nonexistent guessed test filenames aborted collection and establish no result;
they were corrected. An initial review-test assertion expected literal brackets
inside escaped Mermaid labels; the assertion was corrected to test redaction
without requiring unescaped syntax. That assertion was not a product defect.

## Verdict and limits

Calibration and integration are **complete with stated limitations**; no
unresolved actionable issue remained in this review's scope. The coordinator
still owns combined verification and release reporting. This
review does not approve this agent's diagram implementation, certify UI
accessibility, merge or deploy a release, or substitute for human PR acceptance.
The original `infosec-memory-core` package/report was not available for a new
independent scan; synthetic regression results are not live customer acceptance
or representative detection accuracy. Arbitrary prose semantics, runtime
behavior and effective external organizational policies remain unverified.
