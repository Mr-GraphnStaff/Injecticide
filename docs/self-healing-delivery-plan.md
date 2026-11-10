# Self-healing and self-updating delivery plan

Owner: Avery. Updated November 10, 2026. This extends the existing research,
correction and release paths. It does not replace them or declare unverified
standards conformance.

## Current verified starting point

Production is 0.19.0 at 9b5c0f90854ac86355fd030681cb9f9309d4e904.
The November 10 live check attempted all 88 planned research pages, with one
failure. The approved correction pack is active at revision 5 with seven rules.
Collection, research triage, candidate qualification and scanner activation are
different stages; success at one stage does not establish success downstream.

## Ordered work and acceptance

1. **Recover research triage (locally verified; release pending).** Persisted triage failure must make health
   degraded even after restart. Retry retained evidence after five and ten
   minutes, with three attempts per group; do not re-fetch sources to retry local
   processing. Preserve evidence and the last known good active rules. Exhaustion
   remains visible until successful processing; never silently mark it healthy.
   A later successful collection can start a fresh bounded attempt group.
   Schedule deferred policy due times independently of collection; deferral is
   not successful processing. Prove failure, recovery, exhaustion, restart visibility and unchanged collection
   cadence using virtual time, plus exercise the actual HTTP health route.
2. **Finish the interrupted package-editor repair (preserved, not complete).**
   Resolve the recorded browser timeout/download failure with a reproducer,
   verify progress/error/retry behavior and full Office-asset rescan coverage,
   then run the integrated native scan/build/download journey. Complete supported
   fixtures must download; incomplete database inspection must name the file and
   row counts and remain blocked. The actual 3.6.3 package now has complete
   supported Office XML inspection, but two databases retain incomplete coverage.
   Preserve the
   original package and unrelated contextual-rule changes.
3. **Close research-to-scanner delivery (planned).** Review the proposed shared
   assessment contract and representative cases in assessment-contract.md and
   assessment-contract-cases.md before changing finding meanings. Trace a changed approved
   source through evidence hash, candidate, qualification, exact-head CI,
   deployment, active rule revision and a final scan result. Expose each stage's
   last success, pending/blocked state and sanitized failure. A reference-index
   update alone cannot count as a scanner behavior update.
4. **Prove automatic update and rollback (planned).** Reuse the bounded automatic
   lane and finite correction grammar. Require protected-outcome/false-positive
   tests and independent review where required. Test duplicate events, stale
   evidence, failing CI, deployment failure and regression rollback. Activation
   must read back the intended scanner and rule hashes. Retain a known-good
   revision and a clear unresolved incident when recovery fails. Revalidate an
   existing approved correction pack for a new scanner release in the trusted
   delivery lane, without approving different rule contents implicitly.
5. **Verify operation and release (planned).** Confirm the existing 02:00
   America/Chicago schedule, including daylight-saving handling, rather than
   adding a second scheduler. Observe the exact candidate through Azure CI and
   deployment, verify the public user path and record the deployed hashes.

## Boundaries and completion

The base assessment remains organization agnostic; organizational policy and
documented exceptions supplement it. Missing approval evidence remains unknown.
No customer package text, PII, PHI or PCI values enter the model. Model suggestions
and retrieved documents cannot execute code, change access controls, approve
themselves or bypass release/protected-detection gates. This is gated learning
and deterministic updates, not automatic model-weight training.

Use one implementation owner and bounded independent QA/security review.
Each retry needs new evidence; stop and reassess after two equivalent failures
or ten minutes without new diagnostics. No duplicate builds or blind timeout
increases. Completion requires the relevant real user/runtime boundary, not only
unit tests or healthy containers. This document is a work plan, not a release
or conformance claim.

## Remaining capacity investigation

The actual 3.6.3 archive contains two databases with incomplete inspection
(24,261/27,086 and 0/4 reported rows in the recorded run). Evaluate a bounded
deep-inspection/resume path separately. No silent budget increases or download
exception are part of this repair. These counts do not identify the limiting
resource or establish a database-parser defect.
