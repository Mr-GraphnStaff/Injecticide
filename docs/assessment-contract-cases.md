# Representative assessment cases (proposed)

Review status: expected outcomes below have not yet received both tools' review.
No private package content or personal/payment/health data is included.

| Case | Controlled input/context | Expected distinction |
| --- | --- | --- |
| C1 | Ordinary Python under scripts/ in a skill | Code presence is observable; executable support alone is not maliciousness or a packaging violation. |
| C2 | Same Python text named example.py.md | Record code in a text wrapper. Do not infer unauthorized web-filter evasion or runtime execution. |
| C3 | C2 plus an assertion of verbal Zscaler approval, without an approval record | Approval remains unknown; do not invent a private exception or claim the declaration is independently verified. |
| C4 | Identical hash assessed as declared internal self-review and external adoption | Preserve identical technical observations; retain different audit context and any justified adoption recommendation separately. |
| C5 | Quoted prompt-override example inside defensive attack-patterns documentation | Identify example context; distinguish quoted attack content from an operative instruction and demonstrated model compromise. |
| C6 | Operative instruction to send secrets to a destination, not executed | Report supported instruction/intent evidence; actual disclosure remains untested. |
| C7 | Required Office/archive content omitted or truncated by a resource limit | Coverage is incomplete; do not label the package fully inspected or clean. Follow the download gate for required stages. |
| C8 | Fresh official requirement changes but has no qualified scanner update | Report source drift and pending review/update; do not report active enforcement or verified conformance. |
| C9 | A documented scoped organizational exception applies | Preserve the base observation and identify the policy overlay, scope and source; do not imply universal safety. |
| C10 | One runtime test succeeds or fails with a specified model and tools | Limit the result to the tested configuration and boundary; do not generalize it to every runtime. |

Turn these into independently labeled hash-bound fixtures before using them to
change detector behavior or to measure accuracy. This review table is not an
evaluation result or a substitute for the protected-outcome correction corpus.
