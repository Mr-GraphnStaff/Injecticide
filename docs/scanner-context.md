# Static scanner context and evaluation inputs

Scanner 0.2.1 keeps JSON evidence within individual string values rather than
combining unrelated values or test cases. Evidence excerpts for enterprise rules
include all of the matched service, action and autonomy terms.

Under an `evals/` directory, a JSON object with `trigger_prompt` and a recognized
`assertion.type` (`tool_call_forbidden`, `tool_call_requires_precondition`,
`content_diff_forbidden`, or `scope_check`) declares test input. Matching input
and assertion content is retained at review tier with action state
`declared_test_input`. It does not establish actual execution, a passing test,
an enforced guardrail, trusted provenance, or a safe package. Separate fields
such as setup/instructions are still evaluated as active content. Malformed
JSON is scanned line by line, not exempted.

The targeted contextual rules distinguish automatically offering a workflow
step from automatically executing it. Disclosure findings require a verb bound
to a credential target rather than an earlier topic elsewhere in the text.
Self-modification requires a skill write operation/target, not the phrase
"post-execution" or a skill directory mention alone. These deterministic checks
are bounded static signals, not complete language understanding.

Contact patterns remain Sensitive Data regardless of whether they appear in a
reference file or database. A reference path or a corporate-looking email domain
does not authenticate internal ownership or establish that disclosure is allowed.

Approval, sandbox and coverage decisions are separate. Removing a false blocking
finding does not certify an entire package or clear side-effect controls. No
package-name exemption or self-declared custodian trust has been introduced.
Original artifacts must be rescanned for replacement verdicts; an exported report
cannot establish a new artifact-level verdict.
