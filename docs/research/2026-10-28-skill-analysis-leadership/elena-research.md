# Elena — deeper skill analysis through evidence-bearing effects

Research date: October 28, 2026. Elena Voss, AI Security Architect reporting to
Morgan; Avery coordinates and David leads. Actual host: Windows,
`Y:/projects/Injecticide`. This is discovery and measured static inspection, not
industry-leadership certification. No downloaded or uploaded code was executed,
no external model was called, and no dependencies were installed.

## Recommendation

Build **package-wide effect witnesses**: explain which instruction or entrypoint
connects to a sensitive source, through exact calls/returns or bound parameters,
to a consequential sink. Separate a proved supported-syntax connection from a
possible connection and an opaque boundary. The scanner should answer why two
individually ordinary files become consequential together, without treating
ordinary uploads, authentication or documentation as malicious by association.

The immediate bounded function-summary implementation Avery assigned to Ishan
is a useful first mechanism. It must improve whole-report precision as well as
new-detector recall. The strongest follow-on experiment is **binding literal
instruction CLI arguments to known script parameters**. That connects the skill's
instructions and code without requiring a paid natural-language compiler.

This does not reduce the ambition to Python linting: the effect/provenance
contract should support additional language frontends, explicit instruction
evidence and configuration binding. Unsupported semantics remain explicit, not
an excuse to label an incomplete implementation a complete skill analyzer.

## Owning-source inspection and measured baseline

Base commit: `58c1c4bb5dbd683de2aed494ca2785305c1d0788` (published 0.10.0).
The inspected `skill_sandbox/code_security.py` SHA-256 was
`5eb8f329936d84ea61a4e34100844b4aaee33ab43bafe7a917a9b71ffaad8cb4`.

Observed implementation:

- `package_analysis.py:82` invokes the value-flow analyzer separately per file.
- `code_security.py:227` analyzes function bodies with unknown parameters and
  does not connect a call's arguments or return to that body.
- `code_security.py:189` conservatively combines unknown-call arguments into the
  returned value; that is not proof the function returns those arguments.
- `package_graph.py` supplies file reachability and capabilities, explicitly not
  runtime control flow. A file-reference chain is not a data-flow witness.

Executed `analyze_code_security` on authored string inputs; none of their Python
statements or network requests ran:

| Synthetic semantic case | Baseline credential-flow findings | Interpretation |
| --- | ---: | --- |
| Direct environment credential supplied as HTTP request data | 1 | Existing supported positive |
| Helper returns the same credential, caller supplies its return as data | 0 | Argument/return analysis gap |
| Caller passes credential to local helper that sends its parameter | 0 | Parameter-to-callee effect gap |
| Helper returns a public constant | 0 | Benign control without sensitive input |
| Helper discards a credential and returns a public constant, caller uploads return | 1 | Precision gap from unknown-call argument propagation |
| Credential request inside literal `if False` | 1 | Conservative candidate, marked partial; literal infeasibility could reduce review burden |

The helper misses report `complete_supported_syntax` with the explicit narrower
intraprocedural scope. That status is not evidence interprocedural behavior was
checked. The tests above are authored challenges, not representative accuracy.

A separate whole-scan probe paired the same generic `argparse` uploader with
two instruction commands: `--input ~/.ssh/id_rsa` and `--input report.txt`, both
using a synthetic `.invalid` destination. Both yielded zero credential-flow
findings and the same `tool_escape` / `declared_execution_target` findings. The
launcher edge resolved correctly, but `args.input` and `args.url` were not bound
to the instruction's literal values. This does **not** mean the package passed
without findings; it demonstrates absent discriminating source-to-sink evidence.

## Primary research that changes the approach

**SCS, October 24, 2026 preprint.** The paper's mechanism combines constrained
instruction IR and code dependence graphs, then propagates trust, sensitivity
and capability properties. It supports investigating cross-domain relationships
rather than simply adding signatures. Its instruction compiler uses LLMs; that
is not an authorized free component we can silently adopt. Author-reported
benchmark results have not been reproduced here. The anonymous artifact endpoint
could not be inspected; a second read-only HTTP route returned 401 after a
redirect. Implementation availability, license and reuse therefore remain
**STATUS: UNKNOWN — UNVERIFIED**. [Versioned paper](https://arxiv.org/html/2610.33489v1).

**CaMeL, March 2025.** The useful idea for this analyzer is retaining data origin
and permitted-reader metadata separately from control authority. Its published
runtime defense is not a static scanner, and its research repository warns that
the interpreter is not a maintained secure product. We should borrow an evidence
vocabulary and adversarial questions, not imply that static provenance enforces
runtime policy. [Paper](https://arxiv.org/html/2503.18813v1),
[inspected code](https://github.com/google-research/camel-prompt-injection/tree/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8).

**SkillsMetric, August 2026.** Its own evaluation reports important misses for
ordinary destructive commands and natural-language attacks despite combining
multiple static signals. This argues against equating a richer graph or a
weighted signal score with broad coverage. We did not reproduce those results
or obtain a licensed evaluation artifact from this paper. [Versioned paper](https://arxiv.org/html/2608.08468v1).

**SkillSecurer, September 2026.** Its controlled modifications, exact injection
localization and explicit ground-truth verification suggest a stronger evaluation
unit than package-level detection alone. The linked artifact repository returned
404 during this research; its license and usable data are therefore unverified.
No headline detection rate is adopted as our baseline or as proof of general
superiority. [Versioned paper](https://arxiv.org/html/2609.14079v1).

## Implementations actually inspected, pins and reuse fit

Only source text and licenses were read; no third-party module was imported.

| Source snapshot | Specific inspected mechanism | License and reuse decision |
| --- | --- | --- |
| [Cisco skill-scanner `f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1`](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1) | `correlation_analyzer.py` records parameter/sink relations and call-site arguments; a separate network-write lane uses explicit path/hop budgets. `forward_analysis.py` tracks parameter labels through CFG facts. | Actual LICENSE says Apache-2.0, despite GitHub API returning NOASSERTION. Useful inspectable reference for bounded witness extraction; no code copied. Direct engine integration/dependency fit has not been qualified. |
| [CaMeL `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`](https://github.com/google-research/camel-prompt-injection/tree/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8) | `capabilities.py` carries origin/readers; `security_policy.py` checks arguments and defaults to denial when no policy matches. | Apache-2.0 LICENSE inspected. Conceptual/test inspiration; importing the runtime would change our product and trust assumptions. Not proposed. |
| [AgentDojo `089ed468cf3ed0322acc66b0211f26d9d90dbf60`](https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60) | `task_suite.py:281–311` separately checks legitimate-task utility and attacker success. | MIT LICENSE inspected. Reuse this evaluation distinction; its agent-runtime benchmark is not directly a static-skill ground truth set. No model/provider run authorized or performed. |

Content hashes for repeat inspection:

- Cisco `correlation_analyzer.py`:
  `f715a141f558c59aee378b0653e6aefaf3e804343a74ee92e1a73be67fcfaf1e`.
- Cisco `dataflow/forward_analysis.py`:
  `01e8d86ade048c5f9a844134836cc6267d12885e7980412be6e274b48fe4d074`.
- Cisco `LICENSE`:
  `6f8bdae6c2bf096c697839ce3b6305d0c2aab22c14fb761b94c9962a79ae5998`.
- CaMeL `capabilities/capabilities.py`:
  `46a779a6eff0e3e7f35639abe5eff57b2afeee76e8cd02f60f547f56d07ef19f`.
- CaMeL `security_policy.py`:
  `e7a060e0192314613494d7a24ca660a39ddf5bdf0f0cc6300fb9bf3cd4dd5b65`.
- AgentDojo `task_suite/task_suite.py`:
  `2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1`.

Before any code/dataset copying, check the exact selected files' notices and
license obligations. A repository license is not proof every bundled dataset or
third-party component has identical terms. These pins establish what was read,
not installed behavior or a claim a competing engine lacks a feature.

## Falsifiable acceptance and an original next experiment

For the current bounded package engine, require paired cases that make opposite
claims: helper-return/parameter flows should gain exact source→call→sink evidence;
constant returns, shadowed functions, unrelated branches and public inputs must
not acquire that evidence. Recursion, dynamic imports and unresolved calls need
an explicit opaque boundary. Preserve container identity and physical lines.

Test the **whole report**, not only the new API: an old conservative finding
cannot remain a high-confidence flow after a new supported summary proves that
specific value is discarded. Conversely, an unknown summary cannot erase a
measured direct flow. No arbitrary sanitizer-name allowlist should waive risk.

Next experiment: a small independently labeled matrix of literal CLI commands
and known `argparse` scripts, varying only input path, destination, helper
structure and argument order. Bind only measured declarations; no shell
expansion, environment lookup or script execution. Include misleading flag
names, reassignments, dynamic defaults and missing operands as abstention cases.
Success requires correct distinct witnesses for the sensitive-path case, no
credential-flow claim for its public-file pair, exact instruction/script lines,
and explicit unknowns for unsupported bindings. Failure on the pair falsifies
the proposed benefit; more generic warning counts do not count as success.

The hardest uncertainty remains semantic intent across arbitrary natural language
and languages. This free bounded experiment can establish a useful cross-domain
mechanism without pretending that uncertainty is solved. Paid/local-model
semantic adjudication, runtime effect enforcement and representative comparative
accuracy require separate design, access and evaluation evidence.
