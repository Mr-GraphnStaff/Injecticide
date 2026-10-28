# Ishan: package effect provenance as the next analysis capability

Date: October 28, 2026. Author: Ishan, senior architect/backend engineer, reporting
to Avery Chen; David Farris is team lead. Actual runtime: Windows with the checkout
on the Y: share. This is an independent architectural recommendation followed by
the specifically assigned implementation experiment, not a claim of industry
leadership or competitive superiority already established.

## Recommendation

Build a bounded package effect/provenance plane that can explain how a resource
reaches an action through actual local code relationships. The useful unit is an
inspectable source-to-effect witness, with explicit unresolved boundaries. A list
of individually risky words, APIs and files cannot establish that relationship.

The first implementable slice is context-specific Python argument/return
analysis across uniquely resolved package-local imports. Preserve the existing
scanner as a separate lane, but reconcile it against stronger evidence where the
new analysis proves a constant result or a syntactically dead branch. Do not
silently convert opaque calls, decorators, recursion or unsupported languages into
safe conclusions. This is a core analyzer improvement; UI and fixtures present
and challenge its conclusions rather than constitute the capability.

## What exists and what the measured gap means

The published source is 0.10.0. `code_security.py` implements bounded local Python
credential-source to request-payload provenance. `package_graph.py` independently
records declared references, launchers, imports and capabilities. Its call chains
are relationships, not value flow. `behavior_analysis.py` infers broad behavior
from combined text and keywords. None joins a helper's returned source or a
caller's actual parameter value to a callee's network payload.

Directly invoked the current analyzer on six authored synthetic snippets without
executing those snippets. Each case uses only an environment-variable name and a
reserved `.invalid` URL; no secret is read and no request is sent:

| Case | Existing analyzer observations | Initial package-effects observations |
| --- | --- | --- |
| Direct credential variable to request body | 1 | 1 |
| Local function returns a credential source | 0 | 1 |
| Caller passes credential to a local sender parameter | 0 | 1 |
| Local function discards credential and returns a public constant | 1 | 0 |
| Source and request are inside literal `if False` | 1, partial approximation | 0, explicit pruned range |
| Credential used in an authentication header | 0 | 0 |

The first helper misses were reported as complete *supported intraprocedural*
syntax, not full-program completeness; retain that scope distinction. The
constant-return case shows why indiscriminately carrying all call arguments to
its result is unsuitable as strong evidence. These are demonstrative boundary
cases, not a representative accuracy benchmark. Root integration must remove
contradicted old findings only under carefully verified conditions, or the
complete report still retains the old false alarm.

## External evidence used, and what it does not authorize

Reviewed primary documentation, rather than treating remembered tools as proof:

- [CodeQL Python data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/)
  distinguishes local and global flow, with explicit parameter nodes and
  non-value-preserving propagation. It supports the need to model arguments and
  returns instead of inferring behavior from co-occurring APIs.
- [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)
  makes source, sink and intervening graph steps explicit. That motivates a
  witness contract whose path can be inspected, not merely a severity score.
- [CodeQL analysis challenges](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
  identifies runtime call targets, aliasing and scale as real constraints. A
  bounded local implementation should surface these limits rather than imply it
  has solved arbitrary Python.
- [Semgrep's advanced taint documentation](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced)
  documents false alarms from treating opaque calls as propagating every input,
  alongside explicit propagators and side-effect models. This is a reason for
  resolved local behavior and uncertainty, not permission to trust functions
  merely named `sanitize` or `redact`.

No tool dependency, commercial analysis engine, fetched program, paid provider or
uploaded execution was activated. Reusing CodeQL/Semgrep themselves would require
separate integration, footprint, licensing and operating-cost decisions; their
public documentation is a design reference here.

## Concrete implemented contract and analysis model

Assigned implementation lives in new `skill_sandbox/package_effects.py`, with
`analyze_package_effects(text_sources, inventory=None)`. It returns schema version,
status, structured observations, per-path compatible findings, coverage/limits,
and `runtime_verified: false`. Existing finding ID
`credential_source_to_network_payload` is retained. A finding contains physical
source and sink locations plus argument/call/return witness steps. Uploaded
literal values and full credential-bearing destination URLs are not emitted.

The engine parses ASTs as data. It never imports, calls or compiles supplied code
for execution. Local module identities must resolve uniquely inside the same
skill/container boundary. Known external APIs use the existing narrowly defined
source/sink models, with local modules taking precedence over a guessed external
name. Function bodies receive fresh abstract parameter bindings for each analyzed
call context; public and private invocations do not contaminate one another.

Literal dictionary/sequence selection preserves field precision: selecting a
public value must not inherit a sibling secret. Unknown shape/index remains
unknown. Primitive conversion and length operations retain provenance; they are
not declassification. Function and API rebinding must invalidate obsolete
callable identities. Decorators, closures, variadic dispatch, unresolved imports,
recursion and mutable-object uncertainty remain visible boundaries. Unknown calls
retain possible provenance separately from a resolved source-to-sink witness.

Resource limits are explicit: at most 200 Python sources, 128 KiB per source,
2 MiB aggregate source, 20,000 AST nodes per file, 200,000 analysis work units,
8 nested local calls, 256 evaluated contexts, 16 origins per abstract value,
32 witness steps and 80 flow findings. Hitting a limit yields partial analysis,
not a clean pass. Evidence and host operations remain separate from runtime
behavior, authorization and malicious intent.

`coverage.modeled_sink_sites` permits precise legacy reconciliation only for
fully modeled corresponding sites. `coverage.pruned_ranges` applies only to
syntactic constant guards, never to a runtime-dependent condition or one public
call context when another may expose a credential. A caller should preserve old
evidence whenever new analysis reaches an opaque boundary or lacks the necessary
scope. The complete scan—not only this new module—must pass paired controls.

## Stronger possibility surfaced by independent challenge

Elena challenged the Python-only ceiling: skill behavior also crosses from
instructions into command arguments. A literal skill command can supply a private
file path to a generic `argparse` uploader; no helper-only analysis recognizes the
sensitive source if it never binds those command arguments. This is a valuable
next experiment, not a runtime result already delivered by this engine.

Preserve an extension point for entry bindings with instruction file/line,
resolved script identity and literal argv. A separate bounded grammar could bind
recognized `argparse.add_argument` destinations, selected CLI literals and actual
file/network operations into the same witness plane. Unknown shell expansions,
plugin environment variables, remote code and ambiguous launcher options must
remain unresolved. This joins skill instruction evidence to code behavior without
claiming to understand all natural language or paying an LLM to invent a flow.

After that, apply the same typed effect contract to additional languages and
artifact-generated configurations. Maintain the skill-first product scope;
plugins and whole projects remain explicitly future scope. Package provenance,
resource authority and data destination can then be compared across versions,
without treating every changed keyword as a new vulnerability.

## Verification and release conditions

Use paired tests for helper returns, cross-file argument flow, constant-return
controls, literal dead branches, per-call isolation, selected public fields,
local/third-party name collisions, rebinding, archive boundaries and unsupported
constructs. Independent Elena cases must exercise the integrated report as well
as the engine. Maintain exact source lines and common redaction on both dict keys
and nested witness surfaces. Do not claim fewer false alarms until whole-report
reconciliation has actually passed. No result establishes general accuracy,
malicious intent, installed dependency behavior, authorization or safe runtime
execution. Independent review and ordinary production verification remain release
requirements; a persona title or promising architecture is not acceptance.
