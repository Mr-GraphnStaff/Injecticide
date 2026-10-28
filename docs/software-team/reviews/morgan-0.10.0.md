# Morgan independent review — standards presentation, integration and launcher graph 0.10.0

Reviewer: Morgan Hale, Security Architect, reporting to Avery Chen. Date:
October 28, 2026. Runtime: Windows against the shared Injecticide checkout; local
Edge browser. Mentor influences: Ritchie/Thompson and Knuth; working habit: trace
source identity, declared behavior, uncertainty and policy recommendations through
the final report, rather than accepting an author's summary.

## Independence and verdict

**Review complete with stated limitations; no unresolved finding in this reviewed
scope.** Ready for the authorized release checks, subject to final combined suite,
container builds and target verification. This does not claim deployment success.

This same real agent authored `package_formats.py`, `standards_assessment.py`,
`rules/skill_standards.json` and `tests/test_skill_standards.py` as Ishan. Their
semantic conformance correctness is explicitly **excluded** from this independent
verdict; Elena and Mara review that slice. Corrections to those authored files
made during the assignment are author work, not independent review closure.

Reviewed here: Elena's launcher/PEP parser and graph/threat-reference changes,
Mara's standards UI/export presentation, and Avery's readiness integration,
redaction, source checker, fingerprints and packaging. No reviewed implementation
was changed by this reviewer. Independent integration regressions were added in
`tests/test_standards_integration_review.py` with Avery's authorization.

## Confirmed finding and independent closure

P2 — The first integration attached a mandatory portable failure/unknown after
readiness/governance had already been computed. Independent actual scanner probes:

- A complete generic ZIP containing only `demo/README.md` produced standards
  `fail`, yet `readiness=no_static_findings`, format `explicit_portable_profile_checked`
  and brokered `allow`.
- A loose valid `SKILL.md` produced mandatory parent-directory `not_assessed`, yet
  the same misleading readiness/allow result.

Avery moved assessment before the guard and wired only the explicit generic
mandatory format result into decisions. Original probes now return respectively
`needs_review/portable_format_failed/require_further_analysis` and
`incomplete/unverified/require_further_analysis`. Added and executed three
independent integration tests: **3 passed**. The positive paired complete skill
retains measured portable pass and ordinary readiness while vendor/runtime
unknowns remain separate, avoiding an invented blanket incompatibility gate.

## Executed independent verification

- `python -m pytest tests/test_script_launchers.py tests/test_package_graph.py tests/test_process_diagram.py tests/test_process_integration.py tests/test_standards_source_check.py tests/test_skill_sandbox_dockerfile.py tests/test_deployment_assets.py -q`:
  **97 passed**. Covers documented launcher subsets, arguments vs true script
  operands, package declarations, unknown/malformed/dynamic options, virtual
  archive boundaries, unavailable parsers, PEP requirement syntax, secret
  reflection, source line vs manifest file-only citations, diagrams and packaging.
  Elena subsequently declared the graph/parser/threat slice frozen; the only
  later parser edit reported was a source-comment URL correction.
- `node tests/browser/skill_standards.cjs`: **PASS**. Independent execution of the
  actual report React source with synthetic API fixtures verified five separate
  categories, scoped mandatory counts, explicit unknowns, recommendation/vendor
  failure separation, source links/citations, omitted-row warnings, hostile text
  and unsafe-link rejection, keyboard activation of controls/disclosures,
  pagination, 390px reflow, full requirements retained in summary and detailed
  Markdown JSON, and a truthful fallback for legacy reports without assessment.
  No browser page errors were reported.
- Actual shared scanner probe with a fenced `uv run scripts/run.py` command:
  relationship graph and package execution-reference inventory both resolve the
  packaged target and cite physical line 6; execution remains unverified.
- Parsed sandbox Dockerfile COPY inputs and Python local imports independently:
  **26 copied Python modules, zero missing local-module dependencies**. New
  modules and the entire rules directory are included in the flat runtime.
- `git diff --check` passed on the reviewed graph/integration/frontend/tool files.

## Inspected boundaries

The launcher parser performs bounded `shlex` parsing and emits a documented
subset, explicit unknowns and declared package dependencies. It does not expand
shell variables, invoke interpreters/package managers, contact declared URLs or
infer dependency availability. Program argv paths after the recognized script
are not promoted to additional execution targets. Skill-root resolution remains
inside the current virtual archive boundary. Remote-script observations expose
origins, not credential-bearing full destinations.

PEP 723 handling tokenizes Python comments to distinguish actual top-level
metadata from docstrings/literal mentions. TOML and PEP 508/Python specifiers are
parsed only when their existing libraries are available; unavailable, malformed,
dynamic or budget-limited analysis remains unknown/partial. Syntax declarations
do not establish installation, runtime compatibility or execution. The PEP's
ending-line precedence was checked against its primary normative text before
considering candidate parser findings; no unsupported defect was reported.

Avery extended the existing evidence redactor for script candidates, launcher
package declarations, inline dependencies and Python requirements. Assessment and
launcher evidence are attached before the common redactor and diagrams are built
after it; tests exercise new credential-bearing reflection paths. This is bounded
report hygiene, not complete secret discovery.

The source checker is a separate explicit CLI and has no call site in static scan
or API paths. Uploads cannot select source URLs. It uses a fixed local catalog,
HTTPS host allowlist, no userinfo/query/fragment, no redirects, bounded sources and
streamed response sizes, and no environment proxy inheritance. It hashes bytes
without evaluating them. Changed/unavailable/omitted sources demand review rather
than activate rules or mutate the pinned catalog. Output uses exclusive creation
and cannot silently overwrite an existing requested file. The tests use bounded
fake sessions; this review did not rerun a live source refresh.

The UI's overall badge explicitly applies only to mandatory portable format.
Vendor acceptance, guidance, risk relevance and runtime evaluation stay separate.
OWASP AST labels come from the reviewed primary project taxonomy; this is an
advisory relevance mapping, not an OWASP certificate, coverage score, confirmed
exploitability or verified enforcement. Uploaded labels and file evidence render
as React text. Source links require HTTPS without userinfo and open with
`noopener noreferrer`.

## Limits

No original customer package was supplied for acceptance. These are synthetic
static/local browser and direct scanner checks, not runtime skill evaluation,
trigger-accuracy/output-quality evidence, installed dependency validation or
permission enforcement. No paid call, uploaded code execution, production mutable
call, workflow change, key export or automatic rule update was performed by this
reviewer. Container builds, current deployment and actual public scan response
remain release-owner evidence to collect. Manual assistive-technology use and
exhaustive accessibility/contrast conformance were not assessed. No HR warning or
termination was issued.


## Final delta receipt

After source freeze, independently inspected the final threat-inventory change
that excludes fallback interpreter matches inside recognized wrapper spans.
Unsupported wrapper options cannot be bypassed by a nested `python` substring to
assert an execution target. The targeted new regression passed independently.
The final source-checker adjustment expands the static allowlist to the official
launcher documentation hosts and bounds individual retrieved source bodies to
2 MiB; the maximum catalog traversal remains 20. Final source-checker plus
readiness integration subset: **8 passed**. These host/size additions do not add a
scan/API call site, redirects, catalog mutation or automatic rule activation.
Avery separately observed byte drift in two source snapshots; that is recorded as
review-required rather than silently updating rules. No independent live refresh
result is claimed by this reviewer.
