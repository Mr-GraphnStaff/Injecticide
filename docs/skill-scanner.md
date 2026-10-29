# Skill/package inspection

The web scanner, offline CLI and optional local scanner MCP use the same
deterministic Python engine. Static scans do not call a model, fetch uploaded
URLs, install declared dependencies or execute uploaded code. Existing optional
administrator-configured signature verifiers are separate local processes.

## Run locally

From the repository root with its normal Python dependencies installed:

```powershell
python -m skill_sandbox.scan_cli package.skill --output report.json
python -m skill_sandbox.scan_cli package.zip --target-runtime generic --output report.json
```

Output files are never overwritten. Exit codes are 0 for no static review finding
with complete supported-content coverage, 1 for review findings, 2 for invocation
or input errors, and 3 for incomplete inspection without review findings. None
is a runtime safety certification or organizational approval.

ZIP detection uses content as well as filename. Renaming an archive `.skill`
does not change its contents or inspection capabilities. Nested ZIP/skill files
use `!/` paths, for example `inner.zip!/SKILL.md`. Literal member names containing
that reserved delimiter are rejected to preserve source/hash identity. Nested
expansion shares the whole scan's file/byte budgets and has a depth limit;
unsupported compression and budget exclusions remain visible.

## What the result contains

### Context and blocking evidence (0.15.0)

Detection retains `speech_act`, `imperative_evidence`, `target` and `confidence`
for candidate instructions, including examples, quoted/fenced text and supported
decoded projections. Example classification never disables scanning. Confidence
means recognized-syntax evidence strength, not a calibrated accuracy probability.
`policy_evaluation` separately records per-observation response and reasoning.
The contract covers the seven existing high-blocking prose detectors: prompt
override, system/credential disclosure, autonomous authoritative writes, bulk
enterprise modification, workflow manipulation and cross-system automation.
Code/effect detectors retain their independently measured contracts.

Public upload adapters bind `uploaded_artifact`; archive metadata and HTTP form
claims cannot upgrade that source. Python integrations may supply `source_channel`
as an explicit analysis-context keyword; the CLI offers `--source-channel`.
These are policy scenarios, not authenticated runtime provenance. High-confidence
model-directed requests from retrieved documents, tool output, uploads or unknown
sources block; user-turn requests require review, described risks are logged,
illustrative examples are flagged, and unresolved intent/target receives review.
An activation instruction changes how the referenced example is evaluated. Code
data-flow/effect evidence keeps its separate policy and cannot be downgraded by
an illustrative prose label. Other-language speech acts remain unassessed by the
bounded English recognizers, even when supported text extraction is complete.
Structurally recognized evaluation input keeps its existing review presentation
while its policy response is `flag`; this does not count as a governance block.
Recognition depends on actual field structure, never the file's directory name.

Context records, illustrative ranges and activation references have explicit
budgets. Exhaustion is exposed in instruction-context coverage and unresolved
facts remain reviewable. Contextual matching streams the input and prioritizes
operative evidence before bounded display selection, retaining later live
requests after many examples within the supplied analysis budget.

Disclosure classification separates recognized requests from status descriptions,
risk statements and documented attack scenarios. Unknown intent remains reviewable.
An author, filename, reference directory, heading or fenced example does not grant
trust. Operative requests mixed into documentation retain their own evidence and
disposition. These are bounded deterministic syntax checks, not complete language
understanding or runtime observations.

`declared_tool_execution` records invocation capabilities and retains execution
controls separately from `tool_escape`, which requires explicit boundary-bypass
language. `governance_profile.blocking_findings` binds blocking recommendations to
file, rule, action state and observation line/context. Credential handling alone
does not independently establish a disclosure violation. The risk-summary
recommendation follows the contextual governance decision.

Database extraction reports sampled rows and bounded total-row counts per table.
Unavailable totals stay unknown; exhausting the optional count budget preserves
the earlier sample. Token footprint distinguishes complete extracted projections
from complete source text. Creator summaries separate reading declarations,
explicit EOF claims and content without assessable marker text.

Process extraction includes resolved packaged document links and explicit steps
in their plain-text blocks; these are declarations, never execution traces.
Differences among supplied metadata, filename and an explicit first changelog
release are maintenance observations, not format errors or security blocks.

The 0.12.0 candidate adds a source-backed portable frontmatter allowlist and
enforces version declarations as strings at `metadata.version`. A version is
optional; no SemVer or changelog requirement is invented. Misplaced/non-string
version declarations make the skill invalid and require review in every runtime
profile. The scanner still inspects the artifact to return diagnostic evidence;
this is not an HTTP upload rejection or runtime execution enforcement.

All Agent Skills documentation sections are represented in the standards matrix,
including explicit unimplemented authoring, script, client and runtime evaluation
checks. The full site and linked references are available through the research
MCP reference library. See the [source review and implementation map](research/2026-10-28-agent-skills-full-reference.md).

- Original artifact and per-file hashes; accepted and excluded inventory.
- Text/security findings with source locations and separate informational,
  review and governance classifications.
- PNG structure/CRC and supported text metadata, and standalone sfnt font table
  integrity/name metadata. Structural checks do not inspect pixels, establish
  renderer safety, analyze font programs or certify absence of malware.
- A declared relationship graph, entrypoint reachability, missing/escaping
  references, dependency declarations, external origins and capability chains.
  These are recognized declarations, not observed runtime actions.
  Bare filenames are included; case-only alternatives remain explicit mismatches
  rather than being assumed to work on a case-sensitive runtime. Audit/reference
  file labels do not grant unrelated instructions a trust exemption.
- Bounded Python credential-source-to-network URL/payload observations,
  including recognized source behind document suffixes and Python fences.
  Authentication fields and ordinary report uploads have paired negative tests.
  Control flow, authorization, destination trust and arbitrary interprocedural
  behavior are not established by the recognized local value flow.
- Single-layer base64 UTF-8 projections with original encoded offsets/lines and
  encoded/decoded hashes. Other encodings and deeper layers are outside this
  stage. Decoded content is analyzed as data, never executed.
- Separate file/detector input, structure, extraction and display coverage.
  `coverage.inspection_summary` distinguishes text analysis, asset/container
  structure and files without supported inspection. Asset metadata extraction
  does not imply that all original binary content was analyzed.

The web package overview exposes relationship, action-chain, capability and
asset sections. Detailed Markdown/JSON exports retain these evidence stages.

## Skill process diagrams (0.9.0)

Each static scan includes `process_diagram` and `documented_process`. The
diagram joins explicit numbered steps and workflow headings in `SKILL.md`
with recognized package references, capabilities and external origins.
Select **Add process diagram to playground** on the scan result to create
a new separate map. Existing playground drafts and saved maps are preserved;
the generated map is not merged with them. Return to the report to inspect
the evidence or generate another new map.

Known means source evidence exists, not that a command ran. Unknown references
remain `STATUS: UNKNOWN — UNVERIFIED`. Any future inference must identify its
basis and stay distinct from known evidence. Consecutive numbered steps describe
documented order only; no arbitrary conditional branches, approval enforcement,
runtime tool calls or complete process understanding are claimed. Unrecognized
workflows fall back to a relationship view with explicit uncertainty.

Nodes and connections retain file/line evidence where available. A citation
opens the corresponding file's scan evidence, not an uploaded executable or
external destination. Manifest field locations without exact parser evidence
remain file-only. File findings are separate from step-specific attribution.

Export diagram JSON or Mermaid for reuse. The playground map export uses the
existing strict map schema; source-linked diagram JSON remains the provenance
record. Labels are derived after credential redaction, and rendering uses
escaped text. No model call, uploaded-code execution or external diagram
service is involved. Diagram limits and omissions remain visible.

### Calibration boundaries

Reference/template location does not downgrade actual contact or labeled
account-identifier presence. Role-style local parts are lexical contact
observations; they are not proof of public availability, organizational
approval or low disclosure impact in every context. Neither contact presence
nor an account identifier alone establishes exfiltration or legal status.

Empty API-name mentions in Markdown prose are informational; active call
syntax remains reviewable. Native HTML scripts are capability observations,
separate from measurable code hidden behind a document suffix. An actual
upload-policy bypass requires additional policy and behavior evidence.

## Local MCP

The existing research MCP collects research; it is not the skill scanner. The
optional scanner adapter runs locally over stdio:

```powershell
python -m pip install -r skill_sandbox/mcp_requirements.txt
python -m skill_sandbox.mcp_server
```

Use the second command as the local MCP client's server command. Do not launch
it as a public HTTP service. `skill_scanner_capabilities` describes exact stage
scope and budgets; `skill_scan_package` accepts original base64-encoded bytes,
a basename and target runtime. It never accepts arbitrary local file paths or
URLs. This adapter has its own bounded upload limit; larger artifacts can use
the web/CLI path. Connecting it does not authorize an assistant to execute a
skill or approve its deployment.

## Evaluate and compare

```powershell
python tools/skill_milestone_benchmark.py run --output current.json
python tools/skill_milestone_benchmark.py export provider-inputs
python tools/skill_milestone_benchmark.py compare current.json provider-response.json
```

The prepared provider packages have opaque IDs and no answer labels. Input
hashes, supplied text budgets, scope and missing answers remain explicit.
Importing a claimed provider response does not authenticate that provider or
prove it read the input. No provider is contacted by these commands. Billing
account, spend cap and explicit approval are required before paid comparisons.

The authored benchmark is regression evidence, not independently human-labeled
production data or evidence that Injecticide outperforms a particular model.
See `docs/software-team/skill-milestone-evaluation.md` for the failed initial
baseline, corrected cases, metrics and limits. Runtime evaluation continues to
require an explicitly configured isolated runner and authenticated evidence;
static scans never silently turn uploaded scripts into executable tests.
