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
