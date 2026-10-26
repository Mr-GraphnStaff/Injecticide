# Vendor requirements before a package scan

Implementation: 0.6.0. Deployment evidence is recorded separately under
`docs/validation/`.

Research MCP owns official-document collection and freshness. The web scanner
calls its bounded `POST /requirements/check` route for every package scan with a
supported product target. Only a runtime identifier crosses that boundary. No
package bytes, names, findings, model credentials or customer content go to the
research service or vendor. The isolated static sandbox remains offline.

| Runtime | Reviewed surface | Current review coverage |
| --- | --- | --- |
| `openai` | OpenAI plugin skills | Supporting resource layout; unspecified sizes and file/artifact types are unknown |
| `openai-mcp-import` | OpenAI plugin submission via MCP skill import | Skill file/supporting file/resource sizes, file/skill counts, import page and generated-archive limits |
| `claude-code` | Claude Code skills | Compatibility field length and advisory listing truncation; upload limits remain unknown |
| `claude-upload` | Claude custom skill upload guide | Name and description character limits; no assumption these apply to Claude Code/API |
| `gemini` | Gemini CLI skills | Resource layout; no invented numeric caps or file/artifact allowlists |
| `copilot` | Copilot CLI plugin documentation | Product documentation freshness; unreviewed constraints remain unknown |

These are four platform families. Other existing research sources and static
scanner adapters are preserved; this feature does not add requirement profiles
for smaller vendors. Model API context windows, paid upload probes, tenant
policies and actual plugin execution are outside this documentation check.

## Evidence and drift

`research_check_requirements(runtime, refresh=True)` performs a bounded live
refresh of an existing dedicated approved source. `refresh=False` returns cached
evidence explicitly with `live_check: false`; its maximum age is one hour.
Unknown/ambiguous targets require a supported product selection. Automatic
format detection uses a target only when exactly one runtime is indicated.
The MCP tool never changes rules or takes a caller-provided URL.

`research_mcp/requirements.json` holds reviewed requirements and document
fingerprints. `research_mcp/sources.json` holds their fixed collection URLs.
Markdown documents use full response-byte SHA-256. HTML documents use the
existing collector's visible-text projection, excluding scripts/styles and
collapsing whitespace. This avoids treating changing page framework data as a
requirement change. The complete reviewed projections are below the catalog's
100,000-character text retention limit. Reports also retain raw response hashes,
snapshot IDs, source/final URLs, successful retrieval times and review dates.

A document text/hash change, failed/disabled collection, stale evidence, missing
source, concurrent check or failed requested refresh returns
`STATUS: UNKNOWN — UNVERIFIED`. The prior snapshot remains evidence; it cannot
substitute for a successful live check. Concurrent synchronous requirement
checks return unknown/busy rather than queueing unbounded fetches. The web
client has an eight-second response timeout and bounded response size; a vendor
delay can therefore produce an unknown result while bounded collection finishes.
The collector still enforces public DNS, HTTPS scope, robots, byte/time limits
and conditional requests. A valid 304 revalidates retained evidence.

When documentation changes, review the changed primary source and any linked
applicable sections; update the relevant documented values, review date and
fingerprint together; add regression coverage. Source refresh alone never
rewrites reviewed values. No automatic semantic extraction or LLM-generated
rule activation is used.

## Measured checks and unknowns

The scanner compares documented metadata limits against field lengths, without
exporting raw frontmatter. With `openai-mcp-import`, it also measures per-skill
inventory sizes and counts. The OpenAI limits apply to submission-time MCP
imports, not all plugin uploads. Catalog page count and generated archive size
cannot be measured from a static upload and are explicitly unknown. Measured
directory inventories do not prove that a future MCP resource manifest matches.

Vendor evidence appears in the result panel and Markdown export. Passing an
individual documented check is not an overall compatibility pass. Unknown
limits mean neither unlimited nor allowed. Resource folders are not file-type
allowlists. Output artifact types, tenant policies, runtime acceptance and
security remain separate. Static scanning can finish while the report clearly
states that vendor compatibility is unverified.

Direct sandbox/CLI scans remain deterministic/offline and report vendor status
as unverified. They do not imply a live check occurred.

## Official sources reviewed October 26, 2026

- [OpenAI plugin skills](https://developers.openai.com/plugins/build/skills)
- [OpenAI MCP skill import](https://developers.openai.com/plugins/build/mcp-server#import-skills-from-the-mcp-server)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Claude custom skill uploads](https://support.claude.com/en/articles/12512198-how-to-create-custom-skills)
- [Gemini CLI skill authoring](https://geminicli.com/docs/cli/creating-skills/)
- [GitHub Copilot plugins](https://docs.github.com/en/copilot/concepts/customizations/plugins)
