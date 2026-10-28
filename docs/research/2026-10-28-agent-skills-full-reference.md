# Agent Skills site ingestion and implementation review

Date: October 28, 2026. Candidate: 0.12.0, unreleased.

## Coverage and retained evidence

The complete [documentation index](https://agentskills.io/llms.txt) and
[sitemap](https://agentskills.io/sitemap.xml) agree on nine published documentation
pages. All nine were retrieved and read in full. Both HTML and Markdown
representations were captured. Their 23 distinct direct HTTPS reference
destinations were attempted; the HTML pass also retained 302 navigation/reference
edges and found no additional external destinations. Source/target edges are retained.
Fragments are preserved in edges and removed only from fetch identity.

The shipped evidence library is
`research_mcp/reference_docs/agent-skills/manifest.json`. It records 62 source
entries: 57 successful captures and five original fetch failures, with explicit
fallback review outcomes. Raw responses and a locally populated research SQLite
catalog are retained in `tmp/agent-skills-site-ingested-20261028/`; the shipped
library retains extracted text, raw-response fingerprints and separate text
integrity hashes. Retrieval timestamps are actual capture times.

Redistribution retains the full Agent Skills documentation and licensed pinned
examples with attribution and license notices. Other linked pages are represented
by attributed excerpts of at most 200 words, their URLs, hashes and retrieval
outcomes. Complete raw captures remain in local research evidence; they are not
silently republished as project-owned documentation.

The five original failures remain visible even where an alternative was read:

| Linked destination | Outcome and interpretation |
| --- | --- |
| VS Code home | Opened through the web tool; redirects to a query-bearing product homepage. No portable format requirement inferred. |
| Agent Skills Discord invite | Opened through the web tool and captured its approved Discord destination. JavaScript community invitation; no community messages retrieved or membership action taken. |
| Copilot marketplace listing | Opened through the web tool; product/installation listing. The production research fetcher's restriction on arbitrary queries was preserved. |
| Claude SDK TypeScript reference | Original redirects across hosts. Captured the official destination's complete Markdown representation as a separate, attributed supplement. |
| XDG specification | Original redirects to HTTP. Captured the destination over HTTPS as a separate supplement. |

This captures the full published documentation site and its direct references;
it does not claim to mirror every site, repository, marketing page or community
reachable recursively from those references. Technical linked sources were
considered for their relevant skill/script/validation/evaluation sections;
capturing a whole reference is not a claim to have semantically verified every
unrelated section. Source text is research data, never an instruction to the
collector or automatic detector-rule activation.

## Every site page and its implementation consequence

| Official page | Considered material | Incorporation |
| --- | --- | --- |
| [Overview](https://agentskills.io/home) | Portable skill directories and three loading stages | Skill/package inventory and loading-stage footprint; actual loading remains runtime-unverified. |
| [Specification](https://agentskills.io/specification) | Complete directory, YAML, name, description, license, compatibility, metadata, allowed-tools, body, resources, disclosure, references and validation sections | Measured format constraints; portable field allowlist derived from the linked reference implementation; explicit guidance/unassessed rows for remaining sections. |
| [Client showcase](https://agentskills.io/clients) | Supporting products, not a conformance contract | Preserved as context. Its Markdown representation contains only headings; no client-support acceptance claim is derived from that incomplete representation. |
| [Quickstart](https://agentskills.io/skill-creation/quickstart) | Minimal working skill, explicit invocation and model-dependent tool execution | Minimal instruction-only skill remains valid. No scripts, changelog or version is invented as mandatory. Execution reliability remains unassessed. |
| [Best practices](https://agentskills.io/skill-creation/best-practices) | Real expertise, real execution feedback, scope, context budget, procedures, defaults, templates, checklists and validation loops | Authoring guidance and manual improvement actions; heading or keyword presence does not establish quality. |
| [Optimizing descriptions](https://agentskills.io/skill-creation/optimizing-descriptions) | Labeled positive and near-miss queries, repeated real activations, fixed train/validation split, iteration and fresh verification | `trigger_evaluation_methodology` with an actionable manual plan; no trigger score without observed runs. Suggested counts/thresholds remain guidance. |
| [Evaluating skills](https://agentskills.io/skill-creation/evaluating-skills) | Real cases, fresh contexts, with/without or prior-version baseline, artifacts, assertions, evidence, timing/tokens, repeated runs, weak-assertion critique, human review and iteration | `evaluation_methodology`, linked primary-source provenance and detailed manual improvement action. Static scans do not claim these evaluations ran. |
| [Using scripts](https://agentskills.io/skill-creation/using-scripts) | Launchers, prerequisites, pinning, skill-root script paths, inline dependencies, noninteractive input, help/errors, structured output, retries, dry runs, exit codes and output budgets | Existing bounded launcher/reference/PEP 723 inspection plus explicit `reproducible_dependencies`, `script_authoring_guidance` and `script_interface_quality` assessment gaps. Go and Ruby examples are documentation, not a claim that their dependency semantics are fully analyzed. |
| [Client implementation](https://agentskills.io/client-implementation/adding-skills-support) | Discovery scopes/bounds, trust, collisions, parsing, leniency, disclosure/filtering, activation, resource listing, permissions, context preservation and deduplication | `client_lifecycle` records runtime-only behavior as unassessed. Package conformance does not imply client acceptance or enforcement. |

The machine-readable assessment matrix remains
`skill_sandbox/rules/skill_standards.json`. Newly considered sections do not gain
invented passes: unimplemented checks are marked `not_implemented` and their
assessment is `not_assessed`. This is explicit coverage accounting, not completed
runtime evaluation or comprehensive semantic analysis.

## Linked reference material

The full source/target graph and outcomes are in the manifest. The outbound
technical references include skills-ref, Anthropic's skills and skill-creator
repositories, PEP 508, PEP 723, uv and uvx, pipx, npm/npx, Bun/bunx, Deno run, Go
run, XDG and Claude SDK timing data. Product/community links include VS Code,
Copilot, Anthropic, Deno, Bun, RubyGems and Discord. They are retained and
classified, not promoted into portable requirements.

Directory landing pages alone were insufficient for the evaluation references.
Additional captures include the skill-creator instructions, evaluation schemas,
grader, blind comparator, analyzer, trigger/description optimization scripts,
benchmark aggregation and review-viewer sources. These are captured as text;
none was imported, run, installed or treated as instructions for this agent.
Associated upstream license notices are retained in the library.

Reviewed immutable source revisions:

- Agent Skills reference library:
  `69ef37e9424c0a7ea9dd2293b559e43ec8176379`.
- Anthropic skill-creator examples:
  `ca45fc496a3436251f191354091d557da31c15b5`.

The reference library's README calls it a demonstration and says it is not meant
for production use. Injecticide does not install/import it. The explicit field
allowlist was reviewed and implemented locally with deterministic tests.

## Source differences that must remain visible

1. The specification lists the portable fields and shows `metadata.version`; its
   linked validator explicitly rejects extra top-level fields. Strict portable
   validation now checks that allowlist. Vendor-specific extension acceptance
   remains a separate question.
2. The textual specification requires compatibility length 1–500 when present;
   the reference code only checks its maximum length. Injecticide retains the
   documented minimum and tests the empty-value failure.
3. The specification requires string metadata values. The reference validator
   does not fully enforce this. Injecticide retains its string-map validation.
4. The reference validator normalizes/trims names; the textual constraints do
   not specify that transformation. Injecticide does not silently rewrite an
   uploaded identity to make it pass.
5. The website evaluation examples use `assertions` and `assertion_results`;
   the pinned linked creator schema uses `expectations`. They are separate
   representations, not an interchangeable schema. No fabricated evaluation
   result or silently guessed schema conversion is introduced.
6. The client guide recommends lenient loading for certain malformed/cosmetic
   cases. That is client behavior, not evidence that strict format checks passed.
7. The format does not mandate a version, SemVer, changelog, release date or Git
   tag. Injecticide's version-placement policy rejects top-level `version` or
   non-string `metadata.version` across runtime profiles. Version-like text in
   unrestricted Markdown is not mistaken for a frontmatter declaration.

## Runtime behavior and useful follow-up

Reports now attach the relevant evaluation/client/script documentation to each
unassessed area, and the improvement plan gives concrete next steps. A real skill
quality evaluation must use the intended runtime/model, synthetic authorized
inputs, isolated fresh contexts, a baseline, saved actual outputs, evidence-backed
grading, repeated runs and human review. Performance data must distinguish
observed timing/tokens from packaged-text estimates. These evaluation runs have
not been implemented or executed by this change.

Research MCP exposes `research_search_reference_library` and
`research_get_reference_document`; both are read-only, offline and source-bound.
The normal research registry now includes every site page as an exact seed.
Collector cycles remain bounded and do not promise all pages refresh each hour.
The source comparison tool now handles the expanded catalog without silently
omitting its final entries. New source bytes still require review before any
rule changes.

## Validation and release state

The initial focused conformance run passed 73 tests. The subsequent research,
reference-library, official-validator and improvement-plan run passed 71 tests,
with one existing optional-dependency skip. The broad run finished with 917
passes, six skips and two failures: the stale scanner version constant and a
Claude-specific extension being emitted as a portable format warning in the
selected Claude profile. Both were corrected. A fresh run covering the changed
format/version, package analysis, redaction, reference library, research MCP and
scanner MCP areas passed **222 tests with three skips**. This is a targeted
post-fix run, not a claim that the entire broad suite was rerun after correction.

Optional MCP dependency skips mean fresh transport-level discovery/acceptance
was not established in this local environment. Captured-source integrity,
pagination and scanner integration were checked by the Python tests.

These are local authored changes and synthetic regressions. No production
deployment, human PR acceptance, installed-client acceptance or live skill
execution is claimed. Unrelated pre-existing workspace changes remain outside
this work.

Final clean-checkout pre-publication run: **925 passed, six optional MCP SDK skips**. Reviewed-source and schema bytes are preserved through Git checkout. SDK-inclusive transport and container checks are required in Azure before publication.
