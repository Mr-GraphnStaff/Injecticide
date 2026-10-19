# Injecticide: skill, plugin, and governance research

As of October 19, 2026. Repository baseline: `9039d25281a44cc6f717528ad7b87e3f66192e7f`.

Research record: this document captures the proposal reviewed before implementation. The accepted scope is now implemented together as a local 0.2.0 candidate; see [implementation status and validation](IMPLEMENTATION.md) for current delivery details and configuration prerequisites. Production has not been updated by this candidate.

## Decision

Add artifact identification and runtime profiles. Identify package format, discover components, record declared compatibility, and apply common security checks plus the relevant runtime rules. Keep publisher identity unverified until independently validated.

The useful distinction is **format + target runtime + distribution surface + observed capabilities**. An interoperable skill can run under multiple vendors. A plugin can contain skills and executable components. A model provider is not the host enforcing permissions.

The [Agent Skills specification](https://agentskills.io/specification) defines `SKILL.md`, required name/description, optional compatibility/metadata, and experimental allowed-tools. Owner and version can be useful enterprise policy fields without being universally required. The separate [Agent Plugins 1.0 specification](https://agent-plugins.org/specification) defines root `plugin.json`, standard skills/MCP locations, and client extensions. Recognizable filenames and author declarations do not establish authenticity.

## Current Injecticide evidence

Inspected the sandbox, text extraction, scan units, finding enrichment, governance, local catalogs, and fallback scanner at the baseline above.

- The sandbox accepts individual files and ZIP/TAR packages, with archive path and size controls. Container classification is broadly skill/zip/tar, not vendor package semantics.
- No dedicated plugin schema adapter, runtime frontmatter validator, dependency graph, or signature verifier exists in the inspected scanner path.
- Governance recommendations derive from behavior/capabilities. They do not verify tenant configuration, independent approval, or runtime enforcement.
- `violations.json` contains 24 catalog rules and declares version/review date `2026-03-24`. `dispositions.json` declares `2026-06-26`. Review metadata is stale; this does not prove every detector is ineffective or unchanged, because matching behavior also resides in Python modules.
- Text, some SQLite content, and some Office XML are inspected. Unsupported binaries are skipped. Some extraction exclusions appear only in warnings, not per-file results.
- The web fallback and sandbox use separate scanner implementations. New functionality needs shared logic or parity tests.
- The architecture README describes the research MCP, signing and updater as proposed, not deployed services.

Code pointers: [sandbox](../../../skill_sandbox/app.py), [extraction](../../../skill_sandbox/artifact_text.py), [scan units](../../../skill_sandbox/scan_rules.py), [enrichment](../../../skill_sandbox/finding_enrichment.py), [governance](../../../skill_sandbox/governance.py), [fallback](../../../webapp/skill_scanner.py).

## Vendor and format matrix

This is a bounded review of major relevant ecosystems, not every vendor or a complete historical release diff. Relevant source sections were opened on the review date. All-vendor runtime conformance was not tested.

| Ecosystem | Identification evidence | Scanner consequence |
| --- | --- | --- |
| Portable Agent Skill | Directory with `SKILL.md` | Identify generic format compatibility; vendor/author usually unknown. Validate frontmatter and inventory scripts, references and assets. [Specification](https://agentskills.io/specification) |
| Agent Plugins 1.0 | Root `plugin.json` with recognized canonical schema | Identify a component container. Pin local schema versions; enforce containment; report unsupported versions. Never fetch a schema selected by an upload. [Specification](https://agent-plugins.org/specification) |
| Claude Code | Base skill plus runtime extensions; optional `.claude-plugin/plugin.json` | Manifest absence does not rule out a Claude plugin. Inspect default locations and declared paths, hooks, MCP, LSP and other supported components. [Manifest](https://code.claude.com/docs/en/plugins-reference) |
| Claude web/Cowork/API upload | Narrower skill frontmatter than Claude Code | Code-compatible and upload-compatible are distinct results. Code's `allowed-tools` grants temporary pre-approval, not a whitelist; managed policy can change its effect. [Skills](https://code.claude.com/docs/en/skills) |
| OpenAI ChatGPT/Codex | Skill with optional `agents/openai.yaml`; portable or `.codex-plugin/plugin.json` layout | Parse invocation policy and dependencies. Respect documented compatibility-overlay precedence and surface support. [Skills](https://learn.chatgpt.com/docs/build-skills), [packaging](https://developers.openai.com/plugins/build/plugins) |
| Copilot/VS Code | Portable Agent Plugins or legacy Copilot layout | Portable core and `com.github.copilot` components differ from legacy discovery. Inventory agents, hooks, MCP and LSP alongside skills. [Formats](https://docs.github.com/en/enterprise-cloud@latest/copilot/concepts/agents/about-plugins) |
| Gemini CLI | Agent Skill or `gemini-extension.json` | Inspect MCP, hooks and policy TOML. Docs say extension allow/yolo policy decisions are ignored; do not mistake declared policy for effective approval. [Extensions](https://geminicli.com/docs/extensions/reference/), [skill management](https://geminicli.com/docs/cli/using-agent-skills/) |
| Cursor | Portable root manifest or `.cursor-plugin/plugin.json` | Native format adds rules, agents, commands, hooks and variables. Reference documents a portability limitation: portable MCP `${PLUGIN_ROOT}` and `${PLUGIN_DATA}` are not expanded. [Reference](https://prod.cursor.com/docs/reference/plugins) |
| Windsurf/Devin Cascade | `SKILL.md`, current `.devin/skills` and legacy Windsurf locations | Official Windsurf URL now redirects to Devin. Distinguish skills, rules and workflows; support documented aliases. [Skills](https://docs.devin.ai/desktop/cascade/skills) |
| AWS Kiro | Standalone skill or Power | Current Powers follow Agent Plugins with manifest, skills and optional MCP config. Older POWER.md assumptions must not be the only detector. [Skills](https://kiro.dev/docs/skills/), [Powers](https://kiro.dev/docs/powers/) |
| Amazon Q Developer | `.amazonq/rules` instructions | Project rules are a distinct instruction artifact, not proof of an Agent Skill or plugin. [Project rules](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/context-project-rules.html) |
| OpenClaw | Skill metadata, native `openclaw.plugin.json`, or compatible bundle | Native plugins load runtime modules in process; keep them separate from compatible bundles. Install policy and host secret injection are additional deployment concerns. [Skills](https://docs.openclaw.ai/tools/skills), [plugins](https://docs.openclaw.ai/tools/plugin) |
| MCP desktop bundle | `.mcpb`/ZIP with `manifest.json` | A server bundle can contain Node, Python, dependencies or native executables. Inspect launch surfaces without installing or starting it. [MCPB](https://github.com/modelcontextprotocol/mcpb) |
| NVIDIA verified distribution | Skill plus optional release card and detached signature | Governance profile over a skill, not another instruction format. Verify signatures against configured trust anchors; presence alone proves nothing. [Signing](https://docs.nvidia.com/skills/signing-agent-skills), [cards](https://docs.nvidia.com/skills/skill-cards) |

## Governance needs external evidence

Anthropic's enterprise guide recommends independent review, evaluations including coexistence, registry metadata, version pinning and integrity controls. Built-in scanning has documented exclusions, including API uploads and certain organization configurations. These remain deployment concerns beyond static inspection. [Enterprise guide](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise)

Claude organization provisioning differs from plugin group distribution. Multiple group memberships resolve plugin access to the most permissive setting. An upload cannot reveal effective group or organization policy. [Provisioning](https://support.claude.com/en/articles/13119606-provision-and-manage-skills-for-your-organization), [group precedence](https://support.claude.com/en/articles/13837433-manage-plugins-for-your-organization)

Other vendors also separate deployment controls from contents:

- OpenAI documents managed marketplaces and separate connected-app permissions. A packaged MCP declaration proves neither account authorization nor support on every surface. [Management](https://learn.chatgpt.com/docs/enterprise/plugin-management), [controls](https://learn.chatgpt.com/docs/enterprise/apps-and-connectors)
- VS Code documents managed hooks, plugin/marketplace controls and strict plugin-only customization. [Enterprise settings](https://code.visualstudio.com/docs/enterprise/manage-ai-settings)
- Gemini distinguishes administrator controls from local preferences. [Controls](https://geminicli.com/docs/admin/enterprise-controls/)
- Cursor distinguishes behavioral rules from deterministic controls and recommends plugin review and MCP restrictions. [Hardening](https://prod.cursor.com/docs/enterprise/security-hardening)

Proposed evidence states: `observed`, `declared_unverified`, `verified_against_external_evidence`, `not_assessed`, `not_applicable`, `failed`. A package saying `reviewed: true` stays unverified. Missing optional metadata is not a format violation or evidence of malware; selected enterprise policy may separately require it.

## Proposed identification and report contract

Use **Scan AI package**, **Auto-detect**, and optional **Target runtime/surface**. Users should not need to guess a vendor before scanning.

Return independent fields for:

1. Container type and artifact kind: skill, plugin, extension, marketplace, MCP bundle/config, instruction/agent file, mixed package or unknown.
2. Format profiles and versions, backed by parsed fields and file paths.
3. Runtime targets: user-selected, declared, or structurally indicated. Avoid invented percentage confidence scores.
4. Publisher claims, fingerprints and cryptographic verification as separate provenance evidence.
5. Components: nested skills, instructions, code, hooks, servers, policies, dependencies, binary assets and unresolved references.
6. Format findings, security findings, coverage and governance evidence separately.
7. Scanner/ruleset/adapter versions and source-review dates.

Inspect contents instead of trusting suffixes. Handle enclosing directories, multiple roots and marketplace collections. Inventory all packaged content, while explaining which components a chosen runtime actually loads. Preserve conflicting manifest evidence. Unknown format still receives applicable generic checks and `STATUS: UNKNOWN — UNVERIFIED` attribution. Runtime override must not suppress common checks or discovered components.

## Coverage: strategy-deck's skipped assets

The user's excerpt lists four text entries and six unsupported binaries: four OTF fonts and two PNG logos. Those are excerpt counts, not the complete archive. `Binary or non-text content` is expected for these assets in the current extractor. It is not a safety certification.

Proposed per-file states:

| State | Meaning |
| --- | --- |
| `text_analyzed` | Supported text inspected by named detectors. |
| `structured_content_analyzed` | Content extracted; record parser and actual scope. |
| `binary_asset_inventory_only` | Type/size/hash recorded; binary threats unassessed. |
| `executable_not_analyzed` | Executable component lacks applicable analysis. |
| `limited_or_truncated` | Analysis stopped at a stated measurable limit. |
| `rejected_unsafe_entry` | Archive/path/link constraint prevented inspection. |
| `parse_error` | Supported parser failed; not a clean result. |
| `unsupported` | Identify the unsupported content or format. |

Count every inventory entry, including extraction exclusions. Report file and byte coverage plus mandatory-component completeness: many harmless assets must not obscure one unexamined hook. Use partial coverage whenever material remains unassessed.

Suggested wording: **No findings in analyzed content. Binary assets were inventoried but not analyzed.** For this excerpt: **4 text entries analyzed; 6 binary assets not analyzed.** Neither label ordinary fonts/logos malicious nor imply that they received antivirus, font-parser, OCR or image-content analysis.

Nested formats need separate compressed-byte, cumulative-decompression, parser-work and extracted-text budgets. Current Office extraction reads an XML part before truncating extracted text. A text-length limit is not a pre-allocation budget; this is a code-review concern, not a reproduced exploit.

## Code stored as Markdown

User-reported file: `strategy-deck/references/regression-fixture/check-seeded11.py.md`, 3,548 bytes, one review finding. Actual contents and finding evidence are unavailable. **Purpose, execution path and intent: STATUS: UNKNOWN — UNVERIFIED.** The filename alone cannot distinguish a legitimate fixture from deliberate concealment.

A harmless local synthetic test confirmed Python executes valid code from a `.py.md` file when explicitly invoked. Python documents filename-based execution. The user's file was not accessed or run. [Python interface](https://docs.python.org/3/using/cmdline.html#interface-options)

Current helpers classify this path as `reference` and use Markdown scan units because of its outer suffix. It is still text-scanned, not skipped. Location and suffix do not adequately describe an execution target.

Proposed checks:

- Preserve full suffix chain, content syntax and shebang separately.
- Statically inspect code-like text and fenced code without execution. Successful parsing indicates possible code, not malware; simple prose can also parse.
- Trace explicit commands/references that run, copy, rename, decode or import bundled files. Interpreter invocation of Markdown is execution evidence.
- Do not downgrade actionable execution evidence solely because a file lives under references, fixtures or examples. Conversely, do not label teaching examples executed without an invocation signal.
- Distinguish declared execution from heuristic recognition and unresolved dynamic paths.

Resolving this file needs its contents, finding ID/description/samples and parent references. Investigation is pending the user; no verdict has been assigned.

## External scanners, signing and research limits

NVIDIA documents detached OMS signatures, a trust pipeline and release cards. Use administrator-selected trust roots, not certificates trusted solely because they arrived in an upload. A hash identifies bytes, not authorship/approval; a valid signature does not establish harmlessness. [Signing](https://docs.nvidia.com/skills/signing-agent-skills), [pipeline](https://docs.nvidia.com/skills/agent-skill-trust-pipeline), [cards](https://docs.nvidia.com/skills/skill-cards)

External scanners are benchmark candidates, not automatic dependencies:

- Snyk Agent Scan documents local checks plus API analysis, including transmission of skill content after redaction. Private uploads need a deliberate data-handling decision before use. [Repository](https://github.com/snyk/agent-scan)
- SkillSpector supports static and optional provider-backed LLM analysis. Eligible content goes to the configured provider in LLM mode; dependency checks may contact OSV even with no-LLM mode. Inspection of signature containers is explicitly not cryptographic signature verification. Benchmark a pinned static configuration in isolation. [Repository](https://github.com/NVIDIA/SkillSpector)

Verified preprint abstracts: [Under the Hood of SKILL.md](https://arxiv.org/abs/2605.11418) studies semantic registry-stage attacks; [CompoSkill](https://arxiv.org/abs/2608.16246) reports risky compositions of individually scanner-passing skills. This review confirms papers and stated scope, not independent reproduction or population-wide success rates. They support future admission/trigger evaluation and composition review. No new payloads or proven-detection claims are introduced.

## Keeping checks current

Preserve the isolated scanner and the existing proposed research/enforcement boundary. This is a proposed process, not installed automation or an implemented signed updater:

1. Maintain allowlisted standards, official vendor documentation/releases and reproducible research. `sources.json` is the initial evidence register.
2. On a proposed weekly cadence, collect changes outside enforcement. Treat documents as untrusted data. Capture retrieval time, final URL, published version and immutable source revision/hash where available. Fetch failure reduces freshness; keep last-good evidence.
3. Distinguish format changes, runtime behavior, enterprise policy and attack research. A changed page is not automatically a detector.
4. Create attributed candidates with explicit verification status. Unknown claims stay `STATUS: UNKNOWN — UNVERIFIED`; use `No verified research found.` when appropriate.
5. Validate safe parsing, bounded resources, benign/malicious synthetic fixtures, false-positive controls, adapter parity and regression comparisons. Static scans must not execute uploaded code or contact its endpoints.
6. Require independent human review before promotion. A future distribution service should verify signed/versioned bundles, compatibility, integrity, expiry and rollback before atomic activation. Until implemented, use the existing reviewed application/container release process.
7. Include applied versions and review dates in results. Expose current/stale/unknown freshness without pretending dates establish efficacy. Deployment policy determines responses to stale intelligence.
8. Handle advisories out of cycle; periodically rerun representative benign and cross-runtime fixtures without third-party transmission of private content.

Keep normative format requirements, vendor implementation behavior, enterprise policy and research observations separate. Upload-controlled URLs must not cause arbitrary schema/dependency downloads.

## Delivery sequence and acceptance evidence

1. **Coverage and interpretation:** complete inventory, explicit gaps, partial-result wording, code-as-Markdown signals and budgets. Verify fonts/logos remain unassessed rather than falsely safe or malicious.
2. **Adapters:** shared Agent Skills and Agent Plugins first, then runtime/distribution profiles. Test mixed/legacy packages, multiple roots, optional metadata, invalid manifests, escaping paths and unknown versions.
3. **Component analysis:** resolve hooks, launch targets, MCP/LSP, policies and dependencies. Include direct `.py.md` invocation fixtures and benign documented-code controls.
4. **Governance evidence:** fingerprints/optional metadata policy first; configured signature verification and authorized external evidence next. Test absent, declared-only, expired, invalid, wrong-artifact and untrusted signatures separately.
5. **Maintenance/evaluation:** source tracking and controlled releases; isolated trigger/coexistence evaluations later. Optional semantic analysis must never erase deterministic evidence.

`proposed-checks.json` maps 24 planning identifiers to sources and evaluation methods. These are proposed work items, not vulnerability names or active signatures. Major expansion must follow repository version/changelog/human PR acceptance requirements. Do not present an ecosystem as supported before its adapter and corpus exist.

## Remaining boundaries

The 33-source register intentionally has no invented immutable snapshot hashes or claim of exhaustive historical comparison. No vendor tenant was queried, plugin installed, or external scanner run against private content. The strategy-deck archive was not supplied; its specific `.py.md` file remains pending. Compatibility gaps do not establish exploitable vulnerabilities. Static analysis cannot certify every future behavior or external dependency.

The implementation companion supersedes the proposal's delivery-status language. The research sources and uncertainty boundaries above remain applicable. This candidate has not changed production verdicts.
