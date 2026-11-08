# Violations catalog source review — 2026-11-07

Catalog: `skill_sandbox/rules/violations.json` (catalog_version 2026-03-24, 24 rules).
Reviewer: Tomás Quispe (research). Method: each distinct cited URL was fetched on
2026-11-07 and read for the claim the rule makes. Where a cited page did not
support the rule, the current OWASP GenAI 2025 pages were read as candidate
replacements.

## Outcome

- **`last_reviewed` was not changed.** Every rule's citations were checked, but
  only 3 of 24 rules are fully supported by what they cite today. Moving the date
  forward would tell readers the catalog is current when its citations are not.
- Each rule now carries a `source_review` object (`reviewed_on`, `state`, `note`,
  `record`), and the catalog has a top-level `review_note`. These are metadata
  only. Rule `status`, patterns, severities and dispositions are unchanged, so
  detection behaviour is unchanged.
- No new techniques and no new sources were added to the catalog. Candidate
  replacement citations are listed below for a follow-up change, which will need
  its own review.

States: `supported` (a reachable source states the claim), `partial` (the source
exists and is related but does not state the rule's specific claim),
`not_established` (the source exists but gives no checkable support),
`source_mismatch` (the cited page is about something else), and `source_broken`
(the cited URL no longer resolves).

## Sources checked (fetched 2026-11-07)

| URL as cited | Result |
| --- | --- |
| https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Exists. It is the project landing page. It says the project has grown into the OWASP GenAI Security Project at genai.owasp.org, links to "Version 2025", and does not list LLM01 or other items itself. |
| https://simonwillison.net/series/prompt-injection/ | Exists. Prompt-injection series. A specific prompt-leaking post was not confirmed from the page. |
| https://atlas.mitre.org/ | Responds, but the page is rendered by script and only the title "MITRE ATLAS" came back. ATLAS's existence and scope were confirmed via https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/README.md ("a public knowledge base of adversary TTPs targeting AI systems"). |
| https://genai.owasp.org/llm05/ | Exists. It is **"LLM05: Supply Chain Vulnerabilities"** from the 2023/24 list, not an output-handling or obfuscation page. |
| https://docs.anthropic.com/s/claude-code-security | **Broken.** It redirects (301) to https://platform.claude.com/docs/s/claude-code-security, which returns 404. The current page appears to be https://code.claude.com/docs/en/security, which describes a working-directory permission boundary and prompt-injection safeguards. |
| https://www.anthropic.com/engineering/claude-code-sandboxing | Exists ("Making Claude Code safer with sandboxing", Oct 20, 2025). It says filesystem isolation helps prevent "a prompt-injected Claude from modifying sensitive system files". |
| https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization | Exists. Its Security Considerations say "All authorization endpoints MUST be served over HTTPS". Authorization is OPTIONAL in this revision. Later spec revisions were not checked. |
| https://modelcontextprotocol.io/registry/about | Exists (registry in preview). It verifies namespace ownership and leaves security scanning to package registries and downstream aggregators. |

Candidate replacement sources, read on 2026-11-07:

- OWASP LLM01:2025 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/ (Scenario #1 ignoring previous guidelines; Scenario #6 payload splitting; Scenario #9 "Multilingual/Obfuscated Attack" naming Base64; impact list includes revealing system prompts).
- OWASP LLM07:2025 System Prompt Leakage — https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/ (credentials and API keys embedded in system prompts; extraction scenarios).
- OWASP LLM05:2025 Improper Output Handling — https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/ (model output passed to a system shell, exec or eval).
- OWASP LLM03:2025 Supply Chain — https://genai.owasp.org/llmrisk/llm032025-supply-chain/ ("outdated or deprecated components").
- Boucher and Anderson, "Trojan Source: Invisible Vulnerabilities", arXiv:2111.00169 — https://arxiv.org/abs/2111.00169 (Unicode encoding features making code look different from how it executes).
- MITRE ATLAS technique ids, read from https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml: AML.T0050 Command and Scripting Interpreter, AML.T0053 AI Agent Tool Invocation, AML.T0051 LLM Prompt Injection, AML.T0037 Data from Local System, AML.T0025 Exfiltration via Cyber Means. That file reports version 5.6.0 and marks itself deprecated, so check these ids on the live ATLAS site before citing them. STATUS: UNKNOWN — UNVERIFIED against the current ATLAS release.

## Per-rule result

| Rule | State | Basis |
| --- | --- | --- |
| prompt_override | supported | LLM01:2025 Scenario #1. The cited landing page itself does not list LLM01. |
| system_exfiltration | supported | LLM01:2025 impact list; LLM07:2025. |
| secret_exfiltration | partial | LLM01:2025 covers sensitive disclosure in general, not credentials. LLM07:2025 covers credentials in prompts. |
| sensitive_topic | partial | Informational rule. The landing page does not describe it. |
| tool_escape | partial | Related to LLM05:2025 (output to shell/exec), not the same claim. |
| autonomous_authoritative_write | not_established | ATLAS home page only; no technique cited. |
| bulk_enterprise_modification | not_established | Same. |
| workflow_manipulation | not_established | Same. |
| cross_system_automation | not_established | Same. |
| runtime_dependency_install | partial | Cited page is the 2023/24 Supply Chain entry (packages), now LLM03:2025. Runtime installation itself is not described. |
| self_modifying_skill | source_broken | First URL returns 404 after its redirect. The sandboxing post supports filesystem isolation in general only. |
| unicode_deception | source_mismatch | Cited 2023/24 Supply Chain page has no Unicode content. Trojan Source (arXiv:2111.00169) is a verified candidate. |
| dynamic_import_construction | source_mismatch | Cited 2023/24 Supply Chain page does not cover obfuscated imports. No replacement verified. |
| insecure_mcp_transport | partial | The HTTPS requirement covers authorization endpoints only. |
| unverified_mcp_server | partial | The registry supports namespace verification. The trusted-host list is Injecticide policy. |
| dynamic_exec | not_established | ATLAS home page only (candidate AML.T0050, unverified on live site). |
| subprocess_spawn | not_established | Same. |
| network_calls | not_established | ATLAS home page only. |
| filesystem_access | not_established | ATLAS home page only (candidate AML.T0037, unverified). |
| url_fetch | not_established | ATLAS home page only. |
| base64_usage | supported | LLM01:2025 Scenario #9. |
| dangerous_file_ops | not_established | ATLAS home page only. |
| home_write | not_established | ATLAS home page only. |
| sensitive_keywords | partial | The landing page does not describe it. LLM07:2025 is related. |

Totals: 3 supported, 7 partial, 11 not_established, 2 source_mismatch, 1 source_broken.

## Not done

- Rule citations were not replaced. Replacing them changes data that is
  emitted in findings (`sources`), so it needs its own reviewed change.
- The live ATLAS technique pages were not read, because the site renders with
  script.
- Later MCP specification revisions were not checked.
- Pattern quality (false positives and negatives) was not re-evaluated here.
  See `docs/coverage.md` for detection gaps.

## Follow-ups

1. Replace the `self_modifying_skill` broken URL, and the `unicode_deception` and `dynamic_import_construction` mismatched citations.
2. Cite specific ATLAS techniques, checked on the live site, for the 11 ATLAS-only rules, or mark those rules as Injecticide policy rather than externally sourced.
3. Move OWASP citations from the landing page and 2023/24 URLs to the 2025 item pages.
4. Advance `last_reviewed` only once every rule is `supported`.
