# Research MCP candidate validation — October 20, 2026

Candidate branch: `codex/research-mcp`. Version: `0.3.0` (unreleased).
This record captures the completed pre-promotion validation phase. Statements
about pending acceptance and deployment below describe that phase; subsequent
release status is recorded in the pull request and Azure pipeline history.

## Automated checks

- Python 3.12, isolated environment, complete repository suite: **216 passed**.
- Focused coverage includes public-IP socket pinning/TLS hostname preservation,
  scope/redirect rejection, fixed API query propagation, resource budgets,
  source registry reconciliation, frontier rotation, retained baselines,
  API payload validation/backoff, arXiv rate policy, and SDK client/tool calls.
- `git diff --check`: passed (Git reports existing CRLF normalization notices).
- No external LLM evaluation, provider key, paid model call or plugin installation.

## Raspberry Pi validation

- SSH host `pi-codex`, observed hostname `dns.pi.local`, ARM64 Docker.
- Built `injecticide-research-mcp:research-validation-20261020` on the Pi.
- Docker Compose accepted the candidate configuration.
- Ran only `research_mcp` under Compose project `injecticide-research-validation`,
  with an override for container name, loopback port 8201 and validation data volume.
- Compose's health gate reached **healthy**. Actual cgroup `memory.max` was
  **268435456** bytes. Observed working memory during collection was about 66 MiB.
- Real HTTP MCP client discovered all **7 tools**, queried retained snapshots and
  read structured GitHub release data with provenance/hash.
- All five configured GitHub release API sources retained records: Codex,
  Claude Code, Gemini CLI, NVIDIA SkillSpector and Snyk Agent Scan.
- A Codex record observed through MCP had release ID `418453117` and tag
  `rust-v0.164.0-alpha.7`. It is research evidence, not a recommended runtime version.
- Untrusted browser `Origin: http://evil.example` received **403**.
- Separate unauthenticated API probes from the Pi returned **200** for the
  official MCP Registry (`servers`, `metadata`) and Crossref (`status`, `message`).
  These two production adapters are not implemented yet.
- arXiv cs.CR RSS was retrieved; the broader cs.AI feed exceeded the 1 MiB limit
  and was excluded. Codex release API queries use one result because five results
  exceed the same limit. The large OpenAI configuration page uses official Markdown.

The validation collector was stopped after testing; its image and evidence volume
are retained. OOMKilled was false. Existing `injecticide-web` and
`injecticide-skill-sandbox` remained healthy on image tag `88464fc121c7`; Nginx
remained running. The continuous production research service awaits the repository's
human acceptance and release process. No commit, push or merge was performed.

## Limits and follow-up

The collector is a bounded approved-source crawler plus read-only GitHub APIs.
Coverage is partial: source failures, unsupported binary/PDF pages, oversized
responses, incomplete frontiers and unverified research are surfaced explicitly.
Retained content is not permanent audit storage or proof of an exploit.

The free API review is in `api_sources.json`; distinguish documented availability
from an implemented adapter and a live transport probe. MCP Registry incremental
sync, arXiv query search, Crossref enrichment, GitHub commit/content tracking and
optional OpenAlex integration remain future adapters. Source intake cannot activate
enforcement rules. Azure candidate CI and human PR acceptance remain pending.
