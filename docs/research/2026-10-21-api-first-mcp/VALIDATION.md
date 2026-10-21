# API-first Research MCP candidate validation

Date: October 21, 2026. Branch: codex/research-api-first.
Baseline: 92494d086e26feb4a9d94feca17a3cf7a9b20542. Candidate version: 0.5.0,
unreleased, uncommitted working tree. Production promotion has not occurred.

## Implemented scope

Three anonymous public connector families, with five new configured sources:
GitHub Advisories for Python MCP SDK, JavaScript MCP SDK and LangChain Core;
official MCP Registry metadata; Crossref prompt-injection paper metadata.
Five existing GitHub release sources remain enabled. Documentation/feed sources
use explicit approved seeds; broad link discovery is disabled in shipped config.
Total configured source groups: 29. Each new API samples a bounded first page.
No complete pagination, upstream synchronization checkpoint, OSV adapter, GitHub
revision adapter, new arXiv query adapter or authenticated connector is claimed.

No registration, API key or paid service was required. David's authorized email
was not submitted to a provider. Azure metadata confirmed a Pi Key Vault exists;
no secret values were read. Research runtime Key Vault identity/network access
is not implemented. Future credentials must use Key Vault, with no file fallback.

## Automated and independent review evidence

- Isolated Windows Python 3.12 environment installed repository requirements and
  mcp==2.3.0. Full suite: `python -m pytest -q` -> 312 passed in 30.79 seconds.
- Focused MCP/news/independent API acceptance suite: 105 passed, no skips.
  MCP-dependent discovery and calls ran with the SDK installed.
- Rowan contributed 48 independent acceptance cases and reviewed the final
  status UI for semantic accessibility. Ellis independently inspected the
  security boundaries and executed targeted temporary-DB/transport checks.
- Reviews caught and fixed archived off-scope snapshot retrieval, incorrect API
  media acceptance, and shortening valid multi-day Retry-After instructions.
- Evidence covers DNS/scope/query rejection, credential-header rejection,
  media/schema failure, retained last-good snapshots, bounded >1 MiB responses,
  malformed discovery, retry policy and nondestructive registry transitions.

## Catalog preservation and rollback

A consistent SQLite backup was created through SQLite's backup API while opening
the production data volume read-only in a separate helper container. Production
files were not migrated. Backup: `tmp/research-api-20261021/baseline.sqlite3`.

- Size: 76,566,528 bytes. Integrity: `ok`.
- SHA-256: `4eea9584541bcd0660f365854ec43af6f994bfb8c1a57b2fa355e884a2ff9ecf`.
- Baseline: 1,505 page rows and 295 snapshots, across 24 configured source groups.
- Candidate initialization on a separate copy: all 295 snapshots retained;
  1,467 pages classified as archived rather than active fetch targets.
- A second separate volume restored the baseline under the previous image
  `injecticide-research-mcp:92494d086e26`, with outbound networking disabled.
  Integrity remained `ok`; 295 snapshots and 24 configured groups were readable.
  Live MCP exposed seven tools; cached Codex release ID 419641797 and eight news
  items were retrieved. This is restoration of the previous image/config/backup,
  not a claim that old code can consume every possible future migrated database.

Initial backup attempts into the production container's 16 MiB temporary mount
failed for insufficient space; two helper attempts lacked destination write
permissions after dropping capabilities. The successful backup used a separate
helper under the destination directory's owning UID. No partial backup was
accepted as evidence, and the final backup passed integrity/hash checks.

## Candidate runtime

Built on the Raspberry Pi (ARM64), with separate container and volume:
`injecticide-research-api-validation`, `injecticide-research-api-validation-data`.
Image ID: `sha256:49044c39bf6d69b5778de32153e652863e48a8b1b9fc41734933d7e50c53f8ed`.
Limits match research deployment: 256 MiB, 0.5 CPU, 64 PIDs, read-only filesystem,
16 MiB tmpfs, dropped capabilities and no privilege escalation. Candidate host
port was bound only to 127.0.0.1:18200. Production container was unchanged.

First scheduled cycle completed at 17:23:15 UTC (12:23:15 PM America/Chicago):
40 attempts, 26 changed snapshots, two failed attempts, cycle budget reached,
deadline not reached. The five new API sources all collected successfully.
An MCP client inside the candidate discovered all seven tools, queried each new
source, retrieved its snapshot and verified the returned content hash matched.
Raw operator artifacts are under `tmp/research-api-20261021/`.

Second scheduled cycle completed at 17:28:46 UTC (12:28:46 PM Central):
40 attempts, ten changed snapshots, one failed attempt, cycle budget reached,
deadline not reached. Manual refreshes of the five new API sources followed.
MCP Registry timed out intermittently; its last-good evidence remained readable
and the source reported failure. One controlled manual retry after the refresh
cooldown recovered at 17:30:05 UTC. The probe then verified all five source
snapshots through MCP, including their matching hashes. This observed recovery
does not establish long-term provider reliability or automatic immediate retry.

Final pre-restart collection summary: 29 configured groups current within their
bounded contracts, zero fetch errors, zero stale/pending groups, 325 retained
snapshots. Claude's skills page successfully stored 1,237,069 response bytes,
exceeding the old 1 MiB cap. OWASP crawling-policy retrieval also recovered; it
was not bypassed. Historical derived pages are now archived, so these source
counts must not be interpreted as exhaustive collection of the former frontier.

Observed candidate cgroup memory peak was 197,525,504 bytes (about 188.4 MiB)
under the 256 MiB limit during this workload. That is workload evidence, not a
guarantee for every possible 8 MiB response or concurrent access pattern.

Candidate restart retained queryable records from all five new sources; MCP
discovery again returned seven tools, and the news projection remained readable.
The operator probe lives in `tests/research_api_probe.py`; captured outputs are
`scheduled-and-manual-probe.json`, `restart-probe.json` and `rollback-probe.json`
under the temporary evidence directory.

## Browser validation

The SSH account refused forwarding to the candidate port; its restrictions were
not changed. The actual candidate MCP checks ran inside its container. For browser
validation, a captured candidate `/news` response was served by a temporary local
fixture server through the real web news projection and React overview.

- Incomplete coverage rendered explicitly, alongside 29 source status rows.
- Native details/summary opened with keyboard Enter; focus remained on summary,
  with browser focus outline present (auto, 1px).
- At 390px viewport width, document scroll width remained 390px.
- Browser console: zero errors; existing Tailwind CDN and in-browser Babel warnings.
- Screenshots: `tmp/research-api-20261021/source-health.png` and
  `tmp/research-api-20261021/source-health-mobile.png`.
- Independent static accessibility review completed; screen-reader and full
  assistive-technology testing were not performed. Narrow viewport testing is not
  a claim of exhaustive zoom/browser coverage.

## Release status

First bounded increment validated. Following this reviewable report, David
directed production testing because production is his available test surface.
That direction authorizes promotion through the existing PR/Azure pipeline and
live verification; production results will be recorded after execution. This is
not completion of the entire multi-increment PLAN.md or a claim of full upstream
synchronization.
No GitHub workflow, auth configuration, secret, production deployment or remote
account was changed during candidate preparation. Broader API synchronization and Cloudflare recognition
remain later work. Upstream failures and observed resource limits must be stated
with final runtime evidence; passing tests alone does not establish all-source
coverage or long-term provider reliability.
