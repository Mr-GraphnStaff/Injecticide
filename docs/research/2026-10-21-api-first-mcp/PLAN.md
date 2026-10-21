# Research MCP: API-first implementation plan

Date: October 21, 2026
Status: first bounded implementation increment validated; David has directed
production testing through the existing release process. Later increments remain
planned. See VALIDATION.md for executed deployment results.
Baseline: master, 92494d086e26feb4a9d94feca17a3cf7a9b20542.
Team lead: David Farris. Accountable coordinator: Codex.

## Outcome

Replace broad research crawling with documented provider APIs and narrowly
configured official feeds/Markdown. Every enabled source must have a tested
request contract, bounded resource use, provenance, and an honest freshness state.
No automatic rule activation, package installation, or connection to discovered
MCP servers. No claim that an official protocol makes its content trustworthy.

## Evidence and constraints

- The current adapter supports five GitHub release sources. api_sources.json
  records other possibilities; it does not enable them.
- Live checks in this chat found 24 sources, 286 retained snapshots, and 10
  source groups containing errors. These counts are a dated baseline.
- Live MCP discovery and read queries passed. Direct HTTP probes returned 200
  for GitHub Advisories, MCP Registry, Crossref, and an OSV record; arXiv timed
  out. These are connectivity observations, not reliability acceptance.
- Static inspection found raw-HTML URL extraction collecting script fragments
  and assets, a fixed 1 MiB response cap, GET-only transport, and GitHub-specific
  query/rate handling. Adding APIs requires explicit new contracts.
- Catalog startup deletes records removed from source scope. Never cut over by
  replacing the live registry without preserving and migrating its catalog.
- Existing untracked docs/architecture/ and tmp/ material is outside this work.

## Accountable roles

The following are assignment roles, not claims of implementation or sign-off.
Maya (integration) owns source contracts and adapters; Ellis (security) reviews
network/credential/content boundaries; Rowan (QA/reliability) owns acceptance
evidence. Codex integrates work and owns release preparation. David owns product
direction and human acceptance. The three specialists performed separate static
planning assessments in this chat; no new tests were run by those assessments.

## Ordered work packages

| ID | Owner | Dependency | Deliverable | Acceptance |
| --- | --- | --- | --- | --- |
| P1 | Codex + Rowan | None | Record deployed revision/image, registry hash, source states, retention and disk/memory baseline; make consistent SQLite backup | Backup opens in an isolated volume; source and snapshot counts reconcile; recovery instructions recorded |
| P2 | Maya; Ellis reviews | P1 | Inventory all 24 sources; classify API/feed/Markdown/deferred; document exact origin/path/version/method/parameters, schema, terms/license, auth, quota, schedule, freshness target and retention | Every source has a disposition; no disabled source disappears from the coverage report; unsupported access remains visible |
| P3 | Maya; Ellis + Rowan review | P2 | Provider adapter contract and scheduler changes; fix malformed-link/asset discovery; configurable per-connector size budgets under a hard global ceiling | Existing releases still work; unknown destinations/parameters rejected; real document above 1 MiB accepted within its approved cap; oversized stream fails without a partial snapshot |
| P4 | Maya; Rowan validates | P3 | GitHub Advisories vertical slice using approved public packages/ecosystems and updated-time checkpoints | Actual collector writes bounded normalized records; MCP retrieves them with ID/URL/hash/times; repeat refresh, pagination, deduplication and withdrawal behavior verified |
| P5 | Maya; Ellis reviews | P4 | Approved GitHub repository revision tracking, MCP Registry and Crossref adapters, one at a time | Each provider separately passes contract and live-cycle gates; repository commits are not described as adopted standards; registry metadata never triggers installation or server connection |
| P6 | Maya; Ellis reviews | P5 | OSV advisory-ID adapter; targeted arXiv feasibility check | OSV records pass end-to-end gates; package/version POST queries remain deferred until outbound-data policy is explicit; arXiv stays deferred unless actual collector tests succeed |
| P7 | Codex; Rowan reviews | P3; validate with P4-P6 | Per-source operational states in MCP/news and status UI; explicit migration from broad crawling | Distinguish current, stale, pending, blocked, rate-limited, oversized, invalid response, unsupported and disabled; cache age, source age, worker health and coverage remain separate |
| P8 | Codex; independent QA + security | P4, P7; each additional connector independently | Candidate evidence, release notes/version assessment, catalog migration and rollback rehearsal | Release gates below pass; human acceptance obtained through existing process before production promotion |

P4 plus P7 is the first releasable increment. P5/P6 are subsequent increments,
not prerequisites to fixing the current collector. No implementation dates are
promised before sizing P1-P3. No new tracker items are implied by this document.

## Transport and access decisions

1. HTTPS APIs with verified TLS; official RSS/Atom/Markdown only where documented
   and permitted. No generic browser fallback, challenge bypass or spoofed agent.
2. Preserve public-address DNS checks, connection IP pinning, redirect validation,
   source-ID-only refresh, loopback MCP exposure and research/enforcement separation.
3. Add query/body/method rules per provider. Never loosen the fetcher into an
   arbitrary URL or request execution tool. Validate provider pagination URLs.
4. Anonymous access first. Optional provider keys require a demonstrated quota
   need, least privilege and server-side configuration. Never forward credentials
   across origins or retain them in URLs, diagnostics, snapshots or MCP output.
   All new API credentials must be stored in Azure Key Vault. There is no
   .env/file fallback; implement and review runtime identity/network access before
   enabling a credentialed connector. David authorized free useful registrations
   using david@daf-tech.com when needed; this increment requires none.
5. Enforce free quotas and local request/page/byte/deadline budgets. Honor provider
   headers, including Retry-After seconds and HTTP dates; no paid fallback.
6. Prefer smaller official representations. Select numeric response ceilings using
   Pi measurements in P1/P3; retain a finite global maximum. If compression is
   introduced, bound both transfer and decompressed sizes.
7. All fetched text remains untrusted evidence. Preserve publication, observation
   and last-success times separately, plus source identifier, record version,
   content hash, retrieval URL and verification status.

## Test and release gates

- Contract tests: empty results, invalid JSON/XML/schema/media, duplicates,
  withdrawn records, pagination loops, incomplete pages and interrupted cursors.
- Security tests: private/mixed DNS, redirect escape, credential forwarding,
  unexpected parameters, malicious fetched instructions and returned links.
- Recovery tests: 403/429/5xx, malformed rate headers, timeout, restart during
  refresh, storage exhaustion and source disablement. Retain last-good evidence
  while showing its age and the failed attempt.
- Size tests: declared and streamed limits, missing/incorrect Content-Length,
  legitimate >1 MiB document, deadline and decompression expansion if supported.
- Run existing research MCP, news and affected scanner regression tests. Test
  status UI changes in a browser and perform accessibility review before shipping.
- Candidate uses a separate container/project and data volume. For every enabled
  adapter, observe two scheduled collection cycles and one manual refresh through
  the actual collector, then retrieve resulting records through MCP. Confirm the
  website projection remains usable and accurately describes source health.
- Save commands, revision, results, quota headers without secrets, provenance and
  unresolved coverage gaps. A 200 response, worker liveness or green unit suite
  alone cannot satisfy the integration gate.
- Rehearse rollback using previous image/config and preserved database in an
  isolated volume. Do not point an older binary at a migrated DB without proving
  compatibility. Verify MCP reads and retained news after recovery.
- Stop promotion on data loss, credential exposure, scope escape, uncontrolled
  resource use, misleading freshness or failing required regressions.
- Follow AGENTS.md: human acceptance for major changes; version/changelog update
  as applicable; human confirmation before commits touching auth/secrets or
  deployment. GitHub workflows are outside scope.

## Bot identity: separate follow-on work

After collection behavior is reliable, prepare a public crawler-purpose/contact
and opt-out page, stable accurate user-agent, and Web Bot Auth versus IP validation
assessment. Prepare a Cloudflare application as a reviewable deliverable; submitting
it or publishing identity material is a separate action. Recognition does not
grant universal access and is not an API reliability gate.

## Provider references

- GitHub public advisories: https://docs.github.com/en/rest/security-advisories/global-advisories
- GitHub quotas: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- MCP Registry contract: https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md
- Crossref access/quotas: https://www.crossref.org/documentation/retrieve-metadata/rest-api/access-and-authentication/
- OSV contracts: https://google.github.io/osv.dev/api/
- arXiv terms: https://info.arxiv.org/help/api/tou.html
- Cloudflare verification: https://developers.cloudflare.com/bots/concepts/bot/verified-bots/

Recheck provider terms, versions and quotas when implementing each adapter.
OpenAlex/account-based services are deferred until an unmet research need is shown.

## Work ledger

| Item | Status | Evidence / next action |
| --- | --- | --- |
| Team planning assessment | Done, static limitations stated | Separate integration, security and QA assessments in October 21 chat |
| Executable plan | Done | This document; implementation starts at P1 |
| First bounded increment | Validated, awaiting human review | Three public adapter families, five new source entries; 312 tests pass; two scheduled cycles, manual refresh, restart and rollback checked; see VALIDATION.md |
| P4/P5 full synchronization | Deferred | First-page sampling only; no pagination checkpoints or GitHub revision adapter claimed |
| P6 OSV / arXiv adapter | Deferred | Not implemented in first increment |
| Production promotion | Not performed | Human release acceptance and applicable evidence gates remain required |
| Cloudflare recognition | Deferred | Follow-on after collector acceptance |
