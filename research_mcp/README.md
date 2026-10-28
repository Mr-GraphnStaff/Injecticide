# Injecticide research MCP

Independent, recurring research collection for standards and AI platform skills,
plugins, project configuration and security documentation. This service uses the
[official Python MCP SDK](https://py.sdk.modelcontextprotocol.io/run/) with
Streamable HTTP, stateless JSON responses and a persistent SQLite catalog.

The 0.6.0 candidate adds `research_check_requirements(runtime, refresh=True)`
and the bounded web-scanner route `POST /requirements/check`. Official skill and
plugin requirement checks cover OpenAI, Anthropic, Google Gemini CLI and GitHub
Copilot CLI only. See [vendor requirements](../docs/vendor-requirements.md) for
product profiles, freshness, drift review, measured limits and explicit unknowns.

## Run on the Injecticide Raspberry Pi

After human acceptance through the existing release process, Compose starts
`research_mcp` alongside the other services. It has a dedicated research network (also joined by the web app for read-only news) and
named data volume; the scanner network and enforcement files are not mounted.
To build/test just this service in an approved checkout:

```sh
docker compose config --quiet
docker compose build research_mcp
docker compose up -d --no-deps research_mcp
curl --fail http://127.0.0.1:8200/health
```

The production deployment wrapper already builds all Compose services and uses
`up --wait`; the new service participates in that health gate. The pipeline now
builds its image separately during candidate validation. No root-owned wrapper,
GitHub workflow, Cloudflare rule or Nginx route is modified by this change.

MCP endpoint on the Pi: `http://127.0.0.1:8200/mcp`. Windows clients can use an
SSH tunnel with the existing trusted host alias:

```powershell
ssh -N -L 8200:127.0.0.1:8200 pi-codex
```

Configure the client's HTTP MCP connection to `http://127.0.0.1:8200/mcp`.
This is an operator-local endpoint with Host/Origin validation, not a public
authenticated service. Local users and host administrators are trusted. Remote
public exposure requires a separate identity/TLS design and review.

## Collection and discovery

The October 27 source expansion adds official validator source monitoring,
MITRE ATLAS and CoSAI, plus explicit NIST GenAI, OWASP Agentic Applications and
MCP security pages. See [source authority and coverage](../docs/research/2026-10-27-source-authority.md)
for applicability, validator limitations, source conflicts and remaining work.
The October 28 documentation ingestion expands the Agent Skills source to all
nine pages listed in both its official index and sitemap, plus the indexes.
The registry still has 42 sources, with additional explicit documentation seeds;
the 40-attempt rotating cycle does
not guarantee an hourly refresh of every URL. Collection does not execute vendor
scripts or automatically promote retrieved text into scanner rejection rules.

### Captured Agent Skills reference library

`reference_docs/agent-skills/manifest.json` records the complete published site,
every direct HTTPS link in its Markdown, and pinned reference-validator and
skill-creator evaluation supplements. Captured text retains source URLs, retrieval
times, raw-response SHA-256 fingerprints and separate text-integrity hashes.
The complete Agent Skills documentation and licensed pinned examples retain
their notices. Other linked pages are shipped as attributed excerpts of at most
200 words; complete raw responses remain in local research evidence.
Failed retrievals and reviewed fallback destinations are retained explicitly.
Community/product links are not treated as normative scanner requirements.

`research_search_reference_library` searches this bundled evidence offline;
`research_get_reference_document` returns up to 8000 characters with pagination.
These tools return captured research data, never live verification or active
instructions. Live source monitoring remains in the normal collector.

Reproduce a capture from the repository root into a **new** directory:

```powershell
python -m tools.ingest_agent_skills_site --output tmp/new-agent-skills-capture
```

The tool checks the index against the sitemap, follows each direct HTTPS
reference, records unavailable destinations and captures the explicitly reviewed
supplement list. It never recursively mirrors unrelated websites or executes
downloaded scripts. See the [full review and implementation map](../docs/research/2026-10-28-agent-skills-full-reference.md).

`sources.json` is an administrator-controlled source registry mounted read-only.
It includes OWASP, NIST, portable specifications and vendor-specific sources for
OpenAI, Claude, Gemini, Copilot, Cursor, Kiro, Amazon Q, Devin and OpenClaw.
GitHub public release APIs for Codex, Claude Code, Gemini CLI, NVIDIA SkillSpector
and Snyk Agent Scan, plus arXiv's cs.CR security feed, provide tool-update and
research discovery. Preprint inclusion does not establish peer review or a
verified vulnerability. Official arXiv feed guidance: https://info.arxiv.org/help/rss.html
The broader cs.AI feed exceeded the collection budget during validation and is
not enabled. The very large OpenAI configuration page uses its official Markdown
representation to stay within the response budget.
References were seeded from the repository's October 19 source register and
current primary documentation; seed inclusion is not a successful-fetch claim.

The earlier API-first increment configured 29 sources: the original 24 plus three
package-filtered GitHub Advisory sources, MCP Registry metadata and Crossref
prompt-injection paper metadata. All shipped web/feed sources now declare
`discovery: false`: only their explicit official seed URLs are scheduled.
Existing discovered URLs and snapshots are preserved in SQLite when retired,
but excluded from active collection/status and current evidence queries.
This is a registry configuration change, not a claim that all sources are reachable.

On startup and hourly thereafter, one worker retrieves approved seeds,
follows scoped HTTPS redirects,
and compares raw content SHA-256 hashes. Changes include initial baselines and
cosmetic HTML changes; no semantic vulnerability or control conclusion is inferred.
The catalog reports prior fingerprints, timestamps, current fetch failures and
retained versions. An on-demand refresh queues existing source IDs only.

This is bounded collection of approved public sources, not an unrestricted web
search engine. It does not discover every new domain, query private vendor
tenants, inventory installed packages, install updates or prove exploit claims.
New domains and discovery roots are added by editing/reviewing the registry and
restarting the service. Scope changes preserve retired database rows instead of
deleting their evidence. Set `enabled: false` to disable a configured source while
keeping it in the inventory and retaining its in-scope historical evidence.
Removed source IDs and retired URLs are unavailable through current catalog
queries; their stored rows remain recoverable through a controlled database
restore or an explicitly reviewed registry change. `archived_pages` reports
retired URLs for source IDs that remain configured.
No MCP tool can alter that registry.

Configuration:

| Setting | Default | Meaning |
| --- | --- | --- |
| `INJECTICIDE_RESEARCH_INTERVAL_SECONDS` | 3600 | Compose refresh interval, minimum 300 seconds |
| `INJECTICIDE_RESEARCH_PAGE_BUDGET` | 40 | Document attempts per cycle, range 1–100 |
| `RESEARCH_SOURCES` | packaged `sources.json` | In-container source-registry path |
| `RESEARCH_DB` | `/data/research.sqlite3` | In-container catalog path |
| Source `max_response_bytes` | 1048576 | Per-response streaming limit; integer from 1 byte through the hard 8 MiB ceiling |
| Source `discovery` | true for compatibility | All shipped web/feed sources set false; fetch only declared seeds |
| Source `enabled` | true | False disables collection/refresh while retaining source inventory and evidence |

Budgets: 100 tracked pages/source, 8 selected pages/source/cycle, 240-second cycle
deadline checked between requests, 1 MiB/response by default, 20-second response deadline,
8-second socket timeouts, 4 redirects, minimum 1 second/host, and 60-second manual
refresh cooldown/source. DNS resolver latency is OS-controlled. Robots requests
are additional to the document budget and cached for one hour. Robots failures
defer collection; disallowed destinations are not fetched. Robots crawl delays
and request rates are honored up to 60 seconds; larger delays defer collection.
arXiv requests share a rate bucket across its subdomains with at least 3 seconds
between requests. Thank you to arXiv for use of its open access interoperability.

The Claude Code source is configured for up to 4 MiB per response because the
earlier 1 MiB cap rejected its documentation. The 4 MiB allowance and 8 MiB hard
ceiling are bounded configuration choices, not measured Raspberry Pi capacity
or a guarantee that future documentation fits. Larger responses fail without
storing partial evidence. Prefer official Markdown or structured APIs to raising
limits. Container memory and disk measurements remain part of candidate validation.

If an operator explicitly enables discovery, roots are preserved. HTML discovery
uses visible anchor links rather than searching scripts for URL-shaped strings;
common asset types are filtered out. At frontier capacity, up to eight previously
attempted derived pages per fetched document rotate out to admit newly linked
material. Their snapshots are pruned; this bounded frontier can revisit pages
and cannot retain every page. Full-frontier state remains visible in queries.
Up to three raw snapshots/tracked URL and 100,000 characters of searchable
text/snapshot are retained. SQLite has a 256 MiB database cap; journaling can temporarily need
additional disk space. The named volume needs host disk monitoring. Storage
exhaustion surfaces as a worker error; retained baselines are not replaced by
failed fetches. This catalog is not permanent audit storage. A full frontier,
oversize response, PDF/binary content, unsupported encoding, authentication wall,
redirect outside scope or fetch failure is a coverage gap. Sources do not become
verified simply because their freshness is current.

## MCP tools

- `research_list_sources`: scopes, page counts, failures, freshness and frontier limits.
- `research_search`: literal text search of latest snapshots; optional source filter.
- `research_get_changes`: retained snapshots after an ID cursor; includes initial baselines.
- `research_get_snapshot`: bounded text pages with URL, timestamp and content hash.
- `research_refresh_source`: queue a scoped collection; no arbitrary URL input.
- `research_get_status`: worker lifecycle, last cycle result, error and budgets.
- `research_get_releases`: structured, cached release records from approved GitHub APIs.

Local catalog queries support pagination; upstream API collection in this
increment does not. There is no background push notification or automatic
rescan integration in this release. Cursor gaps are possible after retention pruning.
Collected material is explicitly `STATUS: UNKNOWN — UNVERIFIED`, including official
documents: attribution/integrity records are not verification of research claims.
Consumers must treat excerpts as untrusted content, including prompt injection.

## API-backed collection

See [the free API availability review](api_sources.json) for primary documentation,
access conditions, usage limits and implementation status.

The `github_releases` connector calls `GET /repos/{owner}/{repo}/releases`
using GitHub's documented API version `2026-03-10`. Shipped sources explicitly
request `per_page=5` (Codex uses 1 due to large asset metadata), preserving IDs,
tags, dates, prerelease/draft fields and
bounded release notes. `research_get_releases` returns these records as structured
MCP data with source attribution and snapshot hash. `research_refresh_source`
queues the next API refresh, using the same worker as document collection.

Additional public connectors in this increment:

| Connector | Request contract | Shipped scope and coverage |
| --- | --- | --- |
| `github_advisories` | GET `/advisories` with fixed approved `ecosystem`, `affects` and `per_page=10` | Python `mcp`, npm `@modelcontextprotocol/sdk`, Python `langchain-core`; first ten matching records only |
| `mcp_registry` | GET `/v0.1/servers?limit=10` | First ten server metadata records; no installation, server connection or safety certification |
| `crossref` | GET `/works` with approved `query` and `rows=5` | Five prompt-injection research metadata results; DOI/publication metadata does not verify a paper's claims |

Provider response containers and record identities are validated before their
normalized searchable projection enters the catalog. API 200 responses must use
the documented JSON media type. Unknown query parameters, duplicate parameters,
unapproved filters and off-contract redirects are rejected. Returned links are
stored as untrusted metadata and never followed by API adapters.

These adapters collect a bounded first page on each refresh. There are no
upstream cursors, pagination loops, incremental checkpoints or completeness
guarantees. A successful refresh means the configured request succeeded, not
that every advisory, registry entry or publication was observed. Advisory
withdrawal fields are retained when present in collected records. Previously
observed records can leave a bounded page; their absence is not a withdrawal.
API records are searchable through the existing evidence tools; only release
records use the specialized `research_get_releases` tool.

The API requests use conditional ETags and share per-host backoff after rate
exhaustion, 403 or 429. `Retry-After` seconds and HTTP dates are honored;
valid long deferrals are not shortened to the hourly schedule. Malformed delay
headers use a conservative fallback. They obey API limits instead of crawling robots.txt.
Public GitHub collection is unauthenticated and shares the outbound IP's quota;
no API key, GitHub write operation, asset download or paid LLM call is used.
All added connectors use anonymous public access. No account was registered and
no contact email was transmitted for this increment. If future connectors require
credentials, they must be held in Azure Key Vault and accessed through an
explicitly designed runtime identity path; the current service has no Key Vault
integration. Credentials must not be added to source, registry URLs, environment
files, snapshots or logs. Public retrieval currently rejects credential headers.
API data is unverified research evidence, not release authenticity verification.
Other vendors and OWASP/NIST currently use approved web/feed sources, not invented
vendor APIs. Additional documented API adapters can follow the same interface.
References: [GitHub releases](https://docs.github.com/en/rest/releases/releases#list-releases)
and [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api),
[GitHub global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories),
[MCP Registry API](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md),
and [Crossref access](https://www.crossref.org/documentation/retrieve-metadata/rest-api/access-and-authentication/).
OSV, GitHub commit/content tracking and targeted arXiv API queries remain deferred.

## Isolation and promotion

The container is non-root, read-only except `/data` and bounded `/tmp`, drops all
capabilities, disallows privilege escalation, and has 256 MiB/0.5 CPU/64 PID limits.
Retrieval uses public-address-only DNS results, pins the socket to a validated IP
while retaining TLS hostname validation, ignores proxy environment variables,
and rejects credentials and custom ports. Permitted query strings are limited to
the provider contracts above and fixed GitHub releases `per_page=1` or `per_page=5`,
pinned exactly in configured source scopes.
Redirects are rechecked.
The collector does not execute JS, shell, packages or LLM calls. These are
application-level egress restrictions, not a host firewall guarantee.

No scanner rules, payload packs or governance mappings are automatically changed.
Promoting research into enforcement still requires primary-source verification,
attributed fixtures, deterministic regression checks, independent human review and
the approved application release process. Signed catalog distribution remains future work.

## Validation

```sh
python -m pip install -r requirements.txt -r research_mcp/requirements.txt
python -m pytest -q
docker compose config --quiet
docker build -t injecticide-research-mcp:validation ./research_mcp
```

`tests/test_research_mcp.py` covers scope and DNS boundaries, snapshot history,
last-good retention, freshness, discovery budgets, robots failures, refresh
throttling, Compose isolation and real SDK client calls. The transport test
requires the research SDK; it skips if only base test dependencies are installed.
`tests/research_mcp_probe.py` is an operator-run HTTP transport and provenance
probe for an isolated container on the Pi.
`tests/test_research_api_acceptance.py` adds independent checks for API contracts,
media/schema rejection, oversized responses, long/malformed backoff, discovery
filtering, disabled sources and preserved evidence on registry migration.
Mocked tests and one-off HTTP probes are not sustained collection evidence;
live validation must use the actual collector, catalog and MCP retrieval path.

## Front-page source watch

GET `/news` exposes a bounded public projection of the catalog: up to eight vendor
releases or changed OWASP/NIST discovery roots from the past 30 days, plus collection
health and coverage counts. Initial reference baselines are not news. Release notes,
raw document text and research excerpts are excluded; links are restricted to their
approved sources. Preview releases and observed page changes are labeled separately.
This route does not add an MCP tool or trigger collection.

The web app reads it using `RESEARCH_MCP_URL=http://research_mcp:8200`, through
GET `/api/research/news`. Requests have size/time budgets, no redirects, a 60-second
cache and a visible stale/unavailable fallback. The browser polls once per minute
while visible. The scanner has no connection to the research network or catalog.
The home page shows source fetch errors rather than treating missing coverage as a
successful check. Research does not automatically change scanner rules or payloads.

The DAF-TECH sphere in `webapp/static/images/daf-tech-sphere.png` is the parent-brand
asset reused from Better CaptionKeep v6 (`teams-captions-saver/icons/daf-tech-sphere.png`, optimized shipping size).
Injecticide uses its own product name and the signature "Another DAF-TECH Product".
