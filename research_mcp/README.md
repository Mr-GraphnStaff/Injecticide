# Injecticide research MCP

Independent, recurring research collection for standards and AI platform skills,
plugins, project configuration and security documentation. This service uses the
[official Python MCP SDK](https://py.sdk.modelcontextprotocol.io/run/) with
Streamable HTTP, stateless JSON responses and a persistent SQLite catalog.

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

On startup and hourly thereafter, one worker retrieves approved pages, discovers
links in HTML, Markdown/llms.txt and RSS/Atom/XML, follows scoped HTTPS redirects,
and compares raw content SHA-256 hashes. Changes include initial baselines and
cosmetic HTML changes; no semantic vulnerability or control conclusion is inferred.
The catalog reports prior fingerprints, timestamps, current fetch failures and
retained versions. An on-demand refresh queues existing source IDs only.

This is bounded crawling of approved public sources, not an unrestricted web
search engine. It does not discover every new domain, query private vendor
tenants, inventory installed packages, install updates or prove exploit claims.
New domains and discovery roots are added by editing/reviewing the registry and
restarting the service. Pages/snapshots removed from scope are pruned on restart.
No MCP tool can alter that registry.

Configuration:

| Setting | Default | Meaning |
| --- | --- | --- |
| `INJECTICIDE_RESEARCH_INTERVAL_SECONDS` | 3600 | Compose refresh interval, minimum 300 seconds |
| `INJECTICIDE_RESEARCH_PAGE_BUDGET` | 40 | Document attempts per cycle, range 1–100 |
| `RESEARCH_SOURCES` | packaged `sources.json` | In-container source-registry path |
| `RESEARCH_DB` | `/data/research.sqlite3` | In-container catalog path |

Budgets: 100 tracked pages/source, 8 selected pages/source/cycle, 240-second cycle
deadline checked between requests, 1 MiB/response, 20-second response deadline,
8-second socket timeouts, 4 redirects, minimum 1 second/host, and 60-second manual
refresh cooldown/source. DNS resolver latency is OS-controlled. Robots requests
are additional to the document budget and cached for one hour. Robots failures
defer collection; disallowed destinations are not fetched. Robots crawl delays
and request rates are honored up to 60 seconds; larger delays defer collection.
arXiv requests share a rate bucket across its subdomains with at least 3 seconds
between requests. Thank you to arXiv for use of its open access interoperability.

Discovery roots are preserved. At frontier capacity, up to eight previously
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

Queries support pagination; there is no background push notification or automatic
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

The API requests use conditional ETags and share per-host backoff after rate
exhaustion, 403 or 429. They obey API limits instead of crawling robots.txt.
Public GitHub collection is unauthenticated and shares the outbound IP's quota;
no API key, GitHub write operation, asset download or paid LLM call is used.
API data is unverified research evidence, not release authenticity verification.
Other vendors and OWASP/NIST currently use approved web/feed sources, not invented
vendor APIs. Additional documented API adapters can follow the same interface.
References: [GitHub releases](https://docs.github.com/en/rest/releases/releases#list-releases)
and [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

## Isolation and promotion

The container is non-root, read-only except `/data` and bounded `/tmp`, drops all
capabilities, disallows privilege escalation, and has 256 MiB/0.5 CPU/64 PID limits.
Retrieval uses public-address-only DNS results, pins the socket to a validated IP
while retaining TLS hostname validation, ignores proxy environment variables,
and rejects credentials and custom ports. The only permitted query string is
the fixed GitHub releases `per_page=1` or `per_page=5` contract, pinned in source scopes.
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
