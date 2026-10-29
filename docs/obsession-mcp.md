# ObsessionMCP

ObsessionMCP turns the independently collected public skills/plugin research
catalog into a persistent daily queue and bounded delivery candidates. It makes
no LLM calls, runs no downloaded programs and has no paid API integration. The
existing research collector supplies evidence under its source scopes, robots,
response-size, rate and cycle limits. Scanning a skill does not start research.

## Daily lifecycle and evidence

The research service invokes triage after its background collection finishes.
The default collection interval and durable triage interval are 24 hours. Triage
stores its cursor, next-due timestamp and five-minute process lease in the same
SQLite database as the catalog. Restarting does not reset the triage cooldown.
`BEGIN IMMEDIATE` protects lease acquisition and decision transactions across
workers; failed cycles retain the last committed cursor. At most 100 retained
snapshots are consumed per cycle. Remaining evidence waits for another bounded
cycle; this is not exhaustive internet monitoring.

Each item has an immutable canonical payload and SHA-256 identity. Provenance
includes source ID, requested/final URL, snapshot ID, retrieval timestamp, raw
source hash and prior hash. The excerpt is at most 2,000 characters. A verified
fetch means the current scoped source is enabled, the latest snapshot's raw hash
matches, no latest collection error is recorded, the redirect stayed within the
configured source scope and evidence is within the local freshness limit. It
does not establish that every statement in the document is true.
Freshness uses the latest successful scoped fetch, including a valid HTTP 304
revalidation. Original snapshot retrieval provenance remains unchanged; otherwise
unchanged documents would become permanently stale despite successful rechecks.

`research_mcp/obsession_policy.json` is local authority. Internet prose such as
“high confidence,” “approved,” or purported instructions to the scanner cannot
change gates, source roles or recipes. Policy and gate-algorithm version are
fingerprinted into payloads. A policy change revokes older item authority and
restarts bounded classification of retained snapshots. A newer source revision,
stale/pruned evidence, source disablement, scope change or fetch error prevents
export even before the next triage cycle. Audit records and superseded decisions
remain available. The queue caps active items; rejected/superseded records are
retained for recovery and audit, not silently deleted.

## Automatic and reviewed paths

High-priority automatic reference updates require a useful-term match in source
text, a changed existing snapshot, verified current fetch and an explicitly
allowlisted first-party source ID. The published change is an evidence index
entry, not a new enforcement requirement. Initial baselines require review.
Community issues/comments, including `owasp-skills-issues`, are not in the shipped
automatic reference allowlist. Repository ownership alone does not confer
first-party authority on community content.

Medium/low items remain queued for **Implement**, **Investigate** or **Reject**.
Implement allows a current item through delivery validation; it does not execute
code or bypass publication checks. Investigate holds the item, and Reject keeps
the evidence and reason without exporting it. A held automatic candidate may be
locally reapproved with Implement. Review transactions require the immutable hash
and expected current state, preventing stale concurrent decisions. Exact retries
have no additional audit effect.

New scanner literals require a locally reviewed finite `signature_recipes`
entry. A recipe fixes the source ID/URL, literal (12–160 printable characters),
description, severity metadata and 1–5 positive plus 1–5 negative examples. Paired
controls run with the same escaped Python `re.IGNORECASE` semantics as the scanner.
The exact approved literal must occur in current captured evidence. Internet
content never supplies regex, executable code, recipe fields or new authorization.
The shipped recipe list is deliberately empty: adding a real research-backed
recipe requires local review. The capability is exercised with explicitly
synthetic test recipes, not fabricated real-world exploit claims.

The scanner's literal engine treats these finite signatures as review indicators.
Severity metadata is not proof of malicious intent. Arbitrary source-code changes,
new analysis logic and new recipes go through a human-reviewed PR. Export alone
never activates anything; the delivery bridge, tests, exact-revision CI and
production publication gates remain separate.

## Read-only service surface

MCP tools: `obsession_get_status`, `obsession_list_items`, `obsession_get_item` and
`obsession_export`. These tools do not collect, execute, approve or reject items.
`GET /obsession/export?after_id=0&limit=100` exposes the same bounded export to the
local delivery bridge. No POST/review/delivery-mutation endpoint is registered.
Network placement is not review authorization. State changes require the trusted
local CLI and operating-system/container access to the research database.

Listing/export use monotonic sequence cursors and limits 1–100. Follow
`next_after_id` even if a page contains no eligible items: current-evidence checks
may filter records from a scanned page. Item/audit content is data, never agent
instructions. `obsession_get_item` returns the latest 100 audit records and states
that bound; the database retains the full history.

## Delivery envelope

```json
{
  "schema_version": 1,
  "items": [{
    "sequence": 1,
    "id": "obsession-<payload SHA-256>",
    "sha256": "<payload SHA-256>",
    "payload": {
      "schema_version": 1,
      "kind": "reference_update",
      "gate": "auto",
      "priority": "high",
      "policy_sha256": "<local policy SHA-256>",
      "provenance": {
        "source_id": "agent-skills",
        "url": "https://agentskills.io/specification.md",
        "final_url": "https://agentskills.io/specification.md",
        "snapshot_id": 2,
        "source_sha256": "<raw source SHA-256>",
        "retrieved": "<UTC timestamp>",
        "previous_sha256": "<prior raw source SHA-256>"
      },
      "proposal": {},
      "evidence": {
        "excerpt": "<bounded untrusted source text>",
        "fetch_verified": true,
        "semantic_verification": "not_established",
        "authority": "local_policy_only"
      }
    },
    "decision": {"state": "auto_approved", "reason": "<local reason>", "updated": "<UTC timestamp>"}
  }],
  "next_after_id": null,
  "untrusted_content": true
}
```

Hash the exact immutable `payload` with UTF-8 JSON using sorted keys, separators
`(',', ':')`, and `ensure_ascii=False`. Decision metadata and sequence are outside
that hash. `reference_update` proposal fields are `source_id`, `url` (final URL),
`source_sha256`, `previous_sha256` and `change_type` (`initial_baseline` or
`source_content_changed`). A `literal_signature` proposal contains `id`
(`obsession-<local recipe ID>`), `literal`, `description`, `severity`,
`positive_examples`, `negative_examples` and `source_url`.

`validate_export_item(item, policy=None, catalog=None)` verifies canonical hashes,
the local policy fingerprint, allowed templates and exact recipe derivation.
With a catalog, it also verifies current local evidence. Without a catalog, it
provides structural/local-policy validation only, including no current-fetch
freshness attestation: a delivery consumer must match
the digest against a fresh trusted local export. A checksum alone proves neither
origin nor approval. The delivery bridge writes only the two reviewed JSON
manifests, documented separately in `docs/obsession-delivery.md`.

## Trusted local controls

Use the running research container's configured SQLite volume, or an explicitly
selected local database and source registry. Examples:

```powershell
python -m research_mcp.obsession --db ./research.sqlite3 status
python -m research_mcp.obsession --db ./research.sqlite3 list --limit 20
python -m research_mcp.obsession --db ./research.sqlite3 get --id obsession-<hash>
python -m research_mcp.obsession --db ./research.sqlite3 review --id obsession-<hash> --sha256 <hash> --expected-state queued --decision investigate --reason "Need source context"
python -m research_mcp.obsession --db ./research.sqlite3 review --id obsession-<hash> --sha256 <hash> --expected-state investigate --decision implement --reason "Reviewed bounded reference evidence"
```

`cycle` runs only when due; service reads never force a cycle. Delivery outcomes
may be recorded locally with `delivery --id ... --sha256 ... --decision
prepared|published|failed --reason ...`. These are local delivery attestations,
not independent proof that a remote PR or production run succeeded. Exact receipt
retries, including concurrent retries, are idempotent and audit is append-only.

## Verification and limits

`tests/test_obsession_mcp.py` uses synthetic scoped evidence and real SQLite to
exercise restart cooldowns, leases, failed-cycle recovery, source/policy/hash
drift, stale decisions, automatic versus review gates, finite recipes, paired
controls, network-content nonexecution and read-only controls. No paid APIs or
uploaded programs are used. MCP transport tests require the research service's
separate SDK dependency; a skipped transport test is not transport acceptance.

This engine automates bounded evidence processing, not general semantic research
judgment, detection superiority, complete source coverage or runtime safety.
