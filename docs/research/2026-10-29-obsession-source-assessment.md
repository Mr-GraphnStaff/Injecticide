# Obsession source assessment for 0.14.0

Assessed October 29, 2026 against primary publisher material and current code.
The user-supplied intelligence-hub text is a research brief, not verified fact or
runtime instructions. Search coverage is not full standards normalization,
compliance certification, dependency applicability or a vulnerability verdict.

| Resource | Include in this build | Separate review / limitation |
| --- | --- | --- |
| [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/) | Monitor official page and its linked JSON; preserve source hashes and original identifiers. Suggestions inform evidence/review requirements. | Voluntary guidance; do not convert every suggestion into a mandatory scanner rejection. JSON search projection is bounded. |
| [NIST OSCAL](https://github.com/usnistgov/OSCAL) | Monitor official model documentation and source. Keep schema/requirements distinct from security observations. | OSCAL is an interchange language, not itself an AI control catalog. Full OSCAL import and framework crosswalk require separate explicit mappings. |
| [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) | Keep pinned manifest/content source; add official release API so new monthly content becomes a review candidate. | Preserve content versus format versions. Do not execute the supplied API/MCP agent or copy a changing latest alias over reviewed evidence. |
| [OWASP Skills issue tracker](https://github.com/OWASP/www-project-agentic-skills-top-10/issues) | Add issues, closed items/PRs and comments through bounded official GitHub endpoints. Community authors cannot grant automatic release authority. | Latest 100 updated records per endpoint; high activity may exceed the window. Issue statements are not OWASP endorsement. Content pins, scoped updates and receipts inform gate tests, not fabricated threat findings. |
| [CSA AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) | Monitor public publication and foundation pages. Record access failures separately. | Spreadsheet access and redistribution terms need review; no bypass or implied full control import. Incorrect working-group URL from exploratory search was excluded. |
| [NVD developer guidance](https://nvd.nist.gov/developers/vulnerabilities) | Watch official API guidance; preserve explicit unavailable/unknown state when retrieval fails. | No API key registration or complete NVD mirror. Applicability requires exact package/version evidence; broad CVE text cannot establish an affected dependency. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Add official public JSON feed with response and projection budgets; retrieval failure is visible. | Canonical publisher fetch returned HTTP403 in research; verified the publisher-owned [cisagov/kev-data mirror](https://github.com/cisagov/kev-data) and included its accessible raw JSON endpoint. Configured monitoring is not proof of successful live collection. Daily cadence initially; full-feed dependency correlation is not implemented. |
| [FIRST EPSS data guidance](https://www.first.org/epss/data.html) | Monitor official data/API guidance. Keep probability separate from observed exploitation and compliance requirements. | Publisher recommends daily CSV for full synchronization; do not simulate a full mirror with lookup requests. Bulk gzip ingestion needs a bounded adapter; no bulk scores imported here. |
| [OSV API](https://google.github.io/osv.dev/api/) | Monitor official API/schema guidance. Keep private package inventories out of research requests. | No private dependency POST, full OSV mirror or installed-package vulnerability verdict. Such enrichment needs explicit inventory/version matching and budgets. |

## Engineering decisions incorporated now

1. Provenance, content hash, publisher scope, freshness and locally reviewed policy
   determine eligibility. Internet text never supplies confidence, approval,
   commands, regex or deployment paths.
2. Durable daily triage is independent of scans. Source collection precedes
   triage; cursors/leases and review decisions survive restart. The scanner uses
   its release's cached catalog; a research cycle cannot mutate in-flight rules.
3. Initial baselines and non-allowlisted/community material enter review. Approved
   official reference changes can update the evidence index. Novel signatures
   require a reviewed local literal recipe and positive/negative controls using
   the same matcher semantics as production. No novel detector is invented from
   prose. Shipped recipes are empty; extension capability is tested, not seeded
   with a fabricated real-world threat.
4. Research credentials and deployment credentials remain separate. The host
   bridge admits only two JSON paths, tests the candidate, and verifies exact-SHA
   CI from the pinned Azure application/pipeline before automatic merge. Scoped
   deployment is requalified after merge; other changes retain human acceptance.
5. Queue/retrieval errors, partial projections and failed delivery remain explicit.
   Missing success evidence is not treated as proof of release or prevention.
   Content/resource ceilings fail closed and require operator maintenance rather
   than promising unlimited autonomous collection.

## Access, scope and cost

No new paid model, search subscription or infrastructure was enabled. Daily bridge
work uses the existing Pi agent and existing CI. Existing hosted validation still
runs for changed candidates; no claim is made about unused account allowance or
an independently verified zero-dollar bill. Any new provider/account, paid lookup,
registration or cost-bearing expansion requires an estimate and approval first.
Sources are indexed in the existing bounded catalog; a configured endpoint can
remain pending, failed or partial. MCP source status and original snapshots expose
that distinction. No AI-generated cross-framework mapping is presented as official.
