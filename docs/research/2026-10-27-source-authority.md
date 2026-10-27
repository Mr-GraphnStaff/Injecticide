# Official-source and standards coverage

Source review: 2026-10-27. This register records research coverage, not a release
acceptance, successful collection of every seed, or completed scanner remediation.

## Source authority

| Evidence | Primary publisher / collection source | Permitted interpretation |
| --- | --- | --- |
| Runtime compatibility | Existing OpenAI, Claude, Gemini CLI and Copilot product documentation profiles | Apply only to the named product and reviewed version; unknown constraints stay unknown |
| Vendor validation | OpenAI and Anthropic `skill-creator` Python validators; Gemini CLI built-in `validate_skill.cjs`; GitHub CLI `gh skill publish` documentation | Basic format checks; a validator result alone does not establish security or runtime acceptance |
| Portable format | Agent Skills specification and `skills-ref` source/README | Reference implementation comparison; README explicitly says demonstration-only, not for production |
| LLM and agent security | OWASP LLM Top 10, Agentic Applications Top 10, Agentic Skills Top 10 | Risk categories and mitigation guidance; require a measurable detector and applicable evidence before a finding |
| AI risk governance | NIST AI RMF and final NIST AI 600-1 publication landing page | Governance guidance, not skill field limits or automatic certification |
| Threat taxonomy | MITRE ATLAS release manifest and current content export | Map verified behavior to techniques; taxonomy membership does not prove malicious intent |
| MCP security | Official MCP security best practices and CoSAI/OASIS MCP security whitepaper | Protocol-specific security guidance; not a universal skill format gate |
| Advisories and research | Existing GitHub advisory connectors, official tool releases, arXiv and Crossref | Discovery/evidence candidates; preprints and release notices do not establish verified exploits |

Official validator source URLs are separate `validator-*` sources in
`research_mcp/sources.json`. They are fetched as text, never installed or executed
by Research MCP. Tracking upstream `main` detects change; using executable code
requires a separately reviewed immutable revision/hash and tests. Local installed
skill scripts are not assumed to match current upstream versions.

Every configured source declares
`evidence_policy: research_only_requires_review_before_enforcement`. This is
source metadata, not a new enforcement engine. The current requirements service
continues to gate its own documented checks on fresh, unchanged reviewed evidence.
Static scanner rules still require a separate applicability/freshness audit.

## Conflicts and limits

Vendor docs, vendor validators and portable specifications can disagree. Keep
both results with their product scope and source revision; do not combine their
strictest checks into a universal rejection rule. For example, the reviewed
OpenAI validator's allowed field set omits `compatibility`, while Anthropic's
validator and the portable specification include it.

No stale, unavailable or conflicting source should establish a vendor
compatibility failure. Report that compatibility could not be verified. Retain
independently observed security findings separately. A recommendation, reference
implementation limitation or local policy must be labeled as such.

MITRE `dist/ATLAS.yaml` is deprecated. Raw GitHub `ATLAS-latest.yaml` files contain
symlink target text, so collection explicitly targets `dist/v6/ATLAS-2026.09.yaml`
and `dist/manifest.yaml`. A manifest change requires reviewing and advancing the
content URL; fetching symlink text is not full threat coverage.

NIST landing-page collection does not extract the linked PDF's controls. MCP's
dated documentation URL is reviewed when the protocol version changes. These
are explicit coverage limits, not successful standards audits.

The expanded registry has 42 sources and 61 seed URLs. Collection remains bounded
to 40 document attempts per cycle and rotates source order. An hourly worker
does not guarantee every URL is successfully refreshed every hour. Report
per-document last-success timestamps, errors and pending review, rather than
using worker liveness as evidence that requirements are current.

## Remaining remediation

- Integrate reviewed, pinned official validators as separate scoped results;
  the new collection targets alone do not run them in package scans.
- Review current vendor document drift and update affected constraints/tests.
- Make all static format findings distinguish structural errors from unverified
  product compatibility constraints; add false-rejection regression coverage.
- Verify full-read/chunk-marker handling without suppressing security findings.
- Validate the candidate on the Pi before calling the deployed service corrected.

## Candidate verification

- `python -m pytest tests/test_research_mcp.py tests/test_vendor_requirements.py -q`:
  62 passed, 3 skipped. Includes public-address fallback, mixed private/public DNS
  rejection, TLS failure, approved-source scoping and research-text handling.
- A separate local temporary catalog fetched all nine new seed URLs across the
  seven new sources: 9 attempts, 9 retained initial snapshots, zero failures.
  This was the bounded collector, including its robots checks, not a browser-only
  reachability test. It is not deployment verification.
- Reviewed the full retrieved OpenAI, Anthropic and Gemini validator scripts,
  then ran them on controlled valid, malformed and `compatibility` fixtures.
  All three accepted the valid example and rejected malformed metadata. OpenAI
  rejected the compatibility example; Anthropic and Gemini accepted it. These
  are fixture results, not production scanner integration or an uploaded-work audit.
- Temporary raw snapshots, hashes, retrieval timestamps and fixture output are
  under `tmp/official-source-review/`; they are local evidence, not committed
  third-party code or a new production dependency.
