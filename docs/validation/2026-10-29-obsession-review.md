# ObsessionMCP independent security and QA review

Date: 2026-10-29. Reviewer: separate assurance agent Lena, reporting to Avery; David is team lead. Branch: `codex/obsession-mcp-0-14`, checkout `C:/Users/DavidFarris/.codex/worktrees/scanner-context-map-0-13/Injecticide`.

Status: final independent scoped code review recorded below; live operational acceptance remains pending. This is not human PR acceptance, deployment confirmation or proof of autonomous operation. The reviewer may edit this report only; production changes belong to the implementers. No outbound private upload, paid provider, repository publication or remote mutation was performed by this reviewer.

## Boundaries required of the implementation

- Public research is untrusted data. Articles cannot designate their own confidence, reviewer, approval, destination path, code template or deployment action. Locally configured provenance roles, deterministic classification and trusted templates govern eligibility.
- Preserve source ID, requested and final canonical URL, retrieval time, body hash, local classifier/template/scanner version and original evidence. Every redirect must remain within the approved scope. Origin authority and source currency are separate from whether a technique actually applies to this scanner.
- Restrict automatic changes to a small, reviewed literal-signature schema. No arbitrary regular expressions, Python, shell, YAML policies or executable fragments from Internet content. Bound signature count/length/normalization/scan input and matching work. Literal findings establish their measured pattern only, not a newly proved vulnerability or broad intent judgment.
- Classify Implement / Investigate / Reject using local gates, preserve reasons and unknowns. High confidence must mean specified evidence sufficiency, not a claim of universal correctness. Medium/low proposals stay visible without author-controlled self-promotion.
- Bind every review, validation and delivery decision to exact proposal content, source evidence, template and scanner/base revision hashes. Edits or changed dependencies invalidate stale approvals. Use transactional state transitions, explicit compare-and-swap preconditions and idempotency keys to prevent two workers delivering competing versions.
- Keep MCP/web interfaces read-only for review/activation. Local CLI review authority belongs to the trusted host operator, with restrictive filesystem permissions; a user-supplied reviewer string alone is not authentication. Preserve durable ordered audit records for candidate creation, review, validation, rejection, delivery attempts and receipts. State mutation and its audit event must commit atomically.
- Separate the Internet-facing research collector from the privileged delivery bridge. No Git write token, production checkout, Docker socket, host commands or deployment credentials in the research container. The bridge uses fixed reviewed paths/commands and rejects unsafe or author-selected destinations.
- Deliver only from a dedicated clean worktree/staging tree under a lock, with exact origin, branch/base SHA, proposal digest and expected output inventory checked before mutation. Refuse dirty/stale state. Require successful trusted CI for the exact delivered SHA; never interpret the latest unrelated green run as approval. Deployment remains through the existing trusted production pipeline, with rollback evidence.
- New model/API/GPU/cloud spend requires David's notice before activation, including provider/account, expected input volume, estimate and cap. Free-source retrieval and existing infrastructure are not proof of zero operating resource cost. No credentials or private skill content should be sent to a new service implicitly.

## Existing controls actually inspected

`docker-compose.yml` configures the research worker read-only, UID 10001 in its Dockerfile, dropped capabilities, no-new-privileges, a bounded noexec tmpfs, 256 MiB, 0.5 CPU and 64 PIDs. It has a dedicated data volume and loopback-bound host port; preserve these isolation properties. This is source inspection, not a check of current live container settings.

`research_mcp/fetch.py` accepts bounded public HTTPS retrieval, disallows credentials/custom ports, validates source path scope and redirects, checks all DNS answers are public and connects to a pinned address with TLS hostname validation. It does not execute downloaded content. The feature must reuse this boundary instead of introducing a second uncontrolled client.

`azure-pipelines.yml` validates tests/Compose/container builds, then permits the production stage only after success on master outside a PR. It passes `Build.SourceVersion` to a fixed root-owned deploy wrapper. `deploy/pi/injecticide-deploy` validates one full SHA, the approved remote, master reachability, a deployment lock and health/rollback. The wrapper does not independently query CI; trusted pipeline invocation provides that connection.

Pre-existing limitation: the deploy wrapper's cleanliness check explicitly ignores untracked files (`--untracked-files=no`). Untracked/ignored files in a Docker build context can defeat a claim that the built filesystem contains only tracked bytes at the requested SHA. Do not use the production checkout as a research write area; the new bridge needs stricter cleanliness and an isolated staging context. Installed wrapper contents, branch protections and Azure environment approvals have not been inspected by this reviewer and remain unverified.

## Initial acceptance plan (recorded before final implementation review)

| Criterion | Required negative/positive evidence | Current result |
| --- | --- | --- |
| Internet authority isolation | Content claiming approved/high/confidence cannot mutate gate or reviewers; unknown sources fail closed | Not checked |
| Provenance | Wrong source scope, final redirect, modified hash and stale source snapshot refused | Not checked |
| Template/matcher bounds | Regex metacharacters remain literals; long/repeated input bounded; invalid count/length/Unicode rejected explicitly | Not checked |
| Review authorization | Read MCP has no mutation; local CLI enforces exact current identity/hash; rejected/stale approvals cannot deliver | Not checked |
| Audit and races | Concurrent/duplicate review/delivery cannot skip state; rollback/error leaves durable event | Not checked |
| Delivery isolation | Dirty/untracked checkout, wrong origin/base/branch, external path, failed CI and wrong-SHA CI refused | Not checked |
| Legitimate operation | Trusted source candidate reaches appropriate queue; gated literal artifact preserves provenance and existing scan behaviors | Not checked |
| Costs | No new paid calls or private uploads; configured budgets and activation boundaries visible | Source constraints sent; final diff pending |

The final review and actual outcomes are recorded below. This table preserves the initial plan; its initial Not checked entries are superseded by the final outcome. Prior 0.13 scanner/map checks do not certify this separate feature.

## Final independent scoped review

The final core, literal template and delivery bridge were inspected after their authors declared those files stable. This report is authored by an independent reviewer; it is not authorship of the production implementation or submitted tests. The implementation now preserves the main authority boundary: initial/unverified/community material stays queued; current changed allowlisted source evidence can update the evidence index; new literal signatures require a shipped reviewed recipe; a local Implement decision may prepare a human-review PR but does not grant the automatic deployment lane.

**Code-review result:** no unresolved release-blocking defect was observed within the reviewed, locally exercised scope. Operational acceptance remains conditional on the actual deployed MCP transport, checkout credentials, branch/environment protections, scheduled runner and end-to-end exact-candidate pipeline evidence. This is not David's PR acceptance, live deployment confirmation, a claim of general scanner superiority, or proof that every research item is accurate.

### Findings corrected during review

- The first signature example validator used Unicode casefold substring semantics while the production matcher used escaped regex with IGNORECASE. A concrete `credential Straße` / `credential STRASSE` positive was accepted but did not match. Both recipe and scanner controls now use production matcher semantics; the nonmatching Unicode pair is rejected.
- The first credentialed delivery HTTP client inherited redirect forwarding. An offline standard-library probe confirmed a synthetic Authorization header was copied to another origin. The client now rejects redirects and bypasses environment proxies, including for its trusted loopback evidence source.
- Delivery initially read only the first filtered export page, potentially starving eligible candidates after 100 queued entries. It now advances through empty filtered pages under a total 5000-item budget and rejects nonadvancing cursors.
- The draft manual deployment condition treated missing/failed qualification as merely not automatically eligible. Both deployment routes now require successful qualification; automatic deployment also binds its output SHA and rechecks eligibility immediately before the trusted wrapper. Explicit ineligibility and qualifier failure remain different outcomes.
- A seed-index `items` / bridge `updates` schema mismatch was reconciled. CI origin is pinned to the actual Azure app, project, definition, head SHA and build URL; similarly named checks cannot qualify. Review-lane proposals cannot piggyback into automatic merge/deployment. The final bridge also requires the live strict branch-protection policy described below before automatic merge.
- Core review and identical delivery receipt retries now use transactional conflict checks and durable audit events. Host bridge receipts are separate atomic agent-owned files; documentation explicitly says they do not update the research queue delivery audit.

### Checks actually performed

`python -m pytest tests/test_obsession_mcp.py tests/test_obsession_delivery.py tests/test_obsession_signatures.py -q -rs`: **77 passed, 1 skipped in 32.65 seconds**. The skipped MCP transport/tool registration case could not import the `mcp` SDK in this host Python environment. These are authored synthetic controls and stubbed GitHub/CI interactions; they make no remote PR, merge or deployment.

Additional independent inline checks used a temporary SQLite catalog and synthetic source bytes. Initial content claiming HIGH/approved remained queued; a current changed allowlisted reference became an evidence-index candidate without semantic-verification claims. A recomputed checksum on an unsupported arbitrary-code template did not grant authority. Two concurrent identical delivery receipts produced one audit event. A newer source snapshot immediately revoked export of the older item. A synthetic cross-origin credential redirect was refused without making a network request.

Independent template checks rejected 129 indicators, a 161-character literal and the Unicode nonmatching positive. An escaped literal containing `(a+)+$` did not act as a regex on a 2,000,001-character near-miss; the measured single local probe took 0.0094 seconds. This is one bounded authored performance check, not a general latency benchmark.

`git diff --check` passed with line-ending conversion notices only. Reviewed source identities:

| File | SHA-256 |
| --- | --- |
| `research_mcp/obsession.py` | `e2abaa6d26ab0f92287e0d4f248d972bfa6282b1bc468d69ab3cc63125794f73` |
| `research_mcp/obsession_policy.json` | `d9c2037f020f50c7c73beb304f98de7635caa5046d2c95325c03fe58e2707c50` |
| `skill_sandbox/obsession_signatures.py` | `3883c0680796e0c8a70c0166fa9b0ad745cd9a170380265329e645e9be2f98e9` |
| `tools/obsession_delivery.py` | `0edadb715c9ea1f7afe77c6dc31e6177acb51d35e19defc73664cb4056e01c84` |
| `azure-pipelines.yml` | `0ca3f9606c8b3f0944aaa17def83b38531442482d3a55d8e7ceebfb94cd9602b` |

### Acceptance matrix outcome and residual limits

The original design matrix is now locally satisfied for content authority isolation, current provenance checks, literal/template bounds, review-vs-auto separation, transactional review/receipt behavior, strict candidate paths, dirty checkout rejection and exact-SHA/trusted-CI gating. The MCP read-only tool exposure is supported by source inspection here; its runtime registration/transport remains untested in this host due to the missing SDK. Live source collection, current host/container settings and autonomous scheduled execution were not performed by this reviewer.

Local CLI authority relies on the trusted host/process and filesystem permissions. Audit rows and host receipts are durable application evidence, not tamper-proof records against a compromised host or database owner. Fresh local exports do not independently authenticate a fully compromised research service. The bounded templates and independent pipeline qualification limit that service's authority rather than proving its observations true.

The merge request pins the PR head SHA. The bridge additionally checks the current base before the merge request, but this is not an atomic head-and-base compare-and-swap: master can advance between that check and GitHub's merge operation. The final bridge now refuses automatic merge unless the live master protection response proves strict up-to-date checks, administrator enforcement and the exact Azure context bound to application 9426. Missing, unreadable or weaker protection blocks this lane; paired negative tests passed. The subsequent full master validation and exact merged-SHA qualification/deployment still protect deployment from using an unrelated validation result. Live protection settings were not queried by this reviewer; code availability must not be presented as operational activation.

The pre-existing production wrapper's untracked build-context limitation recorded above remains. Daily history is bounded: 256 evidence-index entries, a 5000-item delivery enumeration ceiling and the configured active queue/database limits require future maintenance rather than unlimited unattended growth. The initial signature recipe allowlist is empty; this release automatically records qualifying reference changes, not arbitrary invented detectors. Community issues/comments remain review material, not publisher endorsement or complete issue-history synchronization.

There were no new paid/model calls, private uploads, commits, outbound publication or remote mutations by this reviewer. New automatic PRs can consume existing GitHub/Azure quotas and Pi resources; live billing capacity and any need for purchased capacity are unverified. New paid activation still requires David's advance notice and approval. Full-suite, container, live MCP and pipeline evidence must be supplied separately by the coordinator/CI, with their actual revision and result.
