# Obsession delivery boundaries

Obsession captures and prioritizes research evidence. The research container has
no GitHub credentials, repository mount, Docker socket or publication authority.
Its read-only loopback export is input to a separate host-side delivery bridge.
A valid checksum establishes immutable identity; it does not prove a fetch or
approve a change. The bridge independently validates shipped policy and matches
new payloads against a fresh export whose service-side admission checks retained
snapshot hashes and freshness.

## Daily job

The existing Azure pipeline schedules one run at 11:00 UTC daily on master. The
scheduled run uses the existing Raspberry Pi private agent and skips hosted
validation/build jobs. A host `flock` serializes scheduled deliveries. There are
no model calls, paid scanners or new hosted services. Existing storage, compute,
public-source requests and GitHub/Azure quotas still apply; this is not a promise
of unlimited free infrastructure.

`python3 tools/obsession_delivery.py daily --required-check "Injecticide-CI-CD (Validate candidate Tests and container builds)"`

The job requires a clean dedicated checkout of current origin/master, an isolated requirements-keyed Python virtual environment cached in the existing
agent tools directory (prepared by the job), the local research service on 127.0.0.1:8200 and the
existing repository checkout credential with PR permissions. Missing credentials,
unavailable export, stale evidence, malformed schema or failed tests produce an
explicit unavailable/error outcome; they do not silently activate anything.
Credentials stay in the host process and never enter research content or logs.
Fixed API endpoints ignore environment proxies and reject redirects so authorization cannot cross origins.

Only high-priority automatic candidates can append data to these paths:

- `research_mcp/obsession_updates.json`: schema 1, `updates` list of immutable
  exported candidates; maximum 256 entries.
- `skill_sandbox/rules/obsession_signatures.json`: schema 1, bounded signatures
  validated by the literal-only loader, copied exactly from an approved recipe.

The reference index is evidence bookkeeping. It does not change scanner logic.
Literal recipes require paired positive/negative examples and explicit shipped
policy authority. The initial recipe allowlist is empty; changed prose does not
automatically invent new detectors. Literal matches remain contextual review
indicators, not a maliciousness verdict. Medium/low and other review candidates remain in the durable research queue.
An explicit local CLI Implement decision can prepare a separate supported-template
PR marked HUMAN REVIEW REQUIRED; it cannot automatically merge or deploy.
Investigate and Reject do not prepare a patch. Arbitrary new-code proposals
remain manual engineering work, rather than pretending to generate safe code.

The bridge follows bounded export pagination even when filtered pages are empty,
rejects nonadvancing cursors, stages only the two JSON files, and runs the fixed
full pytest suite before committing or pushing. Research data never supplies a
command, test filename, branch name, URL endpoint or executable patch. A failure
leaves the candidate unpushed for inspection; the next clean scheduled checkout
is the recovery boundary. It does not automatically delete existing PR branches.

## Exact revision gates

Scoped PR branches use `codex/obsession-auto-<digest>`. A subsequent daily run
revalidates their actual base/head JSON against current local exports. It merges
only after the exact head SHA has the successful validation-job check from
Azure Pipelines application ID 9426, pipeline definition 9, the configured
DAF-TECH project GUID and matching build URL. Queued/in-progress, missing, failed,
wrong-producer or wrong-revision checks cannot qualify. Published commit statuses
must also succeed. The bridge additionally requires strict up-to-date master branch protection,
enforced for admins, with the exact named check bound to Azure application ID
9426. Missing protection or an unreadable protection policy blocks automatic
merge; a successful standalone check is insufficient. The merge request pins the
head SHA and respects repository protection; base movement detected before merge stops delivery.

After merge, the regular full validation stage still runs the complete tests and
builds all three container candidates. The Pi independently qualifies the exact
master SHA: only the two append-only JSON transitions can receive an automatic
qualification output, and every added candidate must still match fresh evidence
and current policy. Locally reviewed supported-template changes classify as
human approval required, even when their exact evidence is valid. The automatic deployment job checks that output SHA and
revalidates again immediately before invoking the existing trusted deployment
wrapper. PR and scheduled runs cannot deploy directly.

Broader changes receive an explicit ineligible classification and use the
existing `injecticide-pi-production` protected environment for human approval.
A failed qualification is different from a broader change: it blocks both routes.
The initial feature release changes code/pipeline authority and requires normal
human review; it cannot qualify through its own narrow automatic lane.

## Durable host outcomes

The bridge atomically writes receipts with exact SHA, proposal hashes and outcome
to the agent-owned `~/.local/state/injecticide-obsession` directory (0700 on Pi;
individual files 0600). These survive checkout cleanup. Receipts explicitly say
`queue_delivery_audit: not_updated_host_receipt_only`: the bridge has no privileged
Docker permission or remote research-write endpoint. Research queue delivery
status must be reconciled through its separately authorized local control CLI;
host receipt persistence is not falsely reported as a queue DB update.

## Evidence and limits

`python -m pytest -q tests/test_obsession_delivery.py` exercises synthetic
proposals and stubbed GitHub/CI responses. It checks tampering, stale export
admission, scope boundaries, append-only manifests, review priorities, pagination,
redirect refusal, exact SHA/pipeline identity, merge races and YAML deployment
gates. These tests neither publish a PR nor prove live credentials, approval
configuration, scheduled execution or runtime effectiveness. Live acceptance
requires observing one exact candidate through PR CI, merge, qualification and
trusted deployment, with durable outcomes retained.
