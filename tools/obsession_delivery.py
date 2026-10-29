"""Host-side, bounded Obsession delivery. Research content never supplies commands."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
import urllib.error
import urllib.request
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ALLOWED = {"research_mcp/obsession_updates.json", "skill_sandbox/rules/obsession_signatures.json"}
REPOSITORY = "Mr-GraphnStaff/Injecticide"
BASE = "master"
MAX_BYTES = 2_000_000


class DeliveryError(ValueError):
    """A delivery prerequisite failed; no broader permission is inferred."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def git(*arguments, cwd=ROOT):
    result = subprocess.run(["git", *arguments], cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        # Git stderr may contain an authenticated URL/header; never echo it.
        raise DeliveryError("Git operation failed: " + arguments[0])
    return result.stdout.strip()


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        raise DeliveryError("Redirect refused at fixed delivery endpoint")


def request_json(url, *, headers=None, data=None, method=None):
    request = urllib.request.Request(url, headers=headers or {}, data=None if data is None else canonical(data), method=method)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects).open(request, timeout=20) as response:
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise DeliveryError("Remote prerequisite failed (HTTP " + str(error.code) + ")") from None
    except urllib.error.URLError:
        raise DeliveryError("Required local/export or GitHub service unavailable") from None
    if len(body) > MAX_BYTES:
        raise DeliveryError("Response exceeds delivery budget")
    return json.loads(body)


def export_candidates():
    """Fixed loopback endpoint: no user-selected URL or research-container credential."""
    items, cursor = [], 0
    for _ in range(50):
        result = request_json("http://127.0.0.1:8200/obsession/export?after_id=" + str(cursor) + "&limit=100")
        if not isinstance(result, dict) or result.get("schema_version") != 1 or not isinstance(result.get("items"), list):
            raise DeliveryError("Unsupported Obsession export schema")
        if len(result["items"]) > 100:
            raise DeliveryError("Export page candidate budget exceeded")
        items.extend(result["items"])
        next_cursor = result.get("next_after_id")
        if next_cursor is None:
            return items
        if type(next_cursor) is not int or next_cursor <= cursor:
            raise DeliveryError("Export cursor did not advance")
        cursor = next_cursor
    raise DeliveryError("Export exceeds 5000-item scan budget; human queue maintenance required")


def changed_paths(base, head="HEAD", cwd=ROOT):
    return set(filter(None, git("diff", "--name-only", base, head, cwd=cwd).splitlines()))


def assert_clean(cwd=ROOT):
    if git("status", "--porcelain", "--untracked-files=all", cwd=cwd):
        raise DeliveryError("Delivery requires an entirely clean dedicated checkout")
    if git("remote", "get-url", "origin", cwd=cwd) not in {"https://github.com/" + REPOSITORY, "https://github.com/" + REPOSITORY + ".git"}:
        raise DeliveryError("Unexpected delivery repository")


def github_headers(cwd=ROOT):
    """Use only the existing repository-scoped checkout header, held in memory."""
    keys = ("http.https://github.com/" + REPOSITORY + ".git.extraheader",
            "http.https://github.com/" + REPOSITORY + ".extraheader",
            "http.https://github.com/.extraheader")
    header = ""
    for key in keys:
        result = subprocess.run(["git", "config", "--get", key], cwd=cwd, capture_output=True, text=True)
        header = result.stdout.strip()
        if header:
            break
    if not re.fullmatch(r"(?i)AUTHORIZATION: basic [A-Za-z0-9+/=]+", header):
        raise DeliveryError("Existing checkout GitHub PR credential unavailable; candidate cannot be published")
    return {"Authorization": header.split(":", 1)[1].strip(), "Accept": "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"}


def trusted_ci(run, sha):
    """Pin the observed Azure application, definition, project and build URL."""
    app = run.get("app", {})
    match = re.fullmatch(r"9\|([0-9]+)\|2a547add-01ad-454b-8b55-35c98e76eb53", run.get("external_id", ""))
    url = urlsplit(run.get("details_url", ""))
    return bool(app.get("slug") == "azure-pipelines" and app.get("id") == 9426
                and run.get("head_sha") == sha and match
                and url.scheme == "https" and url.netloc == "dev.azure.com"
                and url.path == "/DAF-TECH/2a547add-01ad-454b-8b55-35c98e76eb53/_build/results"
                and parse_qs(url.query).get("buildId") == [match.group(1)])


class GitHub:
    def __init__(self, headers):
        self.headers = headers

    def api(self, route, data=None, method=None):
        return request_json("https://api.github.com/repos/" + REPOSITORY + route, headers=self.headers, data=data, method=method)

    def publish_pr(self, branch, head_sha, automatic=True):
        owner = REPOSITORY.split("/")[0]
        existing = self.api("/pulls?state=open&base=master&head=" + owner + ":" + branch)
        if existing:
            pull = existing[0]
            if pull["head"]["sha"] != head_sha:
                raise DeliveryError("Existing PR head differs from tested candidate")
            return pull
        return self.api("/pulls", {"title": "Obsession: verified scoped evidence update" if automatic else "Obsession review required: locally approved evidence", "head": branch, "base": BASE,
            "body": ("HIGH AUTOMATIC LANE. " if automatic else "HUMAN REVIEW REQUIRED. Locally reviewed Implement decision prepares this PR; automatic merge/deployment is forbidden. ") + "Updates only the bounded reference index or approved literal signatures. Local fixed tests passed. Automatic eligibility is revalidated independently before merge and deployment; medium/low proposals remain research-only."}, "POST")

    def protected_ruleset(self, required_check):
        """Read effective rules using the existing App's metadata permission."""
        effective = self.api("/rules/branches/master")
        if not isinstance(effective, list) or len(effective) > 100:
            return False
        for rule in effective:
            parameters = rule.get("parameters", {})
            checks = parameters.get("required_status_checks", [])
            if (rule.get("type") != "required_status_checks"
                    or parameters.get("strict_required_status_checks_policy") is not True
                    or not any(check.get("context") == required_check and check.get("integration_id") == 9426 for check in checks)):
                continue
            ruleset_id = rule.get("ruleset_id")
            if type(ruleset_id) is not int or ruleset_id <= 0 or rule.get("ruleset_source_type") != "Repository" or rule.get("ruleset_source") != REPOSITORY:
                continue
            policy = self.api("/rulesets/" + str(ruleset_id))
            if (policy.get("id") != ruleset_id or policy.get("name") != "Injecticide-validated-master"
                    or policy.get("target") != "branch" or policy.get("enforcement") != "active"
                    or policy.get("source_type") != "Repository" or policy.get("source") != REPOSITORY
                    or policy.get("bypass_actors") != []
                    or policy.get("conditions") != {"ref_name": {"include": ["refs/heads/master"], "exclude": []}}):
                continue
            for definition in policy.get("rules", []):
                if (definition.get("type") == "required_status_checks" and definition.get("parameters") == parameters):
                    return True
        return False

    def merge_if_verified(self, pull, required_check, base_sha):
        """No bypass: require exact head, scoped diff and the named trusted CI success."""
        sha = pull["head"]["sha"]
        if not self.protected_ruleset(required_check):
            raise DeliveryError("Automatic merge requires an active exact-master ruleset without bypass actors and a strict Azure check bound to app 9426")
        latest = self.api("/pulls/" + str(pull["number"]))
        if latest["head"]["sha"] != sha or latest["base"]["ref"] != BASE or latest["base"]["sha"] != base_sha:
            raise DeliveryError("PR changed during verification")
        files = self.api("/pulls/" + str(pull["number"]) + "/files?per_page=100")
        if not files or len(files) >= 100 or any(item["filename"] not in ALLOWED or item.get("status") != "modified" for item in files):
            raise DeliveryError("PR exceeds automatic JSON-only scope")
        checks = self.api("/commits/" + sha + "/check-runs?per_page=100")
        runs = checks.get("check_runs", [])
        named = [run for run in runs if run.get("name") == required_check]
        if not required_check or len(runs) >= 100 or not named or any(run.get("status") != "completed" or run.get("conclusion") != "success" for run in named):
            return {"state": "waiting_for_exact_sha_ci", "sha": sha}
        # Require the Azure Pipelines App origin, not a similarly named arbitrary check.
        if any(not trusted_ci(run, sha) for run in named):
            raise DeliveryError("Required CI check has an untrusted producer")
        status = self.api("/commits/" + sha + "/status")
        if status.get("total_count", 0) and status.get("state") != "success":
            return {"state": "waiting_for_commit_statuses", "sha": sha}
        if any(run.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required"} for run in runs):
            return {"state": "checks_failed", "sha": sha}
        if self.api("/git/ref/heads/master")["object"]["sha"] != base_sha:
            raise DeliveryError("Base changed after candidate qualification")
        result = self.api("/pulls/" + str(pull["number"]) + "/merge", {"sha": sha, "merge_method": "squash"}, "PUT")
        return {"state": "merged" if result.get("merged") else "protected_merge_pending", "sha": sha}


def write_json(path, value):
    if path.relative_to(ROOT).as_posix() not in ALLOWED or path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
        raise DeliveryError("Output path outside fixed delivery scope")
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def eligible_candidates(items, include_review=False):
    from research_mcp.obsession import validate_export_item
    accepted = {}
    for item in items:
        if not validate_export_item(item):
            raise DeliveryError("Export candidate failed local policy revalidation")
        payload = item["payload"]
        if (payload.get("gate") == "auto" and payload.get("priority") == "high") or (include_review and payload.get("gate") == "review" and item["decision"].get("state") == "implement"):
            accepted[item["sha256"]] = item
    return accepted


def validate_transition(before, after, eligible, allow_review=False):
    """Append-only data transition; immutable evidence and paired recipes only."""
    index_path = "research_mcp/obsession_updates.json"
    signature_path = "skill_sandbox/rules/obsession_signatures.json"
    old_index, new_index = before[index_path], after[index_path]
    old_manifest, new_manifest = before[signature_path], after[signature_path]
    for value, collection in [(old_index, "updates"), (new_index, "updates"), (old_manifest, "signatures"), (new_manifest, "signatures")]:
        if not isinstance(value, dict) or set(value) != {"schema_version", collection} or value["schema_version"] != 1 or not isinstance(value[collection], list):
            raise DeliveryError("Unexpected bounded data manifest schema")
    previous = old_index["updates"]
    updates = new_index["updates"]
    if len(updates) > 256 or updates[:len(previous)] != previous or len(updates) <= len(previous):
        raise DeliveryError("Reference index must append 1 or more entries within 256-entry budget")
    added = updates[len(previous):]
    hashes = [entry.get("sha256") for entry in updates]
    if len(set(hashes)) != len(hashes):
        raise DeliveryError("Duplicate immutable proposal")
    expected_signatures = []
    automatic = True
    for item in added:
        digest = item.get("sha256")
        if digest not in eligible or canonical(item) != canonical(eligible[digest]):
            raise DeliveryError("Added proposal no longer matches fresh locally verified export")
        if item["payload"]["gate"] != "auto" or item["payload"]["priority"] != "high":
            if not allow_review or item["payload"]["gate"] != "review" or item["decision"].get("state") != "implement":
                raise DeliveryError("Review proposals cannot enter the automatic lane")
            automatic = False
        if item["payload"]["kind"] == "literal_signature":
            expected_signatures.append(item["payload"]["proposal"])
        elif item["payload"]["kind"] != "reference_update":
            raise DeliveryError("Unsupported automatic proposal kind")
    if new_manifest["signatures"] != old_manifest["signatures"] + expected_signatures:
        raise DeliveryError("Signature transition differs from approved paired recipes")
    from skill_sandbox.obsession_signatures import validate_manifest
    validate_manifest(new_manifest)
    return {"eligible": automatic, "added": len(added), "proposal_sha256": [item["sha256"] for item in added]}


def read_manifests(revision="HEAD"):
    return {path: json.loads(git("show", revision + ":" + path)) for path in sorted(ALLOWED)}


def qualify_revision(base, head, eligible, allow_review=False):
    paths = changed_paths(base, head)
    if not paths or not paths <= ALLOWED:
        raise DeliveryError("Automatic delivery permits only the two bounded JSON files")
    return validate_transition(read_manifests(base), read_manifests(head), eligible, allow_review=allow_review)


def qualify_commit(require_eligible=False):
    assert_clean()
    sha = git("rev-parse", "HEAD")
    if os.environ.get("BUILD_SOURCEBRANCH") != "refs/heads/master" or os.environ.get("BUILD_SOURCEVERSION") != sha:
        raise DeliveryError("Automatic deployment requires exact validated master SHA")
    if os.environ.get("BUILD_REASON") in {"PullRequest", "Schedule"}:
        raise DeliveryError("PR and scheduled runs cannot deploy directly")
    paths = changed_paths("HEAD^", "HEAD")
    if not paths or not paths <= ALLOWED:
        if require_eligible:
            raise DeliveryError("Expected automatic eligibility was not retained")
        print("##vso[task.setvariable variable=eligible;isOutput=true]false")
        return {"state": "broader_change_requires_human_environment_approval", "sha": sha}
    result = qualify_revision("HEAD^", "HEAD", eligible_candidates(export_candidates(), include_review=True), allow_review=True)
    if not result["eligible"]:
        if require_eligible:
            raise DeliveryError("Human-reviewed proposal cannot enter automatic deployment")
        print("##vso[task.setvariable variable=eligible;isOutput=true]false")
        return {**result, "state": "locally_reviewed_proposal_requires_human_environment_approval", "sha": sha}
    print("##vso[task.setvariable variable=qualified_sha;isOutput=true]" + sha)
    print("##vso[task.setvariable variable=eligible;isOutput=true]true")
    return {**result, "state": "qualified", "sha": sha}


def deliver(required_check):
    assert_clean()
    if git("rev-parse", "HEAD") != git("rev-parse", "origin/master"):
        raise DeliveryError("Daily checkout is not current origin/master")
    if os.environ.get("BUILD_REASON") != "Schedule" or os.environ.get("BUILD_SOURCEBRANCH") != "refs/heads/master":
        raise DeliveryError("Daily delivery runs only from the scheduled master pipeline")
    exported = export_candidates()
    eligible = eligible_candidates(exported)
    reviewed = eligible_candidates(exported, include_review=True)
    github = GitHub(github_headers())
    # Revisit earlier proposals only after current policy and evidence revalidation.
    pending = github.api("/pulls?state=open&base=master&per_page=100")
    if len(pending) >= 100:
        raise DeliveryError("Open PR enumeration budget exceeded")
    outcomes = []
    for pull in pending:
        branch = pull["head"]["ref"]
        if not re.fullmatch(r"codex/obsession-auto-[a-f0-9]{20}", branch) or pull["head"].get("repo", {}).get("full_name") != REPOSITORY:
            continue
        sha = pull["head"]["sha"]
        if not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise DeliveryError("Invalid PR revision")
        git("fetch", "--no-tags", "origin", sha)
        try:
            qualify_revision("origin/master", sha, eligible)
        except DeliveryError:
            outcomes.append({"number": pull["number"], "state": "review_required_stale_or_ineligible"})
            continue
        outcome = github.merge_if_verified(pull, required_check, git("rev-parse", "origin/master"))
        outcomes.append({"number": pull["number"], **outcome})
        if outcome["state"] == "merged":
            return {"state": "merged_pending_protected_pipeline", "results": outcomes}
    before = read_manifests()
    seen = {entry["sha256"] for entry in before["research_mcp/obsession_updates.json"]["updates"]}
    added = [item for digest, item in sorted(eligible.items()) if digest not in seen][:20]
    automatic = bool(added)
    if not added:
        added = [item for digest, item in sorted(reviewed.items()) if digest not in seen and item["payload"]["gate"] == "review"][:20]
    if not added:
        return {"state": "no_new_eligible_proposals", "results": outcomes}
    after = json.loads(json.dumps(before))
    after["research_mcp/obsession_updates.json"]["updates"].extend(added)
    after["skill_sandbox/rules/obsession_signatures.json"]["signatures"].extend(item["payload"]["proposal"] for item in added if item["payload"]["kind"] == "literal_signature")
    qualification = validate_transition(before, after, reviewed, allow_review=not automatic)
    digest = hashlib.sha256(canonical(qualification["proposal_sha256"])).hexdigest()[:20]
    branch = ("codex/obsession-auto-" if automatic else "codex/obsession-review-") + digest
    matching = next((pull for pull in pending if pull["head"]["ref"] == branch), None)
    if matching:
        return {"state": "existing_pr_pending", "sha": matching["head"]["sha"], "pull_request": matching["html_url"], "results": outcomes}
    git("checkout", "-b", branch)
    for path, value in after.items():
        write_json(ROOT / path, value)
    # No recipe-derived shell, test path, install command or model call is executed.
    result = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT)
    if result.returncode:
        raise DeliveryError("Fixed local test suite failed; proposal remains unpushed")
    paths = set(filter(None, git("diff", "--name-only").splitlines()))
    if not paths or not paths <= ALLOWED or git("ls-files", "--others", "--exclude-standard"):
        raise DeliveryError("Test run changed files outside the scoped candidate")
    git("add", "--", *sorted(paths))
    git("-c", "user.name=Injecticide Obsession", "-c", "user.email=obsession@users.noreply.github.com", "commit", "-m", "Obsession: append locally verified evidence")
    sha = git("rev-parse", "HEAD")
    qualify_revision("origin/master", sha, reviewed, allow_review=not automatic)
    git("push", "origin", "HEAD:refs/heads/" + branch)
    pull = github.publish_pr(branch, sha, automatic=automatic)
    return {"state": "pr_created_waiting_exact_sha_ci" if automatic else "review_pr_created_requires_human_acceptance", "sha": sha, "pull_request": pull["html_url"], "proposal_sha256": qualification["proposal_sha256"], "results": outcomes}


def write_receipt(result, directory=None):
    """Agent-owned host audit; never claim this updates the research queue DB."""
    directory = Path.home() / ".local" / "state" / "injecticide-obsession" if directory is None else Path(directory)
    if directory.is_symlink():
        raise DeliveryError("Receipt directory must not be a symlink")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(directory, 0o700)
    receipt = {"schema_version": 1, "observed": datetime.now(timezone.utc).isoformat(), "outcome": result,
               "queue_delivery_audit": "not_updated_host_receipt_only"}
    content = canonical(receipt)
    name = hashlib.sha256(content).hexdigest() + ".json"
    descriptor, temporary = tempfile.mkstemp(prefix=".receipt-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(content + b"\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, directory / name)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return directory / name


def preflight():
    """Read existing installation capabilities without publication or mutation."""
    github = GitHub(github_headers())
    repository = github.api("")
    permissions = repository.get("permissions", {})
    effective = github.api("/rules/branches/master")
    required_check = "Injecticide-CI-CD (Validate candidate Tests and container builds)"
    visible = False
    strict = False
    selected = False
    for rule in effective if isinstance(effective, list) else []:
        parameters = rule.get("parameters", {})
        checks = parameters.get("required_status_checks", [])
        if (rule.get("type") != "required_status_checks" or rule.get("ruleset_source_type") != "Repository"
                or rule.get("ruleset_source") != REPOSITORY or type(rule.get("ruleset_id")) is not int):
            continue
        if parameters.get("strict_required_status_checks_policy") is not True or not any(check.get("context") == required_check and check.get("integration_id") == 9426 for check in checks):
            continue
        strict = True
        policy = github.api("/rulesets/" + str(rule["ruleset_id"]))
        if policy.get("name") == "Injecticide-validated-master":
            selected = True
            visible = isinstance(policy.get("bypass_actors"), list)
    return {"state": "readonly_preflight", "repository_pull": permissions.get("pull") is True,
            "repository_push": permissions.get("push") is True, "repository_admin": permissions.get("admin") is True,
            "strict_validation_present": strict, "selected_ruleset_present": selected,
            "bypass_actor_visibility": visible, "automatic_ruleset_gate_satisfied": github.protected_ruleset(required_check)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["daily", "qualify-commit", "preflight"])
    parser.add_argument("--required-check", default="")
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args()
    try:
        write_receipt({"state": "started", "command": args.command, "sha": git("rev-parse", "HEAD")})
        result = preflight() if args.command == "preflight" else deliver(args.required_check) if args.command == "daily" else qualify_commit(args.require_eligible)
        write_receipt(result)
        print(json.dumps(result, sort_keys=True))
    except (DeliveryError, ValueError, OSError) as error:
        failure = {"state": "unavailable", "reason": str(error)}
        try:
            write_receipt(failure)
        except (OSError, DeliveryError):
            failure["receipt"] = "unavailable"
        print(json.dumps(failure))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
