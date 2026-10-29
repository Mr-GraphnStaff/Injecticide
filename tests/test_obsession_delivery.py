"""Synthetic proposals and stubbed GitHub only; no remote publication/deploy."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from tools import obsession_delivery as delivery
from research_mcp.obsession import load_policy


INDEX = "research_mcp/obsession_updates.json"
SIGNATURES = "skill_sandbox/rules/obsession_signatures.json"
SHA = "a" * 40
BASE = "b" * 40
CHECK = "Injecticide-CI-CD (Validate candidate Tests and container builds)"


def item(priority="high", gate="auto"):
    policy = load_policy()
    provenance = {"source_id": policy["auto_reference_sources"][0], "url": "https://agentskills.io/specification",
        "final_url": "https://agentskills.io/specification", "snapshot_id": 2, "source_sha256": "c" * 64,
        "previous_sha256": "d" * 64, "retrieved": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}
    payload = {"schema_version": 1, "kind": "reference_update", "gate": gate, "priority": priority,
        "policy_sha256": hashlib.sha256(delivery.canonical(policy)).hexdigest(), "provenance": provenance,
        "proposal": {"source_id": provenance["source_id"], "url": provenance["final_url"], "source_sha256": provenance["source_sha256"],
                     "previous_sha256": provenance["previous_sha256"], "change_type": "source_content_changed"},
        "evidence": {"excerpt": "Synthetic skill specification text", "fetch_verified": True, "semantic_verification": "not_established"}}
    digest = hashlib.sha256(delivery.canonical(payload)).hexdigest()
    return {"sequence": 1, "id": "obsession-" + digest, "sha256": digest, "payload": payload,
            "decision": {"state": "auto_approved" if gate == "auto" else "implement", "reason": "Synthetic fixture", "updated": provenance["retrieved"]}}


def manifests(candidate=None):
    return {INDEX: {"schema_version": 1, "updates": [] if candidate is None else [candidate]},
            SIGNATURES: {"schema_version": 1, "signatures": []}}


def ci():
    return {"name": CHECK, "head_sha": SHA, "status": "completed", "conclusion": "success", "app": {"id": 9426, "slug": "azure-pipelines"},
            "external_id": "9|911|2a547add-01ad-454b-8b55-35c98e76eb53",
            "details_url": "https://dev.azure.com/DAF-TECH/2a547add-01ad-454b-8b55-35c98e76eb53/_build/results?buildId=911&view=logs"}


def test_high_auto_revalidated_and_append_only():
    candidate = item()
    accepted = delivery.eligible_candidates([candidate])
    result = delivery.validate_transition(manifests(), manifests(candidate), accepted)
    assert result["eligible"] and result["added"] == 1


def test_medium_low_never_automatically_activated():
    assert delivery.eligible_candidates([item("medium", "review"), item("low", "review")]) == {}


@pytest.mark.parametrize("change", ["hash", "source", "gate", "priority"])
def test_candidate_tampering_rejected(change):
    candidate = item()
    if change == "hash":
        candidate["sha256"] = "0" * 64
    else:
        candidate["payload"]["provenance"]["source_id"] = "attacker" if change == "source" else candidate["payload"]["provenance"]["source_id"]
        if change in {"gate", "priority"}:
            candidate["payload"][change] = "malformed"
    with pytest.raises(delivery.DeliveryError):
        delivery.eligible_candidates([candidate])


def test_fresh_export_digest_match_required():
    candidate = item()
    with pytest.raises(delivery.DeliveryError, match="fresh locally verified"):
        delivery.validate_transition(manifests(), manifests(candidate), {})


def test_existing_index_not_rewritten_or_deleted():
    candidate = item()
    with pytest.raises(delivery.DeliveryError, match="append"):
        delivery.validate_transition(manifests(candidate), manifests(), {})
    with pytest.raises(delivery.DeliveryError, match="append"):
        delivery.validate_transition(manifests(candidate), manifests(candidate), {})


def test_unapproved_signature_cannot_piggyback_reference_update():
    candidate = item()
    after = manifests(candidate)
    after[SIGNATURES]["signatures"].append({"id": "arbitrary-code"})
    with pytest.raises(delivery.DeliveryError, match="paired recipes"):
        delivery.validate_transition(manifests(), after, delivery.eligible_candidates([candidate]))


def test_duplicate_proposal_rejected():
    candidate = item()
    after = manifests(candidate)
    after[INDEX]["updates"].append(candidate)
    with pytest.raises(delivery.DeliveryError, match="Duplicate"):
        delivery.validate_transition(manifests(), after, delivery.eligible_candidates([candidate]))


def test_export_empty_pages_advance_to_later_high_item(monkeypatch):
    candidate = item()
    calls = []
    def request(url):
        calls.append(url)
        return {"schema_version": 1, "items": [], "next_after_id": 100} if len(calls) == 1 else {"schema_version": 1, "items": [candidate], "next_after_id": None}
    monkeypatch.setattr(delivery, "request_json", request)
    assert delivery.export_candidates() == [candidate]
    assert "after_id=100" in calls[1]


def test_export_repeated_cursor_fails(monkeypatch):
    monkeypatch.setattr(delivery, "request_json", lambda url: {"schema_version": 1, "items": [], "next_after_id": 0})
    with pytest.raises(delivery.DeliveryError, match="did not advance"):
        delivery.export_candidates()


def test_fixed_endpoint_redirects_refused():
    with pytest.raises(delivery.DeliveryError, match="Redirect refused"):
        delivery.NoRedirects().redirect_request(None, None, 302, "Found", {}, "https://attacker.invalid")


@pytest.mark.parametrize("field,value", [("head_sha", "c" * 40), ("external_id", "10|911|2a547add-01ad-454b-8b55-35c98e76eb53"),
    ("details_url", "https://attacker.invalid/?buildId=911"), ("app", {"id": 1, "slug": "azure-pipelines"})])
def test_trusted_ci_pins_exact_sha_pipeline_app_and_project(field, value):
    run = ci()
    assert delivery.trusted_ci(run, SHA)
    run[field] = value
    assert not delivery.trusted_ci(run, SHA)


class FakeGitHub(delivery.GitHub):
    def __init__(self):
        self.run = ci()
        self.base = BASE
        self.status = {"total_count": 0}
        self.files = [{"filename": INDEX, "status": "modified"}]
        self.merged = False
        parameters = {"strict_required_status_checks_policy": True, "required_status_checks": [{"context": CHECK, "integration_id": 9426}]}
        self.effective = [{"type": "required_status_checks", "ruleset_id": 123, "ruleset_source_type": "Repository", "ruleset_source": delivery.REPOSITORY, "parameters": parameters}]
        self.protection = {"id": 123, "name": "Injecticide-validated-master", "target": "branch", "enforcement": "active", "source_type": "Repository", "source": delivery.REPOSITORY, "updated_at": "2026-01-01T00:00:00Z",
            "bypass_actors": [], "conditions": {"ref_name": {"include": ["refs/heads/master"], "exclude": []}}, "rules": [{"type": "required_status_checks", "parameters": deepcopy(parameters)}]}
    def api(self, route, data=None, method=None):
        if route == "/rules/branches/master": return self.effective
        if route == "/rulesets/123": return self.protection
        if route.endswith("/merge"):
            self.merged = True
            assert data["sha"] == SHA
            return {"merged": True}
        if "/files?" in route:
            return self.files
        if "/check-runs?" in route:
            return {"check_runs": [self.run]}
        if route.endswith("/status"):
            return self.status
        if route == "/git/ref/heads/master":
            return {"object": {"sha": self.base}}
        return {"number": 1, "head": {"sha": SHA}, "base": {"ref": "master", "sha": BASE}}


def test_exact_sha_successful_trusted_ci_allows_scoped_merge():
    github = FakeGitHub()
    assert github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)["state"] == "merged"
    assert github.merged


@pytest.mark.parametrize("state", ["queued", "in_progress"])
def test_incomplete_ci_never_merges(state):
    github = FakeGitHub(); github.run["status"] = state
    assert github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)["state"] == "waiting_for_exact_sha_ci"
    assert not github.merged


def test_wrong_pipeline_or_broader_files_cannot_merge():
    github = FakeGitHub(); github.run["external_id"] = "10|911|2a547add-01ad-454b-8b55-35c98e76eb53"
    with pytest.raises(delivery.DeliveryError, match="untrusted producer"):
        github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)
    github = FakeGitHub(); github.files.append({"filename": "tools/evil.py", "status": "modified"})
    with pytest.raises(delivery.DeliveryError, match="JSON-only"):
        github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)


def test_base_changed_race_stops_merge():
    github = FakeGitHub(); github.base = "e" * 40
    with pytest.raises(delivery.DeliveryError, match="Base changed"):
        github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)
    assert not github.merged


def test_failed_commit_status_never_merges():
    github = FakeGitHub(); github.status = {"total_count": 1, "state": "failure"}
    assert github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)["state"] == "waiting_for_commit_statuses"
    assert not github.merged


def test_dirty_checkout_rejected_before_export_or_auth(monkeypatch):
    monkeypatch.setattr(delivery, "git", lambda *args, **kwargs: " M tracked.py" if args[0] == "status" else "")
    with pytest.raises(delivery.DeliveryError, match="entirely clean"):
        delivery.deliver(CHECK)


def test_broader_commit_routes_only_to_manual_approval(monkeypatch):
    monkeypatch.setattr(delivery, "assert_clean", lambda: None)
    monkeypatch.setattr(delivery, "git", lambda *args: SHA)
    monkeypatch.setattr(delivery, "changed_paths", lambda *args: {"webapp/app.py"})
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/master"); monkeypatch.setenv("BUILD_SOURCEVERSION", SHA); monkeypatch.setenv("BUILD_REASON", "IndividualCI")
    assert delivery.qualify_commit()["state"] == "broader_change_requires_human_environment_approval"
    with pytest.raises(delivery.DeliveryError, match="not retained"):
        delivery.qualify_commit(require_eligible=True)


def test_output_paths_cannot_escape_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(delivery, "ROOT", tmp_path)
    with pytest.raises(delivery.DeliveryError, match="fixed delivery scope"):
        delivery.write_json(tmp_path / "tools/evil.py", {})


def test_pipeline_schedule_and_deploy_gates_remain_explicit():
    pipeline = yaml.safe_load((Path(__file__).resolve().parents[1] / "azure-pipelines.yml").read_text(encoding="utf-8"))
    stages = {stage["stage"]: stage for stage in pipeline["stages"]}
    assert pipeline["schedules"][0]["branches"]["include"] == ["master"]
    assert "Schedule" in stages["Validate"]["condition"]
    assert stages["ObsessionDaily"]["jobs"][0]["pool"]["name"] == "Injecticide Pi Private"
    for stage in ["DeployAutomatic", "DeployProduction"]:
        assert "dependencies.QualifyAutomatic.result, 'Succeeded'" in stages[stage]["condition"]
    assert "qualified_sha" in stages["DeployAutomatic"]["condition"]
    assert "eligible'], 'false'" in stages["DeployProduction"]["condition"]
    assert stages["DeployProduction"]["jobs"][0]["environment"] == "injecticide-pi-production"


def test_local_implement_prepares_review_data_but_never_auto_qualifies():
    candidate = item("medium", "review")
    reviewed = delivery.eligible_candidates([candidate], include_review=True)
    assert candidate["sha256"] in reviewed
    with pytest.raises(delivery.DeliveryError, match="automatic lane"):
        delivery.validate_transition(manifests(), manifests(candidate), reviewed)
    result = delivery.validate_transition(manifests(), manifests(candidate), reviewed, allow_review=True)
    assert result["eligible"] is False


def test_atomic_host_receipt_retains_sha_and_admits_queue_audit_gap(tmp_path):
    result = {"state": "pr_created_waiting_exact_sha_ci", "sha": SHA, "proposal_sha256": ["d" * 64]}
    path = delivery.write_receipt(result, tmp_path / "receipts")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    assert receipt["outcome"] == result
    assert receipt["queue_delivery_audit"] == "not_updated_host_receipt_only"
    assert not list(path.parent.glob(".receipt-*"))


def test_export_budget_is_explicit_not_silent_truncation(monkeypatch):
    cursor = 0
    def request(url):
        nonlocal cursor
        cursor += 100
        return {"schema_version": 1, "items": [], "next_after_id": cursor}
    monkeypatch.setattr(delivery, "request_json", request)
    with pytest.raises(delivery.DeliveryError, match="5000-item"):
        delivery.export_candidates()


def test_loopback_client_disables_environment_proxies(monkeypatch):
    observed = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, count): return b'{}'
    class Opener:
        def open(self, request, timeout): return Response()
    def opener(*handlers):
        observed.extend(handlers)
        return Opener()
    monkeypatch.setattr(delivery.urllib.request, "build_opener", opener)
    assert delivery.request_json("http://127.0.0.1:8200/obsession/export") == {}
    assert any(isinstance(handler, delivery.urllib.request.ProxyHandler) and handler.proxies == {} for handler in observed)


@pytest.mark.parametrize("mutation", ["strict", "bypass", "context", "app", "missing", "branch", "evaluate", "source", "missing_bypass", "mismatched_definition"])
def test_automatic_merge_requires_protected_up_to_date_checks(mutation):
    github = FakeGitHub()
    parameters = github.effective[0]["parameters"]
    if mutation == "strict": parameters["strict_required_status_checks_policy"] = False
    elif mutation == "bypass": github.protection["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
    elif mutation == "context": parameters["required_status_checks"][0]["context"] = "Other check"
    elif mutation == "app": parameters["required_status_checks"][0]["integration_id"] = 1
    elif mutation == "branch": github.protection["conditions"]["ref_name"]["include"] = ["refs/heads/other"]
    elif mutation == "evaluate": github.protection["enforcement"] = "evaluate"
    elif mutation == "source": github.protection["source"] = "Other/repo"
    elif mutation == "missing_bypass": del github.protection["bypass_actors"]
    elif mutation == "mismatched_definition": github.protection["rules"][0]["parameters"]["strict_required_status_checks_policy"] = False
    else: github.protection = {}
    with pytest.raises(delivery.DeliveryError, match="active exact-master ruleset"):
        github.merge_if_verified({"number": 1, "head": {"sha": SHA}}, CHECK, BASE)
    assert not github.merged


@pytest.mark.parametrize("url", ["https://github.com/Mr-GraphnStaff/Injecticide", "https://github.com/Mr-GraphnStaff/Injecticide.git"])
def test_exact_approved_checkout_remote_url_forms(monkeypatch, url):
    monkeypatch.setattr(delivery, "git", lambda *args, **kwargs: "" if args[0] == "status" else url)
    delivery.assert_clean()


@pytest.mark.parametrize("url", ["https://github.com/Mr-GraphnStaff/Injecticide.evil", "https://github.com/Other/Injecticide.git", "https://attacker.invalid/Mr-GraphnStaff/Injecticide"])
def test_other_checkout_remote_forms_rejected(monkeypatch, url):
    monkeypatch.setattr(delivery, "git", lambda *args, **kwargs: "" if args[0] == "status" else url)
    with pytest.raises(delivery.DeliveryError, match="Unexpected delivery repository"):
        delivery.assert_clean()


@pytest.mark.parametrize("key", ["http.https://github.com/Mr-GraphnStaff/Injecticide.git.extraheader", "http.https://github.com/Mr-GraphnStaff/Injecticide.extraheader", "http.https://github.com/.extraheader"])
def test_checkout_authorization_header_exact_supported_scopes(monkeypatch, capsys, key):
    from types import SimpleNamespace
    calls = []
    synthetic = "AUTHORIZATION: basic c3ludGhldGljOmZpeHR1cmU="
    def run(arguments, **kwargs):
        calls.append(arguments[-1])
        return SimpleNamespace(stdout=synthetic if arguments[-1] == key else "", returncode=0)
    monkeypatch.setattr(delivery.subprocess, "run", run)
    headers = delivery.github_headers()
    assert headers["Authorization"] == synthetic.split(":", 1)[1].strip()
    assert calls[-1] == key
    assert synthetic not in capsys.readouterr().out
    assert all(scope in {"http.https://github.com/Mr-GraphnStaff/Injecticide.git.extraheader", "http.https://github.com/Mr-GraphnStaff/Injecticide.extraheader", "http.https://github.com/.extraheader"} for scope in calls)


def test_readonly_preflight_reports_only_capability_booleans(monkeypatch):
    github = FakeGitHub()
    original = github.api
    def api(route, data=None, method=None):
        assert data is None and method is None
        return {"permissions": {"pull": True, "push": True, "admin": False}} if route == "" else original(route)
    github.api = api
    monkeypatch.setattr(delivery, "github_headers", lambda: {})
    monkeypatch.setattr(delivery, "GitHub", lambda headers: github)
    outcome = delivery.preflight()
    assert outcome["state"] == "readonly_preflight"
    assert outcome["repository_push"] is True
    assert outcome["repository_admin"] is False
    assert outcome["bypass_actor_visibility"] is True
    assert outcome["automatic_ruleset_gate_satisfied"] is True
    assert all(type(value) is bool for key, value in outcome.items() if key != "state")
    assert github.merged is False


def test_readonly_preflight_exposes_hidden_bypass_without_approving(monkeypatch):
    github = FakeGitHub()
    del github.protection["bypass_actors"]
    original = github.api
    github.api = lambda route, data=None, method=None: {"permissions": {}} if route == "" else original(route)
    monkeypatch.setattr(delivery, "github_headers", lambda: {})
    monkeypatch.setattr(delivery, "GitHub", lambda headers: github)
    outcome = delivery.preflight()
    assert outcome["bypass_actor_visibility"] is False
    assert outcome["repository_pull"] is None
    assert outcome["repository_push"] is None
    assert outcome["repository_admin"] is None
    assert outcome["automatic_ruleset_gate_satisfied"] is False
    assert not github.merged


def attestation(policy):
    visible = {field: policy[field] for field in delivery.VISIBLE_RULESET_FIELDS}
    return {"schema_version": 1, "ruleset_id": policy["id"], "ruleset_updated_at": policy["updated_at"],
            "visible_sha256": hashlib.sha256(delivery.canonical(visible)).hexdigest(), "bypass_actors": [],
            "verified_at": "2026-01-02T00:00:00Z", "verification_method": "owner_authenticated_ruleset_readback", "verified_by": "Mr-GraphnStaff"}


def test_hidden_bypass_requires_matching_owner_attestation(tmp_path, monkeypatch):
    github = FakeGitHub()
    del github.protection["bypass_actors"]
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(attestation(github.protection)), encoding="utf-8")
    monkeypatch.setattr(delivery, "ATTESTATION_PATH", path)
    assert delivery.bypass_attestation_valid(github.protection)
    assert github.protected_ruleset(CHECK)
    assert "research_mcp/obsession_delivery_policy.json" not in delivery.ALLOWED


@pytest.mark.parametrize("mutation", ["version", "fingerprint", "id", "owner", "method", "bypass", "missing_updated", "rule_changed"])
def test_hidden_bypass_attestation_drift_fails_closed(tmp_path, monkeypatch, mutation):
    github = FakeGitHub(); del github.protection["bypass_actors"]
    proof = attestation(github.protection)
    if mutation == "version": proof["ruleset_updated_at"] = "2026-01-03T00:00:00Z"
    elif mutation == "fingerprint": proof["visible_sha256"] = "0" * 64
    elif mutation == "id": proof["ruleset_id"] = 999
    elif mutation == "owner": proof["verified_by"] = "Other"
    elif mutation == "method": proof["verification_method"] = "unverified"
    elif mutation == "bypass": proof["bypass_actors"] = [{"actor_id": 1}]
    elif mutation == "missing_updated": del github.protection["updated_at"]
    elif mutation == "rule_changed": github.protection["rules"].append({"type": "creation"})
    path = tmp_path / "attestation.json"; path.write_text(json.dumps(proof), encoding="utf-8")
    monkeypatch.setattr(delivery, "ATTESTATION_PATH", path)
    assert not github.protected_ruleset(CHECK)


def test_visible_bypass_overrides_previously_valid_attestation(tmp_path, monkeypatch):
    github = FakeGitHub()
    path = tmp_path / "attestation.json"; path.write_text(json.dumps(attestation(github.protection)), encoding="utf-8")
    monkeypatch.setattr(delivery, "ATTESTATION_PATH", path)
    assert delivery.bypass_attestation_valid(github.protection)
    github.protection["bypass_actors"] = [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}]
    assert delivery.bypass_attestation_valid(github.protection)
    assert not github.protected_ruleset(CHECK)
