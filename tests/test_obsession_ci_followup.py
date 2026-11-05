"""Bounded CI follow-up uses fake Git/CI responses and never publishes remotely."""
from copy import deepcopy
import json

import pytest

from tools import obsession_delivery as delivery

SHA = "a" * 40
BASE = "b" * 40
CHECK = "Injecticide-CI-CD (Validate candidate Tests and container builds)"


def setup_followup(monkeypatch, states):
    monkeypatch.setenv("BUILD_REASON", "Schedule")
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/master")
    data = {"head": SHA, "base": BASE, "clock": 0, "git": [], "qualifications": [], "merges": [], "sleeps": []}
    pull = {"number": 7, "state": "open", "head": {"sha": SHA, "repo": {"full_name": delivery.REPOSITORY},
            "ref": "codex/obsession-auto-" + "a" * 20}, "base": {"ref": "master", "sha": BASE}}
    data["pull"] = pull
    def git(*args):
        data["git"].append(args)
        if args == ("rev-parse", "HEAD"): return data["head"]
        if args in [("rev-parse", "origin/master"), ("rev-parse", SHA + "^")]: return data["base"]
        if args == ("checkout", "--detach", BASE): data["head"] = BASE; return ""
        if args == ("fetch", "--no-tags", "origin", "master"): return ""
        raise AssertionError(args)
    class GitHub:
        def api(self, path):
            assert path == "/pulls/7"
            return deepcopy(data["pull"])
        def merge_if_verified(self, candidate, required_check, base):
            assert required_check == CHECK and base == BASE
            data["merges"].append(candidate["head"]["sha"])
            return {"state": states[min(len(data["merges"])-1, len(states)-1)], "sha": SHA}
    exports = []
    def export():
        exports.append(len(exports)+1)
        return exports[-1]
    def qualify(base, sha, eligible):
        assert base == "origin/master" and sha == SHA
        data["qualifications"].append(eligible)
    monkeypatch.setattr(delivery, "assert_clean", lambda: None)
    monkeypatch.setattr(delivery, "git", git)
    monkeypatch.setattr(delivery, "github_headers", lambda: {})
    monkeypatch.setattr(delivery, "GitHub", lambda headers: GitHub())
    monkeypatch.setattr(delivery, "export_candidates", export)
    monkeypatch.setattr(delivery, "eligible_candidates", lambda items: items)
    monkeypatch.setattr(delivery, "qualify_revision", qualify)
    def sleep(seconds):
        data["sleeps"].append(seconds)
        data["clock"] += seconds
        if "after_sleep" in data: data["after_sleep"]()
    data["sleep"] = sleep
    return data


def result():
    return {"state": "pr_created_waiting_exact_sha_ci", "sha": SHA,
            "pull_request": "https://github.com/" + delivery.REPOSITORY + "/pull/7", "results": []}


def run(data, seconds=60):
    return delivery.wait_for_candidate(result(), CHECK, wait_seconds=seconds, poll_seconds=20,
                                       clock=lambda: data["clock"], sleeper=data["sleep"])


def test_new_pr_can_merge_when_exact_ci_finishes_in_same_daily_run(monkeypatch):
    data = setup_followup(monkeypatch, ["waiting_for_exact_sha_ci", "merged"])
    actual = run(data)
    assert actual["state"] == "merged_pending_protected_pipeline"
    assert data["qualifications"] == [1, 2]
    assert data["merges"] == [SHA, SHA] and data["sleeps"] == [20]
    assert not any(args[0] in {"push", "reset", "clean"} for args in data["git"])


def test_changed_head_is_never_reused_after_wait(monkeypatch):
    data = setup_followup(monkeypatch, ["waiting_for_exact_sha_ci"])
    data["after_sleep"] = lambda: data["pull"]["head"].update(sha="c" * 40)
    with pytest.raises(delivery.DeliveryError, match="PR changed"):
        run(data)
    assert data["merges"] == [SHA]


def test_freshness_is_revalidated_and_revocation_blocks_merge(monkeypatch):
    data = setup_followup(monkeypatch, ["waiting_for_exact_sha_ci", "merged"])
    def qualify(base, sha, eligible):
        data["qualifications"].append(eligible)
        if eligible == 2: raise delivery.DeliveryError("Evidence was superseded")
    monkeypatch.setattr(delivery, "qualify_revision", qualify)
    actual = run(data)
    assert actual["state"] == "review_required_stale_or_ineligible"
    assert "superseded" in actual["reason"]
    assert data["merges"] == [SHA]


def test_base_movement_preserves_pr_for_requalification(monkeypatch):
    data = setup_followup(monkeypatch, ["waiting_for_exact_sha_ci"])
    data["after_sleep"] = lambda: data.update(base="c" * 40)
    assert run(data)["state"] == "base_advanced_review_required"
    assert data["merges"] == [SHA]


def test_timeout_is_bounded_and_does_not_republish_or_delete(monkeypatch):
    data = setup_followup(monkeypatch, ["waiting_for_exact_sha_ci"])
    actual = run(data, seconds=40)
    assert actual["state"] == "ci_wait_timed_out"
    assert data["sleeps"] == [20, 20] and data["merges"] == [SHA, SHA]


def test_failed_ci_is_not_retried_as_if_successful(monkeypatch):
    data = setup_followup(monkeypatch, ["checks_failed"])
    assert run(data)["state"] == "checks_failed"
    assert not data["sleeps"]


def test_export_outage_remains_unavailable_not_a_review_decision(monkeypatch):
    data = setup_followup(monkeypatch, ["merged"])
    monkeypatch.setattr(delivery, "export_candidates", lambda: (_ for _ in ()).throw(delivery.DeliveryError("Export unavailable")))
    with pytest.raises(delivery.DeliveryError, match="Export unavailable"):
        run(data)
    assert not data["merges"]


def test_followup_cannot_run_outside_scheduled_master_job(monkeypatch):
    data = setup_followup(monkeypatch, ["merged"])
    monkeypatch.setenv("BUILD_REASON", "Manual")
    with pytest.raises(delivery.DeliveryError, match="scheduled master"):
        run(data)
    assert not data["git"]


def test_review_lane_and_disabled_wait_are_unchanged(monkeypatch):
    data = setup_followup(monkeypatch, ["merged"])
    human = {"state": "review_pr_created_requires_human_acceptance"}
    assert delivery.wait_for_candidate(human, CHECK) == human
    assert delivery.wait_for_candidate(result(), CHECK, wait_seconds=0) == result()
    assert not data["git"]


@pytest.mark.parametrize("change", [{"sha": "not-a-sha"}, {"pull_request": "https://evil.example/pull/7"}])
def test_followup_cannot_take_revision_or_endpoint_from_other_content(monkeypatch, change):
    data = setup_followup(monkeypatch, ["merged"])
    candidate = result(); candidate.update(change)
    with pytest.raises(delivery.DeliveryError, match="fixed repository"):
        delivery.wait_for_candidate(candidate, CHECK)
    assert not data["git"]


def setup_main(monkeypatch, tmp_path, states, wait_seconds=60):
    """Exercise real main/wait/receipt code; publication and external CI stay fake."""
    data = setup_followup(monkeypatch, states)
    data["delivery_calls"] = 0
    data["receipts"] = []
    data["followup_calls"] = 0
    candidate = {**result(), "proposal_sha256": ["d" * 64]}
    data["candidate"] = candidate
    real_receipt = delivery.write_receipt
    real_followup = delivery.wait_for_candidate

    def publish(required_check):
        assert required_check == CHECK
        data["delivery_calls"] += 1
        return deepcopy(candidate)

    def record(outcome):
        path = real_receipt(outcome, tmp_path / "receipts")
        # Read the durable file rather than treating a mock call as persistence.
        data["receipts"].append(json.loads(path.read_text(encoding="utf-8"))["outcome"])
        return path

    def followup(outcome, required_check, *, wait_seconds):
        data["followup_calls"] += 1
        data["receipts_at_followup"] = deepcopy(data["receipts"])
        return real_followup(outcome, required_check, wait_seconds=wait_seconds, poll_seconds=20,
                             clock=lambda: data["clock"], sleeper=data["sleep"])

    monkeypatch.setattr(delivery, "deliver", publish)
    monkeypatch.setattr(delivery, "write_receipt", record)
    monkeypatch.setattr(delivery, "wait_for_candidate", followup)
    monkeypatch.setattr(delivery.sys, "argv", ["obsession_delivery.py", "daily", "--required-check", CHECK,
                                               "--ci-wait-seconds", str(wait_seconds)])
    return data


@pytest.mark.parametrize("seconds", [-1, 901])
def test_main_rejects_invalid_wait_before_publication(monkeypatch, tmp_path, capsys, seconds):
    data = setup_main(monkeypatch, tmp_path, ["merged"], wait_seconds=seconds)
    assert delivery.main() == 1
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "unavailable" and "CI wait" in outcome["reason"]
    assert "pull_request" not in outcome and "prior_state" not in outcome
    assert data["delivery_calls"] == data["followup_calls"] == 0
    assert data["git"] == []


def test_main_preserves_published_identity_when_pr_changes_during_followup(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["waiting_for_exact_sha_ci"])
    data["after_sleep"] = lambda: data["pull"]["head"].update(sha="c" * 40)
    assert delivery.main() == 1
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "ci_followup_failed"
    assert outcome["prior_state"] == "pr_created_waiting_exact_sha_ci"
    assert outcome["failed_stage"] == "ci_followup" and "PR changed" in outcome["reason"]
    for key in ("sha", "pull_request", "proposal_sha256", "results"):
        assert outcome[key] == data["candidate"][key]
    assert [receipt["state"] for receipt in data["receipts"]] == [
        "started", "pr_created_waiting_exact_sha_ci", "ci_followup_failed"]
    assert data["receipts"][-1] == outcome
    assert data["receipts_at_followup"][-1] == data["candidate"]
    assert data["delivery_calls"] == 1 and data["merges"] == [SHA]
    assert not any(args[0] in {"push", "reset", "clean"} for args in data["git"])


def test_main_records_publication_before_successful_followup(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["waiting_for_exact_sha_ci", "merged"])
    assert delivery.main() == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "merged_pending_protected_pipeline"
    assert outcome["sha"] == SHA and outcome["pull_request"] == data["candidate"]["pull_request"]
    assert [receipt["state"] for receipt in data["receipts"]] == [
        "started", "pr_created_waiting_exact_sha_ci", "merged_pending_protected_pipeline"]
    assert data["receipts"][-1] == outcome
    assert data["receipts_at_followup"][-1] == data["candidate"]
    assert data["delivery_calls"] == 1 and data["merges"] == [SHA, SHA]


def test_main_zero_wait_keeps_publication_and_does_not_poll(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["merged"], wait_seconds=0)
    assert delivery.main() == 0
    assert json.loads(capsys.readouterr().out) == data["candidate"]
    assert [receipt["state"] for receipt in data["receipts"]] == ["started", "pr_created_waiting_exact_sha_ci"]
    assert data["delivery_calls"] == 1 and not data["merges"] and not data["sleeps"]


def test_main_keeps_candidate_in_output_if_publication_receipt_fails(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["merged"])
    record = delivery.write_receipt

    def fail_publication_receipt(outcome):
        if outcome.get("state") == "pr_created_waiting_exact_sha_ci":
            raise OSError("simulated receipt write failure")
        return record(outcome)

    monkeypatch.setattr(delivery, "write_receipt", fail_publication_receipt)
    assert delivery.main() == 1
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "outcome_receipt_failed"
    assert outcome["failed_stage"] == "publication_receipt"
    assert outcome["sha"] == SHA and outcome["pull_request"] == data["candidate"]["pull_request"]
    assert data["followup_calls"] == 0 and data["receipts"][-1] == outcome


def test_main_keeps_merged_outcome_when_final_receipt_fails(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["merged"])
    record = delivery.write_receipt

    def fail_merged_receipt(outcome):
        if outcome.get("state") == "merged_pending_protected_pipeline":
            raise OSError("simulated final receipt failure")
        return record(outcome)

    monkeypatch.setattr(delivery, "write_receipt", fail_merged_receipt)
    assert delivery.main() == 1
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "outcome_receipt_failed"
    assert outcome["prior_state"] == "merged_pending_protected_pipeline"
    assert outcome["failed_stage"] == "outcome_receipt"
    assert outcome["sha"] == SHA and outcome["pull_request"] == data["candidate"]["pull_request"]
    assert data["merges"] == [SHA] and data["delivery_calls"] == 1
    assert data["receipts"][-1] == outcome


def test_main_preserves_stdout_identity_when_failure_receipt_is_unavailable(monkeypatch, tmp_path, capsys):
    data = setup_main(monkeypatch, tmp_path, ["waiting_for_exact_sha_ci"])
    data["after_sleep"] = lambda: data["pull"]["head"].update(sha="c" * 40)
    record = delivery.write_receipt

    def fail_error_receipt(outcome):
        if outcome.get("state") == "ci_followup_failed":
            raise OSError("simulated unavailable receipt store")
        return record(outcome)

    monkeypatch.setattr(delivery, "write_receipt", fail_error_receipt)
    assert delivery.main() == 1
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "ci_followup_failed" and outcome["receipt"] == "unavailable"
    assert outcome["sha"] == SHA and outcome["pull_request"] == data["candidate"]["pull_request"]
    assert outcome["proposal_sha256"] == data["candidate"]["proposal_sha256"]
    assert [receipt["state"] for receipt in data["receipts"]] == ["started", "pr_created_waiting_exact_sha_ci"]
    assert data["delivery_calls"] == 1 and data["merges"] == [SHA]
