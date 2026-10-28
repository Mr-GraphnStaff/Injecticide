"""Independent runner policy/denominator probes; no external payload bodies."""
import hashlib
import json

import pytest

from tools.skill_eval import compare_runs, evaluate, security_signals


def fixture(tmp_path):
    raw = b"Independent local authored runner fixture."
    (tmp_path / "input.txt").write_bytes(raw)
    manifest = {"schema_version": 1, "corpus_id": "independent_runner_review",
                "cases": [{"id": "one", "label": "malicious", "label_origin": "authored_test_intent",
                           "category": "unit_only", "split": "development",
                           "source": {"kind": "local_authored_fixture"},
                           "input": {"kind": "raw", "filename": "input.md", "files": [
                               {"path": "input.md", "local_path": "input.txt", "sha256": hashlib.sha256(raw).hexdigest()}]}}]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def scanner_with(findings):
    def scanner(raw, filename, **kwargs):
        return {"files": [{"findings": findings}], "coverage": {"status": "complete_supported_content"},
                "governance_evidence": {"artifact_sha256": hashlib.sha256(raw).hexdigest()},
                "scanner_metadata": {"scanner_version": "independent-unit-fixture"}}
    return scanner


def test_actual_credential_flow_contract_counts_under_declared_review_threshold(tmp_path):
    finding = {"id": "credential_source_to_network_payload", "category": "sensitive_data", "tier": "review",
               "is_actionable": True, "counts_for_governance": True}
    result = evaluate(fixture(tmp_path), scanner=scanner_with([finding]))
    assert result["records"][0]["profiles"]["security_review"]["decision"] == "positive"
    assert result["records"][0]["profiles"]["security_block"]["decision"] == "negative"
    assert result["metrics"]["security_review"]["positive_signal_recall_lower_bound"] == 1


@pytest.mark.parametrize("missing", ["is_actionable", "counts_for_governance"])
def test_missing_threshold_authority_is_abstention_not_positive_or_clear_negative(tmp_path, missing):
    finding = {"id": "ambiguous_security", "category": "prompt", "tier": "block",
               "is_actionable": True, "counts_for_governance": True}
    del finding[missing]
    result = evaluate(fixture(tmp_path), scanner=scanner_with([finding]))
    assert result["records"][0]["profiles"]["security_block"]["decision"] == "abstain"
    assert result["records"][0]["profiles"]["security_review"]["decision"] == "abstain"
    assert result["metrics"]["security_review"]["positive_signal_recall_lower_bound"] == 0
    assert result["metrics"]["security_review"]["positive_signal_recall_upper_bound"] == 1


def test_explicit_positive_survives_unrelated_unknown_policy_metadata(tmp_path):
    known = {"id": "known_security", "category": "prompt", "tier": "block",
             "is_actionable": True, "counts_for_governance": True}
    unknown = {"id": "unknown_security", "category": "prompt", "tier": "block"}
    result = evaluate(fixture(tmp_path), scanner=scanner_with([known, unknown]))
    assert result["records"][0]["profiles"]["security_block"]["decision"] == "positive"


def test_contact_presence_is_never_reclassified_as_malware_by_category_alone():
    finding = {"id": "pii_email_address", "category": "sensitive_data", "tier": "block",
               "is_actionable": True, "counts_for_governance": True}
    assert security_signals({"files": [{"findings": [finding]}]}) == {"security_block": [], "security_review": []}


def test_actual_scanner_enum_can_establish_a_negative_without_changing_denominators(tmp_path):
    # Local authored prose only; no external corpus or uploaded program runs.
    result = evaluate(fixture(tmp_path))
    record = result["records"][0]
    assert record["coverage"] == "complete_supported_content"
    assert all(row["decision"] == "negative" for row in record["profiles"].values())
    metrics = result["metrics"]["security_review"]
    assert metrics["total_cases"] == metrics["upstream_positive_cases"] == 1
    assert metrics["positive_signal_recall_lower_bound"] == metrics["positive_signal_recall_upper_bound"] == 0


@pytest.mark.parametrize("status", ["complete", "complete_future_extension", "partial", "not_assessed", None])
def test_only_actual_canonical_coverage_enum_establishes_negative(tmp_path, status):
    def scanner(raw, filename, **kwargs):
        report = scanner_with([])(raw, filename)
        report["coverage"] = {"status": status}
        return report
    result = evaluate(fixture(tmp_path), scanner=scanner)
    assert all(row["decision"] == "abstain" for row in result["records"][0]["profiles"].values())
    metrics = result["metrics"]["security_review"]
    assert metrics["total_cases"] == metrics["upstream_positive_cases"] == 1
    assert metrics["positive_signal_recall_lower_bound"] == 0
    assert metrics["positive_signal_recall_upper_bound"] == 1


def test_canonical_coverage_does_not_waive_missing_security_metadata(tmp_path):
    finding = {"id": "unknown_authority", "category": "prompt", "tier": "review"}
    result = evaluate(fixture(tmp_path), scanner=scanner_with([finding]))
    profiles = result["records"][0]["profiles"]
    assert profiles["security_review"]["decision"] == "abstain"
    assert profiles["security_block"]["decision"] == "negative"


def test_comparator_rejects_adapter_policy_changes_as_engine_comparison(tmp_path):
    first = evaluate(fixture(tmp_path), scanner=scanner_with([]))
    second = json.loads(json.dumps(first))
    second["coverage_policy"]["version"] = "legacy_unit_policy"
    with pytest.raises(ValueError, match="coverage scoring policy"):
        compare_runs(first, second)
