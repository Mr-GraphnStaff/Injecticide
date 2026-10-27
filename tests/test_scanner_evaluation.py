"""Authored synthetic regression evidence, not an independent benchmark."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.scanner_evaluation import (
    DEFAULT_CORPUS, _load_json, compare_reports, evaluate_corpus, fixture_archive,
)


def report(findings=(), state="text_analyzed", coverage=None, mitigation=None):
    entry = {"path": "demo/reference.md", "assessment_state": state,
             "findings": list(findings)}
    if coverage is not None:
        entry["analysis_coverage"] = coverage
    if mitigation is not None:
        entry["creator_mitigation"] = mitigation
    return {"governance_evidence": {"artifact_sha256": "a" * 64}, "files": [entry],
            "scanner_metadata": {"scanner_version": "test-version"},
            "package_analysis": {"target_runtime": "generic"}}


def finding(line=7, tier="review"):
    return {"id": "pii_email_address", "tier": tier, "severity": "low",
            "observations": [{"line": line, "text": "do-not-copy-sensitive-sample"}],
            "samples": ["do-not-copy-sensitive-sample"]}


def test_compare_refuses_missing_or_different_artifact_identity():
    left, right = report(), report()
    right["governance_evidence"]["artifact_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="hashes differ"):
        compare_reports(left, right)
    for value in (None, "unknown", "a" * 63):
        right["governance_evidence"]["artifact_sha256"] = value
        with pytest.raises(ValueError, match="64 hex"):
            compare_reports(left, right)


def test_comparison_matches_locations_without_echoing_sensitive_evidence():
    result = compare_reports(report([finding()]), report([finding()]))
    row = result["comparisons"][0]
    assert row["outcome"] == "matched"
    assert row["left_locations"] == [7]
    assert result["ground_truth"] == "neither_report_is_ground_truth"
    assert "do-not-copy-sensitive-sample" not in json.dumps(result)


def test_engine_source_identity_is_retained_in_comparison_context():
    first, second = report(), report()
    first["scanner_metadata"]["engine_source_sha256"] = "b" * 64
    second["scanner_metadata"]["engine_source_sha256"] = "c" * 64
    result = compare_reports(first, second)
    assert "b" * 64 in json.dumps(result) and "c" * 64 in json.dumps(result)


def test_comparison_distinguishes_location_and_disposition_differences():
    row = compare_reports(report([finding(7)]), report([finding(20, "info")]))["comparisons"][0]
    assert row["outcome"] == "location_difference"
    assert row["right_locations"] == [20]
    assert "disposition_difference" in row["annotations"]


@pytest.mark.parametrize("state,coverage,expected", [
    ("text_analyzed", None, "unknown"),
    ("text_analyzed", {"text_patterns": {"status": "complete_input"}}, "unknown"),
    ("limited_or_truncated", {"text_rules": {"status": "partial"}}, "unknown"),
    ("limited_or_truncated", {"sensitive_data": {"status": "complete"}}, "unknown"),
    ("limited_or_truncated", {"foo": {"status": "complete"}}, "unknown"),
    ("structured_content_analyzed", {"sensitive_data": {"status": "complete"}}, "unknown"),
    ("text_analyzed", {"foo": {"status": "complete"}}, "unknown"),
    ("text_analyzed", {"extraction": {"status": "complete"}}, "unknown"),
    ("text_analyzed", {"extraction": {"status": "partial"}, "sensitive_data": {"status": "complete"}}, "unknown"),
    ("text_analyzed", {"result_display": {"status": "partial"}, "sensitive_data": {"status": "complete"}}, "unknown"),
    ("text_analyzed", {"text_patterns": {"status": "partial"}, "sensitive_data": {"status": "complete"}}, "unknown"),
    ("unsupported", None, "not_inspected"),
    ("executable_not_analyzed", None, "not_inspected"),
    ("text_analyzed", {"text_rules": {"status": "complete"}, "sensitive_data": {"status": "complete"}}, "not_detected"),
])
def test_absence_requires_actual_inspection_evidence(state, coverage, expected):
    row = compare_reports(report([finding()]), report(state=state, coverage=coverage))["comparisons"][0]
    assert row["outcome"] == expected
    assert row["missing_from"] == "right"


def test_verified_mitigation_and_versions_are_context_not_explanations():
    left = report([finding()])
    right = report(coverage={"text_patterns": {"status": "complete"}}, mitigation={
        "status": "verified", "satisfies_tagging_convention": True})
    right["scanner_metadata"]["scanner_version"] = "other-version"
    row = compare_reports(left, right)["comparisons"][0]
    assert row["outcome"] == "not_detected"
    assert row["annotations"] == ["creator_mitigation_verified_right", "policy_or_rule_version_difference_possible"]
    right["files"][0]["creator_mitigation"]["status"] = "unverifiable"
    assert "creator_mitigation_verified_right" not in compare_reports(left, right)["comparisons"][0]["annotations"]


def test_unknown_source_locations_are_not_claimed_exactly_matched():
    a = finding()
    a.pop("observations")
    row = compare_reports(report([a]), report([finding()]))["comparisons"][0]
    assert "occurrence_alignment_unknown" in row["annotations"]


@pytest.mark.parametrize("field,value", [
    ("analysis_coverage", None),
    ("analysis_coverage", []),
    ("analysis_coverage", {"sensitive_data": []}),
    ("analysis_coverage", {"sensitive_data": {"status": ["complete"]}}),
    ("creator_mitigation", ["x"]),
    ("creator_mitigation", {"status": ["verified"]}),
    ("creator_mitigation", {"satisfies_tagging_convention": "true"}),
    ("path", []),
    ("path", None),
    ("assessment_state", {"status": "complete"}),
    ("skipped", "true"),
    ("skipped", None),
    ("findings", [{"id": "signal", "observations": None}]),
    ("findings", [{"id": [], "observations": []}]),
    ("findings", [{"id": "signal", "observations": ["x"]}]),
])
def test_malformed_consumed_file_fields_raise_safe_value_error(field, value):
    a, b = report([finding()]), report()
    b["files"][0][field] = value
    with pytest.raises(ValueError):
        compare_reports(a, b)


@pytest.mark.parametrize("field,value", [
    ("inventory", ["x"]), ("inventory", None),
    ("inventory", [{"path": "demo/reference.md", "analysis_coverage": None}]),
    ("scanner_metadata", {"catalogs": ["x"]}),
    ("scanner_metadata", {"catalogs": {"name": "rules"}}),
    ("scanner_metadata", {"engine_source_sha256": []}),
    ("package_analysis", {"target_runtime": []}),
    ("package_analysis", {"format_findings": ["x"]}),
    ("governance_evidence", []),
])
def test_malformed_consumed_report_fields_raise_safe_value_error(field, value):
    a, b = report([finding()]), report()
    b[field] = value
    with pytest.raises(ValueError):
        compare_reports(a, b)


def test_conflicting_partial_inventory_cannot_be_overridden_by_complete_file_stage():
    a = report([finding()])
    b = report(coverage={"sensitive_data": {"status": "complete"}})
    b["inventory"] = [{"path": "demo/reference.md", "assessment_state": "limited_or_truncated"}]
    assert compare_reports(a, b)["comparisons"][0]["outcome"] == "unknown"


@pytest.mark.parametrize("stage", ["sensitive_data", "extraction", "result_display"])
def test_partial_detector_coverage_in_inventory_cannot_be_hidden_by_file_record(stage):
    a = report([finding()])
    b = report(coverage={"sensitive_data": {"status": "complete"}})
    b["inventory"] = [{"path": "demo/reference.md", "assessment_state": "text_analyzed",
                       "analysis_coverage": {stage: {"status": "partial"}}}]
    assert compare_reports(a, b)["comparisons"][0]["outcome"] == "unknown"


def test_unknown_rule_cannot_inherit_arbitrary_complete_detector_coverage():
    unknown = finding()
    unknown["id"] = "pii_made_up_rule"
    a = report([unknown])
    b = report(coverage={"sensitive_data": {"status": "complete"}, "foo": {"status": "complete"}})
    assert compare_reports(a, b)["comparisons"][0]["outcome"] == "unknown"


def test_comparison_bounds_consumed_collection_work(monkeypatch):
    from tools import scanner_evaluation as tool
    monkeypatch.setattr(tool, "MAX_REPORT_FILES", 1)
    a, b = report([finding()]), report()
    b["inventory"] = [{"path": "one"}, {"path": "two"}]
    with pytest.raises(ValueError, match="bounded"):
        compare_reports(a, b)


def test_format_findings_and_catalog_fingerprints_are_compared():
    a, b = report(), report()
    a["package_analysis"]["format_findings"] = [{"path": "demo/mcp.json", "id": "configuration_parse_error", "severity": "error"}]
    a["scanner_metadata"]["catalogs"] = [{"name": "rules", "sha256": "a" * 64}]
    b["scanner_metadata"]["catalogs"] = [{"name": "rules", "sha256": "b" * 64}]
    result = compare_reports(a, b)
    assert result["comparisons"][0]["id"] == "configuration_parse_error"
    assert "policy_or_rule_version_difference_possible" in result["comparisons"][0]["annotations"]


def test_catalog_age_alone_does_not_claim_a_rule_version_change():
    a, b = report([finding()]), report([finding()])
    a["scanner_metadata"]["catalogs"] = [{"name": "rules", "sha256": "a" * 64, "age_days": 1}]
    b["scanner_metadata"]["catalogs"] = [{"name": "rules", "sha256": "a" * 64, "age_days": 2}]
    row = compare_reports(a, b)["comparisons"][0]
    assert "policy_or_rule_version_difference_possible" not in row["annotations"]


def test_json_input_rejects_duplicate_keys_and_oversized_input(tmp_path):
    path = tmp_path / "report.json"
    path.write_text('{"files":[],"files":{}}')
    with pytest.raises(ValueError, match="Duplicate"):
        _load_json(path)
    with pytest.raises(ValueError, match="exceeds"):
        _load_json(path, limit=2)


def test_fixture_generation_is_deterministic_bounded_and_never_writes_package_paths():
    case = {"files": [{"path": "demo/data.txt", "text": "hello"}]}
    assert fixture_archive(case) == fixture_archive(case)
    with pytest.raises(ValueError, match="relative"):
        fixture_archive({"files": [{"path": "../outside", "text": "no"}]})
    with pytest.raises(ValueError, match="budget"):
        fixture_archive({"files": [{"path": "demo/data.txt", "padding_characters": 10**9}]})


@pytest.fixture(scope="module")
def evaluated():
    return evaluate_corpus()


def test_authored_corpus_has_no_general_accuracy_claim(evaluated):
    provenance = evaluated["corpus_provenance"]
    assert provenance["kind"] == "authored_synthetic"
    assert provenance["independent_human_labeling"] is False
    assert provenance["held_out"] is False
    assert "accuracy" not in evaluated["summary"]
    assert evaluated["summary"]["case_count"] >= 12
    assert evaluated["summary"]["mismatched_cases"] == 0


def test_coverage_unknown_and_review_burden_stay_separate(evaluated):
    by_id = {case["id"]: case for case in evaluated["cases"]}
    after = by_id["after-text-boundary"]
    assert after["status"] == "incomplete"
    assert after["unknown_due_to_coverage"] == ["pii_email_address"]
    assert after["coverage"]["status"] == "partial"
    assert evaluated["per_rule"]["pii_email_address"]["unknown_due_to_coverage"] >= 1
    assert by_id["enterprise-directory"]["observed_file_matches"]["pii_email_address"] == 2
    assert by_id["documented-script"]["review_findings"] >= 1
    assert by_id["documented-script"]["block_findings"] == 0
    assert evaluated["summary"]["benign_cases_with_blocks"] == 0


def test_evaluation_is_local_without_network_or_uploaded_code(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network access"))
    corpus = json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8"))
    single = copy.deepcopy(corpus["cases"][0])
    # Already-authored fixtures are data to scan; no uploaded program is invoked.
    data = fixture_archive(single)
    from skill_sandbox.app import scan_upload
    assert scan_upload(data, "local.skill")["files"]


def test_compare_cli_is_usable_and_fails_closed_on_identity(tmp_path):
    left, right, output = (tmp_path / name for name in ("left.json", "right.json", "comparison.json"))
    left.write_text(json.dumps(report([finding()])), encoding="utf-8")
    right.write_text(json.dumps(report([finding()])), encoding="utf-8")
    tool = Path(__file__).resolve().parents[1] / "tools" / "scanner_evaluation.py"
    result = subprocess.run([sys.executable, str(tool), "compare", str(left), str(right), "--output", str(output)], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(output.read_text())["same_artifact"] is True
    right.write_text(json.dumps(report() | {"governance_evidence": {}}))
    result = subprocess.run([sys.executable, str(tool), "compare", str(left), str(right)], capture_output=True, timeout=20)
    assert result.returncode == 2
    assert b"artifact_sha256" in result.stderr


@pytest.mark.parametrize("malformed", ["coverage", "inventory", "mitigation"])
def test_compare_cli_rejects_malformed_nested_fields_without_traceback(tmp_path, malformed):
    a, b = report([finding()]), report()
    if malformed == "coverage":
        b["files"][0]["analysis_coverage"] = None
    elif malformed == "inventory":
        b["inventory"] = ["private-sentinel-not-for-diagnostics"]
    else:
        b["files"][0]["creator_mitigation"] = ["private-sentinel-not-for-diagnostics"]
    left, right = tmp_path / "left.json", tmp_path / "right.json"
    left.write_text(json.dumps(a), encoding="utf-8")
    right.write_text(json.dumps(b), encoding="utf-8")
    tool = Path(__file__).resolve().parents[1] / "tools" / "scanner_evaluation.py"
    result = subprocess.run([sys.executable, str(tool), "compare", str(left), str(right)], capture_output=True, timeout=20)
    assert result.returncode == 2
    assert b"Traceback" not in result.stderr
    assert b"private-sentinel" not in result.stderr
