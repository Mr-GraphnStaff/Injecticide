"""Runner contract tests use local authored text, never external holdout bodies."""
import copy
import hashlib
import json

import pytest

from tools.skill_eval import PROFILES, compare_runs, evaluate, input_bytes, read_manifest, security_signals, security_unknowns


def make_manifest(tmp_path, *, split="development"):
    cases = []
    for index, label in enumerate(("malicious", "benign", "malicious", "benign")):
        value = ("Authored unit-test text " + str(index)).encode()
        (tmp_path / f"{index}.txt").write_bytes(value)
        cases.append({"id": f"case-{index}", "label": label, "label_origin": "unit_test_author_intent",
                      "category": "unit_contract", "split": split, "source": {"kind": "local_authored_unit_fixture"},
                      "input": {"kind": "raw", "filename": f"{index}.md", "files": [
                          {"path": f"{index}.md", "local_path": f"{index}.txt", "sha256": hashlib.sha256(value).hexdigest()}]}})
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "corpus_id": "unit_contract_only", "cases": cases}), encoding="utf-8")
    return path


def scan(raw, filename, **kwargs):
    index = int(filename.split('.')[0])
    if index == 3:
        raise RuntimeError("SYNTHETIC_SECRET_MUST_NOT_APPEAR")
    return {"files": [{"findings": [{"id": "unit_security", "category": "prompt", "tier": "block", "counts_for_governance": True, "is_actionable": True}] if index == 0 else []}],
            "coverage": {"status": "partial" if index == 2 else "complete_supported_content"},
            "governance_evidence": {"artifact_sha256": hashlib.sha256(raw).hexdigest()},
            "scanner_metadata": {"scanner_version": "unit-1", "engine_source_sha256": "a" * 64}}


def test_errors_and_partial_negatives_remain_in_denominators(tmp_path):
    result = evaluate(make_manifest(tmp_path), scanner=scan)
    assert len(result["records"]) == 4
    assert [row["profiles"]["security_block"]["decision"] for row in result["records"]] == ["positive", "negative", "abstain", "error"]
    metric = result["metrics"]["security_block"]
    assert metric["upstream_positive_cases"] == metric["upstream_negative_cases"] == 2
    assert metric["positive_signal_recall_lower_bound"] == .5
    assert metric["positive_signal_recall_upper_bound"] == 1
    assert metric["negative_signal_rate_lower_bound"] == 0
    assert metric["negative_signal_rate_upper_bound"] == .5
    assert result["status"] == "incomplete"
    assert "SYNTHETIC_SECRET" not in json.dumps(result)


def test_pii_format_and_non_governance_capability_do_not_become_malware_signals(tmp_path):
    def benign(raw, *args, **kwargs):
        return {"files": [{"findings": [
            {"id": "pii_email_address", "tier": "block", "category": "data"},
            {"id": "capability", "tier": "review", "category": "code", "counts_for_governance": False},
            {"id": "documented", "tier": "block", "category": "prompt", "is_actionable": False}]}],
            "package_analysis": {"format_findings": [{"id": "invalid_frontmatter", "severity": "error"}]},
            "coverage": {"status": "complete_supported_content"}, "governance_evidence": {"artifact_sha256": hashlib.sha256(raw).hexdigest()},
            "scanner_metadata": {"scanner_version": "unit-1"}}
    result = evaluate(make_manifest(tmp_path), scanner=benign)
    assert all(all(value["decision"] == "negative" for value in row["profiles"].values()) for row in result["records"])


def test_review_profile_is_separate_and_declared_before_execution(tmp_path):
    def review(raw, *args, **kwargs):
        result = scan(raw, "0.md")
        result["files"][0]["findings"][0]["tier"] = "review"
        return result
    result = evaluate(make_manifest(tmp_path), scanner=review)
    assert result["records"][0]["profiles"]["security_block"]["decision"] == "negative"
    assert result["records"][0]["profiles"]["security_review"]["decision"] == "positive"
    assert result["profiles"] == PROFILES


def test_holdout_requires_explicit_freeze_and_does_not_silently_change_split(tmp_path):
    path = make_manifest(tmp_path, split="holdout")
    with pytest.raises(ValueError, match="Holdout"):
        evaluate(path, split="holdout", scanner=scan)
    with pytest.raises(ValueError, match="No cases"):
        evaluate(path, scanner=scan)
    result = evaluate(path, split="holdout", freeze_id="caller-declared-test-freeze", scanner=scan)
    assert result["holdout_exposed"] is True
    assert result["freeze_id"] == "caller-declared-test-freeze"


def test_input_integrity_errors_are_counted_not_silently_dropped(tmp_path):
    path = make_manifest(tmp_path)
    (tmp_path / "0.txt").write_text("Changed source", encoding="utf-8")
    result = evaluate(path, scanner=scan)
    assert len(result["records"]) == 4
    assert result["records"][0]["profiles"]["security_review"]["decision"] == "error"
    assert result["records"][0]["input_sha256"] is None
    assert result["metrics"]["security_review"]["upstream_positive_cases"] == 2


@pytest.mark.parametrize("path", ["../outside", "/absolute", "C:/outside", "a\\b", "a/./b", ""])
def test_materialization_rejects_path_aliases_and_escape(tmp_path, path):
    manifest = read_manifest(make_manifest(tmp_path))
    case = manifest["cases"][0]
    case["input"]["files"][0]["path"] = path
    with pytest.raises(ValueError):
        input_bytes(case, tmp_path)


def test_source_native_and_package_views_have_distinct_reproducible_hashes(tmp_path):
    manifest = read_manifest(make_manifest(tmp_path))
    case = manifest["cases"][0]
    raw, _ = input_bytes(case, tmp_path)
    case["input"]["kind"] = "package"
    first, _ = input_bytes(case, tmp_path)
    second, _ = input_bytes(case, tmp_path)
    assert first == second and first != raw


def test_compare_refuses_mismatched_inputs_populations_and_label_authority(tmp_path):
    first = evaluate(make_manifest(tmp_path), scanner=scan)
    second = copy.deepcopy(first)
    second["scanner"] = "external_tool_import"
    assert compare_runs(first, second)["same_inputs"] is True
    for alter in (
        lambda r: r["records"].pop(),
        lambda r: r["records"][0].update(input_sha256="b" * 64),
        lambda r: r["records"][0].update(label_origin="relabeled_by_scanner"),
        lambda r: r.update(manifest_sha256=None),
        lambda r: r.update(scanner_contexts=[{}]),
        lambda r: r.update(coverage_policy={"version": "other"}),
    ):
        other = copy.deepcopy(second)
        alter(other)
        with pytest.raises(ValueError):
            compare_runs(first, other)


def test_report_artifact_claim_must_match_actual_input(tmp_path):
    def wrong(raw, *args, **kwargs):
        report = scan(raw, "0.md")
        report["governance_evidence"]["artifact_sha256"] = "f" * 64
        return report
    result = evaluate(make_manifest(tmp_path), scanner=wrong)
    assert all(row["profiles"]["security_block"]["decision"] == "error" for row in result["records"])


def test_credential_source_to_network_flow_is_security_signal_but_pii_presence_is_not():
    report = {"files": [{"findings": [
        {"id": "credential_source_to_network_payload", "category": "sensitive_data", "tier": "review", "is_actionable": True, "counts_for_governance": True},
        {"id": "pii_email_address", "category": "sensitive_data", "tier": "block", "is_actionable": True, "counts_for_governance": True},
    ]}]}
    signals = security_signals(report)
    assert signals["security_review"] == ["credential_source_to_network_payload"]
    assert signals["security_block"] == []


@pytest.mark.parametrize("missing_or_false", [None, False, 0, "true"])
def test_signal_authority_requires_explicit_boolean_true(missing_or_false):
    base = {"id": "unit_security", "category": "prompt", "tier": "block", "is_actionable": True, "counts_for_governance": True}
    for field in ("is_actionable", "counts_for_governance"):
        finding = {**base, field: missing_or_false}
        assert security_signals({"files": [{"findings": [finding]}]}) == {profile: [] for profile in PROFILES}
        finding.pop(field)
        assert security_signals({"files": [{"findings": [finding]}]}) == {profile: [] for profile in PROFILES}


def test_missing_policy_metadata_abstains_only_for_affected_profile(tmp_path):
    def legacy(raw, *args, **kwargs):
        report = scan(raw, "0.md")
        finding = report["files"][0]["findings"][0]
        finding["tier"] = "review"
        finding.pop("counts_for_governance")
        return report
    result = evaluate(make_manifest(tmp_path), scanner=legacy)
    assert result["records"][0]["profiles"]["security_block"]["decision"] == "negative"
    review = result["records"][0]["profiles"]["security_review"]
    assert review["decision"] == "abstain"
    assert "governance_authority_unreported_or_invalid" in review["unknown_reasons"]


def test_known_ineligible_and_informational_findings_do_not_create_policy_ambiguity():
    findings = [
        {"id": "pii_email_address", "category": "sensitive_data", "tier": "block"},
        {"id": "documented_pattern", "category": "prompt", "tier": "review", "is_actionable": False},
        {"id": "legitimate_capability", "category": "code", "tier": "review", "counts_for_governance": False},
        {"id": "information", "category": "code", "severity": "info"},
    ]
    assert security_unknowns({"files": [{"findings": findings}]}) == {profile: [] for profile in PROFILES}


@pytest.mark.parametrize("status", ["complete", "complete_supported_checks", "complete_input", "partial", "complete_future_version", None])
def test_only_owning_top_level_coverage_enum_allows_negative(tmp_path, status):
    def unknown_coverage(raw, *args, **kwargs):
        report = scan(raw, "1.md")
        report["coverage"]["status"] = status
        return report
    result = evaluate(make_manifest(tmp_path), scanner=unknown_coverage)
    assert all(row["profiles"]["security_review"]["decision"] == "abstain" for row in result["records"])
    assert result["coverage_policy"]["complete_top_level_statuses"] == ["complete_supported_content"]


def test_actual_static_scan_complete_coverage_contract_yields_scoped_negative(tmp_path):
    path = make_manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["cases"] = manifest["cases"][:1]
    manifest["cases"][0]["input"]["filename"] = "SKILL.md"
    raw = b"---\nname: example\ndescription: Harmless authored local fixture\n---\n# Example\nRead the provided text.\n"
    (tmp_path / "0.txt").write_bytes(raw)
    manifest["cases"][0]["input"]["files"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(manifest), encoding="utf-8")
    # This invokes the actual static scanner on harmless authored text, not an
    # external corpus body or runtime tool. The scanner supplies the enum.
    result = evaluate(path)
    row = result["records"][0]
    assert row["coverage"] == "complete_supported_content"
    assert row["profiles"]["security_review"]["decision"] == "negative"
    assert row["profiles"]["security_review"]["unknown_reasons"] == []
