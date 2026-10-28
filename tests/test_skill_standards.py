"""Paired synthetic requirements cases; no provider calls or uploaded execution."""
import pytest
import yaml

from skill_sandbox.package_formats import inspect_formats
from skill_sandbox import standards_assessment
from skill_sandbox.standards_assessment import build_standards_assessment


def document(**fields):
    return "---\n" + yaml.safe_dump({"name": "demo", "description": "Summarize supplied input.", **fields}, sort_keys=False) + "---\nRead the supplied input.\n"


def assess(files=None, target="generic", file_type="zip", findings=()):
    files = files if files is not None else {"demo/SKILL.md": document()}
    entries = [{"path": path, "assessment_state": "text_analyzed", "findings": list(findings)} for path in files]
    texts = {path: text for path, text in files.items() if text is not None}
    analysis = inspect_formats(entries, texts, target)
    result = {"files": entries, "file_type": file_type, "package_analysis": analysis, "coverage": {"status": "complete"}}
    return build_standards_assessment(result, [{"path": p, "text": t} for p, t in texts.items()]), result


def row(report, rule_id, path=None):
    return next(r for r in report["requirements"] if r["id"] == rule_id and (path is None or r["path"] == path))


def test_valid_skill_has_measured_mandatory_passes_and_explicit_unknown_axes():
    report, _ = assess()
    assert report["overall_status"] == "pass"
    assert report["overall_status_scope"] == "applicable_mandatory_portable_format_checks_only"
    assert report["summary"]["mandatory_fail"] == 0
    assert report["source"]["revision"].startswith("sha256:")
    assert len(report["source"]["source_sha256"]) == 64
    assert {r["category"] for r in report["requirements"]} == {"format", "vendor_compatibility", "authoring_guidance", "security", "runtime_evaluation"}
    for rule_id in ("vendor_runtime_compatibility", "security_coverage", "trigger_accuracy", "output_quality", "script_behavior", "runtime_control_enforcement"):
        assert row(report, rule_id)["status"] == "not_assessed"
    assert all(r["implementation_status"] in {"implemented", "not_implemented"} and r["test_refs"] for r in report["requirements"])


@pytest.mark.parametrize("value,expected", [("", "fail"), ("a" * 500, "pass"), ("a" * 501, "fail"), ([], "fail"), (False, "fail")])
def test_compatibility_optional_field_explicit_one_to_five_hundred_boundary(value, expected):
    report, result = assess({"demo/SKILL.md": document(compatibility=value)})
    assert row(report, "compatibility_value")["status"] == expected
    assert row(report, "compatibility_value")["line"] == 4
    assert any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"]) == (expected == "fail")


@pytest.mark.parametrize("field,value,rule_id", [("metadata", {"version": 3}, "metadata_value"), ("metadata", [], "metadata_value"), ("allowed-tools", ["Read"], "allowed_tools_value")])
def test_optional_portable_field_types_are_measured(field, value, rule_id):
    report, _ = assess({"demo/SKILL.md": document(**{field: value})})
    assert row(report, rule_id)["status"] == "fail"
    assert report["overall_status"] == "fail"


def test_license_semantics_and_unspecified_types_do_not_invent_mandatory_failure():
    report, _ = assess({"demo/SKILL.md": document(license=123)})
    assert row(report, "license_value")["status"] == "not_assessed"
    assert row(report, "license_value")["requirement_level"] == "recommendation"
    assert report["overall_status"] == "pass"


def test_vendor_extensions_fail_strict_portability_without_claiming_vendor_rejection():
    report, result = assess({"demo/SKILL.md": document(**{"disable-model-invocation": True, "future-vendor-field": "opaque"})})
    assert report["overall_status"] == "fail"
    assert row(report, "frontmatter_fields")["status"] == "fail"
    assert row(report, "frontmatter_extensions")["status"] == "not_assessed"
    assert any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"])


def test_vendor_selected_is_advisory_even_with_failed_portable_constraints():
    report, result = assess({"demo/SKILL.md": document(compatibility="")}, target="claude-code")
    assert row(report, "compatibility_value")["status"] == "fail"
    assert all(f["severity"] == "warning" for f in result["package_analysis"]["format_findings"])
    assert row(report, "vendor_runtime_compatibility")["status"] == "not_assessed"


def test_missing_entrypoint_and_name_directory_match_have_different_evidence():
    report, _ = assess({"demo/README.md": "No entrypoint supplied."})
    assert row(report, "skill_entrypoint")["status"] == "fail"
    report, _ = assess({"SKILL.md": document()}, file_type="skill")
    assert row(report, "name_directory_match")["status"] == "not_assessed"
    assert report["overall_status"] == "not_assessed"
    report, _ = assess({"wrong/SKILL.md": document()})
    assert row(report, "name_directory_match")["status"] == "fail"


def test_folder_named_skills_does_not_invent_a_mandatory_entrypoint():
    report, _ = assess({"skills/demo/SKILL.md": document(), "skills/missing/references/note.md": "Sample."})
    assert row(report, "skill_collection_intent")["status"] == "not_assessed"
    assert not any(r["status"] == "fail" for r in report["requirements"] if r["requirement_level"] == "mandatory")
    report, _ = assess({"demo/SKILL.md": document(), "demo/assets/skills/training/data.csv": "Sample."})
    assert report["overall_status"] == "pass"
    assert not any(r["id"] == "skill_collection_intent" for r in report["requirements"])


def test_case_sensitive_entrypoint_and_unavailable_content_never_false_pass():
    report, _ = assess({"demo/skill.md": document()})
    assert row(report, "skill_entrypoint")["status"] == "fail"
    report, _ = assess({"demo/SKILL.md": None})
    assert row(report, "yaml_frontmatter")["status"] == "not_assessed"
    assert report["overall_status"] == "not_assessed"
    report, _ = assess({"inner.zip!/SKILL.md": document()})
    assert row(report, "name_directory_match")["status"] == "not_assessed"


@pytest.mark.parametrize("front", ["name: demo\nmetadata: &x {version: '1'}\ndescription: *x", "name: demo\ndescription: test\nextra: " + "x" * 131073], ids=["yaml_alias", "frontmatter_budget"])
def test_parser_limits_are_not_portable_invalidity(front):
    report, result = assess({"demo/SKILL.md": "---\n" + front + "\n---\n"})
    assert row(report, "yaml_frontmatter")["status"] == "not_assessed"
    assert report["overall_status"] == "not_assessed"
    assert result["package_analysis"]["skills"][0]["validation"] == "not_assessed"
    assert all(f["severity"] != "error" for f in result["package_analysis"]["format_findings"])


@pytest.mark.parametrize("front", ["name: demo\nname: second\ndescription: text", "name: [unclosed", "- list\n- not-a-mapping"])
def test_true_syntax_and_ambiguous_mapping_errors_fail_measured_frontmatter(front):
    report, _ = assess({"demo/SKILL.md": "---\n" + front + "\n---\n"})
    assert row(report, "yaml_frontmatter")["status"] == "fail"
    assert report["overall_status"] == "fail"


def test_recommendations_are_not_mandatory_format_failures_or_estimated_tokens():
    report, _ = assess({"demo/SKILL.md": document() + "Instruction.\n" * 500})
    assert row(report, "body_line_guidance")["status"] == "fail"
    assert report["overall_status"] == "pass"
    assert row(report, "body_token_guidance")["status"] == "not_assessed"
    assert row(report, "body_token_guidance")["token_measurement"] == "not_available"


def test_no_body_minimal_spec_example_and_unicode_name_are_not_invented_failures():
    report, _ = assess({"demo/SKILL.md": document().split("Read the supplied input.")[0]})
    assert report["overall_status"] == "pass"
    body = row(report, "markdown_body")
    assert body["line"] == 4
    report, _ = assess({"café/SKILL.md": document(name="café")})
    assert report["overall_status"] == "pass"


def test_security_taxonomy_is_relevance_only_even_with_observed_detector():
    report, _ = assess(findings=[{"id": "prompt_override"}])
    risks = report["security_guidance"]["risks"]
    assert len(risks) == 10
    assert risks[0]["observed_detector_ids"] == ["prompt_override"]
    assert all(r["status"] == r["risk_exploitability"] == r["runtime_enforcement"] == "not_assessed" for r in risks)
    assert "coverage_percentage" not in report["security_guidance"]


def test_row_and_skill_budgets_never_report_complete_pass(monkeypatch):
    monkeypatch.setattr(standards_assessment, "MAX_ROWS", 2)
    report, _ = assess()
    assert len(report["requirements"]) == 2
    assert report["summary"]["omitted_rows"] > 0
    assert report["overall_status"] == "not_assessed"
    assert report["limits"][0]["omitted_rows"] == report["summary"]["omitted_rows"]
    monkeypatch.setattr(standards_assessment, "MAX_ROWS", 6000)
    monkeypatch.setattr(standards_assessment, "MAX_SKILLS", 1)
    report, _ = assess({"demo/SKILL.md": document(), "second/SKILL.md": document(name="second")})
    assert report["summary"]["omitted_skills"] == 1
    assert report["overall_status"] == "not_assessed"


def test_no_network_or_raw_frontmatter_value_reflection(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network access"))
    secret = "SYNTHETIC_PRIVATE_LITERAL_123456"
    report, _ = assess({"demo/SKILL.md": document(metadata={"secret": secret})})
    import json
    assert secret not in json.dumps(report)
