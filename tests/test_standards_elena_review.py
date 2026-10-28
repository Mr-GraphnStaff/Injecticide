"""Elena's independent conformance/integration challenges; authored fixtures."""
import io
import zipfile

import pytest

from skill_sandbox.app import scan_upload
from skill_sandbox.standards_assessment import build_standards_assessment
from tools.check_skill_standards_sources import main as source_check_main


BODY = "---\nname: demo\ndescription: Review supplied material.\n---\n"


def package(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return scan_upload(buffer.getvalue(), "independent.skill", "generic")


@pytest.mark.parametrize("files", [{"demo/README.md": "No entrypoint."}, {"demo/skill.md": BODY}])
def test_explicit_portable_entrypoint_failure_cannot_leave_execution_allow(files):
    report = package(files)
    assert report["standards_assessment"]["overall_status"] == "fail"
    assert report["readiness"]["status"] == "needs_review"
    assert report["governance_profile"]["brokered_tokens"]["decision"] != "allow"
    assert report["governance_profile"]["customer_managed_keys"]["decision"] != "allow"


def test_optional_resource_folder_name_cannot_invent_mandatory_skill_entrypoint():
    report = package({"demo/SKILL.md": BODY, "demo/references/skills/python/gotchas.md": "Supporting notes."})
    assessment = report["standards_assessment"]
    assert assessment["overall_status"] == "pass"
    assert not any(row["id"] == "skill_entrypoint" and row["status"] == "fail" for row in assessment["requirements"])


def test_virtual_archive_root_does_not_invent_original_parent_directory():
    assessment = build_standards_assessment(
        {"files": [{"path": "inner.zip!/SKILL.md", "findings": []}],
         "package_analysis": {"target_runtime": "generic"}, "coverage": {"status": "complete"}, "file_type": "zip"},
        [{"path": "inner.zip!/SKILL.md", "text": BODY}])
    directory = next(row for row in assessment["requirements"] if row["id"] == "name_directory_match")
    assert directory["status"] == "not_assessed"
    assert assessment["overall_status"] == "not_assessed"


def test_authoring_recommendation_never_becomes_mandatory_format_or_runtime_failure():
    report = package({"demo/SKILL.md": BODY + "Ordinary documented text.\n" * 510})
    assessment = report["standards_assessment"]
    assert assessment["overall_status"] == "pass"
    assert next(row for row in assessment["requirements"] if row["id"] == "body_line_guidance")["status"] == "fail"
    assert all(row["status"] == "not_assessed" for row in assessment["requirements"] if row["category"] in {"security", "runtime_evaluation"})
    assert report["readiness"]["status"] != "needs_review"


def test_parser_safety_limit_is_unknown_and_never_claims_portable_syntax_invalidity():
    report = package({"demo/SKILL.md": "---\nname: demo\ndescription: Review material.\nmetadata: &meta {version: '1'}\n---\n"})
    assessment = report["standards_assessment"]
    assert assessment["overall_status"] == "not_assessed"
    assert next(row for row in assessment["requirements"] if row["id"] == "yaml_frontmatter")["status"] == "not_assessed"
    assert not any(row["severity"] == "error" for row in report["package_analysis"]["format_findings"])
    assert report["coverage"]["status"] == "partial"


def test_source_check_cli_refuses_existing_output_before_any_network_or_mutation(tmp_path, monkeypatch):
    output = tmp_path / "existing.json"
    output.write_text("preserve original", encoding="utf-8")
    monkeypatch.setattr("tools.check_skill_standards_sources.check_sources", lambda *args, **kwargs: pytest.fail("network path must not start"))
    with pytest.raises(SystemExit) as exit_info:
        source_check_main(["--output", str(output)])
    assert exit_info.value.code == 2
    assert output.read_text(encoding="utf-8") == "preserve original"
