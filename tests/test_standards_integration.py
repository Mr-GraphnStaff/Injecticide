"""Whole-scan conformance boundaries using authored synthetic packages."""
import io
import json
import zipfile

from skill_sandbox.app import scan_upload


def package(files, target="generic"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return scan_upload(stream.getvalue(), "fixture.skill", target)


def skill(extra="", body="Summarize the supplied text."):
    return "---\nname: demo\ndescription: Synthetic fixture\n" + extra + "---\n" + body


def rows(result, identifier):
    return [r for r in result["standards_assessment"]["requirements"] if r["id"] == identifier]


def test_empty_compatibility_fails_input_conformance_and_readiness():
    result = package({"demo/SKILL.md": skill("compatibility: ''\n")})
    assert rows(result, "compatibility_value")[0]["status"] == "fail"
    assert result["readiness"]["status"] == "needs_review"
    assert result["standards_assessment"]["source"]["source_sha256"]


def test_vendor_extension_is_a_strict_portable_failure_and_vendor_support_unknown():
    result = package({"demo/SKILL.md": skill("context: fork\nfuture-extension: value\n")})
    assert rows(result, "frontmatter_fields")[0]["status"] == "fail"
    assert rows(result, "frontmatter_extensions")[0]["status"] == "not_assessed"
    assert rows(result, "vendor_runtime_compatibility")[0]["status"] == "not_assessed"
    assert any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"])
    assert result["readiness"]["status"] == "needs_review"


def test_parser_budget_is_unassessed_and_incomplete_rather_than_invalid_syntax():
    result = package({"demo/SKILL.md": skill("description-padding: '" + "x" * 132000 + "'\n")})
    assert rows(result, "yaml_frontmatter")[0]["status"] == "not_assessed"
    assert result["coverage"]["status"] == "partial"
    assert not any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"])
    assert result["governance_profile"]["brokered_tokens"]["decision"] != "allow"


def test_inline_dependency_evidence_and_standards_do_not_reflect_credentials(monkeypatch):
    def forbid_network(*args, **kwargs):
        raise AssertionError("Static package scanning must not contact a destination")
    monkeypatch.setattr("socket.create_connection", forbid_network)
    secret = "SYNTHETIC_STANDARDS_SECRET_12345678"
    script = '# /// script\n# dependencies = ["demo @ https://user:' + secret + '@packages.invalid/demo.whl"]\n# ///\nprint("sample")\n'
    result = package({"demo/SKILL.md": skill(body='Run `uv run scripts/extract.py`.\npassword="' + secret + '"'),
                      "demo/scripts/extract.py": script})
    assert secret not in json.dumps(result)
    edges = result["package_analysis"]["relationship_graph"]["edges"]
    assert any(e["target"] == "demo/scripts/extract.py" and e["status"] == "resolved" for e in edges)
    assert not any("uv run" in e["target"] for e in edges)
    assert rows(result, "script_behavior")[0]["status"] == "not_assessed"


def test_single_file_does_not_claim_a_parent_directory_check_was_completed():
    result = scan_upload(skill().encode(), "SKILL.md", "generic")
    assert rows(result, "name_directory_match")[0]["status"] == "not_assessed"
