"""Source-backed portable format and website ingestion regression cases."""
import hashlib
import json
from pathlib import Path

import pytest

from skill_sandbox.package_formats import BASE_FIELDS, frontmatter, inspect_formats
from tests.test_standards_integration import package, skill, rows
from tools.ingest_agent_skills_site import capture, index_documents, links
from research_mcp.fetch import Response


@pytest.mark.parametrize("runtime", ["auto", "generic", "claude-code", "openai"])
@pytest.mark.parametrize("extra", ["version: '1.0'\n", "metadata:\n  version: 1.0\n", "metadata:\n  version: null\n", "version: 'old'\nmetadata:\n  version: 'new'\n"])
def test_misplaced_or_nonstring_version_is_never_an_accepted_skill(runtime, extra):
    result = package({"demo/SKILL.md": skill(extra)}, target=runtime)
    findings = result["package_analysis"]["format_findings"]
    assert any(row["id"] == "skill_version_declaration" and row["severity"] == "error" for row in findings)
    assert result["package_analysis"]["skills"][0]["validation"] == "invalid"
    assert result["readiness"]["status"] == "needs_review"
    assert result["governance_profile"]["brokered_tokens"]["decision"] not in {"allow", "allow_with_warnings"}


@pytest.mark.parametrize("version", [None, "'1.0'", "1.0.0", "'release-october'", "''"])
def test_optional_string_version_has_no_invented_semver_rule_or_body_restriction(version):
    extra = "" if version is None else "metadata:\n  version: " + version + "\n"
    result = package({"demo/SKILL.md": skill(extra, body="Example version: 3.2\n# Changelog\n## 2.0\n")})
    assert result["standards_assessment"]["overall_status"] == "pass"
    assert not any(row["id"] == "skill_version_declaration" for row in result["package_analysis"]["format_findings"])


def test_allowlist_rejects_unknown_fields_with_reference_validator_provenance():
    for field in ("version", "author", "future-extension"):
        result = package({"demo/SKILL.md": skill(field + ": 'example'\n")})
        row = rows(result, "frontmatter_fields")[0]
        assert row["status"] == "fail"
        assert row["sources"][0]["url"].endswith("skills_ref/validator.py")
        assert len(row["sources"][0]["revision"]) == 40
        assert row["line"] == 4
    assert BASE_FIELDS == {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}


def test_complete_site_guidance_is_explicit_without_fake_runtime_passes():
    result = package({"demo/SKILL.md": skill()})
    for rule in ("body_instruction_quality", "optional_resource_layout", "script_authoring_guidance", "reference_file_guidance", "metadata_key_guidance", "reproducible_dependencies", "script_interface_quality", "client_lifecycle", "evaluation_methodology", "trigger_evaluation_methodology"):
        row = rows(result, rule)[0]
        assert row["status"] == "not_assessed"
        assert row["implementation_status"] == "not_implemented"
    assert "evaluating-skills.md" in rows(result, "evaluation_methodology")[0]["sources"][0]["url"]
    assert result["standards_assessment"]["overall_status"] == "pass"


def test_site_indexes_are_complete_and_reject_external_index_targets():
    assert index_documents("[a](https://agentskills.io/home.md)\n[b](https://agentskills.io/specification.md)") == ["https://agentskills.io/home.md", "https://agentskills.io/specification.md"]
    for value in ("", "https://example.org/doc.md", "https://agentskills.io/home.md?q=extra"):
        with pytest.raises(ValueError):
            index_documents(value)
    assert links("[x](https://agentskills.io/specification#metadata-field)") == ["https://agentskills.io/specification#metadata-field"]


def test_ingestion_retains_bytes_hash_and_unavailable_links_without_execution(tmp_path):
    raw = b"---\nname: sample\n---\n__import__('os').system('never execute')"
    row, text, _ = capture("https://agentskills.io/home.md", tmp_path,
                           lambda *a, **k: Response(a[0], 200, {"content-type": "text/markdown"}, raw))
    assert row["status"] == "retrieved"
    assert row["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / row["raw_file"]).read_bytes() == raw
    assert "never execute" in text
    missing, _, _ = capture("https://agentskills.io/home.md", tmp_path,
                            lambda *a, **k: Response(a[0], 404, {}, b"missing"))
    assert missing["status"] == "unknown_unverified"
    assert "raw_file" not in missing


def test_new_website_research_seeds_include_every_published_document():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "research_mcp/sources.json").read_text(encoding="utf-8"))
    source = next(row for row in data["sources"] if row["id"] == "agent-skills")
    assert len([url for url in source["seeds"] if url.endswith(".md")]) == 9
    assert "https://agentskills.io/skill-creation/evaluating-skills.md" in source["seeds"]
    assert source["discovery"] is False
