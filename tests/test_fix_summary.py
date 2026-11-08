"""What to fix: findings grouped by cause. Synthetic data only."""
import copy
import io
import json
import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skill_sandbox.fix_summary import build_fix_summary
from skill_sandbox.app import scan_upload


def finding(fid, tier="review", severity="medium", **extra):
    return {"id": fid, "tier": tier, "severity": severity, **extra}


def result(*files, **extra):
    base = {"files": [{"path": path, "findings": list(findings)} for path, findings in files]}
    base.update(extra)
    return base


def by_cause(summary):
    return {item["cause"]: item for item in summary["items"]}


def test_disguised_script_is_one_cause_with_each_file_listed_once():
    scan = result(("s/a.py.md", [finding("executable_packaged_as_document"), finding("declared_execution_target"),
                                 finding("code_in_text_artifact")]),
                  ("s/b.py.txt", [finding("code_in_text_artifact"), finding("executable_packaged_as_document")]),
                  ("s/guide.md", [finding("code_in_text_artifact")]))
    items = by_cause(build_fix_summary(scan))
    disguised = items["disguised_script"]
    assert disguised["files"] == ["s/a.py.md", "s/b.py.txt"]
    assert disguised["finding_ids"] == ["code_in_text_artifact", "declared_execution_target", "executable_packaged_as_document"]
    assert disguised["count"] == 5 and disguised["priority"] == "review"
    # Code in a plain document with no execution declaration is a separate cause.
    assert items["code_in_documents"]["files"] == ["s/guide.md"]


def test_causes_priorities_and_ordering_are_deterministic():
    scan = result(("SKILL.md", [finding("prompt_override", tier="block", severity="high"),
                                finding("pii_email_address"), finding("sensitive_topic", tier="info", severity="info")]),
                  ("cfg.py", [finding("hardcoded_secret", tier="block", severity="high"), finding("subprocess_spawn"),
                              finding("filesystem_access"), finding("brand_new_detector")]))
    first = build_fix_summary(copy.deepcopy(scan))
    assert first == build_fix_summary(copy.deepcopy(scan))
    assert first["schema"] == "injecticide-fix-summary/v1"
    order = [(item["priority"], item["cause"]) for item in first["items"]]
    assert order == [("block", "hardcoded_secrets"), ("block", "prompt_injection"), ("review", "personal_data"),
                     ("review", "execution"), ("review", "other:brand_new_detector"), ("info", "informational")]
    for item in first["items"]:
        assert set(item) >= {"id", "title", "priority", "cause", "action", "files", "finding_ids", "count"}
        assert len(item["files"]) == len(set(item["files"]))
    execution = by_cause(first)["execution"]
    assert execution["finding_ids"] == ["filesystem_access", "subprocess_spawn"] and execution["count"] == 2
    info = by_cause(first)["informational"]
    assert info["collapsed"] is True and info["finding_ids"] == ["sensitive_topic"]
    assert len({item["id"] for item in first["items"]}) == len(first["items"])


def test_format_failures_name_the_fields_and_references_and_database_gaps_are_listed():
    message = ("Portable frontmatter permits only name, description, license, compatibility, metadata and "
               "allowed-tools; put additional properties such as version inside metadata. Found: owner, size_note.")
    scan = result(("skill/SKILL.md", []), ("skill/data.db", []),
                  standards_assessment={"requirements": [
                      {"id": "frontmatter_fields", "status": "fail", "requirement_level": "mandatory",
                       "path": "skill/SKILL.md", "message": message},
                      {"id": "body_token_guidance", "status": "fail", "requirement_level": "recommendation", "path": "skill/SKILL.md"}]},
                  package_analysis={"relationship_graph": {"edges": [
                      {"source": "skill/SKILL.md", "target": "skill/missing.md", "status": "missing"},
                      {"source": "skill/SKILL.md", "target": "skill/ok.md", "status": "resolved"}]}})
    scan["files"][1]["database_profile"] = {"coverage": {"status": "partial"}}
    items = by_cause(build_fix_summary(scan))
    fmt = items["format_failures"]
    assert fmt["fields"] == ["owner", "size_note"] and fmt["failed_checks"] == ["frontmatter_fields"]
    assert "owner, size_note" in fmt["action"]
    assert items["unresolved_references"]["files"] == ["skill/SKILL.md"]
    assert items["unresolved_references"]["reference_statuses"] == ["missing"]
    assert items["database_coverage"]["files"] == ["skill/data.db"]


def test_policy_allowed_findings_are_noted_not_hidden():
    scan = result(("dir.db", [finding("contact_directory", policy_disposition="allowed_by_policy", policy_rule="R6"),
                              finding("pii_phone_number")]))
    item = by_cause(build_fix_summary(scan))["personal_data"]
    assert item["count"] == 2 and item["allowed_by_policy"] == 1 and item["policy_rules"] == ["R6"]
    assert "R6" in item["policy_note"]


def test_empty_and_partial_results_are_tolerated():
    assert build_fix_summary({})["items"] == []
    assert build_fix_summary({"files": [{"path": "x"}]})["items"] == []


def test_real_scan_groups_a_disguised_script_and_copies_no_secret():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", "---\nname: demo\ndescription: Synthetic demo skill.\n---\n"
                         "Run `python scripts/tool.py.md` to start.\n")
        archive.writestr("demo/scripts/tool.py.md", "import subprocess\nsubprocess.run(['echo', 'hi'])\n"
                         "TOKEN = 'sk_live_" + "Z9y8X7w6V5u4T3s2R1q0P9o8" + "'\n")
    policy = json.dumps({"schema": "injecticide-org-policy/v1", "organization": "Example Org (fictional)",
                         "policy_name": "P", "compiled_date": "2026-11-01", "sources": [{"id": "S", "title": "T"}],
                         "rules": [{"id": "R1", "title": "Scripts allowed", "source": "S", "requirement": "x",
                                    "when": {"finding": "executable_packaged_as_document"}, "effect": "allow",
                                    "enforcement": "mandatory"}]})
    report = scan_upload(buffer.getvalue(), "demo.zip", "auto", None, policy)
    items = by_cause(report["fix_summary"])
    assert items["disguised_script"]["files"] == ["demo/scripts/tool.py.md"]
    assert items["disguised_script"]["allowed_by_policy"] == 1
    assert items["hardcoded_secrets"]["priority"] == "block"
    assert report["fix_summary"]["items"][0]["priority"] == "block"
    assert "sk_live_Z9y8" not in json.dumps(report["fix_summary"])
