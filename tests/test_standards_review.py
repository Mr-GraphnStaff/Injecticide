"""Independent QA: portable intent boundaries and whole-report integration.

These are authored synthetic cases, not a representative accuracy benchmark.
"""
import io
import json
import zipfile

import pytest

from skill_sandbox.app import scan_upload
from skill_sandbox.package_graph import build_package_graph
from skill_sandbox.standards_assessment import build_standards_assessment


def assess(files, coverage="complete"):
    records = [{"path": path, "findings": [], "assessment_state": "text_analyzed"}
               for path in files]
    return build_standards_assessment(
        {"files": records, "package_analysis": {"target_runtime": "generic"},
         "coverage": {"status": coverage}, "file_type": "zip"},
        [{"path": path, "text": text} for path, text in files.items()],
    )


def test_allowed_nested_resources_are_not_inferred_as_new_skill_packages():
    # The official portable specification permits arbitrary extra directories.
    # A resource folder called "skills" inside this skill is still a resource.
    report = assess({
        "demo/SKILL.md": "---\nname: demo\ndescription: Review supplied input.\n---\n",
        "demo/assets/skills/training/data.csv": "label,value\nexample,1\n",
    })
    assert report["overall_status"] == "pass"
    entries = [row for row in report["requirements"] if row["id"] == "skill_entrypoint"]
    assert [(row["path"], row["status"]) for row in entries] == [("demo/SKILL.md", "pass")]


@pytest.mark.parametrize("coverage,expected", [("complete", "fail"), ("partial", "not_assessed")])
def test_missing_entrypoint_requires_complete_inventory_to_establish_absence(coverage, expected):
    # In a capped/partial archive inventory the missing entrypoint may simply
    # be outside inspected entries. A complete paired case still fails.
    report = assess({"skills/demo/references/note.md": "Example resource.\n"}, coverage)
    row = next(row for row in report["requirements"] if row["id"] == "skill_entrypoint")
    assert row["status"] == expected
    assert report["overall_status"] == expected


def test_scanner_integration_preserves_unknown_axes_and_redacts_cross_module_credentials():
    secret = "MARA_INDEPENDENT_SYNTHETIC_TOKEN_610394"
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("demo/SKILL.md", "---\nname: demo\ndescription: Review supplied input.\n---\n"
                         f'password="{secret}"\n'
                         '`uv run --with "requests @ https://u:' + secret + '@example.test/pkg.whl" scripts/review.py`\n')
        archive.writestr("demo/scripts/review.py", '# /// script\n# dependencies = ["requests @ https://u:'
                         + secret + '@example.test/pkg.whl"]\n# requires-python = ">=3.11"\n# ///\n'
                         'raise RuntimeError("Scanner must never execute uploaded Python")\n')
    report = scan_upload(package.getvalue(), "independent-review.skill", target_runtime="generic")
    assert secret not in json.dumps(report)
    assessment = report["standards_assessment"]
    assert assessment["overall_status"] == "pass"
    for row in assessment["requirements"]:
        if row["category"] in {"security", "runtime_evaluation"} or row["id"] == "vendor_runtime_compatibility":
            assert row["status"] == "not_assessed"
    graph = report["package_analysis"]["relationship_graph"]
    assert any(edge["target"] == "demo/scripts/review.py" and edge["kind"] == "execution_reference"
               for edge in graph["edges"])
    assert graph["inline_script_metadata"][0]["runtime_verified"] is False
    assert report["evidence_redaction"]["status"] == "applied"
    assert report["process_diagram"]["runtime_verified"] is False


def test_manifest_launcher_citation_does_not_claim_placeholder_line_is_exact():
    files = {"package.json": '{\n  "scripts": {\n    "start": "uv run scripts/review.py"\n  }\n}',
             "scripts/review.py": "print('not executed')\n"}
    graph = build_package_graph([{"path": path, "text": text} for path, text in files.items()],
                                [{"path": path} for path in files])
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "execution_reference")
    assert edge.get("line") is None or edge.get("line_accuracy") == "file_only"
