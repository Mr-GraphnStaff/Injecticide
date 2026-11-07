"""End-to-end static scan contracts for source-backed diagrams."""
import io
import json
import zipfile

from skill_sandbox.app import scan_upload


def scan_package(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return scan_upload(stream.getvalue(), "process.skill", "generic")


def test_diagram_uses_redacted_sources_and_retains_exact_workflow_citations():
    secret = "SYNTHETIC_DIAGRAM_SECRET_123456789"
    report = scan_package({
        "example/SKILL.md": '# Process\n1. Read [notes](references/notes.md).\n'
                            f'2. Review password="{secret}" before continuing.\n',
        "example/references/notes.md": 'Documented inputs only.\n',
    })
    assert secret not in json.dumps(report)
    diagram = report["process_diagram"]
    assert diagram["runtime_verified"] is False
    steps = [node for node in diagram["nodes"] if node["kind"] == "step"]
    assert any(any(c["line"] == 2 for c in n["citations"]) for n in steps)
    assert any("[REDACTED]" in n["label"] for n in steps)
    assert diagram["artifact_sha256"] == report["governance_evidence"]["artifact_sha256"]
    assert all(not e["execution_verified"] for e in diagram["edges"])


def test_embedded_rescan_cites_physical_document_lines():
    text = '# Helper\n\n```python\nvalue = input()\nresult = eval(value)\n```\n'
    report = scan_upload(text.encode(), "helper.py.md", "generic")
    embedded = [finding for finding in report["files"][0]["findings"]
                if finding["id"] == "dynamic_exec" and finding.get("evidence_scope") == "embedded_source"]
    assert embedded
    assert embedded[0]["observations"][0]["line"] == 5
    assert embedded[0]["observations"][0]["embedded_line"] == 2
    assert embedded[0]["samples"][0].startswith("line 5:")


def test_diagram_playground_export_validates_without_external_calls():
    from architecture_map import plan_map
    report = scan_package({"SKILL.md": '# Process\n1. Read [notes](notes.md).\n',
                           "notes.md": 'Input documentation.\n'})
    plan = plan_map(report["process_diagram"]["architecture_map"])
    assert plan["status"] == "modeled_only"
    exported_nodes = report["process_diagram"]["architecture_map"]["nodes"]
    # Documented steps are listed inside their file rather than drawn as boxes.
    assert not any(node["kind"] == "step" for node in exported_nodes)
    skill = next(node for node in exported_nodes if node["kind"] == "skill")
    assert "Documented steps (" in skill["controls"] and "Read notes." in skill["controls"]
    assert "](" not in skill["controls"]
    assert any(node["kind"] == "artifact" for node in exported_nodes)


def test_long_shared_path_prefixes_keep_distinct_nodes_and_findings():
    from skill_sandbox.process_diagram import build_process_diagram
    prefix = "long-directory/" * 38
    paths = [prefix + "one.md", prefix + "two.md"]
    diagram = build_process_diagram({
        "files": [{"path": path, "findings": [{"id": str(i)}],
                   "assessment_state": "text_analyzed"} for i, path in enumerate(paths)],
        "package_analysis": {"relationship_graph": {"status": "complete", "edges": [], "entrypoints": paths}},
    })
    assert {node["path"] for node in diagram["nodes"]} == set(paths)
    assert [node["finding_ids"] for node in diagram["nodes"]] == [["0"], ["1"]]
    assert all(node["assessment_state"] == "text_analyzed" for node in diagram["nodes"])


def test_scanned_synthetic_skill_has_overview_real_kinds_and_meaningful_plan():
    from architecture_map import plan_map, validate_map
    from tests.test_architecture_overview import vendor_review_sources
    report = scan_package(vendor_review_sources())
    diagram = report["process_diagram"]
    overview = diagram["overview"]
    assert overview["schema"] == "injecticide-overview/v1"
    declared = [a["label"] for a in overview["areas"] if a["source"] == "declared" and a["id"] != "area-entry"]
    assert declared == ["Weekly vendor summary", "Vendor risk check", "Raise a ticket"]
    validate_map(diagram["architecture_map"])
    kinds = {n["kind"] for n in diagram["architecture_map"]["nodes"]}
    assert {"skill", "code", "retrieval", "output", "mcp", "approval"} <= kinds
    plan = plan_map(diagram["architecture_map"])
    assert any(t["id"].startswith("path-") for t in plan["tests"])
    assert plan["summary"]["suggested_tests"] > 1


def test_router_text_is_redacted_like_other_evidence():
    secret = "SYNTHETIC_ROUTER_SECRET_123456789"
    report = scan_package({
        "ticketing/SKILL.md": "| Need | Load |\n|---|---|\n"
                              f'| Tickets password="{secret}" | [t](t.md) |\n| Weekly | [w](w.md) |\n',
        "ticketing/t.md": "T", "ticketing/w.md": "W"})
    assert secret not in json.dumps(report)
    assert report["process_diagram"]["overview"]["areas"]
