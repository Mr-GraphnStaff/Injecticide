"""Authored static-diagram acceptance cases; no uploaded code executes."""
import json

from architecture_map import validate_map
from skill_sandbox import process_diagram
from skill_sandbox.package_graph import build_package_graph
from skill_sandbox.process_diagram import build_process_diagram, extract_documented_steps


def report(sources):
    files = [{"path": path, "assessment_state": "text_analyzed", "findings": []} for path in sources]
    return {"files": files, "package_analysis": {"relationship_graph": build_package_graph(
        [{"path": path, "text": text} for path, text in sources.items()], files)},
        "governance_evidence": {"artifact_sha256": "a" * 64}}


def test_document_reference_script_capability_and_origin_are_source_backed():
    source = report({"SKILL.md": "Read [workflow](docs/flow.md).",
                     "docs/flow.md": "Run `python scripts/run.py`.",
                     "scripts/run.py": "import requests\nrequests.get('https://example.test/private?token=secret')",
                     "orphan.md": "Unreferenced source."})
    source["files"][2]["findings"] = [{"id": "network_calls"}]
    diagram = build_process_diagram(source)
    script = next(n for n in diagram["nodes"] if n.get("path") == "scripts/run.py")
    assert script["finding_ids"] == ["network_calls"]
    assert any(n["entrypoint"] for n in diagram["nodes"])
    assert any(n["kind"] == "capability" and n["label"] == "network access" for n in diagram["nodes"])
    origin = next(n for n in diagram["nodes"] if n["kind"] == "external")
    assert origin["label"] == "https://example.test"
    relation = next(e for e in diagram["edges"] if e["label"] == "names network destination")
    assert relation["citations"] == [{"path": "scripts/run.py", "line": 2, "line_accuracy": "exact"}]
    assert "private" not in json.dumps(diagram)
    assert "token=secret" not in json.dumps(diagram)
    assert all(n["execution_verified"] is False for n in diagram["nodes"])
    assert all(e["execution_verified"] is False for e in diagram["edges"])
    assert diagram["runtime_verified"] is False
    assert "not execution order" in diagram["scope"]
    validate_map(diagram["architecture_map"])


def test_missing_case_mismatch_and_dynamic_links_are_explicit_unknowns():
    diagram = build_process_diagram(report({"SKILL.md": "[missing](missing.md)\n[case](LOWER.md)\n[dynamic](${DIR}/run.py)",
                                           "lower.md": "Exists with different case."}))
    unresolved = [n for n in diagram["nodes"] if n["kind"] == "unresolved"]
    assert len(unresolved) == 3
    assert {n["status"] for n in unresolved} == {"missing", "case_mismatch", "dynamic_reference_unresolved"}
    assert all(n["verification"] == process_diagram.UNKNOWN for n in unresolved)
    assert all(n["knowledge_status"] == "unknown" for n in unresolved)
    assert all(n["path"] is None for n in unresolved)
    assert diagram["status"] == "partial"
    assert all(e["verification"] == process_diagram.UNKNOWN for e in diagram["edges"])
    assert all(e["knowledge_status"] == "unknown" for e in diagram["edges"])


def test_unreferenced_files_are_isolated_not_connected_as_workflow_steps():
    diagram = build_process_diagram(report({"SKILL.md": "No declared links.", "one.md": "", "two.md": ""}))
    assert len(diagram["nodes"]) == 3
    assert diagram["edges"] == []
    assert diagram["unsupported_analysis"] == ["execution_order", "conditional_control_flow", "runtime_tool_calls", "approval_enforcement"]


def test_manifest_placeholder_line_is_not_an_exact_citation():
    source = report({"package.json": '{"scripts":{"start":"node main.js"}}', "main.js": "console.log('example')"})
    diagram = build_process_diagram(source)
    capability = next(n for n in diagram["nodes"] if n["kind"] == "capability")
    assert capability["citations"] == [{"path": "package.json", "line": None, "line_accuracy": "file_only"}]
    # command_argument also uses the manifest placeholder line; its edge must
    # remain file-only even though its reference kind is execution_reference.
    assert all(c["line"] is None for e in diagram["edges"]
               if e["kind"] in {"execution_reference", "capability", "manifest_component"}
               for c in e["citations"])


def test_budget_omissions_upstream_limits_and_dangling_edges_are_visible(monkeypatch):
    monkeypatch.setattr(process_diagram, "MAX_NODES", 2)
    monkeypatch.setattr(process_diagram, "MAX_EDGES", 1)
    source = report({"SKILL.md": "[one](one.md)\n[two](two.md)\n[three](three.md)",
                     "one.md": "", "two.md": "", "three.md": ""})
    source["package_analysis"]["relationship_graph"]["limits"] = [{"kind": "source_characters", "path": "three.md"}]
    result = build_process_diagram(source)
    assert result["omitted"] == {"nodes": 2, "edges": 2}
    assert {x["kind"] for x in result["limits"]} == {"source_characters", "diagram_node_count", "diagram_edge_count"}
    assert result["status"] == "partial"
    ids = {n["id"] for n in result["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in result["edges"])
    validate_map(result["architecture_map"])


def test_uploaded_mermaid_directives_html_and_quotes_are_label_data():
    path = 'evil"]\nclick n0 "javascript:bad"\n%%{init: {"securityLevel":"loose"}}%%<img>.md'
    source = {"files": [{"path": path, "findings": []}], "package_analysis": {"relationship_graph": {"entrypoints": [path]}}}
    result = build_process_diagram(source)
    assert len(result["mermaid"].splitlines()) == 3
    assert "<img>" not in result["mermaid"]
    assert "%%{init" not in result["mermaid"]
    assert '"javascript:' not in result["mermaid"]
    assert '#34;' in result["mermaid"]
    assert result["nodes"][0]["path"] == path
    validate_map(result["architecture_map"])


def test_no_relationship_analysis_is_partial_and_deterministic():
    source = {"files": [{"path": "SKILL.md"}]}
    result = build_process_diagram(source)
    assert result == build_process_diagram(source)
    assert result["status"] == "partial"
    assert result["limits"] == [{"kind": "relationship_analysis_unavailable"}]
    assert result["edges"] == []


def test_cyclic_references_do_not_expand_or_invent_execution_order():
    source = report({"SKILL.md": "[a](a.md)", "a.md": "[entry](SKILL.md)"})
    result = build_process_diagram(source)
    assert len(result["nodes"]) == 2 and len(result["edges"]) == 2
    assert all(e["label"] == "references document" for e in result["edges"])


def test_external_destinations_do_not_carry_authentication_or_private_paths():
    source = report({"SKILL.md": "No destinations."})
    source["package_analysis"]["relationship_graph"]["external_references"] = [
        {"source": "SKILL.md", "line": 1, "url": "https://user:password@example.test:443/private?token=abc#xyz"}]
    result = build_process_diagram(source)
    assert next(n for n in result["nodes"] if n["kind"] == "external")["label"] == "https://example.test:443"
    serialized = json.dumps(result)
    assert "password" not in serialized and "private" not in serialized and "token=" not in serialized


def test_explicit_steps_have_exact_lines_and_only_adjacent_numbered_order():
    sources = [{"path": "demo/SKILL.md", "text": "# Example\n## Workflow\n1. Read the input.\n\n2. Ask for approval.\n3. If approved, create a report.\nUnrelated prose.\n4. Store results.\n1. Start a different list."}]
    documented = extract_documented_steps(sources)
    assert [s["line"] for s in documented["steps"]] == [2, 3, 5, 6, 8, 9]
    assert [s["step_type"] for s in documented["steps"]] == ["section", "instruction", "approval_mention", "condition_mention", "instruction", "instruction"]
    assert [s["previous_step_id"] for s in documented["steps"]] == [None, None, "step_1", "step_2", None, None]
    source = report({"demo/SKILL.md": sources[0]["text"]})
    source["documented_process"] = documented
    source["files"][0]["findings"] = [{"id": "unrelated_finding"}]
    result = build_process_diagram(source)
    assert len([n for n in result["nodes"] if n["kind"] == "step"]) == 6
    assert len([e for e in result["edges"] if e["kind"] == "documented_order"]) == 2
    assert not any(e["kind"] == "branch" for e in result["edges"])
    assert all(n["finding_ids"] == [] for n in result["nodes"] if n["kind"] == "step")
    assert result["documented_step_status"] == "explicit_steps"
    validate_map(result["architecture_map"])


def test_fenced_code_and_companion_documents_are_not_skill_process_steps():
    sources = [{"path": "SKILL.md", "text": "```markdown\n1. This is a code example.\n```\n~~~\n2. Another example.\n~~~\n1. Actual step."},
               {"path": "README.md", "text": "1. Not the skill entrypoint."}]
    result = extract_documented_steps(sources)
    assert [s["text"] for s in result["steps"]] == ["Actual step."]
    assert result["steps"][0]["line"] == 7


def test_absent_process_steps_are_unknown_not_guessed_from_prose():
    documented = extract_documented_steps([{"path": "SKILL.md", "text": "This skill reads data and produces reports."}])
    assert documented["status"] == "unknown" and not documented["steps"]
    source = report({"SKILL.md": "This skill reads data and produces reports."})
    source["documented_process"] = documented
    assert process_diagram.UNKNOWN in build_process_diagram(source)["process_understanding"]


def test_step_limits_are_reported_without_claiming_complete_workflow(monkeypatch):
    monkeypatch.setattr(process_diagram, "MAX_STEPS", 2)
    result = extract_documented_steps([{"path": "SKILL.md", "text": "1. A\n2. B\n3. C"}])
    assert result["status"] == "partial" and len(result["steps"]) == 2
    assert result["limits"] == [{"kind": "documented_step_count", "path": "SKILL.md"}]


def test_frontmatter_and_hidden_comments_are_not_visible_workflow():
    result = extract_documented_steps([{"path": "SKILL.md", "text": "---\ndescription: |\n  1. YAML description.\n---\n<!--\n1. Hidden author note.\n-->\n1. Visible instruction."}])
    assert [s["text"] for s in result["steps"]] == ["Visible instruction."]
    assert result["steps"][0]["line"] == 8


def test_source_evidence_and_runtime_uncertainty_remain_separate_in_exports():
    source = report({"SKILL.md": "1. Read [instructions](missing.md).\n2. Save output."})
    source["documented_process"] = extract_documented_steps([
        {"path": "SKILL.md", "text": "1. Read instructions.\n2. Save output."}])
    result = build_process_diagram(source)
    assert result["source_evidence_summary"] == {
        "present_files": 1, "documented_steps": 2, "recognized_capabilities": 0,
        "external_origins": 0, "unresolved_references": 1}
    reasons = {item["code"]: item for item in result["uncertainty_reasons"]}
    assert reasons["unresolved_references"]["count"] == 1
    assert "runtime_unverified" in reasons and "trust_unassessed" in reasons
    assert "documented_steps_unrecognized" not in reasons
    exported = result["architecture_map"]
    assert all(n["trust"] == n["sensitivity"] == "unknown" for n in exported["nodes"])
    step = next(n for n in exported["nodes"] if n["kind"] == "step")
    assert "documented step" in step["controls"]
    unresolved = next(n for n in exported["nodes"] if n["kind"] == "unresolved_reference")
    assert "target unresolved (missing)" in unresolved["controls"]
    assert "Source: SKILL.md" in unresolved["controls"]
    assert all("Runtime: unverified" in n["controls"] for n in exported["nodes"])
    validate_map(exported)


def test_uncertainty_explanation_preserves_absent_analysis_and_graph_limits():
    result = build_process_diagram({"files": [{"path": "SKILL.md"}]})
    reasons = {item["code"]: item for item in result["uncertainty_reasons"]}
    assert reasons["analysis_limits"]["count"] == 1
    assert "documented_steps_unrecognized" in reasons
    assert result["status"] == "partial"
