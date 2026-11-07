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
    # Documented steps are listed inside their file, not drawn as boxes.
    assert not any(n["kind"] == "step" for n in exported["nodes"])
    skill = next(n for n in exported["nodes"] if n["kind"] == "skill")
    assert "Documented steps (2; completeness unverified): Read instructions.; Save output." in skill["controls"]
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


def test_disguised_script_and_bare_name_link_to_the_packaged_file_not_missing():
    source = report({"my-skill/SKILL.md": "Run `python scripts/lint.py`. See [load](load-order.md). Read `load-order.md` and `nowhere.md`.",
                     "my-skill/scripts/lint.py.md": "print('x')",
                     "my-skill/capabilities/load-order.md": "Steps."})
    graph = source["package_analysis"]["relationship_graph"]
    statuses = {(e["target"], e["status"]) for e in graph["edges"]}
    assert ("my-skill/scripts/lint.py", "document_suffix_variant") in statuses
    variant = next(e for e in graph["edges"] if e["status"] == "document_suffix_variant")
    assert variant["variant_candidates"] == [{"path": "my-skill/scripts/lint.py.md"}]
    assert any(e["status"] == "name_only_match" for e in graph["edges"])
    diagram = build_process_diagram(source)
    labels = {n["label"] for n in diagram["nodes"] if n["kind"] == "unresolved"}
    assert "my-skill/scripts/lint.py" not in labels and "my-skill/load-order.md" not in labels
    lint = next(n for n in diagram["nodes"] if n.get("path") == "my-skill/scripts/lint.py.md")
    assert any(e["target"] == lint["id"] and e["label"] == "names file packaged under a document suffix"
               for e in diagram["edges"])
    validate_map(diagram["architecture_map"])


def test_ambiguous_bare_name_stays_unresolved():
    source = report({"SKILL.md": "Read `notes.md`.", "a/notes.md": "A", "b/notes.md": "B"})
    statuses = {e["status"] for e in source["package_analysis"]["relationship_graph"]["edges"]}
    diagram = build_process_diagram(source)
    if "ambiguous_name_match" in statuses:
        assert any(n["kind"] == "unresolved" for n in diagram["nodes"])


def test_duplicate_references_merge_and_self_references_are_dropped():
    source = report({"SKILL.md": "See [a](docs/a.md). Again [a](docs/a.md). And [me](SKILL.md).",
                     "docs/a.md": "A"})
    diagram = build_process_diagram(source)
    pairs = [(e["source"], e["target"]) for e in diagram["edges"]]
    assert len(pairs) == len(set(pairs))
    assert all(source_id != target_id for source_id, target_id in pairs)
    merged = next(e for e in diagram["edges"] if e["label"] == "references document")
    assert len(merged["citations"]) >= 1


def test_truncated_map_says_so_in_its_name(monkeypatch):
    monkeypatch.setattr(process_diagram, "MAX_NODES", 2)
    source = report({"SKILL.md": "See [a](a.md) and [b](b.md).", "a.md": "A", "b.md": "B"})
    diagram = build_process_diagram(source)
    assert diagram["omitted"]["nodes"] > 0
    validate_map(diagram["architecture_map"])


def test_playground_limits_match_the_architecture_schema():
    from architecture_map import SCHEMA
    assert process_diagram.MAP_MAX_NODES == SCHEMA["properties"]["nodes"]["maxItems"]
    assert process_diagram.MAP_MAX_EDGES == SCHEMA["properties"]["edges"]["maxItems"]


def test_large_package_map_keeps_files_groups_folders_and_says_it_is_partial(monkeypatch):
    monkeypatch.setattr(process_diagram, "MAP_MAX_NODES", 6)
    sources = {"skill/SKILL.md": "1. **Run** `lint`.\n2. Read [a](docs/a.md) and [b](docs/b.md) and [x](scripts/x.py).\n"
                                 + "".join(f"See [n{i}](notes/n{i}.md).\n" for i in range(8)) + "Also [gone](gone.md).",
               "skill/docs/a.md": "A", "skill/docs/b.md": "B", "skill/scripts/x.py.md": "print(1)"}
    sources.update({f"skill/notes/n{i}.md": "N" for i in range(8)})
    source = report(sources)
    source["documented_process"] = extract_documented_steps([{"path": "skill/SKILL.md", "text": sources["skill/SKILL.md"]}])
    diagram = build_process_diagram(source)
    exported = diagram["architecture_map"]
    validate_map(exported)
    labels = [n["label"] for n in exported["nodes"]]
    assert len(labels) == 6 and labels[0] == "SKILL.md" and exported["nodes"][0]["kind"] == "skill"
    assert "gone.md" in labels  # unresolved references are always kept
    assert not any(n["kind"] == "step" for n in exported["nodes"])
    assert "Run lint." in exported["nodes"][0]["controls"] and "**" not in exported["nodes"][0]["controls"]
    assert diagram["map_omitted"]["components"] > 0
    assert "partial: showing 6 of" in exported["name"]
    # Folders start their own column; one folder never shares a column with another mid-way.
    columns = {}
    for node in exported["nodes"]:
        columns.setdefault(node["x"], []).append(node)
    assert len({n["id"] for n in exported["nodes"]}) == 6
    evidence_ids = {n["id"] for n in diagram["nodes"]}
    skill_id = exported["nodes"][0]["id"]
    assert skill_id in evidence_ids  # citations stay attached in the playground


def full_report(sources):
    source = report(sources)
    source["documented_process"] = extract_documented_steps(
        [{"path": path, "text": text} for path, text in sources.items()],
        source["package_analysis"]["relationship_graph"])
    return source


def _map_kinds(diagram):
    return {n["label"]: n["kind"] for n in diagram["architecture_map"]["nodes"]}


def test_scan_evidence_maps_to_real_kinds_and_flags_on_a_synthetic_skill():
    from tests.test_architecture_overview import vendor_report
    diagram = build_process_diagram(vendor_report())
    exported = diagram["architecture_map"]
    validate_map(exported)
    kinds = _map_kinds(diagram)
    assert kinds["SKILL.md"] == "skill"
    assert kinds["data/vendors.sqlite"] == "data"
    assert kinds["scripts/sync_vendors.py"] == "code"
    assert kinds["scripts/export.py.md"] == "code"  # document-suffixed script
    assert kinds["capabilities/weekly-report.md"] == "artifact"
    assert kinds["https://feeds.example-corp.test (fetched content)"] == "retrieval"
    assert kinds["https://ticketing.example-corp.test (write destination)"] == "output"
    assert kinds["ticketing (MCP server)"] == "mcp"
    assert kinds["WebFetch (web tool)"] == "retrieval"
    assert kinds["Bash (shell tool)"] == "code"
    assert any(kind == "approval" for kind in kinds.values())
    ids = {n["id"]: n for n in exported["nodes"]}
    for edge in exported["edges"]:
        source, target = ids[edge["source"]], ids[edge["target"]]
        # Untrusted exactly on edges leaving fetched content; write exactly on evidenced writes.
        assert edge["untrusted"] == (source["kind"] == "retrieval")
        if edge["write"]:
            assert target["kind"] == "output" or target["label"] == "data/vendors.sqlite"
    assert any(e["write"] and ids[e["target"]]["kind"] == "output" for e in exported["edges"])
    # sqlite3.connect names the store but does not establish a write.
    assert not any(e["write"] and ids[e["target"]]["kind"] == "data" for e in exported["edges"])


def test_planner_proposes_path_edge_control_and_package_tests_for_the_synthetic_skill():
    from architecture_map import plan_map
    from tests.test_architecture_overview import vendor_report
    exported = build_process_diagram(vendor_report())["architecture_map"]
    plan = plan_map(exported)
    titles = [t["title"] for t in plan["tests"]]
    kinds = {n["id"]: n["kind"] for n in exported["nodes"]}
    paths = [t for t in plan["tests"] if t["id"].startswith("path-")]
    assert {kinds[t["node_ids"][0]] for t in paths} == {"retrieval"}
    assert {"code", "mcp"} <= {kinds[t["node_ids"][-1]] for t in paths}
    assert titles.count("Verify control enforcement and routing") == 1  # the approval mention
    assert titles.count("Inspect the skill or plugin package") == 1
    assert any(t["id"].startswith("edge-") for t in plan["tests"])
    assert plan["summary"]["suggested_tests"] >= 10


def test_documentation_only_skill_keeps_neutral_kinds_and_one_package_test():
    from architecture_map import plan_map
    source = full_report({"SKILL.md": "Read [notes](notes.md). Docs at https://docs.example-corp.test/guide.",
                     "notes.md": "Notes."})
    diagram = build_process_diagram(source)
    kinds = set(_map_kinds(diagram).values())
    assert kinds == {"skill", "artifact", "external_reference"}
    assert not any(e["untrusted"] or e["write"] for e in diagram["architecture_map"]["edges"])
    assert plan_map(diagram["architecture_map"])["summary"]["suggested_tests"] == 1


def test_unknown_http_method_is_not_called_a_fetch_or_a_write():
    source = report({"SKILL.md": "Run `python run.py`.",
                     "run.py": "import requests\nrequests.request(method, 'https://api.example-corp.test/x')"})
    diagram = build_process_diagram(source)
    assert _map_kinds(diagram)["https://api.example-corp.test"] == "external_reference"
    assert not any(e["untrusted"] or e["write"] for e in diagram["architecture_map"]["edges"])


def test_file_write_syntax_marks_only_that_link_as_a_write():
    source = report({"SKILL.md": "Run `python run.py`.",
                     "run.py": "out = open('report.csv', 'w')\nsrc = open('input.csv')",
                     "report.csv": "a", "input.csv": "b"})
    exported = build_process_diagram(source)["architecture_map"]
    labels = {n["id"]: n["label"] for n in exported["nodes"]}
    flags = {labels[e["target"]]: e["write"] for e in exported["edges"] if labels[e["source"]] == "run.py"}
    assert flags["report.csv"] is True and flags["input.csv"] is False


def test_negated_approval_is_not_an_approval_gate():
    positive = full_report({"SKILL.md": "Show a preview and wait for approval."})
    negative = full_report({"SKILL.md": "Post without approval or preview."})
    assert "approval" in _map_kinds(build_process_diagram(positive)).values()
    assert "approval" not in _map_kinds(build_process_diagram(negative)).values()
