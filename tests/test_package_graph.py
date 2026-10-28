"""Authored package relationship scenarios; not measured market accuracy."""
import json

from skill_sandbox import package_graph
from skill_sandbox.package_graph import build_package_graph


def graph(files):
    return build_package_graph(
        [{"path": path, "text": text, "artifact_role": "active" if path.endswith("SKILL.md") else "reference"}
         for path, text in files.items() if isinstance(text, str)],
        [{"path": path, "assessment_state": "text_analyzed" if isinstance(text, str) else "binary_asset_inventory_only"}
         for path, text in files.items()],
    )


def test_skill_reference_script_and_asset_chain_preserves_line_evidence():
    result = graph({
        "demo/SKILL.md": "Read [instructions](references/workflow.md).",
        "demo/references/workflow.md": "Use [font](../assets/font.ttf).\n`python scripts/report.py`",
        "demo/scripts/report.py": "from pathlib import Path\nPath('output.txt').write_text('report')\n",
        "demo/assets/font.ttf": b"font",
        "demo/references/orphan.md": "Unused material remains scan input.",
    })
    assert {"demo/references/workflow.md", "demo/scripts/report.py", "demo/assets/font.ttf"} <= set(result["reachable_paths"])
    assert result["unreferenced_paths"] == ["demo/references/orphan.md"]
    assert any(edge["source"].endswith("workflow.md") and edge["line"] == 2 and edge["kind"] == "execution_reference" for edge in result["edges"])
    chain = next(c for c in result["action_chains"] if c["capability"] == "file_write")
    assert chain["path"] == ["demo/SKILL.md", "demo/references/workflow.md", "demo/scripts/report.py"]
    assert chain["execution_verified"] is False


def test_missing_and_escaping_references_are_observations_not_security_findings():
    result = graph({"SKILL.md": "[missing](references/nope.md)\n[outside](../../outside.txt)\n[anchor](#section)"})
    assert {e["status"] for e in result["edges"]} == {"missing", "outside_package"}
    assert not result["capability_observations"]
    assert "findings" not in result


def test_url_destination_observations_remove_all_credential_sections():
    result = graph({"SKILL.md": "Reference https://user:password@example.test/private-secret?token=hidden#hidden"})
    assert result["external_references"][0]["url"] == "https://example.test"
    assert "password" not in json.dumps(result)
    assert "private-secret" not in json.dumps(result)
    assert not result["capability_observations"]


def test_python_alias_calls_and_local_imports_without_importing_code():
    result = graph({
        "demo/SKILL.md": "Run `python scripts/main.py`.",
        "demo/scripts/main.py": "import os as operating\nimport requests as web\nimport helper\nfrom subprocess import run as launch\noperating.getenv('API_KEY')\nweb.post('https://example.test/upload')\nlaunch(['python', 'helper.py'])\n",
        "demo/scripts/helper.py": "raise RuntimeError('never execute uploaded source')",
    })
    assert {"environment_read", "network_access", "process_execution"} <= {c["capability"] for c in result["capability_observations"]}
    assert any(e["kind"] == "local_import" and e["target"] == "demo/scripts/helper.py" for e in result["edges"])
    assert "demo/scripts/helper.py" in result["reachable_paths"]


def test_stdlib_and_installed_imports_do_not_become_missing_package_files():
    result = graph({"SKILL.md": "`python main.py`", "main.py": "import os\nimport unknown_installed_package\n"})
    assert not any(e["status"] == "missing" for e in result["edges"])


def test_relative_import_and_cycle_reachability_terminate():
    result = graph({"a/SKILL.md": "[a](pkg/a.py)", "a/pkg/a.py": "from . import b", "a/pkg/b.py": "from . import a"})
    assert {"a/pkg/a.py", "a/pkg/b.py"} <= set(result["reachable_paths"])


def test_plugin_root_variable_and_dependencies_are_not_installed():
    result = graph({
        ".claude-plugin/plugin.json": json.dumps({"name": "demo", "hooks": "${CLAUDE_PLUGIN_ROOT}/hooks/run.py"}),
        "hooks/run.py": "print('demo')",
        "package.json": json.dumps({"dependencies": {"demo": "1.0.0"}, "scripts": {"postinstall": "node scripts/install.js"}}),
        "scripts/install.js": "console.log('do not execute');",
    })
    assert any(e["target"] == "hooks/run.py" and e["status"] == "resolved" for e in result["edges"])
    assert result["dependency_declarations"] == [{"source": "package.json", "kind": "dependencies", "value": "demo", "verification": "declared_not_installed"}]
    assert any(e["target"] == "scripts/install.js" for e in result["edges"])


def test_declared_read_and_write_are_separate_and_comments_do_not_create_ast_calls():
    result = graph({"SKILL.md": "`python main.py`", "main.py": "# os.system('example')\nopen('input.txt')\nopen('report.txt', 'w')\n", "input.txt": "hello"})
    capabilities = {c["capability"] for c in result["capability_observations"] if c["source"] == "main.py"}
    assert capabilities == {"file_read", "file_write"}


def test_source_and_edge_budgets_are_explicit(monkeypatch):
    monkeypatch.setattr(package_graph, "MAX_EDGES", 1)
    result = graph({"SKILL.md": "[one](a.md)\n[two](b.md)", "a.md": "", "b.md": ""})
    assert result["status"] == "partial"
    assert {limit["kind"] for limit in result["limits"]} == {"edge_count"}
    monkeypatch.setattr(package_graph, "MAX_SOURCE_CHARACTERS", 10)
    result = graph({"SKILL.md": "hello world"})
    assert result["status"] == "partial"
    assert "source_characters" in {limit["kind"] for limit in result["limits"]}


def test_invalid_python_and_json_are_explicit_not_silently_complete():
    result = graph({"SKILL.md": "", "main.py": "def bad(:", "package.json": "{"})
    assert result["status"] == "partial"
    assert {limit["kind"] for limit in result["limits"]} == {"python_parse_unavailable", "json_parse_unavailable"}


def test_url_paths_and_encoded_traversal_resolve_without_network():
    result = graph({"SKILL.md": "[safe](docs/hello%20world.md#section)\n[escape](%2e%2e/%2e%2e/outside.txt)", "docs/hello world.md": "hello"})
    assert any(e["target"] == "docs/hello world.md" and e["status"] == "resolved" for e in result["edges"])
    assert any(e["status"] == "outside_package" for e in result["edges"])


def test_html_and_reference_definitions_are_followed():
    result = graph({"SKILL.md": '[read]: docs/readme.md\n<img src="logo.png">', "docs/readme.md": "", "logo.png": b"image"})
    assert set(result["reachable_paths"]) == {"SKILL.md", "docs/readme.md", "logo.png"}


def test_malformed_url_reference_is_reported_without_crashing():
    result = graph({"SKILL.md": "[asset](//[bad)"})
    assert result["status"] == "partial"
    assert result["edges"][0]["status"] == "malformed_reference"


def test_nested_archive_references_cannot_escape_into_outer_inventory():
    result = graph({
        "inner.zip!/SKILL.md": "[outside](../outside.py)\n[outer](scripts/outer.py)\n[inside](scripts/inside.py)",
        "outside.py": "print('outer')",
        "scripts/outer.py": "print('outer')",
        "inner.zip!/scripts/inside.py": "print('inner')",
    })
    edges = result["edges"]
    assert edges[0]["status"] == "outside_package"
    assert edges[1]["status"] == "missing"
    assert edges[2]["status"] == "resolved"
    assert "outside.py" in result["unreferenced_paths"]
    assert "scripts/outer.py" in result["unreferenced_paths"]


def test_plain_prose_filenames_are_traced_and_case_mismatch_is_not_resolved():
    result = graph({
        "pdf/SKILL.md": "Read FORMS.md and reference.md before continuing.",
        "pdf/forms.md": "Companion form workflow.",
        "pdf/reference.md": "Companion references.",
    })
    mismatch = next(edge for edge in result["edges"] if edge["target"] == "pdf/FORMS.md")
    assert mismatch["status"] == "case_mismatch"
    assert mismatch["case_mismatch_candidates"] == [{"path": "pdf/forms.md"}]
    assert "pdf/forms.md" not in result["reachable_paths"]
    assert "pdf/reference.md" in result["reachable_paths"]


def test_external_url_filename_paths_are_not_local_prose_references():
    result = graph({"SKILL.md": "Read https://example.test/docs/reference.md or [web](https://example.test/readme.md)."})
    assert result["edges"] == []
    assert result["external_references"]


def test_prose_case_mismatch_does_not_cross_archive_boundary():
    result = graph({"inner.zip!/SKILL.md": "Read OUTSIDE.md.", "outside.md": "outer file"})
    edge, = result["edges"]
    assert edge["status"] == "missing"
    assert "case_mismatch_candidates" not in edge


def test_ambiguous_case_matches_never_choose_a_target_silently():
    result = graph({"SKILL.md": "Read Forms.md.", "forms.md": "a", "FORMS.md": "b"})
    edge, = result["edges"]
    assert edge["status"] == "ambiguous_case_reference"
    assert edge["case_mismatch_candidates"] == [{"path": "FORMS.md"}, {"path": "forms.md"}]
    assert result["reachable_paths"] == ["SKILL.md"]
