"""Paired authored launcher and inline metadata cases, no runtime invocation."""
import io
import json
import zipfile

import pytest

from skill_sandbox import script_launchers
from skill_sandbox.app import scan_upload
from skill_sandbox.package_graph import build_package_graph
from skill_sandbox.script_launchers import parse_script_command, inspect_inline_script_metadata


def graph(files):
    return build_package_graph([{"path": p, "text": t} for p, t in files.items()],
                               [{"path": p, "assessment_state": "text_analyzed"} for p in files])


@pytest.mark.parametrize("command", ["uv run scripts/extract.py", "uv run python scripts/extract.py",
    "uv run --with rich==13.0 scripts/extract.py --output result.json",
    "uv run --with 'rich>=12,<14' --python 3.12 --no-project python -u scripts/extract.py data.csv",
    "pipx run --path scripts/extract.py --input input.py", "deno run --allow-read scripts/extract.ts input.ts",
    "bun run scripts/extract.tsx input.tsx", "node scripts/extract.js result.js"])
def test_documented_local_targets_are_not_their_arguments(command):
    parsed = parse_script_command(command)
    assert parsed["status"] == "recognized_static_syntax"
    assert parsed["script"].startswith("scripts/extract.")
    assert parsed["execution_verified"] is False


@pytest.mark.parametrize("command,dependency", [
    ("pipx run --spec esptool==4.6.2 esptool.py input.py", "esptool==4.6.2"),
    ("pipx run black document.py", "black"),
    ("npx --yes eslint@9.0.0 input.js", "eslint@9.0.0"),
    ("npx --package=typescript tsc input.ts", "typescript"),
    ("npm exec -- eslint input.js", "eslint"),
    ("uvx --from ruff==0.7.0 ruff check input.py", "ruff==0.7.0"),
])
def test_package_commands_are_not_missing_local_scripts(command, dependency):
    parsed = parse_script_command(command)
    assert parsed["script"] is None
    assert parsed["status"] == "recognized_static_syntax"
    assert dependency in {d["value"] for d in parsed["package_declarations"]}


@pytest.mark.parametrize("command", ["uv run --unrecognized scripts/extract.py", "uv run $SCRIPT", "uv run -",
                                     "npx --call 'node scripts/run.js'", "pipx run --spec", "uv run 'unclosed"])
def test_unknown_or_malformed_command_has_no_guessed_target(command):
    parsed = parse_script_command(command)
    assert parsed["status"] == "unknown"
    assert parsed["script"] is None


def test_graph_launcher_references_are_physical_root_relative_and_argument_bounded():
    result = graph({"demo/SKILL.md": "Read [workflow](references/flow.md).",
                    "demo/references/flow.md": "# Flow\nRun `uv run --with rich scripts/extract.py input.py --output report.py`.",
                    "demo/scripts/extract.py": "print('not executed')",
                    "demo/references/scripts/extract.py": "print('wrong shadow')"})
    edges = [e for e in result["edges"] if e["source"].endswith("flow.md")]
    assert len(edges) == 1
    assert edges[0]["target"] == "demo/scripts/extract.py"
    assert edges[0]["line"] == 2 and edges[0]["status"] == "resolved"
    assert edges[0]["kind"] == "execution_reference"
    assert any(d["value"] == "rich" for d in result["dependency_declarations"])
    assert not any("input.py" in e["target"] or "report.py" in e["target"] for e in edges)


def test_bare_launcher_arguments_are_not_discovered_as_prose_files():
    result = graph({"SKILL.md": "uv run scripts/extract.py input.py --output report.py",
                    "scripts/extract.py": "print('not executed')"})
    assert [e["target"] for e in result["edges"]] == ["scripts/extract.py"]


def test_npx_package_and_pipx_spec_never_generate_file_edges():
    result = graph({"SKILL.md": "`npx eslint@9.0.0 input.js`\n`pipx run --spec esptool esptool.py input.py`"})
    assert result["edges"] == []
    assert len(result["dependency_declarations"]) == 2


def test_launcher_options_after_operand_are_only_program_arguments():
    parsed = parse_script_command("pipx run black --spec imaginary-package --path input.py")
    assert parsed["script"] is None
    assert parsed["package_declarations"] == [{"kind": "pipx_package", "value": "black"}]
    parsed = parse_script_command("npx eslint@9 --package imaginary-package input.js")
    assert parsed["package_declarations"] == [{"kind": "npm_package", "value": "eslint@9"}]


def test_pipx_ambiguous_filename_resolves_only_when_packaged():
    missing = graph({"SKILL.md": "`pipx run test.py`"})
    assert missing["edges"] == []
    assert missing["launcher_observations"][0]["status"] == "unknown"
    existing = graph({"SKILL.md": "`pipx run test.py`", "test.py": "print('not executed')"})
    assert existing["edges"][0]["target"] == "test.py"
    assert existing["launcher_observations"][0]["status"] == "recognized_static_syntax"


def test_nested_launcher_cannot_escape_into_outer_inventory():
    result = graph({"inner.zip!/SKILL.md": "`uv run ../outside.py`\n`uv run scripts/run.py`",
                    "outside.py": "print('outer')", "inner.zip!/scripts/run.py": "print('inner')"})
    assert result["edges"][0]["status"] == "outside_package"
    assert result["edges"][1]["target"] == "inner.zip!/scripts/run.py"


def test_subprocess_and_manifest_arguments_are_not_fake_execution_files():
    result = graph({"SKILL.md": "[main](main.py)",
                    "main.py": "import subprocess\nsubprocess.run(['python','run.py','input.py'])\n",
                    "run.py": "print('not executed')"})
    assert any(e["target"] == "run.py" for e in result["edges"])
    assert not any(e["target"] == "input.py" for e in result["edges"])


def metadata(body):
    return inspect_inline_script_metadata("# /// script\n" + "\n".join("# " + line for line in body.splitlines()) + "\n# ///\nprint('not executed')\n")


def test_pep723_static_inventory_has_exact_block_line_and_no_runtime_claim():
    result = metadata('dependencies = ["requests>=2,<3", "rich==13.*"]\nrequires-python = ">=3.11"')
    assert result["dependencies"] == ["requests>=2,<3", "rich==13.*"]
    assert result["requires_python"] == ">=3.11"
    assert result["line"] == 1 and result["runtime_verified"] is False
    assert result["status"] == ("parsed_declarations" if script_launchers.Requirement else "unknown")


@pytest.mark.parametrize("body", ['dependencies = [', 'dependencies = "requests"',
    'dependencies = [123]', 'dependencies = ["${PACKAGE}"]', 'requires-python = 311',
    'requires-python = ">=banana"', 'dependencies = ["not a requirement !!!"]', 'tool = "not a table"'])
def test_malformed_dynamic_or_invalid_metadata_is_explicitly_unknown(body):
    result = metadata(body)
    assert result["status"] == "unknown" and result["limits"]


def test_metadata_duplicate_unclosed_string_mention_and_unavailable_parsers(monkeypatch):
    assert inspect_inline_script_metadata('# /// script\n# dependencies = []\n')["status"] == "unknown"
    assert inspect_inline_script_metadata('# /// script\n# dependencies=[]\n# ///\n# /// script\n# dependencies=[]\n# ///\n')["status"] == "unknown"
    assert inspect_inline_script_metadata('"""\n# /// script\n# dependencies=["not-real"]\n# ///\n"""')["status"] == "not_present"
    monkeypatch.setattr(script_launchers, "tomllib", None)
    assert metadata('dependencies = []')["limits"] == ["toml_parser_unavailable"]


def test_missing_semantic_parser_retains_declarations_without_validation_claim(monkeypatch):
    monkeypatch.setattr(script_launchers, "Requirement", None)
    result = metadata('dependencies = ["requests"]')
    assert result["dependencies"] == ["requests"]
    assert result["status"] == "unknown" and result["requirement_validation"] == "not_performed"


def test_metadata_budgets_are_explicit_and_graph_partial(monkeypatch):
    monkeypatch.setattr(script_launchers, "MAX_DEPENDENCIES", 1)
    result = graph({"SKILL.md": "`uv run run.py`", "run.py": '# /// script\n# dependencies=["requests","rich"]\n# ///\n'})
    assert result["status"] == "partial"
    assert "inline_dependency_budget" in {limit["kind"] for limit in result["limits"]}


def test_whole_report_redacts_pep723_url_and_launcher_dependency_credentials():
    secret = "ELENA_PEP723_SYNTHETIC_SECRET_2436"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", '---\nname: demo\ndescription: A synthetic case.\n---\n`uv run --with "requests @ https://u:' + secret + '@example.test/pkg.whl?token=' + secret + '" scripts/run.py`')
        archive.writestr("demo/scripts/run.py", '# /// script\n# dependencies = ["requests @ https://u:' + secret + '@example.test/pkg.whl?token=' + secret + '"]\n# ///\nprint("not executed")\n')
    result = scan_upload(buffer.getvalue(), "demo.skill")
    assert secret not in json.dumps(result)
    assert result["package_analysis"]["relationship_graph"]["inline_script_metadata"]


def test_remote_script_operand_exposes_only_origin_in_graph():
    result = graph({"SKILL.md": '`uv run https://user:secret@example.test/private.py?token=hidden`'})
    serialized = json.dumps(result)
    assert "private.py" not in serialized and "secret" not in serialized and "hidden" not in serialized
    assert any(row["url"] == "https://example.test" for row in result["external_references"])


def test_whole_report_redacts_credential_literal_reflected_in_script_path():
    secret = "ELENA_LAUNCHER_PATH_SECRET_4938"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", '---\nname: demo\ndescription: A synthetic case.\n---\npassword="' + secret + '"\n`uv run scripts/' + secret + '.py`\n')
        archive.writestr("demo/scripts/" + secret + ".py", "print('not executed')\n")
    result = scan_upload(buffer.getvalue(), "demo.skill")
    assert secret not in json.dumps(result)
    launcher = result["package_analysis"]["relationship_graph"]["launcher_observations"][0]
    assert "REDACTED" in launcher["script"]


def test_whole_scan_uv_target_agrees_with_graph_without_treating_argument_as_script():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", '---\nname: demo\ndescription: A synthetic case.\n---\n`uv run --with rich scripts/run.py input.py`\n')
        archive.writestr("demo/scripts/run.py", "print('not executed')\n")
        archive.writestr("demo/input.py", "print('not a script target')\n")
    result = scan_upload(buffer.getvalue(), "demo.skill")
    refs = result["package_analysis"]["execution_references"]
    assert any(r["target"] == "demo/scripts/run.py" and r["line"] == 5 for r in refs)
    assert not any(r["target"] == "demo/input.py" for r in refs)
    script = next(f for f in result["files"] if f["path"] == "demo/scripts/run.py")
    assert any(f["id"] == "declared_execution_target" for f in script["findings"])


def test_explicit_interpreter_can_target_document_suffix_without_guessing_argument():
    parsed = parse_script_command("uv run python scripts/helper.py.md input.py")
    assert parsed["script"] == "scripts/helper.py.md"


def test_manifest_declarations_never_expose_placeholder_line_as_exact():
    result = graph({"package.json": '{\n "scripts": {\n "start":"uv run scripts/run.py"\n }\n}',
                    "scripts/run.py": "print('not executed')"})
    assert result["launcher_observations"][0]["line"] is None
    assert result["edges"][0]["line"] is None
    assert result["capability_observations"][0]["line"] is None


@pytest.mark.parametrize("command,target", [("zsh helper.sh input.sh", "helper.sh"),
    ("fish helper.fish input.fish", "helper.fish"), ("groovy helper.groovy input.groovy", "helper.groovy"),
    ("cscript //nologo helper.vbs input.vbs", "helper.vbs"), ("cmd /c helper.cmd input.cmd", "helper.cmd")])
def test_legacy_interpreter_targets_remain_measured_without_scanning_arguments(command, target):
    parsed = parse_script_command(command)
    assert parsed["status"] == "recognized_static_syntax"
    assert parsed["script"] == target


def test_unknown_wrapper_options_cannot_be_bypassed_by_inner_interpreter_regex():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", '---\nname: demo\ndescription: A synthetic case.\n---\n`uv run --unrecognized python scripts/run.py`\n')
        archive.writestr("demo/scripts/run.py", "print('not executed')\n")
    result = scan_upload(buffer.getvalue(), "demo.skill")
    assert not result["package_analysis"]["execution_references"]
    graph_result = result["package_analysis"]["relationship_graph"]
    assert graph_result["launcher_observations"][0]["status"] == "unknown"
    assert graph_result["status"] == "partial"
