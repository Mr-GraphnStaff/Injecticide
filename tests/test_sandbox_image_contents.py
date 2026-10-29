"""Reconstruct the Docker COPY inventory and exercise the image's flat imports.

This is a packaging regression, not a claim that a real container was built.
The release pipeline separately boots the actual built image without networking.
"""
import ast
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath


CONTEXT = Path(__file__).resolve().parents[1] / "skill_sandbox"


def reconstruct(root, dockerfile=None):
    """Apply this image's local COPY instructions to an isolated /app layout."""
    root.mkdir()
    dockerfile = (CONTEXT / "Dockerfile").read_text() if dockerfile is None else dockerfile
    for line in dockerfile.splitlines():
        instruction, _, arguments = line.strip().partition(" ")
        if instruction.upper() != "COPY":
            continue
        parts = json.loads(arguments) if arguments.startswith("[") else shlex.split(arguments)
        # Explicitly fail when Docker syntax outgrows this reconstruction rather
        # than silently pretending an unsupported COPY was tested.
        assert not any(part.startswith("--") for part in parts), "Extend reconstruction for COPY flags"
        assert len(parts) >= 2
        sources, destination = parts[:-1], parts[-1]
        relative = PurePosixPath(destination).relative_to("/app")
        assert ".." not in relative.parts
        for source in sources:
            matches = list(CONTEXT.glob(source))
            assert matches, f"Docker COPY has no local source: {source}"
            for origin in matches:
                target = root.joinpath(*relative.parts)
                if origin.is_dir():
                    shutil.copytree(origin, target, dirs_exist_ok=True)
                else:
                    if destination.endswith("/") or len(sources) > 1 or len(matches) > 1:
                        target /= origin.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(origin, target)
    return root


def import_and_scan(bundle):
    # Isolated mode excludes PYTHONPATH and the repository working directory;
    # only the reconstructed image files supply the flat application modules.
    script = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import app
assert Path(app.__file__).parent.resolve() == Path(sys.argv[1]).resolve()
result = app.scan_upload(b'---\\nname: packaged-smoke\\ndescription: Summarize supplied text.\\n---\\nSummarize supplied text.', 'SKILL.md')
assert result['summary']['total_files'] == 1
assert result['files'][0]['path'] == 'SKILL.md'
print('sandbox flat-module import and scan passed')
"""
    return subprocess.run([sys.executable, "-I", "-c", script, str(bundle)], cwd=bundle,
                          capture_output=True, text=True, timeout=30, check=False)


def test_docker_copy_inventory_includes_every_statically_imported_local_module(tmp_path):
    bundle = reconstruct(tmp_path / "app")
    missing = []
    for source in bundle.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module.split(".")[0]]
            elif isinstance(node, ast.Import):
                modules = [alias.name.split(".")[0] for alias in node.names]
            else:
                continue
            for module in modules:
                if (CONTEXT / (module + ".py")).is_file() and not (bundle / (module + ".py")).is_file():
                    missing.append(f"{source.name} imports omitted local module {module}.py")
    assert not missing, "\n".join(sorted(set(missing)))


def test_reconstructed_sandbox_flat_application_imports_and_scans(tmp_path):
    result = import_and_scan(reconstruct(tmp_path / "app"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "sandbox flat-module import and scan passed" in result.stdout


def test_reconstruction_reproduces_missing_module_failure_when_copy_is_removed(tmp_path):
    dockerfile = (CONTEXT / "Dockerfile").read_text()
    removed = "\n".join(line for line in dockerfile.splitlines() if not line.startswith("COPY obsession_signatures.py "))
    assert removed != dockerfile
    result = import_and_scan(reconstruct(tmp_path / "app", removed))
    assert result.returncode != 0
    assert "ModuleNotFoundError" in result.stderr and "obsession_signatures" in result.stderr
