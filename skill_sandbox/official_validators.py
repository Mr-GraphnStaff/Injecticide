"""Run reviewed vendor format validators locally; uploaded code is never imported.

The upstream skill-creator scripts are reference checks, not product acceptance
contracts or security audits. Their results never decide execution policy.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

try:
    from .package_formats import frontmatter
except ImportError:
    from package_formats import frontmatter

ROOT = Path(__file__).resolve().parent / "vendor_validators"
MAX_VALIDATOR_FILES = 50


def _diagnostic(valid, message):
    """Explain the reference check without reflecting uploaded metadata values."""
    if valid:
        return "Reviewed official skill-creator frontmatter check passed."
    if message.startswith("Unexpected key"):
        return "Frontmatter includes a field unsupported by this pinned skill-creator reference."
    for field in ("name", "description"):
        if message.startswith("Missing '" + field + "'"):
            return "The reference requires the frontmatter field: " + field + "."
    if message.startswith("Name"):
        return "The skill name does not meet this reference validator's type, naming or length rules."
    if message.startswith("Description"):
        return "The description does not meet this reference validator's type, character or length rules."
    if message.startswith("Compatibility"):
        return "The compatibility value does not meet this reference validator's type or length rules."
    return "Reviewed official skill-creator frontmatter check failed; compare its pinned source with the selected product requirements."


def _validator(name, entry):
    path = ROOT / name / "quick_validate.py"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError("Reviewed validator integrity check failed")
    spec = importlib.util.spec_from_file_location("injecticide_official_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError("Reviewed validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_skill


def _header(text):
    # Enforce the scanner's bounded, unique-key, anchor-free YAML profile before
    # an upstream script calls yaml.safe_load. No uploaded modules are imported.
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("No canonical YAML frontmatter available for validation")
    for index, line in enumerate(lines[1:], 1):
        if line == "---":
            header = "\n".join(lines[:index + 1]) + "\n"
            frontmatter(header)
            return header
    raise ValueError("Complete YAML frontmatter unavailable")


def attach_official_validator_results(result, texts):
    analysis = result.get("package_analysis", {})
    runtime = analysis.get("target_runtime", "auto")
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    if runtime in {"openai", "openai-mcp-import"}:
        names = ["openai"]
    elif runtime in {"claude-code", "claude-upload"}:
        names = ["anthropic"]
    elif runtime in {"auto", "generic"}:
        names = ["openai", "anthropic"]
    else:
        names = []
    results = []
    for index, skill in enumerate(analysis.get("skills", [])):
        path = skill["path"]
        if not names:
            results.append({"id": "official_validator_unavailable", "runtime": runtime,
                "path": path, "status": "unavailable", "scope": "format_validation_only",
                "diagnostics": ["No reviewed executable validator is bundled for this product. No pass was inferred."],
                "policy_effect": "none", "runtime_acceptance_verified": False})
            continue
        for name in names:
            entry = manifest["validators"][name]
            row = {"id": name + "_skill_creator", "runtime": runtime, "path": path,
                "publisher": entry["publisher"], "revision": entry["revision"],
                "source_url": entry["source_url"], "sha256": entry["sha256"],
                "reviewed_on": manifest["reviewed_on"], "scope": "format_validation_only",
                "applicability": "skill_creator_reference_not_runtime_contract",
                "content_scope": "complete_frontmatter_only", "policy_effect": "none",
                "runtime_acceptance_verified": False}
            if index >= MAX_VALIDATOR_FILES:
                row.update(status="unavailable", diagnostics=["Local validator file-count budget exceeded."])
                results.append(row)
                continue
            try:
                header = _header(texts.get(path, ""))
            except (ValueError, RecursionError):
                row.update(status="unavailable", diagnostics=["Complete frontmatter is outside the bounded local parser profile; the official validator was not run."])
                results.append(row)
                continue
            try:
                validate = _validator(name, entry)
                # Use a fixed file name in an isolated scratch directory. The
                # original package path can never select executable source.
                with tempfile.TemporaryDirectory(prefix="injecticide-format-") as scratch:
                    (Path(scratch) / "SKILL.md").write_text(header, encoding="utf-8")
                    valid, message = validate(Path(scratch))
                # Upstream diagnostics may echo user-controlled metadata. Do not
                # return those values as a new disclosure channel.
                row.update(status="pass" if valid else "fail", diagnostics=[_diagnostic(valid, message)])
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                row.update(status="error", diagnostics=["Reviewed local validator was unavailable or failed its integrity/execution check."])
            results.append(row)
    result["official_validator_results"] = results
    return result
