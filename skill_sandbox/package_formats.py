"""Local, bounded format adapters. Uploads never choose a schema to download.

Sources: https://agentskills.io/specification and https://agent-plugins.org/specification
Runtime references are recorded in rules/package_sources.json.
"""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry

SCHEMA_ROOT = Path(__file__).resolve().parent / "schemas"
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
RUNTIMES = ("auto", "generic", "claude-code", "claude-upload", "openai", "openai-mcp-import", "copilot", "gemini", "cursor", "cascade", "kiro", "openclaw")
BASE_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
CODE_FIELDS = {"argument-hint", "arguments", "disable-model-invocation", "user-invocable", "model", "context", "agent", "hooks", "disallowed-tools"}
MAX_CONFIG_CHARS = 131072


class ParserLimitError(ValueError):
    """Input may be valid YAML/JSON, but exceeds the local safe parser profile."""


class UniqueSafeLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate YAML mappings as well as unsafe object tags."""


def _unique_yaml(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("Duplicate or non-string YAML mapping key")
        result[key] = loader.construct_object(value_node)
    return result


UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_yaml)


def bounded_data(text: str, kind: str = "json"):
    if len(text) > MAX_CONFIG_CHARS:
        raise ParserLimitError("Configuration exceeds 128 KiB parser budget")
    try:
        if kind == "json":
            def reject_constant(value):
                raise ValueError("Nonstandard JSON numeric constant")
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError(f"Duplicate key: {key}")
                    result[key] = value
                return result
            result = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
        else:
            tokens = list(yaml.scan(text))
            if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in tokens):
                raise ParserLimitError("YAML anchors/aliases are outside the bounded parser profile")
            result = yaml.load(text, Loader=UniqueSafeLoader)
        pending = [(result, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 24 or nodes > 10000:
                raise ParserLimitError("Configuration nesting/node budget exceeded")
            if isinstance(item, dict):
                pending.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                pending.extend((value, depth + 1) for value in item)
        return result
    except RecursionError as exc:
        raise ParserLimitError("Configuration exceeds safe parser recursion limits") from exc
    except yaml.YAMLError as exc:
        raise ValueError("Invalid configuration syntax") from exc


def frontmatter(text: str):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("Missing YAML frontmatter")
    header_characters = 0
    for end, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            data = bounded_data("\n".join(lines[1:end]), "yaml")
            if not isinstance(data, dict):
                raise ValueError("Skill frontmatter must be a mapping")
            return data
        header_characters += len(line) + (1 if end > 1 else 0)
        if header_characters > MAX_CONFIG_CHARS:
            raise ParserLimitError("Frontmatter exceeds 128 KiB parser budget")
    raise ValueError("Unterminated YAML frontmatter")


def portable_skill_checks(data, path):
    """Measured portable constraints, separate from vendor acceptance/guidance."""
    name, description = data.get("name"), data.get("description")
    parent = PurePosixPath(path).parent.name
    if parent.endswith("!"):
        # A nested archive's virtual container identity is not the skill's
        # original directory name.
        parent = ""
    checks = []

    def add(rule_id, valid, message, *, applicable=True):
        checks.append({"id": rule_id, "status": "not_applicable" if not applicable else "pass" if valid else "fail", "message": message})

    add("name_required", isinstance(name, str) and bool(name), "Required name is a nonempty string.")
    add("name_length", isinstance(name, str) and 1 <= len(name) <= 64, "Name must contain 1–64 characters.")
    add("name_characters", isinstance(name, str) and bool(name) and name == name.lower() and all(c.isalnum() or c == "-" for c in name), "Name uses lowercase alphanumeric characters and hyphens.")
    add("name_hyphens", isinstance(name, str) and bool(name) and not name.startswith("-") and not name.endswith("-") and "--" not in name, "Name has no leading, trailing or consecutive hyphens.")
    if parent:
        add("name_directory_match", isinstance(name, str) and parent == name, "Name matches the supplied parent directory.")
    else:
        checks.append({"id": "name_directory_match", "status": "not_assessed", "message": "The upload does not provide the original parent directory name."})
    add("description_required", isinstance(description, str) and bool(description.strip()), "Required description is a nonempty string.")
    add("description_length", isinstance(description, str) and 1 <= len(description) <= 1024, "Description must contain 1–1024 characters.")
    compatibility = data.get("compatibility")
    add("compatibility_value", isinstance(compatibility, str) and 1 <= len(compatibility) <= 500, "Optional compatibility must be a string containing 1–500 characters.", applicable="compatibility" in data)
    metadata = data.get("metadata")
    add("metadata_value", isinstance(metadata, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()), "Optional metadata maps string keys to string values.", applicable="metadata" in data)
    add("allowed_tools_value", isinstance(data.get("allowed-tools"), str), "Experimental allowed-tools is a space-separated string; runtime support is separate.", applicable="allowed-tools" in data)
    return checks


def safe_package_path(base: str, value: str):
    """Resolve literal package paths only; never expand upload-provided variables."""
    value = value.replace("\\", "/")
    if not value or value.startswith(("/", "~")) or ":" in value or "\x00" in value:
        return None
    parts = list(PurePosixPath(base).parts) if base else []
    boundary = len(parts)
    for part in PurePosixPath(value).parts:
        if part == "..":
            if len(parts) <= boundary:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


def _schema_findings(data, kind, path):
    """Pinned schemas have internal refs only; remote retrieval is disabled."""
    schema = json.loads((SCHEMA_ROOT / f"agent-plugins-1.0.0.{kind}.json").read_text())
    known = set(schema["properties"])
    issues = []
    candidate = dict(data)
    # The normative spec says unknown core keys are reported and ignored.
    for key in set(candidate) - known:
        issues.append({"id": "unknown_manifest_field", "path": path, "detail": f"Ignored core field: {key}", "severity": "warning"})
        candidate.pop(key)
    if kind == "plugin" and "extensions" in candidate and not isinstance(candidate["extensions"], dict):
        issues.append({"id": "invalid_extensions", "path": path, "detail": "Non-object extensions ignored", "severity": "warning"})
        candidate.pop("extensions")
    validator = Draft202012Validator(schema, registry=Registry())
    for error in validator.iter_errors(candidate):
        issues.append({"id": "manifest_schema", "path": path, "detail": "Schema constraint failed: " + str(error.validator) + " at " + "/".join(str(p) for p in error.absolute_path)[:200], "severity": "error"})
        if len(issues) >= 20:
            break
    return issues


def inspect_formats(records, texts, target_runtime="auto"):
    if target_runtime not in RUNTIMES:
        raise ValueError("Unsupported target runtime")
    profiles, packages, issues, components, skills = [], [], [], [], []
    config_data = {}
    indicators = set()
    specs = {
        ".claude-plugin/plugin.json": ("claude-code", "claude-plugin"),
        ".codex-plugin/plugin.json": ("openai", "codex-plugin"),
        ".cursor-plugin/plugin.json": ("cursor", "cursor-plugin"),
        "gemini-extension.json": ("gemini", "gemini-extension"),
        "openclaw.plugin.json": ("openclaw", "openclaw-plugin"),
    }
    for entry in records:
        path = entry["path"]
        text = texts.get(path)
        name = PurePosixPath(path).name
        if text is None:
            continue
        if name in {"plugin.json", "marketplace.json", "gemini-extension.json", "openclaw.plugin.json", "manifest.json", "mcp.json", ".mcp.json", "hooks.json", "lsp.json", ".lsp.json", "openai.yaml", "package.json"}:
            try:
                data = bounded_data(text, "yaml" if name.endswith(".yaml") else "json")
                if not isinstance(data, dict):
                    raise ValueError("Manifest/configuration must be an object")
                config_data[path] = data
            except ParserLimitError as exc:
                entry.setdefault("analysis_coverage", {})["format_validation"] = {"status": "partial", "reason": str(exc)}
                issues.append({"id": "configuration_parse_not_assessed", "path": path, "detail": str(exc), "severity": "warning"})
                continue
            except ValueError as exc:
                issues.append({"id": "configuration_parse_error", "path": path, "detail": str(exc)[:300], "severity": "error"})
                continue
            for marker, (runtime, profile) in specs.items():
                if path == marker or path.endswith("/" + marker):
                    root = path[:-len(marker)].rstrip("/")
                    packages.append({"kind": "plugin" if "plugin" in profile else "extension", "profile": profile, "root": root, "manifest": path})
                    indicators.add(runtime)
            if name == "plugin.json" and "/.claude-plugin/" not in "/" + path and "/.codex-plugin/" not in "/" + path and "/.cursor-plugin/" not in "/" + path:
                root = str(PurePosixPath(path).parent)
                root = "" if root == "." else root
                schema = data.get("$schema")
                if schema == PLUGIN_SCHEMA:
                    profiles.append({"format": "agent-plugins", "version": "1.0.0", "path": path})
                    packages.append({"kind": "plugin", "profile": "agent-plugins", "root": root, "manifest": path})
                    issues.extend(_schema_findings(data, "plugin", path))
                    extensions = data.get("extensions", {})
                    if isinstance(extensions, dict):
                        for namespace, runtime in (("com.openai", "openai"), ("com.github.copilot", "copilot")):
                            if namespace in extensions:
                                indicators.add(runtime)
                else:
                    packages.append({"kind": "plugin", "profile": "legacy-or-unknown-plugin", "root": root, "manifest": path})
                    if schema:
                        issues.append({"id": "unsupported_schema", "path": path, "detail": "Unrecognized schema; not downloaded", "severity": "warning"})
            if name == "marketplace.json":
                packages.append({"kind": "marketplace", "profile": "marketplace", "root": str(PurePosixPath(path).parent), "manifest": path})
            if name == "manifest.json" and "server" in data and ("manifest_version" in data or "dxt_version" in data):
                packages.append({"kind": "mcp_bundle", "profile": "mcpb", "root": str(PurePosixPath(path).parent), "manifest": path})
            if name == "openai.yaml":
                indicators.add("openai")
            if name == "mcp.json" and data.get("$schema") == MCP_SCHEMA:
                issues.extend(_schema_findings(data, "mcp", path))
        if name == "SKILL.md":
            format_coverage = {"status": "complete_input", "supplied_characters": len(text),
                               "inspected_characters": None, "parser_max_characters": MAX_CONFIG_CHARS,
                               "reason": "Bounded frontmatter parser; body text is outside format validation."}
            entry.setdefault("analysis_coverage", {})["format_validation"] = format_coverage
            portable_selected = target_runtime == "generic"
            authority = {"kind": "portable_specification", "source_url": "https://agentskills.io/specification",
                         "applicability": "explicit_portable_profile" if portable_selected else "unverified_for_selected_runtime",
                         "enforcement": "selected_local_format_contract" if portable_selected else "advisory_only",
                         "vendor_compatibility_verified": False}
            skill = {"path": path, "root": str(PurePosixPath(path).parent), "metadata": {},
                     "validation": "valid_portable_profile" if portable_selected else "parsed_vendor_compatibility_unverified",
                     "validation_authority": authority}
            try:
                data = frontmatter(text)
                skill["field_lengths"] = {key: len(data[key]) for key in ("name", "description", "compatibility")
                                         if isinstance(data.get(key), str)}
                skill["frontmatter"] = data
                metadata = data.get("metadata", {})
                skill["metadata"] = {str(k): str(v)[:300] for k, v in metadata.items()} if isinstance(metadata, dict) else {}
                checks = portable_skill_checks(data, path)
                skill["portable_checks"] = checks
                problems = [check["message"] for check in checks if check["status"] == "fail"]
                if set(data) - BASE_FIELDS and target_runtime in {"generic", "claude-upload"}:
                    issues.append({"id": "skill_frontmatter" if target_runtime == "claude-upload" else "frontmatter_extension",
                                   "path": path, "detail": "Additional frontmatter fields are assessed separately from portable base constraints; selected vendor acceptance is unverified.",
                                   "severity": "warning", "authority": {**authority, "enforcement": "advisory_only"}})
                if set(data) & CODE_FIELDS:
                    indicators.add("claude-code")
                for problem in problems:
                    issues.append({"id": "skill_frontmatter", "path": path, "detail": problem,
                                   "severity": "error" if portable_selected else "warning", "authority": authority})
                if problems and portable_selected:
                    skill["validation"] = "invalid"
            except ParserLimitError as exc:
                skill["validation"] = "not_assessed"
                format_coverage.update(status="partial", reason=str(exc))
                issues.append({"id": "skill_format_not_assessed", "path": path, "detail": str(exc), "severity": "warning", "authority": {"kind": "local_parser_safety", "applicability": "bounded_parser_limit", "vendor_compatibility_verified": False}})
            except ValueError as exc:
                skill["validation"] = "invalid"
                format_coverage.update(status="partial", reason=str(exc))
                issues.append({"id": "skill_frontmatter", "path": path, "detail": str(exc), "severity": "error",
                               "authority": {"kind": "local_parser_safety", "applicability": "configuration_cannot_be_safely_parsed",
                                             "vendor_compatibility_verified": False}})
            skills.append(skill)
            components.append({"kind": "skill", "path": path})
            profiles.append({"format": "agent-skills", "version": "unversioned-spec", "path": path})
        for marker, runtime in ((".kiro/", "kiro"), (".gemini/", "gemini"), (".cursor/", "cursor"), (".devin/", "cascade"), (".windsurf/", "cascade"), (".github/", "copilot"), (".openclaw/", "openclaw")):
            if marker in path:
                indicators.add(runtime)
        if name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md"} or ".amazonq/rules/" in path:
            components.append({"kind": "instructions", "path": path})
    for path, data in config_data.items():
        for key in ("hooks", "mcpServers", "lspServers", "commands", "agents", "skills", "dependencies", "policies", "scripts", "server", "openclaw"):
            if key in data:
                components.append({"kind": key, "path": path, "declaration": key})
    for package in packages:
        data = config_data[package["manifest"]]
        if package["profile"] not in {"agent-plugins", "marketplace", "legacy-or-unknown-plugin"}:
            identity = data.get("id") if package["profile"] == "openclaw-plugin" else data.get("name")
            if not isinstance(identity, str) or not identity.strip():
                issues.append({"id": "native_manifest_name", "path": package["manifest"], "detail": "Native manifest identity is missing; current product requirement has not been verified.", "severity": "warning",
                               "authority": {"kind": "vendor_compatibility", "applicability": "unverified_for_selected_runtime", "enforcement": "advisory_only"}})
        if package["profile"] == "agent-plugins":
            mcp = (package["root"] + "/mcp.json").lstrip("/")
            if mcp in config_data and config_data[mcp].get("$schema") != MCP_SCHEMA:
                issues.append({"id": "manifest_schema", "path": mcp, "detail": "Portable MCP configuration requires its supported canonical schema identifier", "severity": "error"})
        siblings = [p for p in packages if p["root"] == package["root"] and p["manifest"] != package["manifest"]]
        if siblings:
            issues.append({"id": "multiple_manifest_profiles", "path": package["manifest"], "detail": "Multiple package manifests share a root; runtime precedence requires review", "severity": "warning"})
    kinds = {p["kind"] for p in packages}
    kind = "mixed_package" if len(kinds) > 1 else next(iter(kinds), "skill" if skills else "instruction_file" if texts else "unknown")
    return {"artifact_kind": kind, "packages": packages, "format_profiles": profiles,
            "runtime_targets": [{"runtime": r, "evidence": "structural_indicator_not_publisher_identity"} for r in sorted(indicators)],
            "target_runtime": target_runtime, "publisher_provenance": "unverified", "format_findings": issues[:100],
            "validation_scope": "explicit_portable_contracts_and_local_parse_safety; vendor_acceptance_checked_separately", "skills": skills,
            "components": components[:500], "configurations": config_data}
