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
        raise ValueError("Configuration exceeds 128 KiB parser budget")
    try:
        if kind == "json":
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError(f"Duplicate key: {key}")
                    result[key] = value
                return result
            result = json.loads(text, object_pairs_hook=unique)
        else:
            tokens = list(yaml.scan(text))
            if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in tokens):
                raise ValueError("YAML anchors/aliases are outside the bounded parser profile")
            result = yaml.load(text, Loader=UniqueSafeLoader)
        pending = [(result, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 24 or nodes > 10000:
                raise ValueError("Configuration nesting/node budget exceeded")
            if isinstance(item, dict):
                pending.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                pending.extend((value, depth + 1) for value in item)
        return result
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("Invalid or excessively nested configuration") from exc


def frontmatter(text: str):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("Missing YAML frontmatter")
    for end, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            data = bounded_data("\n".join(lines[1:end]), "yaml")
            if not isinstance(data, dict):
                raise ValueError("Skill frontmatter must be a mapping")
            return data
    raise ValueError("Unterminated YAML frontmatter")


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
            skill = {"path": path, "root": str(PurePosixPath(path).parent), "metadata": {}, "validation": "valid"}
            try:
                data = frontmatter(text)
                skill["field_lengths"] = {key: len(data[key]) for key in ("name", "description", "compatibility")
                                         if isinstance(data.get(key), str)}
                skill["frontmatter"] = data
                metadata = data.get("metadata", {})
                skill["metadata"] = {str(k): str(v)[:300] for k, v in metadata.items()} if isinstance(metadata, dict) else {}
                problems = []
                n, d = data.get("name"), data.get("description")
                if not isinstance(n, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", n) or len(n) > 64:
                    problems.append("Invalid or missing skill name")
                parent = PurePosixPath(path).parent.name
                if parent and isinstance(n, str) and parent != n:
                    problems.append("Skill name differs from parent directory")
                if not isinstance(d, str) or not d.strip() or len(d) > 1024:
                    problems.append("Missing or oversized description")
                if "compatibility" in data and (not isinstance(data["compatibility"], str) or len(data["compatibility"]) > 500):
                    problems.append("Invalid compatibility field")
                if "metadata" in data and (not isinstance(metadata, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items())):
                    problems.append("metadata must map strings to strings")
                if target_runtime in {"generic", "claude-upload"} and set(data) - BASE_FIELDS:
                    problems.append("Frontmatter fields unsupported by selected upload/portable profile")
                elif set(data) & CODE_FIELDS:
                    indicators.add("claude-code")
                for problem in problems:
                    issues.append({"id": "skill_frontmatter", "path": path, "detail": problem, "severity": "error"})
                if problems:
                    skill["validation"] = "invalid"
                if target_runtime in {"generic", "claude-upload"} and "allowed-tools" in data and not isinstance(data["allowed-tools"], str):
                    issues.append({"id": "allowed_tools_type", "path": path, "detail": "Selected profile requires a string", "severity": "error"})
            except ValueError as exc:
                skill["validation"] = "invalid"
                issues.append({"id": "skill_frontmatter", "path": path, "detail": str(exc), "severity": "error"})
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
                issues.append({"id": "native_manifest_name", "path": package["manifest"], "detail": "Native manifest requires a nonempty name", "severity": "error"})
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
            "validation_scope": "pinned_portable_schemas_and_documented_runtime_security_fields", "skills": skills,
            "components": components[:500], "configurations": config_data}
