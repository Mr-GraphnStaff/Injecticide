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
    # The specification's linked skills-ref validator explicitly checks this
    # allowlist. Vendor extensions are evaluated separately from portability.
    extra = sorted(str(key)[:60] for key in set(data) - BASE_FIELDS)
    found = (" Found: " + ", ".join(extra[:10]) + (f" and {len(extra) - 10} more" if len(extra) > 10 else "") + ".") if extra else ""
    add("frontmatter_fields", not extra, "Portable frontmatter permits only name, description, license, compatibility, metadata and allowed-tools; put additional properties such as version inside metadata." + found)
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


def inspect_formats(records, texts, target_runtime="auto", filename=""):
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
                # Known Claude Code fields are extensions, not a selected
                # Claude runtime format error. Their portable check still fails
                # explicitly in the separate standards assessment.
                known_code_extensions = target_runtime == "claude-code" and (set(data) - BASE_FIELDS) <= CODE_FIELDS
                problems = [check["message"] for check in checks if check["status"] == "fail"
                            and not (check["id"] == "frontmatter_fields" and known_code_extensions)]
                # Injecticide's version declaration policy applies in every
                # runtime profile. Markdown/version examples are not parsed as
                # declarations. No semantic-version format is invented here.
                invalid_version = "version" in data or (isinstance(metadata, dict)
                    and "version" in metadata and not isinstance(metadata["version"], str))
                if invalid_version:
                    issues.append({"id": "skill_version_declaration", "path": path,
                        "detail": "Declare the skill version only as a string at metadata.version in YAML frontmatter. Version is optional; no semantic-version pattern is required.",
                        "severity": "error", "authority": {
                            "kind": "injecticide_version_declaration_policy",
                            "source_url": "https://agentskills.io/specification#metadata-field",
                            "enforcement": "selected_local_format_contract",
                            "vendor_compatibility_verified": False}})
                if set(data) - BASE_FIELDS and target_runtime in {"generic", "claude-upload"}:
                    issues.append({"id": "skill_frontmatter" if target_runtime == "claude-upload" else "frontmatter_extension",
                                   "path": path, "detail": "Additional frontmatter fields are assessed separately from portable base constraints; selected vendor acceptance is unverified.",
                                   "severity": "warning", "authority": {**authority, "enforcement": "advisory_only"}})
                if set(data) & CODE_FIELDS:
                    indicators.add("claude-code")
                for problem in problems:
                    issues.append({"id": "skill_frontmatter", "path": path, "detail": problem,
                                   "severity": "error" if portable_selected else "warning", "authority": authority})
                if invalid_version or (problems and portable_selected):
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
    anatomy, configuration_roots, instruction_paths = plugin_anatomy(records, texts, config_data, packages, target_runtime, filename)
    return {"artifact_kind": kind, "packages": packages, "format_profiles": profiles,
            "runtime_targets": [{"runtime": r, "evidence": "structural_indicator_not_publisher_identity"} for r in sorted(indicators)],
            "target_runtime": target_runtime, "publisher_provenance": "unverified", "format_findings": issues[:100],
            "validation_scope": "explicit_portable_contracts_and_local_parse_safety; vendor_acceptance_checked_separately", "skills": skills,
            "components": components[:500], "configurations": config_data,
            "plugin_anatomy": anatomy, "configuration_roots": configuration_roots,
            "instruction_paths": instruction_paths}


# Claude Code component discovery profile, reviewed 2026-11-27 against:
# https://code.claude.com/docs/en/plugins/manifest-reference
# https://code.claude.com/docs/en/plugins/components
# This inventories static declarations. It neither loads a plugin nor establishes
# Claude.ai/Cowork support, permissions, successful execution, or publisher trust.
PLUGIN_COMPONENTS = {
    "skills": ("skills", "add", "instructions", "Task matching or explicit skill invocation"),
    "commands": ("commands", "replace", "instructions", "Explicit namespaced command invocation"),
    "agents": ("agents", "replace", "instructions", "Subagent delegation"),
    "outputStyles": ("output-styles", "replace", "instructions", "Output style selection"),
    "workflows": ("workflows", "replace", "workflow_code", "Workflow invocation; runtime behavior not verified"),
    "themes": ("themes", "replace", "appearance", "Theme selection"),
    "hooks": ("hooks/hooks.json", "merge", "event_handlers", "Declared lifecycle event"),
    "mcpServers": (".mcp.json", "merge", "tool_server", "Host starts/connects to server; tools invoked separately"),
    "lspServers": (".lsp.json", "merge", "local_process", "Host starts a language server"),
    "monitors": ("monitors/monitors.json", "replace", "background_process", "Session start or declared skill trigger"),
    "bin": ("bin", "default", "executable_candidate", "Explicit tool command; executable permissions not established"),
    "evals": ("evals", "replace", "evaluation", "Separate evaluation run; not executed by Injecticide"),
}


def plugin_anatomy(records, texts, configs, packages, target_runtime="auto", filename=""):
    """Explain bounded, virtual-path component ownership without reading disk paths.

    Resolved configuration objects join the existing threat inspection input;
    raw commands, prompts, user-config defaults and credentials never enter this
    anatomy projection. Nested archives and nested plugins own their own files.
    """
    paths = {row["path"] for row in records if isinstance(row.get("path"), str)}
    marker = ".claude-plugin/plugin.json"
    manifests = {path[:-len(marker)].rstrip("/"): path for path in paths
                 if path == marker or path.endswith("/" + marker)}
    roots = set(manifests)
    explicit = target_runtime == "claude-code" or filename.lower().endswith(".plugin")
    if explicit:
        for path in paths:
            if PurePosixPath(path).name == "SKILL.md" and not any(part in {"skills", "references", "examples", "fixtures"} for part in path.split("/")[:-1]):
                parent = str(PurePosixPath(path).parent)
                roots.add("" if parent == "." else parent)
    for path in sorted(paths):
        parts = path.split("/")
        for index, part in enumerate(parts[:-1]):
            if part in {"skills", "commands", "agents", "hooks", "output-styles", "workflows", "themes", "monitors", "bin"}:
                candidate = "/".join(parts[:index])
                # A reference example is not evidence of an installed plugin.
                if explicit and not any(p in {"references", "examples", "fixtures", ".claude-plugin"} for p in parts[:index]):
                    roots.add(candidate)
                break
        if parts[-1] in {".mcp.json", ".lsp.json"} and explicit:
            roots.add("/".join(parts[:-1]))
    foreign_roots = {item["root"] if item["root"] != "." else "" for item in packages
                     if item["profile"] not in {"claude-plugin", "legacy-or-unknown-plugin"}}
    roots = {value for value in roots if value in manifests or not any(
        not other or value == other or value.startswith(other + "/") for other in foreign_roots)}
    roots = {value for value in roots if value in manifests or not any(
        other != value and (not other or value.startswith(other + "/")) for other in roots)}
    roots = sorted(roots, key=lambda value: (len(value), value))
    omitted_roots = max(0, len(roots) - 32)
    all_roots, roots = sorted(set(roots) | foreign_roots), roots[:32]
    report = {"schema": "injecticide-plugin-anatomy/v1", "profile": "claude-code",
              "reviewed_on": "2026-11-27", "status": "not_applicable", "plugins": [],
              "component_count": 0, "omitted_components": 0, "omitted_plugins": omitted_roots,
              "sources": ["https://code.claude.com/docs/en/plugins/manifest-reference",
                          "https://code.claude.com/docs/en/plugins/components"],
              "scope": "Static plugin layout and declared activation. Nothing was installed, started or invoked. Other hosts may support different components.",
              "limits": ["Component load success, permissions, executable bits and publisher identity are unverified.",
                         "Marketplace-provided overrides and runtime settings were not supplied; inferred discovery can differ.",
                         "All supplied files remain security-inspected, including defaults the manifest does not select."]}
    configuration_roots = {}
    instruction_paths = set()
    input_partial = False

    def owned(path, root):
        prefix = root + "/" if root else ""
        if not path.startswith(prefix) or "!/" in path[len(prefix):]:
            return False
        return not any(other != root and (not root or other.startswith(prefix))
                       and path.startswith(other + "/") for other in all_roots)

    for root in roots:
        manifest = manifests.get(root)
        data = configs.get(manifest, {})
        plugin = {"root": root or ".", "manifest": manifest,
                  "recognition": "manifest_observed" if manifest else "layout_candidate",
                  "name": data.get("name")[:200] if isinstance(data.get("name"), str) else None,
                  "version": data.get("version")[:100] if isinstance(data.get("version"), str) else None,
                  "components": [], "observations": [], "counts": {}, "configuration_fields": []}
        report["plugins"].append(plugin)
        local = sorted(path for path in paths if owned(path, root))
        prefix = root + "/" if root else ""
        experiment = data.get("experimental") if isinstance(data.get("experimental"), dict) else {}
        if manifest and manifest not in configs:
            plugin["observations"].append("Manifest could not be parsed; default layout observations do not establish host loading.")
            input_partial = True
        if not manifest:
            plugin["observations"].append("Manifest absent: layout is a candidate. The installed name may come from the directory or marketplace.")
        if any(path.startswith(prefix + ".claude-plugin/") and path != manifest for path in local):
            plugin["observations"].append("Files beyond plugin.json occur inside .claude-plugin/. Component defaults belong at the plugin root.")

        def add(kind, path, state="observed", **extra):
            nonlocal input_partial
            instruction = kind in {"skills", "commands", "agents", "outputStyles"} or extra.get("role") == "instructions"
            if state == "observed" and instruction and path not in texts:
                state = "unresolved"
                extra["reason"] = "instruction_content_not_assessed"
            if state == "unresolved":
                input_partial = True
            if state == "observed" and instruction and path in texts:
                instruction_paths.add(path)
            report["component_count"] += 1
            plugin["counts"][kind] = plugin["counts"].get(kind, 0) + 1
            if report["component_count"] > 500:
                report["omitted_components"] += 1
                return None
            _, _, role, activation = PLUGIN_COMPONENTS.get(kind, (None, None, "configuration", "Configuration supplied by user"))
            row = {"kind": kind, "path": path, "state": state, "role": role,
                   "activation": activation, "execution": "not_observed", **extra}
            plugin["components"].append(row)
            return row

        def resolve(raw):
            if not isinstance(raw, str) or len(raw) > 1024:
                return None, "unsupported_path_form"
            if "${" in raw or "\\" in raw:
                return None, "variable_or_platform_path_unresolved"
            if raw != "." and not raw.startswith("./") or ".." in raw.split("/"):
                return None, "path_not_contained"
            relative = raw[2:] if raw.startswith("./") else ""
            path = prefix + relative.rstrip("/")
            if path and not owned(path + "/" if path not in paths else path, root):
                return None, "different_plugin_or_archive_owner"
            return path.rstrip("/"), None

        def parsed(path):
            nonlocal input_partial
            if path not in paths:
                return None
            if path not in configs:
                try:
                    value = bounded_data(texts[path])
                    if not isinstance(value, (dict, list)):
                        raise ValueError("Expected configuration object or monitor array")
                    configs[path] = {"monitors": value} if isinstance(value, list) else value
                except (ValueError, KeyError):
                    input_partial = True
                    return None
            configuration_roots[path] = root
            return configs[path]

        def bounded(items, label):
            nonlocal input_partial
            if len(items) > 100:
                input_partial = True
                plugin["observations"].append(f"{label}: {len(items) - 100} entries omitted by the 100-entry inspection limit.")
            return items[:100]

        for kind, (default, behavior, _, _) in PLUGIN_COMPONENTS.items():
            declared = experiment.get(kind) if kind in {"themes", "monitors", "evals"} else data.get(kind)
            supplied = kind in (experiment if kind in {"themes", "monitors", "evals"} else data)
            if kind == "bin":
                declared, supplied = None, False
            if kind in {"themes", "monitors"} and supplied and kind in data:
                plugin["observations"].append(f"Both experimental.{kind} and legacy {kind} are declared; combined precedence was not established.")
                input_partial = True
            if kind in {"themes", "monitors"} and not supplied and kind in data:
                declared, supplied = data[kind], True
            selector_key = "experimental." + kind if kind in {"themes", "monitors", "evals"} else kind
            defaults = [prefix + default]
            selectors = [] if supplied and behavior == "replace" else [(value, "default") for value in defaults]
            if supplied:
                values = declared if isinstance(declared, list) and kind != "monitors" else [declared]
                if kind == "evals" and isinstance(declared, list):
                    values = declared[:1]
                    if len(declared) > 1:
                        plugin["observations"].append("experimental.evals uses only the first declared directory.")
                if len(values) > 100:
                    input_partial = True
                    plugin["observations"].append(f"{selector_key}: more than 100 declarations; remaining declarations not assessed.")
                for value in values[:100]:
                    if isinstance(value, str) and value.startswith("https://") and kind == "mcpServers":
                        add(kind, manifest, "unresolved", origin="remote_bundle", declared_by=manifest,
                            reason="Remote bundle not fetched; its contents and endpoint were not assessed.")
                    elif isinstance(value, str):
                        if kind == "evals" and not value.startswith(("./", "/")):
                            value = "./" + value
                        path, reason = resolve(value)
                        if not reason and ((kind == "agents" and not path.endswith(".md")) or (kind == "skills" and path in paths)):
                            reason = "component_requires_file" if kind == "agents" else "skills_requires_directory"
                        if reason:
                            add(kind, manifest, "unresolved", reason=reason, declared_by=manifest)
                            input_partial = True
                        else:
                            selectors.append((path, "manifest"))
                    elif kind in {"commands", "hooks", "mcpServers", "lspServers", "monitors"}:
                        selectors.append((value, "inline"))
                    else:
                        add(kind, manifest, "unresolved", reason="unsupported_declaration_form", declared_by=manifest)
                        input_partial = True
            if supplied and behavior == "replace":
                default_paths = [p for p in local if p == prefix + default or p.startswith(prefix + default + "/")]
                selected_paths = [p for p, _ in selectors if isinstance(p, str)]
                for path in default_paths:
                    if not any(path == p or path.startswith(p + "/") for p in selected_paths):
                        add(kind, path, "ignored_default", discovery="default_replaced_by_manifest", declared_by=manifest)
            merged = {}
            for selector, discovery in selectors:
                if kind in {"hooks", "mcpServers", "lspServers", "monitors"}:
                    source = manifest if discovery == "inline" else selector
                    value = selector if discovery == "inline" else parsed(selector)
                    if value is None:
                        if discovery != "default" or selector in paths:
                            add(kind, source, "unresolved", reason="configuration_missing_or_unreadable", declared_by=manifest)
                        continue
                    if kind == "hooks":
                        events = value.get("hooks", {}) if discovery != "inline" and isinstance(value, dict) else value
                        if not isinstance(events, dict):
                            add(kind, source, "unresolved", reason="unsupported_hook_shape")
                            input_partial = True
                            continue
                        for event, groups in bounded(list(events.items()), "hook events"):
                            if not isinstance(groups, list):
                                add(kind, source, "unresolved", reason="unsupported_hook_groups")
                                continue
                            for group in bounded(groups, "hook groups"):
                                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                                    add(kind, source, "unresolved", reason="unsupported_hook_group")
                                    continue
                                for handler in bounded(group["hooks"], "hook handlers"):
                                    handler_type = handler.get("type") if isinstance(handler, dict) else None
                                    add(kind, source, "observed" if handler_type in {"command", "http", "mcp_tool", "prompt", "agent"} else "unresolved", discovery=discovery, name=str(event)[:100],
                                        activation="Lifecycle event: " + str(event)[:100],
                                        handler_type=handler_type if handler_type in {"command", "http", "mcp_tool", "prompt", "agent"} else "unknown",
                                        role="local_process" if handler_type == "command" else "remote_request" if handler_type == "http" else "instructions" if handler_type in {"prompt", "agent"} else "tool_invocation")
                    else:
                        entries = value.get("monitors", []) if kind == "monitors" and isinstance(value, dict) else value.get(kind, value) if isinstance(value, dict) else value
                        items = list(enumerate(entries)) if isinstance(entries, list) else list(entries.items()) if isinstance(entries, dict) else []
                        if len(items) > 100:
                            input_partial = True
                        for name, config in bounded(items, kind):
                            if not isinstance(config, dict):
                                add(kind, source, "unresolved", reason="unsupported_configuration_shape")
                                continue
                            identity = str(config.get("name", name)) if kind == "monitors" else str(name)
                            trigger = config.get("when", "always")
                            trigger = trigger if trigger == "always" or isinstance(trigger, str) and re.fullmatch(r"on-skill-invoke:[A-Za-z0-9_-]{1,64}", trigger) else "unrecognized_trigger"
                            role = "local_process" if config.get("command") else "remote_endpoint" if config.get("url") else "unresolved_server"
                            row = add(kind, source, name=identity[:128], discovery=discovery, declared_by=manifest,
                                      role="background_process" if kind == "monitors" else role,
                                      activation=trigger if kind == "monitors" else PLUGIN_COMPONENTS[kind][3])
                            if kind in {"mcpServers", "lspServers"} and row:
                                if identity in merged:
                                    merged[identity]["state"] = "superseded_declaration"
                                merged[identity] = row
                elif kind == "commands" and isinstance(selector, dict):
                    for name, config in bounded(list(selector.items()), "inline commands"):
                        if not isinstance(config, dict):
                            add(kind, manifest, "unresolved", reason="unsupported_command_shape")
                        elif isinstance(config.get("content"), str) and "source" not in config:
                            add(kind, manifest, name=str(name)[:128], discovery="inline", declared_by=manifest)
                        elif isinstance(config.get("source"), str) and "content" not in config:
                            path, reason = resolve(config["source"])
                            add(kind, path if path in paths else manifest, "unresolved" if reason or path not in paths else "observed",
                                name=str(name)[:128], discovery="manifest", declared_by=manifest,
                                reason=reason or ("source_not_supplied" if path not in paths else None))
                        else:
                            add(kind, manifest, "unresolved", reason="command_needs_exactly_one_source_or_content")
                elif isinstance(selector, str):
                    candidates = [p for p in local if not selector or p == selector or p.startswith(selector + "/")]
                    if kind == "skills":
                        candidates = [p for p in candidates if PurePosixPath(p).name == "SKILL.md" and len(p[len(selector):].strip("/").split("/")) <= 2]
                    elif kind in {"agents", "commands", "outputStyles"}:
                        candidates = [p for p in candidates if p.endswith(".md")]
                    elif kind == "workflows":
                        candidates = [p for p in candidates if p.endswith(".js")]
                    elif kind == "themes":
                        candidates = [p for p in candidates if p.endswith(".json")]
                    if kind == "skills" and discovery == "default" and not candidates and not supplied and not any(p.startswith(prefix + "skills/") for p in local) and prefix + "SKILL.md" in local:
                        candidates = [prefix + "SKILL.md"]
                    if not candidates and discovery != "default":
                        add(kind, manifest, "unresolved", reason="declared_path_not_supplied_or_wrong_type", declared_by=manifest)
                    for path in candidates:
                        if not any(row["kind"] == kind and row["path"] == path and row["state"] == "observed" for row in plugin["components"]):
                            add(kind, path, discovery=discovery, declared_by=manifest)
                    if kind == "bin" and candidates:
                        plugin["observations"].append("Top-level bin/ is a Claude Code executable surface. Reviewed vendor docs say Claude.ai and Cowork do not install plugins containing it; host acceptance was not tested.")
        options = data.get("userConfig", {})
        if isinstance(options, dict):
            for name, option in bounded(list(options.items()), "user configuration"):
                if isinstance(option, dict):
                    plugin["configuration_fields"].append({"name": str(name)[:128], "sensitive": option.get("sensitive") is True,
                        "type": option.get("type") if option.get("type") in {"string", "number", "boolean", "file", "directory"} else "unknown"})
        channels = data.get("channels", [])
        if isinstance(channels, list):
            for channel in bounded(channels, "channels"):
                if isinstance(channel, dict):
                    add("channels", manifest, name=str(channel.get("server", "unspecified"))[:128],
                        role="message_channel", activation="External messages through a declared MCP server")
    report["status"] = "partial" if omitted_roots or report["omitted_components"] or input_partial else "observed" if roots else "not_applicable"
    report["analysis_status"] = "partial" if omitted_roots or input_partial else "observed" if roots else "not_applicable"
    return report, configuration_roots, sorted(instruction_paths)
