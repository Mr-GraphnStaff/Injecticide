"""Bounded package relationships and source-backed capability observations.

This module reads uploaded text as data. It does not import package code, resolve
network destinations, install dependencies, or infer that a declaration executes.
The graph describes recognized syntax, not complete language understanding.
"""
from __future__ import annotations

import ast
import json
import posixpath
import re
import shlex
from collections import deque
from urllib.parse import unquote, urlsplit

try:
    from .script_launchers import COMMAND_START, parse_script_command, inspect_inline_script_metadata
except ImportError:
    from script_launchers import COMMAND_START, parse_script_command, inspect_inline_script_metadata


MAX_NODES = 500
MAX_EDGES = 2000
MAX_OBSERVATIONS = 500
MAX_SOURCE_CHARACTERS = 1024 * 1024
MAX_TOTAL_CHARACTERS = 4 * 1024 * 1024
MAX_AST_CHARACTERS = 131072
MAX_AST_NODES = 20000
MAX_JSON_NODES = 10000
MAX_LINE_CHARACTERS = 16384
MAX_CHAINS = 200
MAX_CHAIN_DEPTH = 32
PATH_EXTENSIONS = r"(?:md|txt|json|ya?ml|toml|py|pyw|js|mjs|cjs|jsx|ts|tsx|sh|bash|ps1|cmd|bat|rb|pl|php|lua|r|sql|csv|png|jpe?g|svg|ttf|otf|woff2?|pdf|docx|xlsx|pptx)"
PATH_TOKEN = re.compile(r"(?:\$\{[A-Z_]+\}[/\\])?(?:\.{1,2}[/\\])?(?:[A-Za-z0-9_.@+ -]+[/\\])*[A-Za-z0-9_.@+ -]+\." + PATH_EXTENSIONS + r"(?:#[^\s]*)?$", re.I)
INLINE_LINK = re.compile(r"!?\[[^\]\n]{0,1024}\]\(\s*(?:<([^>\n]+)>|([^\s)]+))(?:\s+[^)\n]*)?\)")
REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]\n]{1,256}\]:\s*(?:<([^>\n]+)>|([^\s]+))")
BACKTICK = re.compile(r"`([^`\n]{1,4096})`")
HTML_LINK = re.compile(r"\b(?:src|href)\s*=\s*[\"']([^\"'\n]{1,4096})[\"']", re.I)
URL = re.compile(r"(?:https?|wss?)://[^\s<>\"'`]+", re.I)
BARE_PATH = re.compile(r"(?<![A-Za-z0-9_./:@+\\-])(?:\.{1,2}/)?(?:[A-Za-z0-9_.@+~-]+/)*[A-Za-z0-9_@+~-][A-Za-z0-9_.@+~-]*\." + PATH_EXTENSIONS + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9_-])", re.I)
ROOT_FILES = {"skill.md", "plugin.json", "manifest.json", "gemini-extension.json", "openclaw.plugin.json", "hooks.json", "mcp.json", ".mcp.json"}


def build_package_graph(text_sources, inventory):
    """Return additive, JSON-serializable observations for an extracted package.

    ``text_sources`` follows app._build_text_sources. ``inventory`` includes all
    accepted/excluded file records. Call the normal report redactor after adding
    this result; local reference evidence may contain uploaded literal values.
    """
    graph = _Graph(inventory)
    remaining = MAX_TOTAL_CHARACTERS
    for index, source in enumerate(text_sources):
        if index >= MAX_NODES:
            graph.limit("source_count")
            break
        path, original = source.get("path"), source.get("text")
        if not isinstance(path, str) or not isinstance(original, str) or path not in graph.paths:
            continue
        length = min(len(original), MAX_SOURCE_CHARACTERS, remaining)
        text = original[:length]
        remaining -= length
        if length < len(original):
            graph.limit("source_characters", path)
        graph.inspect_text(path, text)
        if remaining <= 0:
            graph.limit("aggregate_source_characters")
            break
    return graph.result()


class _Graph:
    def __init__(self, inventory):
        self.nodes = []
        self.paths = set()
        self.edges = []
        self.edge_keys = set()
        self.external = []
        self.external_keys = set()
        self.observations = []
        self.observation_keys = set()
        self.dependencies = []
        self.launchers = []
        self.inline_metadata = []
        self.limits = []
        self.limit_keys = set()
        for index, record in enumerate(inventory):
            if index >= MAX_NODES:
                self.limit("inventory_count")
                break
            path = record.get("path")
            if not isinstance(path, str) or path in self.paths:
                continue
            self.paths.add(path)
            self.nodes.append({"path": path, "assessment_state": record.get("assessment_state", "unknown"),
                               "required_component": bool(record.get("required_component"))})
        self.skill_roots = sorted({posixpath.dirname(p) for p in self.paths if posixpath.basename(p).lower() == "skill.md"}, key=len, reverse=True)

    def limit(self, kind, path=None):
        key = (kind, path)
        if key not in self.limit_keys:
            self.limit_keys.add(key)
            self.limits.append({"kind": kind, **({"path": path} if path else {})})

    def external_reference(self, path, raw, line, kind):
        if len(self.external) >= MAX_OBSERVATIONS:
            self.limit("external_reference_count")
            return
        try:
            parsed = urlsplit(raw)
            # Origins retain destination evidence without reflecting credentials,
            # secret-bearing URL paths, queries or fragments.
            hostname = parsed.hostname
            if not hostname:
                return
            hostname = "[" + hostname + "]" if ":" in hostname else hostname
            port = ":" + str(parsed.port) if parsed.port else ""
            origin = parsed.scheme.lower() + "://" + hostname + port
        except ValueError:
            self.limit("unparseable_url", path)
            return
        key = (path, origin, line, kind)
        if key not in self.external_keys:
            self.external_keys.add(key)
            self.external.append({"source": path, "line": line, "kind": kind, "url": origin,
                                  "verification": "not_contacted", "redaction": "userinfo_path_query_fragment_removed"})

    def reference(self, source, raw, line, kind):
        if len(self.edges) >= MAX_EDGES:
            self.limit("edge_count")
            return
        raw = raw.strip().strip("\"'")
        if not raw or raw.startswith("#") or len(raw) > 4096:
            return
        if raw.startswith(("http://", "https://", "ws://", "wss://")):
            self.external_reference(source, raw, line, kind)
            return
        normalized = unquote(raw.split("#", 1)[0].split("?", 1)[0]).replace("\\", "/")
        if not normalized:
            return
        try:
            parsed = urlsplit(normalized)
        except ValueError:
            self.limit("unparseable_reference", source)
            self.edges.append({"source": source, "target": normalized, "line": line, "kind": kind,
                               "status": "malformed_reference", "evidence_scope": "declared_static_reference"})
            return
        # ``!/`` is the virtual boundary used for expanded nested archives.
        # A member reference cannot resolve into its containing archive/package.
        boundary = source.rsplit("!/", 1)[0] + "!" if "!/" in source else ""

        def inside_boundary(candidate):
            return candidate.startswith(boundary + "/") if boundary else not (candidate == ".." or candidate.startswith("../"))
        if parsed.scheme or normalized.startswith(("/", "~")):
            target, status = normalized, "external_package_path"
        else:
            symbolic_root = re.match(r"^\$\{(?:CLAUDE_PLUGIN_ROOT|CODEX_PLUGIN_ROOT|PLUGIN_ROOT)\}/", normalized)
            if symbolic_root:
                normalized = normalized[symbolic_root.end():]
                directory = posixpath.dirname(source)
                root = posixpath.dirname(directory) if posixpath.basename(directory).startswith(".") else directory
                candidates = [posixpath.normpath(posixpath.join(root, normalized))]
            elif "$" in normalized or "{{" in normalized or any(c in normalized for c in "*?["):
                target, status = normalized, "dynamic_reference_unresolved"
                candidates = None
            else:
                roots = [posixpath.dirname(source)]
                skill_roots = [root for root in self.skill_roots if source.startswith(root + "/") and root not in roots and inside_boundary(root + "/placeholder")]
                # Documented script commands resolve from the containing skill
                # root, including commands written in references/*.md. Ordinary
                # document links retain their source-relative interpretation.
                if kind == "execution_reference" and posixpath.splitext(source)[1].lower() in {".md", ".txt"}:
                    roots = skill_roots + roots
                else:
                    roots.extend(skill_roots)
                if boundary not in roots:
                    roots.append(boundary)
                candidates = [posixpath.normpath(posixpath.join(root, normalized)) for root in roots]
            if candidates is not None:
                matches = list(dict.fromkeys(c for c in candidates if c in self.paths and inside_boundary(c)))
                if matches:
                    target, status = matches[0], "resolved"
                else:
                    target = candidates[0]
                    status = "outside_package" if not inside_boundary(target) else "missing"
                    # Report spelling differences without guessing that a
                    # case-sensitive runtime will successfully open the file.
                    case_matches = sorted({path for path in self.paths if inside_boundary(path)
                                           and any(path.casefold() == candidate.casefold() for candidate in candidates)})
                    if case_matches:
                        status = "case_mismatch" if len(case_matches) == 1 else "ambiguous_case_reference"
        key = (source, target, line, kind, status)
        if key not in self.edge_keys:
            self.edge_keys.add(key)
            edge = {"source": source, "target": target, "line": line, "kind": kind,
                    "status": status, "evidence_scope": "declared_static_reference"}
            if status in {"case_mismatch", "ambiguous_case_reference"}:
                edge["case_mismatch_candidates"] = [{"path": path} for path in case_matches]
            self.edges.append(edge)

    def observe(self, path, line, capability, operation, **details):
        if operation == "manifest_command_declaration":
            line = None
            details["line_accuracy"] = "file_only"
        key = (path, line, capability, operation)
        if key in self.observation_keys:
            return
        if len(self.observations) >= MAX_OBSERVATIONS:
            self.limit("capability_observation_count")
            return
        self.observation_keys.add(key)
        self.observations.append({"source": path, "line": line, "capability": capability,
                                  "operation": operation, "evidence_scope": "recognized_source_syntax",
                                  "execution_verified": False, **details})

    def inspect_text(self, path, text):
        suffix = posixpath.splitext(path)[1].lower()
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE_CHARACTERS:
                self.limit("line_characters", path)
                line = line[:MAX_LINE_CHARACTERS]
            for pattern in (INLINE_LINK, REFERENCE_LINK, HTML_LINK):
                for match in pattern.finditer(line):
                    value = next(value for value in match.groups() if value is not None)
                    self.reference(path, value, line_no, "document_reference")
            commands = list(COMMAND_START.finditer(line))
            for match in BACKTICK.finditer(line):
                if PATH_TOKEN.fullmatch(match[1].strip()) and parse_script_command(match[1].strip()) is None:
                    self.reference(path, match[1], line_no, "resource_reference")
            for match in URL.finditer(line):
                self.external_reference(path, match[0].rstrip(".,;)]}"), line_no, "destination_mention")
            # Plain prose often names companion documents without Markdown
            # link syntax. Exclude URL/link/code spans already handled above;
            # a URL path ending in .md is never a local-file declaration.
            reserved = [match.span() for pattern in (URL, INLINE_LINK, REFERENCE_LINK, HTML_LINK, BACKTICK)
                        for match in pattern.finditer(line)]
            reserved.extend(match.span() for match in commands)
            if suffix in {".md", ".txt", ".skill"}:
                for match in BARE_PATH.finditer(line):
                    if not any(start <= match.start() < end for start, end in reserved):
                        self.reference(path, match[0], line_no, "prose_resource_reference")
            for match in commands:
                self.command_argument(path, match["command"], line_no)
        if suffix in {".py", ".pyw"}:
            metadata = inspect_inline_script_metadata(text)
            self.inline_metadata.append({"source": path, **metadata})
            for reason in metadata["limits"]:
                self.limit(reason, path)
            for value in metadata["dependencies"]:
                self.dependency(path, "pep723_dependency", value, metadata["line"], line_accuracy="metadata_block_start")
            self.inspect_python(path, text)
        if suffix == ".json":
            self.inspect_json(path, text)

    def inspect_python(self, path, text):
        if len(text) > MAX_AST_CHARACTERS:
            self.limit("python_parse_characters", path)
            return
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self.limit("python_parse_unavailable", path)
            return
        aliases = {}
        nodes = []
        for node in ast.walk(tree):
            if len(nodes) >= MAX_AST_NODES:
                self.limit("python_ast_nodes", path)
                return
            nodes.append(node)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = node.module + "." + alias.name
        for node in nodes:
            line = getattr(node, "lineno", 1)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.python_import(path, alias.name, 0, line)
            elif isinstance(node, ast.ImportFrom):
                self.python_import(path, node.module or "", node.level, line)
                if not node.module:
                    for alias in node.names:
                        self.python_import(path, alias.name, node.level, line)
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func, aliases)
            literal = _string(node.args[0]) if node.args else None
            if name in {"open", "io.open", "pathlib.Path"} and literal and name != "pathlib.Path":
                mode = _string(node.args[1]) if len(node.args) > 1 else next((_string(k.value) for k in node.keywords if k.arg == "mode"), "r")
                capability = "file_write" if isinstance(mode, str) and any(c in mode for c in "wax+") else "file_read" if isinstance(mode, str) else "file_access_mode_unknown"
                self.observe(path, line, capability, name)
                self.reference(path, literal, line, "source_file_access")
            elif name in {"os.getenv", "os.environ.get"}:
                self.observe(path, line, "environment_read", name)
            elif name in {"eval", "exec", "compile"}:
                self.observe(path, line, "dynamic_code", name)
            elif name.startswith(("subprocess.", "os.system", "os.popen")):
                self.observe(path, line, "process_execution", name)
                if literal:
                    self.command_argument(path, literal, line)
                elif node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                    values = [_string(item) for item in node.args[0].elts]
                    if all(isinstance(value, str) for value in values):
                        self.command_argument(path, shlex.join(values), line)
                    else:
                        self.limit("dynamic_command_arguments", path)
            elif name.startswith(("requests.", "httpx.", "urllib.request.", "socket.")):
                self.observe(path, line, "network_access", name)
                if literal:
                    self.external_reference(path, literal, line, "network_call_destination")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "mkdir"}:
                receiver = node.func.value
                if isinstance(receiver, ast.Call) and _call_name(receiver.func, aliases) in {"pathlib.Path", "Path"} and receiver.args:
                    target = _string(receiver.args[0])
                    capability = "file_read" if node.func.attr.startswith("read_") else "file_delete" if node.func.attr == "unlink" else "file_write"
                    self.observe(path, line, capability, "pathlib.Path." + node.func.attr)
                    if target:
                        self.reference(path, target, line, "source_file_access")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"b64decode", "b85decode", "a85decode", "fromhex"}:
                self.observe(path, line, "data_decoding", name)
            if isinstance(node, ast.Call) and name == "__import__":
                self.observe(path, line, "dynamic_import", name)

    def python_import(self, path, module, level, line):
        if not module:
            return
        prefix = "../" * max(0, level - 1) if level else ""
        target = prefix + module.replace(".", "/")
        # Imports outside the uploaded inventory are dependency observations,
        # not missing files: stdlib and installed packages may supply them.
        parent = posixpath.dirname(path)
        for candidate in (target + ".py", target + "/__init__.py"):
            resolved = posixpath.normpath(posixpath.join(parent, candidate))
            if resolved in self.paths or (level == 0 and candidate in self.paths):
                self.reference(path, candidate, line, "local_import")
                return

    def command_argument(self, path, text, line, *, line_accuracy="exact"):
        parsed = parse_script_command(text)
        if parsed is None:
            return
        if len(self.launchers) >= MAX_OBSERVATIONS:
            self.limit("launcher_observation_count", path)
            return
        # A bare pipx *.py operand is file-or-package dependent. Resolve only
        # when the exact file exists inside this package/container; never invent
        # a missing file finding for a potential package name.
        candidate = parsed.get("script_candidate")
        if candidate:
            boundary = path.rsplit("!/", 1)[0] + "!" if "!/" in path else ""
            roots = [posixpath.dirname(path), boundary]
            roots.extend(root for root in self.skill_roots if path.startswith(root + "/"))
            if any(posixpath.normpath(posixpath.join(root, candidate)) in self.paths
                   and (not boundary or posixpath.normpath(posixpath.join(root, candidate)).startswith(boundary + "/"))
                   for root in roots):
                parsed = {**parsed, "script": candidate, "status": "recognized_static_syntax"}
                parsed.pop("reason", None)
                parsed.pop("verification", None)
        if parsed.get("external_script"):
            # Keep the same origin-only destination disclosure contract as
            # other graph references, including remote launcher operands.
            raw_destination = parsed["external_script"]
            self.external_reference(path, raw_destination, line if line_accuracy == "exact" else None, "remote_script_declaration")
            parsed = {**parsed, "external_script": "origin_recorded_in_external_references"}
        source_line = line if line_accuracy == "exact" else None
        self.launchers.append({"source": path, "line": source_line, "line_accuracy": line_accuracy, **parsed})
        if line_accuracy == "exact":
            self.observe(path, line, "process_execution", "launcher_declaration")
        if parsed["status"] == "unknown":
            self.limit(parsed["reason"], path)
        if parsed.get("script"):
            self.reference(path, parsed["script"], source_line, "execution_reference")
        for item in parsed["package_declarations"]:
            self.dependency(path, item["kind"], item["value"], source_line, line_accuracy=line_accuracy)

    def dependency(self, path, kind, value, line=None, line_accuracy="exact"):
        if len(self.dependencies) >= MAX_OBSERVATIONS:
            self.limit("dependency_count", path)
            return
        self.dependencies.append({"source": path, "kind": kind, "value": value,
                                  "line": line, "line_accuracy": line_accuracy, "verification": "declared_not_installed"})

    def inspect_json(self, path, text):
        if len(text) > MAX_AST_CHARACTERS:
            self.limit("json_parse_characters", path)
            return
        try:
            data = json.loads(text)
        except (ValueError, RecursionError, MemoryError):
            self.limit("json_parse_unavailable", path)
            return
        pending, count = [(data, None)], 0
        while pending:
            value, field = pending.pop()
            count += 1
            if count > MAX_JSON_NODES:
                self.limit("json_nodes", path)
                return
            if isinstance(value, dict):
                if field in {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}:
                    for name in value:
                        if len(self.dependencies) >= MAX_OBSERVATIONS:
                            self.limit("dependency_count")
                            break
                        self.dependencies.append({"source": path, "kind": field, "value": str(name)[:256], "verification": "declared_not_installed"})
                pending.extend((child, key) for key, child in value.items())
            elif isinstance(value, list):
                pending.extend((child, field) for child in value)
            elif isinstance(value, str):
                if field in {"command", "script", "install", "postinstall", "preinstall", "prepare", "start", "test"}:
                    self.observe(path, 1, "process_execution", "manifest_command_declaration")
                    self.command_argument(path, value, 1, line_accuracy="file_only")
                if field in {"skills", "commands", "agents", "hooks", "mcpServers", "path", "entry", "main", "module", "script"} and PATH_TOKEN.fullmatch(value) and parse_script_command(value) is None:
                    self.reference(path, value, None, "manifest_component")

    def result(self):
        roots = sorted(p for p in self.paths if posixpath.basename(p).lower() in ROOT_FILES)
        adjacency = {p: [] for p in self.paths}
        for edge in self.edges:
            if edge["status"] == "resolved":
                adjacency[edge["source"]].append(edge)
        routes = {root: [root] for root in roots}
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for edge in adjacency[current]:
                target = edge["target"]
                if target in routes:
                    continue
                if len(routes[current]) >= MAX_CHAIN_DEPTH:
                    self.limit("relationship_depth", target)
                    continue
                routes[target] = routes[current] + [target]
                queue.append(target)
        chains = []
        for observation in self.observations:
            source = observation["source"]
            if source in routes:
                if len(chains) >= MAX_CHAINS:
                    self.limit("action_chain_count")
                    break
                chains.append({"path": routes[source], "capability": observation["capability"], "operation": observation["operation"],
                               "line": observation["line"], "evidence_scope": "declared_relationship_to_source_syntax", "execution_verified": False})
        return {"status": "partial" if self.limits else "complete_supported_syntax", "nodes": self.nodes, "edges": self.edges,
                "entrypoints": roots, "reachable_paths": sorted(routes), "unreferenced_paths": sorted(self.paths - routes.keys()),
                "external_references": self.external, "dependency_declarations": self.dependencies,
                "launcher_observations": self.launchers, "inline_script_metadata": self.inline_metadata,
                "capability_observations": self.observations, "action_chains": chains, "limits": self.limits,
                "scope": "Declared references and recognized source syntax only; reachability is not execution or malicious intent. Unreferenced files remain scan inputs; missing/dynamic links require review. No network, imports, dependency installation or package execution performed.",
                "supported_parsers": ["markdown_links", "inline_resource_paths", "prose_resource_paths", "documented_launcher_subset", "python_ast", "json_declarations", "pep723_inline_metadata_when_parsers_available"],
                "unsupported_analysis": ["runtime_control_flow", "arbitrary_language_semantics", "dynamic_path_resolution"]}


def _string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _call_name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value, aliases)
        return prefix + "." + node.attr if prefix else node.attr
    return ""
