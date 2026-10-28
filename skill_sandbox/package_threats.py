"""Measured package capabilities, not a claim that all executable code is malicious.

Sources: Python command-line interface; Anthropic enterprise skill review checklist;
Agent Plugins 1.0 MCP/runtime contract. See rules/package_sources.json.
"""
from __future__ import annotations

import ast
import hashlib
import posixpath
import re
import shlex
from html.parser import HTMLParser
from itertools import islice
from pathlib import PurePosixPath
from urllib.parse import urlsplit

try:
    from .package_formats import safe_package_path
except ImportError:
    from package_formats import safe_package_path

EXECUTABLE_SUFFIXES = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".php", ".lua", ".r", ".groovy", ".vbs", ".wsf", ".sql", ".exe", ".dll", ".so", ".java", ".go", ".rs", ".c", ".cpp", ".swift"}
LANGUAGE_ALIASES = {"python": "python", "py": "python", "javascript": "javascript", "js": "javascript", "node": "javascript",
                    "typescript": "typescript", "ts": "typescript", "bash": "shell", "sh": "shell", "shell": "shell", "zsh": "shell", "fish": "shell",
                    "powershell": "powershell", "pwsh": "powershell", "ps1": "powershell", "ruby": "ruby", "rb": "ruby", "perl": "perl", "pl": "perl",
                    "php": "php", "lua": "lua", "r": "r", "batch": "batch", "bat": "batch", "cmd": "batch", "sql": "sql",
                    "groovy": "groovy", "vbscript": "vbscript", "java": "java", "go": "go", "rust": "rust", "c": "c", "cpp": "cpp", "c++": "cpp", "swift": "swift"}
SOURCES = [
    {"name": "Anthropic enterprise skills review", "url": "https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise"},
    {"name": "Python script interface", "url": "https://docs.python.org/3/using/cmdline.html#interface-options"},
    {"name": "Node.js command-line API", "url": "https://nodejs.org/api/cli.html"},
    {"name": "Microsoft PowerShell CLI", "url": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh"},
]
COMMAND_RE = re.compile(r"\b(?:python(?:3(?:\.\d+)?)?|python\.exe|bash|sh|zsh|fish|node|nodejs|deno|bun|pwsh|powershell|ruby|perl|php|lua|Rscript|groovy|cscript|wscript|cmd(?:\.exe)?)\s+([^\n`]+)", re.I)
SECRET_RE = re.compile(r"(?:api[_-]?key|access[_-]?token|password|secret)\s*[=:]\s*['\"]([^'\"\n]{12,})['\"]", re.I)


class _BrowserScriptParser(HTMLParser):
    """Recognize declared browser script syntax without rendering the document."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.script_capable = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        script_type = (attributes.get("type") or "").strip().lower()
        if tag == "script" and script_type in {"", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}:
            self.script_capable = True
        if any(name.startswith("on") and value for name, value in attrs):
            self.script_capable = True


def _html_script_capable(text):
    parser = _BrowserScriptParser()
    parser.feed(text)
    return parser.script_capable


def embedded_blocks(text):
    """Read fenced source as data, including a triple fence inside a four fence."""
    lines = text.splitlines()
    blocks = []
    index, remaining = 0, 131072
    while index < len(lines) and len(blocks) < 8 and remaining > 0:
        opening = re.fullmatch(r"[ \t]*(`{3,}|~{3,})([A-Za-z0-9_+#.-]+)[ \t]*", lines[index])
        if not opening or opening.group(2).lower() not in LANGUAGE_ALIASES:
            index += 1
            continue
        fence, declared_language = opening.groups()
        language = LANGUAGE_ALIASES[declared_language.lower()]
        start = index + 1
        index = start
        while index < len(lines) and not re.fullmatch(r"[ \t]*" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", lines[index]):
            index += 1
        if index < len(lines):
            body = '\n'.join(lines[start:index])
            if len(body) <= remaining:
                blocks.append({"language": language, "text": body, "line": start + 1})
                remaining -= len(body)
        index += 1
    return blocks


def finding(rule_id, description, samples, *, category="code", severity="medium"):
    samples = [str(s)[:300] for s in samples][:3]
    return {"id": rule_id, "category": category, "severity": severity, "tier": "review",
            "description": description, "finding_category": "execution_primitive" if category == "code" else "connector_risk",
            "subject": "package_component", "action_state": "declared", "disposition": "require_approval",
            "count": len(samples), "samples": samples, "observations": [], "counts_for_governance": False,
            "status": "verified", "sources": SOURCES, "is_actionable": True, "display_kind": "actionable_finding"}


def code_evidence(path, text):
    suffixes = PurePosixPath(path).suffixes
    result = {"suffixes": suffixes, "code_like": False, "language": None,
              "mixed_executable_suffix": any(s.lower() in EXECUTABLE_SUFFIXES for s in suffixes[:-1]), "evidence": []}
    if PurePosixPath(path).suffix.lower() in EXECUTABLE_SUFFIXES:
        result.update(code_like=True, language="declared_by_suffix")
        result["evidence"].append("executable_or_source_suffix")
    if text.startswith("#!"):
        result.update(code_like=True, language="shebang")
        result["evidence"].append("interpreter_shebang")
    if PurePosixPath(path).suffix.lower() in {".html", ".htm", ".xhtml"} and _html_script_capable(text):
        result.update(code_like=True, language="browser_script")
        result["evidence"].append("html_script_element")
    if len(text) <= 131072:
        try:
            tree = ast.parse(text)
            nodes = list(ast.walk(tree))
            structural = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            if len(nodes) <= 10000 and (any(isinstance(n, structural) for n in nodes)
                    or (result["mixed_executable_suffix"] and any(isinstance(n, ast.Call) for n in nodes))):
                result.update(code_like=True, language="python")
                result["evidence"].append("python_syntax_with_code_nodes")
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass
    if re.search(r"^\s*```(?:python|javascript|bash|sh|powershell)\b", text, re.M):
        result["evidence"].append("documented_code_fence")
    blocks = embedded_blocks(text)
    if blocks and "documented_code_fence" not in result["evidence"]:
        result["evidence"].append("documented_code_fence")
    result["embedded_analysis_limited"] = len(blocks) >= 8 or len(text) > 131072
    result["embedded_blocks"] = [{"language": block["language"], "line": block["line"],
                                   "sha256": hashlib.sha256(block["text"].encode()).hexdigest()} for block in blocks]
    if result["mixed_executable_suffix"]:
        preferred = next(({".py": "python", ".pyw": "python", ".js": "javascript", ".ts": "typescript", ".sh": "shell", ".ps1": "powershell"}.get(s.lower()) for s in suffixes[:-1] if s.lower() in EXECUTABLE_SUFFIXES), None)
        for block in sorted(blocks, key=lambda b: b["language"] == preferred, reverse=True):
            if block["language"] == "python":
                try:
                    nodes = list(ast.walk(ast.parse(block["text"])))
                    if len(nodes) <= 10000 and any(isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.Call)) for n in nodes):
                        result.update(code_like=True, language="python")
                        result["evidence"].append("python_fence_in_mixed_suffix_artifact")
                        break
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    pass
            else:
                result.update(code_like=True, language=block["language"])
                result["evidence"].append("declared_script_fence_in_mixed_suffix_artifact")
                break
    if not blocks and not result["code_like"]:
        # Observable syntax indicators, not a malware classifier or full parser.
        signatures = (
            ("php", r"^\s*<\?php\b"),
            ("javascript", r"(?m)^\s*(?:const|let|var)\s+\w+\s*=\s*require\s*\("),
            ("javascript", r"(?m)^\s*(?:import\s+.+\s+from\s+['\"]|(?:async\s+)?function\s+\w+\s*\([^\n]*\)\s*\{)"),
            ("powershell", r"(?im)^\s*(?:param\s*\(|\$(?:[A-Za-z_]\w*)\s*=\s*(?:Get-|New-|Invoke-|['\"]))"),
            ("batch", r"(?im)^\s*@echo\s+off\b"),
            ("perl", r"(?m)^\s*use\s+(?:strict|warnings)\s*;"),
            ("ruby", r"(?m)^\s*require(?:_relative)?\s+['\"]"),
        )
        for language, pattern in signatures:
            if re.search(pattern, text):
                result.update(code_like=True, language=language)
                result["evidence"].append("source_syntax_indicator:" + language)
                break
    return result


def inspect_threats(records, texts, analysis):
    entries = {e["path"]: e for e in records}
    components, dependencies, references, issues = [], [], [], []
    paths = set(entries)
    invoked = set()
    inventory_limited = [False]
    generated = {}

    def resolve(source, root, target):
        resolved = safe_package_path(root, target)
        if resolved and "!/" in source:
            boundary = source.rsplit("!/", 1)[0] + "!/"
            if not resolved.startswith(boundary):
                return None
        return resolved

    # Link known extraction outputs to packaged sources before resolving launches.
    # This recognizes a literal sed pipeline, not arbitrary shell semantics.
    extraction_re = re.compile(r"\bsed\s+-n\b[^\n]*?\s+(?P<input>[\w./-]+|\"[^\"\n]+\"|'[^'\n]+')\s*\|[^\n]*?\s>\s*(?P<output>[\w./-]+)\b")
    for source, text in texts.items():
        source_parent = posixpath.dirname(source)
        skill_root = next((s["root"] for s in analysis["skills"] if source == s["path"] or source.startswith(s["root"].rstrip("/") + "/")), source_parent)
        if skill_root == ".":
            skill_root = ""
        for match in islice(extraction_re.finditer(text), 64):
            input_name = match.group("input").strip("\"'")
            candidates = [resolve(source, base, input_name) for base in (skill_root, source_parent)]
            original = next((p for p in candidates if p in paths), None)
            if original:
                output = resolve(source, skill_root, match.group("output"))
                if output and PurePosixPath(output).suffix.lower() in EXECUTABLE_SUFFIXES:
                    generated[output] = original
                    invoked.add(original)
                    references.append({"source": source, "target": original, "kind": "declared_fence_extraction", "generated_target": output})

    def command_targets(source, command, base):
        # Only expand standardized package-root placeholders lexically, never env vars.
        for marker in ("${CLAUDE_PLUGIN_ROOT}/", "${PLUGIN_ROOT}/", "${extensionPath}/"):
            command = command.replace(marker, "./")
        for index, match in enumerate(islice(COMMAND_RE.finditer(command), 65)):
            if index == 64:
                inventory_limited[0] = True
                break
            try:
                tokens = shlex.split(match.group(1).replace("`", ""), posix=True)
            except ValueError:
                continue
            for token in tokens[:16]:
                token = token.rstrip(",;)").lstrip("(")
                if token.startswith("-") or not PurePosixPath(token).suffix:
                    continue
                roots = [base] + sorted({p["root"] for p in analysis["skills"] + analysis["packages"]
                                       if p["root"] not in {"", "."} and source.startswith(p["root"].rstrip("/") + "/")}, key=len, reverse=True)
                candidates = [resolve(source, root, token) for root in roots]
                resolved = next((p for p in candidates if p in paths or p in generated), None)
                original = resolved if resolved in paths else generated.get(resolved)
                if original:
                    invoked.add(original)
                    references.append({"source": source, "target": original, "kind": "declared_interpreter_invocation", **({"generated_target": resolved} if original != resolved else {})})
                    break

    for path, text in texts.items():
        entry = entries[path]
        evidence = code_evidence(path, text)
        entry["content_analysis"] = evidence
        blocks = embedded_blocks(text)
        entry.setdefault("analysis_coverage", {})["embedded_code"] = {
            "status": "partial" if evidence["embedded_analysis_limited"] else "complete_input",
            "total_characters": len(text), "inspected_characters": None,
            "embedded_characters_supplied": sum(len(block["text"]) for block in blocks),
            "embedded_blocks_supplied": len(blocks), "maximum_embedded_blocks": 8,
            "maximum_embedded_characters": 131072,
            "supplied_block_ranges": [{"start_line": b["line"], "end_line": b["line"] + len(b["text"].splitlines()) - 1} for b in blocks],
            "reason": "Embedded/whole-source analysis hit its character or block budget; supplied ranges do not imply omitted content is safe." if evidence["embedded_analysis_limited"]
                      else "Supported source structures and bounded recognized code blocks inspected; exact character traversal is not measured."}
        if evidence["embedded_analysis_limited"]:
            inventory_limited[0] = True
        if evidence["code_like"]:
            components.append({"kind": "code", "path": path, "evidence": evidence["evidence"]})
            native_browser_script = PurePosixPath(path).suffix.lower() in {".html", ".htm", ".xhtml"} and not evidence["mixed_executable_suffix"]
            if native_browser_script:
                item = finding("embedded_browser_script", "HTML contains script-capable content. Browser execution, external access and organizational approval are not verified; this observation does not establish an upload-policy bypass.", [path] + evidence["evidence"], severity="info")
                item.update(tier="info", disposition="info", is_actionable=False, display_kind="informational_signal", finding_category="capability_observation")
                entry["findings"].append(item)
            elif PurePosixPath(path).suffix.lower() not in EXECUTABLE_SUFFIXES:
                entry["findings"].append(finding("code_in_text_artifact", "Code-like content is stored in a text/documentation file; inspect its invocation before use.", [path] + evidence["evidence"]))
                if evidence["mixed_executable_suffix"] or evidence["code_like"]:
                    entry["file_type_policy"] = {"signal": "executable_packaged_as_document", "potential_upload_control_bypass": True,
                                                 "organization_policy_verified": False, "malware_determination": "not_established"}
                    entry["findings"].append(finding("executable_packaged_as_document", "Executable source is stored with a document extension. Review its declared invocation and applicable upload policy; an actual policy bypass and malicious behavior are not established.", [path] + evidence["evidence"]))
        base = str(PurePosixPath(path).parent)
        base = "" if base == "." else base
        command_targets(path, text, base)
        for index, match in enumerate(islice(re.finditer(r"\b(?:cp|copy|mv|move|ren|rename|base64\s+-d)\s+([^\n`]+)", text), 65)):
            if index == 64:
                inventory_limited[0] = True
                break
            command = match.group(1)
            try:
                tokens = shlex.split(command)
            except ValueError:
                continue
            if len(tokens) >= 2:
                source = resolve(path, base, tokens[0])
                destination = tokens[2] if len(tokens) > 2 and tokens[1] == ">" else tokens[1]
                if source in paths and PurePosixPath(destination).suffix.lower() in EXECUTABLE_SUFFIXES:
                    invoked.add(source)
                    references.append({"source": path, "target": source, "kind": "declared_copy_to_executable_name"})

    def walk(value, source, root, depth=0):
        if depth > 24 or len(components) >= 500 or len(issues) >= 100 or len(dependencies) >= 200:
            return
        if isinstance(value, dict):
            entry_point = value.get("entry_point")
            if isinstance(entry_point, str):
                resolved = resolve(source, root, entry_point)
                components.append({"kind": "declared_entry_point", "path": source, "target": resolved})
                if resolved in paths:
                    invoked.add(resolved)
                    references.append({"source": source, "target": resolved, "kind": "declared_entry_point"})
                else:
                    issues.append({"id": "component_path", "path": source, "detail": "Entry point missing or escapes the package", "severity": "error"})
            if PurePosixPath(source).name == "package.json" and isinstance(value.get("scripts"), dict):
                for name, command in list(value["scripts"].items())[:64]:
                    if isinstance(command, str):
                        components.append({"kind": "package_script", "path": source, "name": str(name)[:100], "execution": "declared_not_run"})
                        entries[source]["findings"].append(finding("declared_process_launch", "Dependency manifest declares a script or install step; it is not executed by this scan.", [str(name)]))
                        command_targets(source, command, root)
            if isinstance(value.get("command"), str):
                command = value["command"]
                args = value.get("args", [])
                components.append({"kind": "launch_command", "path": source, "command": command[:200], "args_count": len(args) if isinstance(args, list) else 0})
                entries[source]["findings"].append(finding("declared_process_launch", "Configuration declares a process/hook command; review its code and privileges.", [command]))
                command_targets(source, command + " " + " ".join(str(a) for a in args if isinstance(a, str)) if isinstance(args, list) else command, root)
                # Portable command is one token, not a shell expression.
                if analysis["configurations"].get(source, {}).get("$schema") and re.search(r"[;&|\n]", command):
                    issues.append({"id": "shell_command_in_executable_field", "path": source, "detail": "Portable command must be one executable token", "severity": "error"})
                if command.startswith(("./", "../", "/")):
                    resolved = resolve(source, root, command)
                    if resolved in paths:
                        invoked.add(resolved)
                        references.append({"source": source, "target": resolved, "kind": "configured_executable"})
                    else:
                        issues.append({"id": "component_path", "path": source, "detail": "Configured executable is missing or escapes the package", "severity": "error"})
            url = value.get("url")
            if isinstance(url, str):
                try:
                    parsed = urlsplit(url)
                    hostname = parsed.hostname
                except ValueError:
                    issues.append({"id": "invalid_endpoint_url", "path": source, "detail": "Malformed component endpoint", "severity": "error"})
                    parsed, hostname = urlsplit(""), None
                if parsed.scheme in {"http", "ws"} and hostname not in {"localhost", "127.0.0.1", "::1"}:
                    entries[source]["findings"].append(finding("insecure_component_transport", "Remote component uses unencrypted transport.", [url], category="code"))
                dependencies.append({"kind": "endpoint", "source": source, "value": f"{parsed.scheme}://{hostname or ''}", "verification": "not_contacted", "redaction": "userinfo_path_query_removed"})
            for key, item in value.items():
                if key in {"env", "headers"} and isinstance(item, dict):
                    for name, secret in item.items():
                        if isinstance(secret, str) and re.search(r"token|secret|password|api.?key|authorization", str(name), re.I) and secret and not re.search(r"\$\{|\{\{", secret):
                            entries[source]["findings"].append(finding("literal_credential_declaration", "Configuration contains a literal credential-like value. Value redacted from this finding.", [f"{key}.{name}=[REDACTED]"], category="credential"))
                if key in {"source", "skills", "agents", "hooks", "lspServers", "mcpServers", "outputStyles", "cwd", "extensions"}:
                    for candidate in ([item] if isinstance(item, str) else item if isinstance(item, list) else []):
                        if isinstance(candidate, str) and candidate.startswith(("./", "../", "/")):
                            resolved = resolve(source, root, candidate)
                            exists = resolved in paths or any(p.startswith((resolved or "<invalid>") + "/") for p in paths)
                            if not resolved or not exists:
                                issues.append({"id": "component_path", "path": source, "detail": "Escaping or missing component path: " + candidate[:200], "severity": "error"})
                walk(item, source, root, depth + 1)
        elif isinstance(value, list):
            if len(value) > 1000:
                inventory_limited[0] = True
            for item in value[:1000]:
                walk(item, source, root, depth + 1)

    for source, data in analysis["configurations"].items():
        package = next((p for p in analysis["packages"] if p["manifest"] == source), None)
        root = package["root"] if package else posixpath.dirname(source)
        if root == ".":
            root = ""
        walk(data, source, root)
    permissions = []
    for skill in analysis["skills"]:
        data = skill.get("frontmatter", {})
        if "hooks" in data:
            walk(data["hooks"], skill["path"], skill["root"] if skill["root"] != "." else "")
        allowed = data.get("allowed-tools")
        if allowed:
            permissions.append({"path": skill["path"], "allowed_tools": allowed, "meaning": "runtime_specific_preapproval_not_universal_tool_restriction"})
            if re.search(r"\*|\bBash\b|\bWrite\b|\bEdit\b", str(allowed)):
                entries[skill["path"]]["findings"].append(finding("broad_tool_preapproval", "Skill declares broad or side-effecting tool pre-approval; runtime and managed policy determine its effect.", [str(allowed)]))
    for path in sorted(invoked):
        entries[path]["declared_execution_target"] = True
        if PurePosixPath(path).suffix.lower() not in EXECUTABLE_SUFFIXES and entries[path].get("content_analysis", {}).get("embedded_blocks"):
            evidence = entries[path]["content_analysis"]
            evidence.update(code_like=True, language=evidence["language"] or "declared_embedded_source")
            if not any(c["kind"] == "code" and c["path"] == path for c in components):
                components.append({"kind": "code", "path": path, "evidence": ["declared_execution_of_embedded_source"]})
            if not any(f["id"] == "executable_packaged_as_document" for f in entries[path]["findings"]):
                entries[path]["file_type_policy"] = {"signal": "executable_packaged_as_document", "potential_upload_control_bypass": True,
                                                     "organization_policy_verified": False, "malware_determination": "not_established"}
                entries[path]["findings"].append(finding("executable_packaged_as_document", "Packaged document contains declared script source and extraction or execution instructions. Review the applicable file-type policy; an actual policy bypass and malicious behavior are not established.", [path]))
        entries[path]["findings"].append(finding("declared_execution_target", "Another packaged artifact declares execution or conversion of this file; reference-directory naming does not establish trust.", [r["source"] for r in references if r["target"] == path]))
    for path in texts:
        if PurePosixPath(path).name in {"requirements.txt", "package.json", "pyproject.toml", "uv.lock", "package-lock.json"}:
            dependencies.append({"kind": "dependency_manifest", "source": path, "verification": "not_installed_or_vulnerability_queried"})
    return {"components": components[:500], "dependencies": dependencies[:200], "execution_references": references[:200],
            "inventory_limited": inventory_limited[0] or len(components) >= 500 or len(dependencies) >= 200 or len(references) >= 200 or len(issues) >= 100,
            "permissions": permissions[:200], "format_findings": issues[:100], "invoked_paths": invoked,
            "composition_analysis": {"status": "static_capability_inventory_only", "runtime_chain_safety": "not_assessed",
                                     "reason": "A static package scan cannot establish live cross-skill behavior."}}
