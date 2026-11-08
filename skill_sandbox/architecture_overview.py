"""Readable architecture overview of a scanned skill, from static evidence only.

Two phases. ``extract_declared_structure`` reads package text (before report
redaction, like documented steps) for declared routers, allowed tools, named
connectors, other skills, documented fetch/write lines and approval mentions.
``build_overview`` then groups files into areas from the redacted report.

Nothing is executed or contacted. Declared areas come from a router or index
table in the package; every other grouping is labelled ``inferred`` with its
basis. A read or write direction is stated only when source syntax or a
documented instruction establishes it; otherwise it is ``unknown``.
"""
from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

SCHEMA = "injecticide-overview/v1"
STRUCTURE_SCHEMA = "injecticide-declared-structure/v1"
MAX_SOURCES = 500
MAX_SOURCE_CHARACTERS = 256 * 1024
MAX_TOTAL_CHARACTERS = 4 * 1024 * 1024
MAX_RECORDS = 400  # per declared-structure list
MAX_AREAS = 24
MAX_SHARED = 40
MAX_DATA_STORES = 40
MAX_EXTERNAL = 60
MAX_LINKS = 300
MAX_EVIDENCE = 5
MAX_DEPTH = 32
SHARED_MINIMUM_AREAS = 3

DATA_EXTENSIONS = {".sqlite", ".sqlite3", ".db", ".db3", ".csv", ".tsv", ".jsonl", ".ndjson",
                   ".parquet", ".xlsx", ".xls"}
CODE_EXTENSIONS = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash",
                   ".ps1", ".psm1", ".cmd", ".bat", ".rb", ".pl", ".php", ".lua", ".r"}
DOCUMENT_SUFFIXES = (".md", ".txt")
DISGUISED_FINDINGS = {"executable_packaged_as_document", "code_in_text_artifact", "declared_execution_target"}
SECRET_FINDINGS = {"hardcoded_secret", "secret_exfiltration", "credential_source_to_network_payload"}
EXECUTION_FINDINGS = {"dynamic_exec", "subprocess_spawn", "runtime_dependency_install", "declared_tool_execution",
                      "dynamic_import_construction", "shell_command_in_executable_field", "embedded_executable_blob"}
COVERAGE_FINDINGS = {"database_not_cleared", "opaque_database"}
COVERAGE_STATES = {"limited_or_truncated", "unsupported", "executable_not_analyzed", "not_assessed", "skipped"}
SENSITIVE_DATA_CLASSES = {"personal_email", "ssn", "date_of_birth", "home_address", "financial", "health", "credential"}
BADGES = (("disguised_script", "Disguised scripts"), ("secret", "Secrets"), ("personal_data", "Personal data"),
          ("execution", "Code execution"), ("coverage_gap", "Coverage gaps"))

# HTTP client calls whose method establishes the direction; others stay unknown.
READ_CALLS = {"get", "head", "options", "urlretrieve"}
WRITE_CALLS = {"post", "put", "patch", "delete"}
# Agent tool names (Claude Code / Agent Skills ``allowed-tools``) with a documented direction.
READ_TOOLS = {"read", "grep", "glob", "ls"}
WEB_TOOLS = {"webfetch", "websearch"}
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
SHELL_TOOLS = {"bash", "powershell"}

ROUTER_FILE = re.compile(r"(?:^|[-_./])(?:index|router|routing|catalog|load[-_ ]?order|toc|map)(?:[-_.]|$)", re.I)
TABLE_SEPARATOR = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)*\|?\s*$")
LIST_ITEM = re.compile(r"^\s{0,6}(?:[-*+]|\d{1,3}[.)])\s+(.+)$")
CONNECTOR_HEADER = re.compile(r"connector|tool|mcp|integration|system|service", re.I)
LINK = re.compile(r"!?\[([^\]\n]*)\]\([^)\n]*\)")
PATHISH = re.compile(r"`?[\w./@+~-]*[\w@+~-]\.(?:md|txt|json|ya?ml|py|js|ts|sh|ps1|sql|csv|sqlite3?|db)`?", re.I)
MCP_TOOL = re.compile(r"\bmcp__([A-Za-z0-9-]{1,64})__([A-Za-z0-9_-]{1,64})")
MCP_NAMED = re.compile(r"\b([A-Za-z][\w.-]{1,62})\s+MCP\b|\bMCP\s+server\s+[`\"']?([A-Za-z][\w.-]{1,62})", re.I)
SKILL_MENTION = re.compile(r"(?:`([a-z0-9][a-z0-9-]{1,63})`|\b([a-z0-9]+(?:-[a-z0-9]+)+))\s+skill\b", re.I)
URL = re.compile(r"(?:https?|wss?)://[^\s<>\"'`)]+", re.I)
FETCH_VERB = re.compile(r"\b(?:(?i:fetch\w*|download\w*|retriev\w*|scrap\w*|crawl\w*|brows\w*)|GET)\b")
WRITE_VERB = re.compile(r"\b(?:POST|PUT|PATCH|DELETE|(?i:upload\w*|submit\w*|publish\w*))\b")
APPROVAL = re.compile(r"\b(?:preview\w*|approv\w*|confirm\w*|sign[- ]off|human review)\b", re.I)
NEGATION = re.compile(r"\b(?:without|never|skip\w*|no|not|don't|doesn't)\b", re.I)
FAMILY = re.compile(r"^([a-z][a-z0-9]{1,15})[-_][a-z0-9]", re.I)


def _str(value, limit=300):
    return value[:limit] if isinstance(value, str) else ""


def _list(value, limit=3000):
    return value[:limit] if isinstance(value, list) else []


def _plain(text, limit=120):
    text = re.sub(r"^\s{0,6}(?:[-*+]|\d{1,3}[.)])\s+", "", text or "")
    text = LINK.sub(r"\1", text)
    text = re.sub(r"(\*\*|__|`)", "", text)
    text = re.sub(r"\s*(?:→|->|=>|⇒)\s*", " ", text)
    return re.sub(r"\s+", " ", text).strip(" |:-—–")[:limit]


def _origin(raw):
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return ""
        host = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
        return parsed.scheme + "://" + host + (":" + str(parsed.port) if parsed.port else "")
    except ValueError:
        return ""


def _graph_targets(graph):
    """(source, line) -> package targets of resolved or single-variant references."""
    targets = {}
    for edge in _list(graph.get("edges")):
        if not isinstance(edge, dict):
            continue
        target = edge_target(edge)
        if target:
            targets.setdefault((edge.get("source"), edge.get("line")), []).append(target)
    return targets


def edge_target(edge):
    """The packaged file a graph edge evidently names, or ``""``."""
    if edge.get("status") == "resolved":
        return _str(edge.get("target"), 4096)
    variants = [c.get("path") for c in _list(edge.get("variant_candidates")) if isinstance(c, dict)]
    if edge.get("status") in {"document_suffix_variant", "name_only_match"} and len(variants) == 1:
        return _str(variants[0], 4096)
    return ""


# ---------------------------------------------------------------------------
# Phase 1: declared structure from package text.

def extract_declared_structure(text_sources, graph=None):
    graph = graph or {}
    line_targets = _graph_targets(graph)
    result = {"schema": STRUCTURE_SCHEMA, "routes": [], "tools": [], "skill_mentions": [],
              "documented_flows": [], "approval_mentions": [], "limits": []}

    def record(kind, item):
        if len(result[kind]) >= MAX_RECORDS:
            if {"kind": kind + "_count"} not in result["limits"]:
                result["limits"].append({"kind": kind + "_count"})
            return
        result[kind].append(item)

    remaining = MAX_TOTAL_CHARACTERS
    sources = [s for s in text_sources if isinstance(s, dict) and isinstance(s.get("path"), str)
               and isinstance(s.get("text"), str)][:MAX_SOURCES]
    if len(text_sources) > MAX_SOURCES:
        result["limits"].append({"kind": "structure_source_count"})
    own_names = set()
    for source in sources:
        path, text = source["path"], source["text"]
        if posixpath.splitext(path)[1].lower() not in {".md", ".txt", ".skill"}:
            continue
        bounded = text[:min(MAX_SOURCE_CHARACTERS, remaining)]
        remaining -= len(bounded)
        if len(bounded) < len(text):
            result["limits"].append({"kind": "structure_source_characters", "path": path})
        lines = bounded.splitlines()
        is_entry = posixpath.basename(path).lower() == "skill.md"
        body_start = 0
        if is_entry:
            body_start = _frontmatter(path, lines, record, own_names)
        if is_entry or ROUTER_FILE.search(posixpath.basename(path)):
            _routes(path, lines, body_start, line_targets, record)
        fence = False
        for line_no, line in enumerate(lines, 1):
            if line_no <= body_start:
                continue
            if re.match(r"^\s{0,3}(`{3,}|~{3,})", line):
                fence = not fence
                continue
            for match in MCP_TOOL.finditer(line):
                record("tools", {"value": match[0][:160], "path": path, "line": line_no, "origin": "body"})
            for match in SKILL_MENTION.finditer(line):
                name = (match[1] or match[2]).lower()
                if name not in own_names and not name.startswith(("pre-", "re-")):
                    record("skill_mentions", {"value": name, "path": path, "line": line_no})
            if fence:
                continue
            # A named service operation is a write only when both its verb and
            # the surrounding instruction declare a mutation. A bare identifier,
            # allowed-tools entry, or negated instruction is not a write trace.
            if not NEGATION.search(line) and re.search(
                    r"\b(?:write|create|update|delete|publish|upload|submit|append|send)\b", line, re.I):
                for operation in re.findall(r"`([A-Za-z][A-Za-z0-9]*_(?:[A-Za-z0-9]+_)*[A-Za-z0-9]+)`", line):
                    parts = operation.lower().split("_")
                    if len(parts) >= 3 and parts[1] in {
                            "create", "update", "delete", "publish", "upload", "submit", "append", "send"}:
                        record("tools", {"value": operation[:160], "path": path, "line": line_no,
                                         "origin": "documented-operation", "direction": "write"})
            if URL.search(line):
                reads, writes = bool(FETCH_VERB.search(line)), bool(WRITE_VERB.search(line))
                if reads != writes:
                    record("documented_flows", {"path": path, "line": line_no,
                                                "direction": "read" if reads else "write"})
            if APPROVAL.search(line) and not NEGATION.search(line):
                record("approval_mentions", {"path": path, "line": line_no, "text": _plain(line, 200)})
    return result


def _frontmatter(path, lines, record, own_names):
    if not lines or lines[0].strip() != "---":
        return 0
    end = next((i for i, line in enumerate(lines[1:200], 1) if line.strip() in {"---", "..."}), None)
    if end is None:
        return 0
    key = None
    for index in range(1, end):
        line = lines[index]
        match = re.match(r"^([A-Za-z][\w-]*)\s*:\s*(.*)$", line)
        if match:
            key, value = match[1].lower(), match[2].strip()
            if key == "name" and value:
                own_names.add(value.strip("\"'").lower())
        elif key and re.match(r"^\s+", line):
            value = line.strip()
            value = value[1:].strip() if value.startswith("-") else value
        else:
            continue
        if key == "allowed-tools":
            for token in re.findall(r"[A-Za-z_][\w.-]*(?:\([^)]*\))?", value.strip("[]\"'")):
                name = token.split("(", 1)[0]
                record("tools", {"value": name[:160], "path": path, "line": index + 1, "origin": "allowed-tools"})
        elif key == "compatibility":
            for match in MCP_NAMED.finditer(value):
                name = match[1] or match[2]
                if name.lower() not in {"an", "the", "a", "any", "remote", "local"}:
                    record("tools", {"value": "mcp:" + name[:150], "path": path, "line": index + 1,
                                     "origin": "compatibility"})
    return end + 1


def _routes(path, lines, body_start, line_targets, record):
    """Rows of tables or lists that map a need to package files."""
    index = body_start
    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith("|") and index + 1 < len(lines) and TABLE_SEPARATOR.match(lines[index + 1]):
            header = _cells(line)
            connector_columns = {i for i, cell in enumerate(header) if CONNECTOR_HEADER.search(cell)}
            rows, index = [], index + 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                cells = _cells(lines[index])
                targets = [t for t in line_targets.get((path, index + 1), []) if t != path]
                if targets:
                    need = next((_plain(c) for i, c in enumerate(cells)
                                 if i not in connector_columns and not PATHISH.search(c) and _plain(c)), "")
                    connectors = [name for i in connector_columns if i < len(cells)
                                  for name in re.split(r"\s*[,;/]\s*|\s+and\s+", _plain(cells[i], 300))
                                  if name and not PATHISH.search(name)]
                    rows.append({"path": path, "line": index + 1, "text": need, "form": "table",
                                 "reference_paths": list(dict.fromkeys(targets))[:20],
                                 "connectors": [{"value": name[:80]} for name in connectors[:10]],
                                 "connector_header": [_plain(header[i], 60) for i in sorted(connector_columns) if i < len(header)]})
                index += 1
            if len(rows) >= 2:
                for row in rows:
                    record("routes", row)
            continue
        if LIST_ITEM.match(line):
            rows = []
            while index < len(lines) and (LIST_ITEM.match(lines[index]) or not lines[index].strip()):
                item = LIST_ITEM.match(lines[index])
                targets = [t for t in line_targets.get((path, index + 1), []) if t != path] if item else []
                # Index inventories list related files too; only conditional
                # load instructions declare caller-need routing in list form.
                routing = item and re.search(r"^(?:if|when|for)\b.*\b(?:load|read|use|consult)\b", item[1], re.I)
                if routing and targets:
                    need = _plain(PATHISH.sub("", LINK.sub(lambda m: "" if PATHISH.search(m[0]) and _plain(m[1]) == "" else m[1], item[1])))
                    if len(need) >= 3:
                        rows.append({"path": path, "line": index + 1, "text": need, "form": "list",
                                     "reference_paths": list(dict.fromkeys(targets))[:20], "connectors": []})
                index += 1
            if len(rows) >= 2:
                for row in rows:
                    record("routes", row)
            continue
        index += 1


def _cells(line):
    text = line.strip()
    text = text[1:] if text.startswith("|") else text
    text = text[:-1] if text.endswith("|") else text
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", text)]


# ---------------------------------------------------------------------------
# Shared evidence classification (also used by the playground map).

def is_data_file(path, record=None):
    return (posixpath.splitext(path)[1].lower() in DATA_EXTENSIONS
            or isinstance((record or {}).get("database_profile"), dict))


def disguised_paths(graph):
    """Files that a reference names as a script packaged under a document suffix."""
    found = set()
    for edge in _list(graph.get("edges")):
        if isinstance(edge, dict) and edge.get("status") == "document_suffix_variant":
            found.update(c.get("path") for c in _list(edge.get("variant_candidates"))
                         if isinstance(c, dict) and isinstance(c.get("path"), str))
    return found


def is_code_file(path, record=None, disguised=frozenset()):
    record = record or {}
    if posixpath.splitext(path)[1].lower() in CODE_EXTENSIONS or path in disguised:
        return True
    stem, suffix = posixpath.splitext(path)
    if suffix.lower() in DOCUMENT_SUFFIXES and posixpath.splitext(stem)[1].lower() in CODE_EXTENSIONS:
        return True  # tool.py.md
    ids = {f.get("id") for f in _list(record.get("findings")) if isinstance(f, dict)}
    return bool(ids & DISGUISED_FINDINGS) or record.get("effective_artifact_role") == "execution_component"


def origin_directions(graph, declared=None):
    """origin -> {"read": [(path, line)], "write": [...], "mention": [...]} from static evidence.

    Direction comes from a recognized HTTP client method on the same source line
    as the destination, or from a documented line that fetches or posts to it.
    """
    calls = {}
    for item in _list(graph.get("capability_observations")):
        if isinstance(item, dict) and item.get("capability") == "network_access":
            method = _str(item.get("operation"), 200).rsplit(".", 1)[-1].lower()
            direction = "read" if method in READ_CALLS else "write" if method in WRITE_CALLS else "unknown"
            calls[(item.get("source"), item.get("line"))] = direction
    documented = {(item.get("path"), item.get("line")): item.get("direction")
                  for item in _list((declared or {}).get("documented_flows")) if isinstance(item, dict)}
    result = {}
    for item in _list(graph.get("external_references")):
        if not isinstance(item, dict) or not isinstance(item.get("source"), str):
            continue
        origin = _origin(_str(item.get("url"), 4096))
        if not origin:
            continue
        key = (item["source"], item.get("line"))
        direction = calls.get(key) if item.get("kind") == "network_call_destination" else documented.get(key)
        bucket = result.setdefault(origin, {"read": [], "write": [], "mention": []})
        bucket[direction if direction in {"read", "write"} else "mention"].append(key)
    for bucket in result.values():
        # The URL text of a recognized call is also a plain mention; count the line once.
        directed = set(bucket["read"]) | set(bucket["write"])
        bucket["mention"] = [key for key in dict.fromkeys(bucket["mention"]) if key not in directed]
        bucket["read"], bucket["write"] = list(dict.fromkeys(bucket["read"])), list(dict.fromkeys(bucket["write"]))
    return result


def write_lines(graph):
    """(source, line) pairs where source syntax writes or deletes a file."""
    return {(item.get("source"), item.get("line")) for item in _list(graph.get("capability_observations"))
            if isinstance(item, dict) and item.get("capability") in {"file_write", "file_delete"}}


def declared_tools(declared):
    """Normalised declared tools: name -> {"kind", "direction", "untrusted", "evidence"}."""
    tools = {}
    for item in _list((declared or {}).get("tools")):
        if not isinstance(item, dict):
            continue
        value = _str(item.get("value"), 160)
        evidence = {"path": _str(item.get("path"), 4096), "line": item.get("line")}
        mcp = MCP_TOOL.fullmatch(value)
        if mcp or value.startswith("mcp:"):
            name, kind = (mcp[1] if mcp else value[4:]), "mcp"
            direction, untrusted = "unknown", False
        else:
            name, kind = value, "tool"
            lowered = value.lower()
            direction = ("read" if lowered in READ_TOOLS | WEB_TOOLS else "write" if lowered in WRITE_TOOLS
                         else "unknown")
            untrusted = lowered in WEB_TOOLS
            if lowered in WEB_TOOLS:
                kind = "retrieval"
            elif lowered in SHELL_TOOLS:
                kind = "code"
        if item.get("origin") == "documented-operation" and item.get("direction") == "write":
            direction = "write"
        if not name:
            continue
        entry = tools.setdefault((kind, name.lower()), {"name": name, "kind": kind, "direction": direction,
                                                        "untrusted": untrusted, "evidence": []})
        if direction == "write":
            entry["direction"] = "write"
        if item.get("origin") == "documented-operation":
            entry.setdefault("used_by_targets", set()).add(evidence["path"])
        if len(entry["evidence"]) < MAX_EVIDENCE and evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)
    for route in _list((declared or {}).get("routes")):
        if not isinstance(route, dict):
            continue
        header = " ".join(_str(h, 60) for h in _list(route.get("connector_header")))
        for connector in _list(route.get("connectors")):
            name = _str(connector.get("value") if isinstance(connector, dict) else None, 80)
            if not name:
                continue
            kind = "mcp" if re.search(r"\bmcp\b", name + " " + header, re.I) else "tool"
            name = re.sub(r"\s*\(?\bmcp\b\)?\s*", " ", name, flags=re.I).strip() or name
            entry = tools.setdefault((kind, name.lower()), {"name": name, "kind": kind, "direction": "unknown",
                                                            "untrusted": False, "evidence": []})
            evidence = {"path": _str(route.get("path"), 4096), "line": route.get("line")}
            if len(entry["evidence"]) < MAX_EVIDENCE and evidence not in entry["evidence"]:
                entry["evidence"].append(evidence)
            entry.setdefault("used_by_targets", set()).update(_list(route.get("reference_paths")))
    return tools


# ---------------------------------------------------------------------------
# Phase 2: overview from the redacted report.

def build_overview(report):
    graph = (report.get("package_analysis") or {}).get("relationship_graph") or {}
    documented = report.get("documented_process") or {}
    declared = documented.get("declared_structure") or {}
    files = {f["path"]: f for f in _list(report.get("files"))
             if isinstance(f, dict) and isinstance(f.get("path"), str)}
    inventory = list(files)
    for item in _list(graph.get("nodes")):
        if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"] not in files:
            inventory.append(item["path"])
    entries = [p for p in _list(graph.get("entrypoints")) if isinstance(p, str)
               and posixpath.basename(p).lower() == "skill.md"]
    if not entries:
        entries = [p for p in inventory if posixpath.basename(p).lower() == "skill.md"]
    limits = []

    adjacency, distances_from = {}, {}
    for edge in _list(graph.get("edges")):
        if isinstance(edge, dict) and isinstance(edge.get("source"), str):
            target = edge_target(edge)
            if target and target != edge["source"]:
                adjacency.setdefault(edge["source"], []).append(target)
    data_paths = [p for p in inventory if is_data_file(p, files.get(p))]
    data_set = set(data_paths)

    routes = [r for r in _list(declared.get("routes")) if isinstance(r, dict)]
    router_files = {r.get("path") for r in routes}
    entry_files = list(dict.fromkeys(entries + [p for p in router_files if p in files or p in inventory]))
    entry_set = set(entry_files)

    # Declared areas: rows naming the same target join one area.
    areas, seed_owner = [], {}
    for route in routes:
        targets = [t for t in _list(route.get("reference_paths")) if isinstance(t, str)
                   and t not in entry_set and t not in data_set]
        if not targets:
            continue
        owner = next((seed_owner[t] for t in targets if t in seed_owner), None)
        if owner is None:
            if len(areas) >= MAX_AREAS:
                if {"kind": "overview_area_count"} not in limits:
                    limits.append({"kind": "overview_area_count"})
                continue
            label = _str(route.get("text"), 120) or _title(targets[0])
            owner = {"id": "area-" + str(len(areas) + 1), "label": label, "source": "declared",
                     "basis": "Router " + route.get("form", "table") + " in " + posixpath.basename(_str(route.get("path"), 4096))
                              + " line " + str(route.get("line")), "seeds": []}
            areas.append(owner)
        for target in targets:
            if target not in seed_owner:
                seed_owner[target] = owner
                owner["seeds"].append(target)

    def reach(area, blocked):
        seen, frontier, distance = {}, [(s, 0) for s in area["seeds"]], {}
        while frontier:
            current, depth = frontier.pop(0)
            if current in seen or depth > MAX_DEPTH:
                continue
            seen[current] = depth
            for target in adjacency.get(current, []):
                if target in blocked or target in seen:
                    continue
                frontier.append((target, depth + 1))
        return {p: d for p, d in seen.items() if p not in area["seeds"]}

    def blocked_for(area):
        return entry_set | data_set | (set(seed_owner) - set(area["seeds"]))

    claimed = set(seed_owner)
    for area in areas:
        claimed.update(reach(area, blocked_for(area)))

    # Inferred areas for files the router does not claim.
    def unclaimed():
        return [p for p in inventory if p not in claimed and p not in entry_set and p not in data_set]

    def add_inferred(label, basis, members):
        if len(areas) >= MAX_AREAS:
            if {"kind": "overview_area_count"} not in limits:
                limits.append({"kind": "overview_area_count"})
            return
        area = {"id": "area-" + str(len(areas) + 1), "label": label, "source": "inferred",
                "basis": basis, "seeds": list(members)}
        areas.append(area)
        for path in members:
            seed_owner[path] = area
            claimed.add(path)

    families = {}
    for path in unclaimed():
        match = FAMILY.match(posixpath.basename(path))
        if match:
            families.setdefault(match[1].lower(), []).append(path)
    for prefix, members in sorted(families.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(members) >= 2:
            add_inferred(prefix + "-* files", "Inferred: filename family " + prefix + "-*", sorted(members))
    # Reference communities: connected groups of still-unclaimed files.
    pool = set(unclaimed())
    neighbours = {p: set() for p in pool}
    for source, targets in adjacency.items():
        for target in targets:
            if source in pool and target in pool:
                neighbours[source].add(target)
                neighbours[target].add(source)
    for start in sorted(pool):
        if start in claimed or not neighbours[start]:
            continue
        group, stack = set(), [start]
        while stack:
            current = stack.pop()
            if current not in group:
                group.add(current)
                stack.extend(neighbours[current] - group)
        if len(group) >= 2:
            hub = max(sorted(group), key=lambda p: len(neighbours[p]))
            add_inferred(_title(hub) + " group", "Inferred: reference community around " + posixpath.basename(hub),
                         sorted(group))
    # Folders for what remains (for example flat references/ directories).
    root = posixpath.dirname(entries[0]) if len(entries) == 1 else ""
    folders = {}
    for path in unclaimed():
        relative = path[len(root) + 1:] if root and path.startswith(root + "/") else path
        folder = relative.split("/", 1)[0] if "/" in relative else ""
        if folder:
            folders.setdefault(folder, []).append(path)
    for folder, members in sorted(folders.items()):
        if len(members) >= 2:
            add_inferred(folder + "/", "Inferred: shared folder " + folder + "/", sorted(members))

    # Membership: seeds, then the closest area; files reached by 3+ areas are shared.
    reaches = [(area, reach(area, blocked_for(area))) for area in areas]
    owner_of = {path: area["id"] for path, area in seed_owner.items()}
    users = {}
    for area, reached in reaches:
        for path, depth in reached.items():
            if path not in seed_owner:
                users.setdefault(path, []).append((depth, area["id"]))
    shared = []
    for path in sorted(users):
        used_by = sorted({area_id for _, area_id in users[path]}, key=_area_order)
        if len(used_by) >= SHARED_MINIMUM_AREAS and len(shared) < MAX_SHARED:
            shared.append({"id": "shared-" + str(len(shared) + 1), "label": _title(path), "path": path,
                           "used_by": used_by})
            owner_of[path] = shared[-1]["id"]
        else:
            if len(used_by) >= SHARED_MINIMUM_AREAS and {"kind": "overview_shared_count"} not in limits:
                limits.append({"kind": "overview_shared_count"})
            owner_of[path] = min(users[path], key=lambda item: (item[0], _area_order(item[1])))[1]

    entry_area = {"id": "area-entry", "label": "Skill entry", "source": "inferred",
                  "basis": "Inferred: skill entry filename" + (" and router location" if router_files - set(entries) else ""),
                  "seeds": entry_files}
    for path in entry_files:
        owner_of[path] = entry_area["id"]

    data_stores = []
    for path in data_paths[:MAX_DATA_STORES]:
        profile = (files.get(path) or {}).get("database_profile")
        profile = profile if isinstance(profile, dict) else None
        tables = [t for t in _list((profile or {}).get("tables")) if isinstance(t, dict)]
        counts = [t.get("row_count") for t in tables if isinstance(t.get("row_count"), int) and not isinstance(t.get("row_count"), bool)]
        classes = sorted({c for t in tables for col in _list(t.get("columns")) if isinstance(col, dict)
                          for c in _list(col.get("data_classes")) if isinstance(c, str)})
        coverage = (profile or {}).get("coverage") if isinstance((profile or {}).get("coverage"), dict) else {}
        data_stores.append({"id": "data-" + str(len(data_stores) + 1), "label": posixpath.basename(path),
                            "path": path, "row_count": sum(counts) if counts else None, "data_classes": classes,
                            "coverage_status": _str(coverage.get("status"), 40) or ("not_profiled" if profile is None else "unknown")})
        owner_of[path] = data_stores[-1]["id"]
    if len(data_paths) > MAX_DATA_STORES:
        limits.append({"kind": "overview_data_store_count"})

    # External systems.
    external, external_index = [], {}

    def system(key, label, kind, direction, untrusted, evidence):
        if key not in external_index:
            if len(external) >= MAX_EXTERNAL:
                if {"kind": "overview_external_count"} not in limits:
                    limits.append({"kind": "overview_external_count"})
                return None
            external_index[key] = {"id": "ext-" + str(len(external) + 1), "label": label[:120], "kind": kind,
                                   "direction": direction, "untrusted": untrusted, "evidence": []}
            external.append(external_index[key])
        item = external_index[key]
        if item["direction"] != direction:
            item["direction"] = "write" if "write" in {item["direction"], direction} else (
                "read" if "read" in {item["direction"], direction} else "unknown")
        item["untrusted"] = item["untrusted"] or untrusted
        for entry in evidence:
            if len(item["evidence"]) < MAX_EVIDENCE and entry not in item["evidence"]:
                item["evidence"].append(entry)
        return item["id"]

    links = {}

    def link(source, target, write=False, untrusted=False):
        if not source or not target or source == target:
            return
        item = links.setdefault((source, target), {"source": source, "target": target, "count": 0,
                                                   "write": False, "untrusted": False})
        item["count"] += 1
        item["write"] = item["write"] or write
        item["untrusted"] = item["untrusted"] or untrusted

    tools = declared_tools(declared)
    entry_id = entry_area["id"]
    for (kind, _), tool in tools.items():
        label = tool["name"] + (" (MCP)" if kind == "mcp" else "")
        out_kind = "mcp" if kind == "mcp" else "tool"
        system_id = system(("tool", out_kind, tool["name"].lower()), label, out_kind, tool["direction"],
                           tool["untrusted"], tool["evidence"])
        users_of_tool = {owner_of.get(p) for p in tool.get("used_by_targets", ()) if owner_of.get(p)}
        for user in sorted(users_of_tool or {entry_id}):
            if tool["direction"] == "read" and tool["untrusted"]:
                link(system_id, user, untrusted=True)
            else:
                link(user, system_id, write=tool["direction"] == "write")
    for origin, buckets in sorted(origin_directions(graph, declared).items()):
        direction = "write" if buckets["write"] else "read" if buckets["read"] else "unknown"
        evidence = [{"path": p, "line": line} for p, line in (buckets["read"] + buckets["write"] + buckets["mention"])]
        system_id = system(("web", origin), urlsplit(origin).hostname or origin, "web", direction,
                           bool(buckets["read"]), evidence)
        for p, _ in buckets["read"]:
            link(system_id, owner_of.get(p), untrusted=True)
        for p, _ in buckets["write"]:
            link(owner_of.get(p), system_id, write=True)
        for p, _ in buckets["mention"]:
            link(owner_of.get(p), system_id)
    for mention in _list(declared.get("skill_mentions")):
        if isinstance(mention, dict) and _str(mention.get("value"), 80):
            path = _str(mention.get("path"), 4096)
            system_id = system(("skill", mention["value"]), mention["value"], "other_skill", "unknown", False,
                               [{"path": path, "line": mention.get("line")}])
            link(owner_of.get(path), system_id)

    # File-to-file links between areas, shared services and data stores.
    writes = write_lines(graph)
    for edge in _list(graph.get("edges")):
        if isinstance(edge, dict):
            target = edge_target(edge)
            if target:
                link(owner_of.get(edge.get("source")), owner_of.get(target),
                     write=(edge.get("source"), edge.get("line")) in writes)

    steps_by_path = {}
    for step in _list(documented.get("steps")):
        if isinstance(step, dict) and isinstance(step.get("path"), str):
            steps_by_path[step["path"]] = steps_by_path.get(step["path"], 0) + 1
    disguised = disguised_paths(graph)
    out_areas = []
    ordered_areas = ([entry_area] + areas if routes else areas + [entry_area]) if entry_files else areas
    for area in ordered_areas:
        members = sorted(p for p, owner in owner_of.items() if owner == area["id"])
        out_areas.append({"id": area["id"], "label": area["label"], "source": area["source"],
                          "basis": area["basis"], "files": members,
                          "entry_files": [p for p in area["seeds"] if p in members][:20],
                          "risk_badges": risk_badges(members, files, disguised),
                          "steps": sum(steps_by_path.get(p, 0) for p in members)})
    assigned = set(owner_of)
    unassigned = sum(1 for p in inventory if p not in assigned)
    ordered_links = sorted(links.values(), key=lambda item: (-item["count"], item["source"], item["target"]))
    if len(ordered_links) > MAX_LINKS:
        limits.append({"kind": "overview_link_count"})
    return {"schema": SCHEMA, "areas": out_areas, "shared_services": shared, "data_stores": data_stores,
            "external_systems": external, "links": ordered_links[:MAX_LINKS], "unassigned_files": unassigned,
            "limits": limits + [item for item in _list(declared.get("limits")) if isinstance(item, dict)],
            "scope": "Static grouping of package files. Declared areas come from a router in the package; "
                     "inferred areas state their basis. Directions are unknown unless source syntax or a "
                     "documented instruction establishes them. Nothing was executed or contacted."}


def risk_badges(paths, files, disguised=frozenset()):
    counts = {code: 0 for code, _ in BADGES}
    for path in paths:
        record = files.get(path) or {}
        ids = {f.get("id") for f in _list(record.get("findings")) if isinstance(f, dict) and isinstance(f.get("id"), str)}
        profile = record.get("database_profile") if isinstance(record.get("database_profile"), dict) else {}
        classes = {c for t in _list(profile.get("tables")) if isinstance(t, dict)
                   for col in _list(t.get("columns")) if isinstance(col, dict)
                   for c in _list(col.get("data_classes")) if isinstance(c, str)}
        coverage = (profile.get("coverage") or {}).get("status") if isinstance(profile.get("coverage"), dict) else None
        if ids & DISGUISED_FINDINGS or path in disguised:
            counts["disguised_script"] += 1
        if ids & SECRET_FINDINGS:
            counts["secret"] += 1
        if any(i.startswith(("pii_", "phi_")) for i in ids) or classes & SENSITIVE_DATA_CLASSES:
            counts["personal_data"] += 1
        if ids & EXECUTION_FINDINGS:
            counts["execution"] += 1
        if ids & COVERAGE_FINDINGS or record.get("assessment_state") in COVERAGE_STATES or coverage in {"partial", "opaque"}:
            counts["coverage_gap"] += 1
    return [{"code": code, "label": label, "count": counts[code]} for code, label in BADGES if counts[code]]


def _area_order(area_id):
    tail = area_id.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def _title(path):
    name = posixpath.basename(path)
    for _ in range(2):
        stem, suffix = posixpath.splitext(name)
        if suffix and len(suffix) <= 8:
            name = stem
    words = re.sub(r"[-_]+", " ", name).strip()
    return (words[:1].upper() + words[1:])[:120] if words else path[:120]
