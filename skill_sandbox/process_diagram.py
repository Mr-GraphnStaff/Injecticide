"""Source-backed process views of static scan evidence, never execution traces.

Build this view after report redaction. Package content is data: no instructions,
code, destinations, or Mermaid directives from the upload are executed.
"""
from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

MAX_NODES = 100
MAX_EDGES = 200
MAX_INPUT_ITEMS = 3000
MAX_STEPS = 60
MAX_STEP_SOURCE_CHARACTERS = 1024 * 1024
UNKNOWN = "STATUS: UNKNOWN — UNVERIFIED"
SCOPE = ("Documented references and recognized source capabilities; arrows describe "
         "relationships, not execution order. Runtime behavior, conditions, approvals "
         "and outputs are unverified unless separately evidenced.")
RELATIONS = {
    "document_reference": "references document",
    "resource_reference": "references resource",
    "prose_resource_reference": "mentions resource",
    "execution_reference": "declares command reference",
    "local_import": "declares local import",
    "source_file_access": "names file in source",
    "manifest_component": "declares manifest component",
}
# Unresolved references linked to the one packaged file they evidently name.
VARIANT_LABELS = {
    "document_suffix_variant": "names file packaged under a document suffix",
    "name_only_match": "names file by bare name; path unresolved",
}


def extract_documented_steps(text_sources, relationship_graph=None):
    """Extract explicit Markdown steps, preserving source lines and uncertainty.

    This recognizes syntax rather than interpreting prose. Approval/condition
    words are mentions, not verified controls or inferred branches. Only adjacent
    numbered entries (allowing blank lines) establish documented ordering.
    """
    steps, limits = [], []
    sources = [source for source in text_sources if isinstance(source.get("path"), str)
               and isinstance(source.get("text"), str)]
    by_path = {source["path"]: source for source in sources}
    selected = {path for path in by_path if posixpath.basename(path).lower() == "skill.md"}
    # Follow only resolved packaged document links. No uploaded URL is fetched,
    # and an unrelated file's numbered list is not silently called the process.
    edges = (relationship_graph or {}).get("edges", [])[:MAX_INPUT_ITEMS]
    for _ in range(8):
        linked = {edge.get("target") for edge in edges
                  if edge.get("source") in selected and edge.get("status") == "resolved"
                  and edge.get("kind") in {"document_reference", "resource_reference", "prose_resource_reference"}
                  and edge.get("target") in by_path
                  and edge.get("target", "").lower().endswith((".md", ".txt"))}
        if linked <= selected:
            break
        selected.update(linked)
    else:
        limits.append({"kind": "documented_reference_depth"})
    sources = [source for source in sources if source["path"] in selected]
    workflow_name = re.compile(r"workflow|process|procedure|load[-_ ]order|runbook|boot", re.I)
    sources.sort(key=lambda source: (posixpath.basename(source["path"]).lower() != "skill.md",
                                     not bool(workflow_name.search(source["path"])), source["path"]))
    remaining = MAX_STEP_SOURCE_CHARACTERS
    for source in sources:
        path, original = source.get("path"), source.get("text")
        companion = posixpath.basename(path).lower() != "skill.md"
        bounded = original[:remaining]
        remaining -= len(bounded)
        if len(bounded) < len(original):
            limits.append({"kind": "documented_step_source_characters", "path": path})
        previous, previous_number, fence = None, None, None
        documented_text_fence = False
        frontmatter, comment = False, False
        for line_no, raw in enumerate(bounded.splitlines(), 1):
            if line_no == 1 and raw.strip() == "---":
                frontmatter = True
                continue
            if frontmatter:
                if raw.strip() in {"---", "..."}:
                    frontmatter = False
                continue
            if comment:
                comment = "-->" not in raw
                previous, previous_number = None, None
                continue
            fence_match = re.match(r"^\s{0,3}(`{3,}|~{3,})", raw)
            if fence_match:
                marker = fence_match[1]
                if fence is None:
                    fence = marker[0], len(marker)
                    language = raw[fence_match.end():].strip().lower()
                    documented_text_fence = companion and language in {"", "text", "plaintext", "markdown", "md"}
                elif marker[0] == fence[0] and len(marker) >= fence[1]:
                    fence = None
                    documented_text_fence = False
                previous, previous_number = None, None
                continue
            if fence is not None and not documented_text_fence:
                continue
            if "<!--" in raw:
                # Hidden author notes are not visible documented process steps.
                comment = "-->" not in raw
                previous, previous_number = None, None
                continue
            numbered = re.match(r"^\s{0,3}(\d{1,3})([a-z]?)[.)]\s+(.+)$", raw)
            heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", raw)
            section = heading and re.search(r"\b(?:workflow|process|procedure|steps?|phases?|stages?)\b", heading[1], re.I)
            if not numbered and not section:
                if raw.strip():
                    previous, previous_number = None, None
                continue
            if len(steps) >= MAX_STEPS:
                limits.append({"kind": "documented_step_count", "path": path})
                return {"status": "partial", "scope": "Explicit Markdown steps; runtime, branches and approval enforcement unverified.",
                        "steps": steps, "limits": limits}
            text = numbered[3] if numbered else heading[1]
            if len(text) > 500:
                limits.append({"kind": "documented_step_text_characters", "path": path})
            number = int(numbered[1]) if numbered and not numbered[2] else None
            step_type = "section" if section and not numbered else "approval_mention" if re.search(
                r"\b(?:approval|approve|permission|confirmation|confirm)\b", text, re.I) else "condition_mention" if re.match(
                r"(?:if|when|unless|otherwise)\b", text, re.I) else "instruction"
            predecessor = previous if numbered and previous_number is not None and number == previous_number + 1 else None
            item = {"id": "step_" + str(len(steps)), "path": path, "line": line_no,
                    "text": text[:500], "step_type": step_type, "number": number,
                    "previous_step_id": predecessor}
            if numbered and numbered[2]:
                item["documented_number"] = numbered[1] + numbered[2]
            if documented_text_fence:
                item["evidence_scope"] = "documented_text_block_not_executed"
            steps.append(item)
            previous, previous_number = (item["id"], number) if numbered else (None, None)
        if remaining <= 0:
            limits.append({"kind": "documented_step_source_budget"})
            break
    return {"status": "partial" if limits else "explicit_steps" if steps else "unknown",
            "scope": "Explicit Markdown steps; runtime, branches and approval enforcement unverified.",
            "steps": steps, "limits": limits}


def _text(value, limit=512):
    return value[:limit] if isinstance(value, str) else ""


def _path(value):
    # A clipped label is harmless; a clipped identity can merge distinct files
    # and lose their findings. Scanner inventories already bound source input.
    return value if isinstance(value, str) else ""


def _items(value):
    return value[:MAX_INPUT_ITEMS] if isinstance(value, list) else []


def _citation(path, record=None):
    record = record or {}
    line = record.get("line")
    # The JSON parser currently records line 1 for the whole manifest rather
    # than an exact field location. Do not turn that placeholder into a citation.
    exact = record.get("kind") != "manifest_component" and record.get("operation") != "manifest_command_declaration"
    if path.lower().endswith(".json") and record.get("kind") == "execution_reference":
        exact = False
    exact = exact and isinstance(line, int) and not isinstance(line, bool) and line > 0
    return {"path": path, "line": line if exact else None,
            "line_accuracy": "exact" if exact else "file_only"}


def _mermaid_text(value):
    # Mermaid decimal entities protect quoted labels as documented at
    # https://mermaid.js.org/syntax/flowchart.html#entity-codes-to-escape-characters
    # Encode all punctuation except a small readable subset, including the
    # entity marker itself. Uploaded directives and HTML remain label data.
    return "".join(c if c.isascii() and (c.isalnum() or c in " /._-:")
                   else "#" + str(ord(c)) + ";" for c in value)


def _origin(value):
    try:
        parsed = urlsplit(_text(value, 4096))
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host:
            host = "[" + host + "]"
        return parsed.scheme + "://" + host + (":" + str(parsed.port) if parsed.port else "")
    except ValueError:
        return ""


def _first_edge_per_pair(edges):
    seen, result = set(), []
    for item in edges:
        pair = (item["source"], item["target"])
        if pair not in seen:
            seen.add(pair)
            result.append(item)
    return result


def build_process_diagram(report):
    """Derive bounded JSON, Mermaid and playground maps from a redacted report.

    Source paths and citation lines identify scan evidence, not clickable URLs.
    No conditional flow is inferred from ordering or graph reachability.
    """
    graph = report.get("package_analysis", {}).get("relationship_graph") or {}
    documented = report.get("documented_process") or {}
    files = {f["path"]: f for f in _items(report.get("files"))
             if isinstance(f, dict) and isinstance(f.get("path"), str)}
    entries = {_path(p) for p in _items(graph.get("entrypoints")) if isinstance(p, str)}
    nodes, edges, lookup, omitted_nodes = [], [], {}, set()
    omitted_edges = 0
    limits = [{"kind": _text(item.get("kind")), **({"path": _text(item["path"])} if item.get("path") else {})}
              for item in _items(graph.get("limits")) if isinstance(item, dict)]
    limits.extend(item.copy() for item in _items(documented.get("limits")) if isinstance(item, dict))
    if not graph:
        limits.append({"kind": "relationship_analysis_unavailable"})
    if any(isinstance(value, list) and len(value) > MAX_INPUT_ITEMS for value in graph.values()):
        limits.append({"kind": "diagram_input_items"})

    def node(key, kind, label, path=None, citation=None, **details):
        if key in lookup:
            current = lookup[key]
            if citation and citation not in current["citations"]:
                current["citations"].append(citation)
            return current["id"]
        if len(nodes) >= MAX_NODES:
            omitted_nodes.add(key)
            return None
        record = files.get(path, {})
        item = {"id": "n" + str(len(nodes)), "kind": kind, "label": _text(label, 160),
                "path": path, "citations": [citation] if citation else [],
                "finding_ids": list(dict.fromkeys(_text(f.get("id"), 100) for f in _items(record.get("findings"))
                                                   if isinstance(f, dict) and f.get("id"))),
                "entrypoint": path in entries if kind == "file" else False,
                "knowledge_status": "unknown" if kind == "unresolved" else "known",
                "knowledge_scope": "source_evidence_only",
                "execution_verified": False, **details}
        if kind == "step":
            item["source_file_finding_ids"] = item["finding_ids"]
            item["finding_ids"] = []
        nodes.append(item)
        lookup[key] = item
        return item["id"]

    def file_node(path):
        path = _path(path)
        if not path:
            return None
        return node(("file", path), "file", path, path, _citation(path),
                    assessment_state=files.get(path, {}).get("assessment_state", "unknown"))

    edge_lookup = {}

    def edge(source, target, label, kind, status, citation):
        nonlocal omitted_edges
        if source is not None and source == target:
            return  # a file referring to itself adds no relationship
        key = (source, target, label, kind, status)
        if source is not None and target is not None and key in edge_lookup:
            current = edge_lookup[key]
            if citation and citation not in current["citations"]:
                current["citations"].append(citation)
            return
        if source is None or target is None or len(edges) >= MAX_EDGES:
            omitted_edges += 1
            return
        edge_lookup[key] = None  # replaced below
        edges.append({"id": "e" + str(len(edges)), "source": source, "target": target,
                      "label": label, "kind": kind, "status": status,
                      "knowledge_status": "known" if status == "resolved" else "unknown",
                      "knowledge_scope": "source_evidence_only",
                      "verification": "static_evidence_only" if status == "resolved" else UNKNOWN,
                      "citations": [citation], "execution_verified": False})
        edge_lookup[key] = edges[-1]

    for path in sorted(entries):
        file_node(path)
    step_ids = {}
    for record in _items(documented.get("steps")):
        if not isinstance(record, dict):
            continue
        path, text = _path(record.get("path")), _text(record.get("text"), 500)
        if not path or not text:
            continue
        citation = _citation(path, record)
        source_id = file_node(path)
        step_id = node(("step", record.get("id")), "step", text, path, citation,
                       text=text, step_type=_text(record.get("step_type"), 100),
                       verification="documented_not_executed")
        step_ids[record.get("id")] = step_id
        edge(source_id, step_id, "documents step", "documented_step", "resolved", citation)
        previous = record.get("previous_step_id")
        if previous in step_ids:
            edge(step_ids[previous], step_id, "documented order; runtime unverified", "documented_order", "resolved", citation)
    for record in _items(graph.get("edges")):
        if not isinstance(record, dict):
            continue
        source, target = _path(record.get("source")), _path(record.get("target"))
        if not source or not target:
            continue
        kind, status = _text(record.get("kind"), 100), _text(record.get("status"), 100)
        citation = _citation(source, record)
        source_id = file_node(source)
        variants = [_path(c.get("path")) for c in _items(record.get("variant_candidates")) if isinstance(c, dict)]
        label = RELATIONS.get(kind, "declares reference")
        if status == "resolved":
            target_id = file_node(target)
        elif status in VARIANT_LABELS and len(variants) == 1 and variants[0]:
            target_id, label = file_node(variants[0]), VARIANT_LABELS[status]
        else:
            target_id = node(("unresolved", target, status), "unresolved", target, None, citation,
                             status=status or "unknown", verification=UNKNOWN)
        edge(source_id, target_id, label, kind, status or "unknown", citation)
    for record in _items(graph.get("capability_observations")):
        if not isinstance(record, dict):
            continue
        path, capability = _path(record.get("source")), _text(record.get("capability"), 100)
        if not path or not capability:
            continue
        citation = _citation(path, record)
        source_id = file_node(path)
        target_id = node(("capability", path, capability), "capability",
                         capability.replace("_", " "), None, citation,
                         capability=capability, verification="recognized_source_syntax")
        edge(source_id, target_id, "contains capability syntax", "capability", "resolved", citation)
    for record in _items(graph.get("external_references")):
        if not isinstance(record, dict):
            continue
        path, origin = _path(record.get("source")), _origin(record.get("url"))
        if not path or not origin:
            continue
        citation = _citation(path, record)
        source_id = file_node(path)
        target_id = node(("external", origin), "external", origin, None, citation,
                         verification="not_contacted")
        label = "names network destination" if record.get("kind") == "network_call_destination" else "mentions external origin"
        edge(source_id, target_id, label, "external_reference", "resolved", citation)
    for path in files:
        file_node(path)
    if omitted_nodes:
        limits.append({"kind": "diagram_node_count"})
    if omitted_edges:
        limits.append({"kind": "diagram_edge_count"})
    unresolved = sum(n["kind"] == "unresolved" for n in nodes)
    status = "partial" if limits or graph.get("status") == "partial" or unresolved else "static_relationships"
    result = {"schema_version": 1, "status": status, "scope": SCOPE,
              "runtime_verified": False, "nodes": nodes, "edges": edges, "limits": limits,
              "omitted": {"nodes": len(omitted_nodes), "edges": omitted_edges},
              "unresolved_nodes": unresolved,
              "unsupported_analysis": ["execution_order", "conditional_control_flow", "runtime_tool_calls", "approval_enforcement"],
              "artifact_sha256": report.get("governance_evidence", {}).get("artifact_sha256")}
    result["documented_step_status"] = documented.get("status", "unknown")
    result["process_understanding"] = ("Explicit documented steps extracted; completeness unverified."
                                       if step_ids else UNKNOWN + ": No explicit documented steps recognized; showing static relationships only.")
    # Counts describe the bounded visible graph, never complete package coverage.
    result["source_evidence_summary"] = {
        label: sum(n["kind"] == kind for n in nodes)
        for label, kind in (("present_files", "file"), ("documented_steps", "step"),
                            ("recognized_capabilities", "capability"),
                            ("external_origins", "external"),
                            ("unresolved_references", "unresolved"))
    }
    result["uncertainty_reasons"] = [
        {"code": "runtime_unverified", "message": "Source evidence is available; execution, conditions, approvals and outputs were not tested."},
        {"code": "trust_unassessed", "message": "Playground trust and sensitivity are unassessed; this does not mean the source relationship is missing."},
    ]
    if unresolved:
        result["uncertainty_reasons"].append({
            "code": "unresolved_references", "count": unresolved,
            "message": "Referenced targets could not be resolved. Select each target for its recorded reason."})
    if not step_ids:
        result["uncertainty_reasons"].append({
            "code": "documented_steps_unrecognized",
            "message": "No explicit documented steps were recognized; references do not establish a workflow."})
    if limits:
        result["uncertainty_reasons"].append({
            "code": "analysis_limits", "count": len(limits),
            "message": "Recorded analysis limits make this view partial; consult limits and omissions for coverage."})
    mermaid = ["flowchart LR", "  %% Static references and capabilities; runtime and execution order unverified."]
    for item in nodes:
        label = item["label"] + (" - " + UNKNOWN if item["kind"] == "unresolved" else "")
        mermaid.append('  ' + item["id"] + '["' + _mermaid_text(label) + '"]')
    for item in edges:
        mermaid.append("  " + item["source"] + ' -->|"' + _mermaid_text(item["label"]) + '"| ' + item["target"])
    result["mermaid"] = "\n".join(mermaid)
    # Interoperability uses only the existing strict playground schema. Separate
    # citations above remain authoritative; controls carry the static-view caveat.
    result["architecture_map"], result["map_omitted"] = _playground_map(
        graph, documented, files, entries, lookup, edges)
    return result


MAP_ROWS, MAP_COLUMN_WIDTH, MAP_ROW_HEIGHT = 15, 250, 112
# The playground schema's limits (architecture_map.py); the sandbox image does
# not ship that module, and tests assert these stay equal.
MAP_MAX_NODES, MAP_MAX_EDGES = 100, 200
MAP_SIDE_SLOTS = 10  # at most this many unresolved names, and capabilities/origins
MAP_KIND = {"file": "artifact", "capability": "capability", "external": "external_reference",
            "unresolved": "unresolved_reference"}


def _plain_label(value, limit=160):
    """Markdown emphasis and code marks are noise in a map label."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", value or "")  # [text](target) -> text
    text = re.sub(r"(\*\*|__|`)", "", text)
    text = re.sub(r"^\s*#+\s*", "", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _playground_map(graph, documented, files, entries, lookup, evidence_edges):
    """A readable, bounded component map for the playground.

    Components are package files, recognized capabilities, named origins and
    unresolved references. Documented steps are listed inside their file rather
    than drawn as boxes. When the package exceeds the playground limits, the
    entry skill, unresolved references and the most-connected components are
    kept and the name says how much is shown. Node and edge IDs reuse the
    evidence view's IDs where the same component or relation exists there, so
    playground citations stay attached.
    """
    max_nodes, max_edges = MAP_MAX_NODES, MAP_MAX_EDGES
    components, relations = {}, {}

    def component(key, kind, path, label, status=None):
        if key not in components:
            components[key] = {"key": key, "kind": kind, "path": path, "label": label,
                               "status": status, "sources": []}
        return key

    def relate(source, target):
        if source != target:
            relations.setdefault((source, target), None)

    for path in files:
        component(("file", path), "file", path, path)
    for path in entries:
        component(("file", path), "file", path, path)
    for record in _items(graph.get("edges")):
        if not isinstance(record, dict):
            continue
        source, target = _path(record.get("source")), _path(record.get("target"))
        if not source or not target:
            continue
        status = _text(record.get("status"), 100) or "unknown"
        variants = [_path(c.get("path")) for c in _items(record.get("variant_candidates")) if isinstance(c, dict)]
        source_key = component(("file", source), "file", source, source)
        if status == "resolved":
            target_key = component(("file", target), "file", target, target)
        elif status in VARIANT_LABELS and len(variants) == 1 and variants[0]:
            target_key = component(("file", variants[0]), "file", variants[0], variants[0])
        else:
            target_key = component(("unresolved", target, status), "unresolved", None, target, status)
            components[target_key]["sources"].append(source)
        relate(source_key, target_key)
    for record in _items(graph.get("capability_observations")):
        if isinstance(record, dict) and _path(record.get("source")) and _text(record.get("capability"), 100):
            name = _text(record.get("capability"), 100)
            key = component(("capability", name), "capability", None, name.replace("_", " "))
            components[key]["sources"].append(_path(record.get("source")))
            relate(component(("file", _path(record["source"])), "file", _path(record["source"]), _path(record["source"])), key)
    for record in _items(graph.get("external_references")):
        if isinstance(record, dict) and _path(record.get("source")) and _origin(record.get("url")):
            origin = _origin(record.get("url"))
            key = component(("external", origin), "external", None, origin)
            components[key]["sources"].append(_path(record.get("source")))
            relate(component(("file", _path(record["source"])), "file", _path(record["source"]), _path(record["source"])), key)

    steps = {}
    for record in _items(documented.get("steps")):
        if isinstance(record, dict) and _path(record.get("path")) and _text(record.get("text")):
            steps.setdefault(_path(record["path"]), []).append(_plain_label(_text(record["text"], 300), 120))

    degree = {key: 0 for key in components}
    for source, target in relations:
        degree[source] += 1
        degree[target] += 1

    def score(item):
        findings = files.get(item["path"], {}).get("findings") if item["path"] else None
        return bool(findings) * 20 + len(steps.get(item["path"], [])) + degree[item["key"]]

    def ranked(kinds):
        return sorted((item for item in components.values() if item["kind"] in kinds),
                      key=lambda item: (-score(item), item["label"]))

    # Package files carry the structure. Unresolved names and capabilities are
    # bounded so passing prose mentions cannot crowd the files out.
    entry_items = [item for item in ranked({"file"}) if item["path"] in entries]
    shown = entry_items[:max_nodes]
    reserved = ranked({"unresolved"})[:MAP_SIDE_SLOTS] + ranked({"capability", "external"})[:MAP_SIDE_SLOTS]
    package_files = [item for item in ranked({"file"}) if item["path"] in files and item not in shown]
    shown += package_files[:max(0, max_nodes - len(shown) - len(reserved))]
    shown += reserved[:max(0, max_nodes - len(shown))]
    shown_keys = {item["key"] for item in shown}

    # Labels relative to the entry skill's folder when every file shares it.
    roots = {posixpath.dirname(path) for path in entries}
    root = next(iter(roots)) if len(roots) == 1 and next(iter(roots)) else ""
    def relative(path):
        return path[len(root) + 1:] if root and path.startswith(root + "/") else path

    def group(item):
        if item["kind"] == "file":
            folder = posixpath.dirname(relative(item["path"]))
            return (0, "") if not folder else (1, folder)
        return {"capability": (2, "Capabilities"), "external": (3, "Named origins"),
                "unresolved": (4, "Unresolved references")}[item["kind"]]

    shown.sort(key=lambda item: (group(item), not (item["path"] in entries), relative(item["label"])))
    evidence_ids = {key: value["id"] for key, value in lookup.items()}
    used_ids, nodes, ids = set(evidence_ids.values()), [], {}
    column, row, previous_group = 0, 0, None
    for index, item in enumerate(shown):
        current = group(item)
        if previous_group is not None and current != previous_group and row:
            # Each folder starts a new column when it fits; otherwise after a gap row.
            remaining = sum(1 for other in shown[index:] if group(other) == current)
            if row + 1 + remaining > MAP_ROWS:
                column, row = column + 1, 0
            else:
                row += 1
        if row >= MAP_ROWS:
            column, row = column + 1, 0
        previous_group = current
        node_id = evidence_ids.get(item["key"])
        if node_id is None:
            node_id = "m" + str(index)
            while node_id in used_ids:
                node_id += "x"
            used_ids.add(node_id)
        ids[item["key"]] = node_id
        is_entry = item["kind"] == "file" and item["path"] in entries
        folder = current[1] or "skill root"
        if item["kind"] == "file":
            evidence = "package file present"
        elif item["kind"] == "unresolved":
            evidence = "target unresolved (" + (item["status"] or "unknown") + ")"
        elif item["kind"] == "capability":
            evidence = "recognized capability syntax"
        else:
            evidence = "origin named in source; not contacted"
        file_steps = steps.get(item["path"], []) if item["path"] else []
        step_text = (" Documented steps (" + str(len(file_steps)) + "; completeness unverified): "
                     + "; ".join(file_steps)) if file_steps else ""
        sources = item["path"] or "; ".join(dict.fromkeys(item["sources"][:3]))
        controls = ("Source evidence: " + evidence + ". Group: " + folder + ". Runtime: unverified. "
                    "Trust and sensitivity: unassessed. Source: " + sources + "." + step_text)
        label = relative(item["label"]) if item["kind"] in {"file", "unresolved"} else item["label"]
        nodes.append({"id": node_id, "kind": "skill" if is_entry else MAP_KIND[item["kind"]],
                      "label": _plain_label(label), "x": min(2750, 40 + column * MAP_COLUMN_WIDTH),
                      "y": min(1700, 30 + row * MAP_ROW_HEIGHT), "trust": "unknown", "sensitivity": "unknown",
                      "controls": controls[:1000]})
        row += 1

    evidence_edge_ids = {}
    for item in evidence_edges:
        evidence_edge_ids.setdefault((item["source"], item["target"]), item["id"])
    entry_keys = {("file", path) for path in entries}
    candidate_pairs = [pair for pair in relations if pair[0] in shown_keys and pair[1] in shown_keys]
    candidate_pairs.sort(key=lambda pair: (not (pair[0] in entry_keys or pair[1] in entry_keys),
                                           -(degree[pair[0]] + degree[pair[1]])))
    map_edges = []
    for index, (source, target) in enumerate(candidate_pairs[:max_edges]):
        pair = (ids[source], ids[target])
        edge_id = evidence_edge_ids.get(pair) or "me" + str(index)
        map_edges.append({"id": edge_id, "source": pair[0], "target": pair[1], "untrusted": False, "write": False})
    omitted = {"components": len(components) - len(shown), "links": len(relations) - len(map_edges)}
    name = "Scanned skill: documented relationships"
    if omitted["components"] or omitted["links"]:
        name += f" (partial: showing {len(shown)} of {len(components)} components, {len(map_edges)} of {len(relations)} links)"
    return {"schema_version": 1, "name": name[:160], "nodes": nodes, "edges": map_edges}, omitted
