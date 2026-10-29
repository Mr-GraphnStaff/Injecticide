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


def extract_documented_steps(text_sources):
    """Extract explicit Markdown steps, preserving source lines and uncertainty.

    This recognizes syntax rather than interpreting prose. Approval/condition
    words are mentions, not verified controls or inferred branches. Only adjacent
    numbered entries (allowing blank lines) establish documented ordering.
    """
    steps, limits = [], []
    remaining = MAX_STEP_SOURCE_CHARACTERS
    for source in text_sources:
        path, original = source.get("path"), source.get("text")
        if not isinstance(path, str) or not isinstance(original, str) or posixpath.basename(path).lower() != "skill.md":
            continue
        bounded = original[:remaining]
        remaining -= len(bounded)
        if len(bounded) < len(original):
            limits.append({"kind": "documented_step_source_characters", "path": path})
        previous, previous_number, fence = None, None, None
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
                elif marker[0] == fence[0] and len(marker) >= fence[1]:
                    fence = None
                previous, previous_number = None, None
                continue
            if fence is not None:
                continue
            if "<!--" in raw:
                # Hidden author notes are not visible documented process steps.
                comment = "-->" not in raw
                previous, previous_number = None, None
                continue
            numbered = re.match(r"^\s{0,3}(\d{1,3})[.)]\s+(.+)$", raw)
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
            text = numbered[2] if numbered else heading[1]
            if len(text) > 500:
                limits.append({"kind": "documented_step_text_characters", "path": path})
            number = int(numbered[1]) if numbered else None
            step_type = "section" if section and not numbered else "approval_mention" if re.search(
                r"\b(?:approval|approve|permission|confirmation|confirm)\b", text, re.I) else "condition_mention" if re.match(
                r"(?:if|when|unless|otherwise)\b", text, re.I) else "instruction"
            predecessor = previous if numbered and previous_number is not None and number == previous_number + 1 else None
            item = {"id": "step_" + str(len(steps)), "path": path, "line": line_no,
                    "text": text[:500], "step_type": step_type, "number": number,
                    "previous_step_id": predecessor}
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

    def edge(source, target, label, kind, status, citation):
        nonlocal omitted_edges
        if source is None or target is None or len(edges) >= MAX_EDGES:
            omitted_edges += 1
            return
        edges.append({"id": "e" + str(len(edges)), "source": source, "target": target,
                      "label": label, "kind": kind, "status": status,
                      "knowledge_status": "known" if status == "resolved" else "unknown",
                      "knowledge_scope": "source_evidence_only",
                      "verification": "static_evidence_only" if status == "resolved" else UNKNOWN,
                      "citations": [citation], "execution_verified": False})

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
        target_id = file_node(target) if status == "resolved" else node(
            ("unresolved", target, status), "unresolved", target, None, citation,
            status=status or "unknown", verification=UNKNOWN)
        edge(source_id, target_id, RELATIONS.get(kind, "declares reference"), kind,
             status or "unknown", citation)
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
    result["architecture_map"] = {
        "schema_version": 1, "name": "Scanned skill: documented relationships",
        "nodes": [{"id": n["id"], "kind": "skill" if n["entrypoint"] else {
                       "step": "step", "file": "artifact", "capability": "capability",
                       "external": "external_reference", "unresolved": "unresolved_reference"}[n["kind"]],
                   "label": n["label"], "x": 40 + (i % 6) * 480, "y": 30 + (i // 6) * 110,
                   "trust": "unknown", "sensitivity": "unknown",
                   "controls": ("Source evidence: " + {
                       "file": "package file present", "step": "documented step; completeness unverified",
                       "capability": "recognized capability syntax", "external": "origin named in source; not contacted",
                       "unresolved": "target unresolved (" + n.get("status", "unknown") + ")",
                   }[n["kind"]] + ". Runtime: unverified. Trust and sensitivity: unassessed. " +
                       "Source: " + (n["path"] or "; ".join(c["path"] for c in n["citations"][:3])))[:1000]}
                  for i, n in enumerate(nodes)],
        "edges": [{"id": e["id"], "source": e["source"], "target": e["target"], "untrusted": False, "write": False}
                  for e in edges],
    }
    return result
