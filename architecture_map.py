"""Bounded, deterministic test planning for user-declared AI system maps.

No endpoints are contacted and no declared control is treated as verified.
"""

from collections import deque
import hashlib
import json

from jsonschema import Draft202012Validator

KINDS = {
    "user": "Person / user", "llm_client": "LLM client / app",
    "edge": "Edge / WAF", "gateway": "AI gateway",
    "model": "Model", "agent": "Agent / orchestrator", "mcp": "MCP server",
    "tool": "Tool / API", "skill": "Skill / plugin", "retrieval": "Retrieval / RAG",
    "memory": "Memory / vector store", "code": "Code runner", "data": "Data store",
    "approval": "Human approval", "security": "Security control", "output": "Output / destination",
    "step": "Documented step", "artifact": "Package file",
    "capability": "Recognized capability", "external_reference": "External reference",
    "unresolved_reference": "Unresolved reference",
}
TEXT = {"type": "string", "maxLength": 160}
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "name", "nodes", "edges"],
    "properties": {
        "schema_version": {"const": 1}, "name": TEXT,
        "nodes": {"type": "array", "maxItems": 100, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["id", "kind", "label", "x", "y", "trust", "sensitivity", "controls"],
            "properties": {
                "id": {"type": "string", "pattern": "^[a-zA-Z0-9_-]{1,64}$"},
                "kind": {"enum": list(KINDS)}, "label": TEXT,
                "x": {"type": "number", "minimum": 0, "maximum": 3000},
                "y": {"type": "number", "minimum": 0, "maximum": 1800},
                "trust": {"enum": ["external", "internal", "privileged", "unknown"]},
                "sensitivity": {"enum": ["public", "internal", "sensitive", "unknown"]},
                "controls": {"type": "string", "maxLength": 1000},
            }}},
        "edges": {"type": "array", "maxItems": 200, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["id", "source", "target", "untrusted", "write"],
            "properties": {
                "id": {"type": "string", "pattern": "^[a-zA-Z0-9_-]{1,64}$"},
                "source": TEXT, "target": TEXT,
                "untrusted": {"type": "boolean"}, "write": {"type": "boolean"},
            }}},
    },
}
VALIDATOR = Draft202012Validator(SCHEMA)
LLM = "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"
AGENTIC = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
SKILLS = "https://owasp.org/projects/agentic-skills-top-10"


def validate_map(document):
    # Stop at the first error: malformed arrays must not allocate an error per item.
    error = next(VALIDATOR.iter_errors(document), None)
    if error is not None:
        raise ValueError(f"Invalid map at {'.'.join(map(str, error.path))}: {error.message[:200]}")
    nodes = {node["id"]: node for node in document["nodes"]}
    if len(nodes) != len(document["nodes"]):
        raise ValueError("Duplicate component identifiers")
    if len({edge["id"] for edge in document["edges"]}) != len(document["edges"]):
        raise ValueError("Duplicate connection identifiers")
    if any(e["source"] not in nodes or e["target"] not in nodes for e in document["edges"]):
        raise ValueError("Every connection must reference existing components")
    return nodes


def plan_map(document):
    """Suggest tests from exact declared graph signals, never vulnerability verdicts."""
    nodes = validate_map(document)
    adjacency = {key: [] for key in nodes}
    for edge in document["edges"]:
        adjacency[edge["source"]].append(edge)
    tests = []
    omitted = 0

    def add(key, title, reason, path, edge_ids, expectation, reference, engine):
        nonlocal omitted
        if len(tests) >= 500:
            omitted += 1
            return
        tests.append(dict(id=key, title=title, reason=reason, node_ids=path,
                          edge_ids=edge_ids, expected_evidence=expectation,
                          reference=reference, suggested_engine=engine, status="not_run"))

    # One shortest declared path per source/destination; cycles cannot expand forever.
    for start in document["nodes"]:
        if start["trust"] != "external" and start["kind"] != "retrieval":
            continue
        queue = deque([(start["id"], [start["id"]], [])])
        seen = {start["id"]}
        while queue:
            current, path, edge_ids = queue.popleft()
            if len(path) > 1 and nodes[current]["kind"] in {"code", "tool", "mcp", "memory"}:
                add(f"path-{start['id']}-{current}", "Untrusted content reaching an action boundary",
                    "An external or retrieval component has a directed path to an action or memory component.",
                    path, edge_ids, "Controlled input, tool/action trace, approval decision and observed side effects; use an authorized test environment.",
                    AGENTIC, "Manual scenario / configured endpoint harness")
            for edge in adjacency[current]:
                if edge["target"] not in seen:
                    seen.add(edge["target"])
                    queue.append((edge["target"], path + [edge["target"]], edge_ids + [edge["id"]]))
    for node in document["nodes"]:
        key, kind = node["id"], node["kind"]
        if kind in {"edge", "gateway", "security", "approval"}:
            add(f"control-{key}", "Verify control enforcement and routing",
                "This component is declared as a control; the map cannot establish enforcement or coverage.",
                [key], [], "Request identifiers, effective policy, observed allow/block decision and proof traffic traversed this control.",
                LLM, "Vendor telemetry / controlled request replay")
        if kind == "skill":
            add(f"package-{key}", "Inspect the skill or plugin package",
                "This component introduces packaged instructions or executable capabilities.", [key], [],
                "Package hash, scanner version, findings and coverage limits.", SKILLS, "Injecticide package scanner")
        if kind in {"model", "agent"}:
            add(f"prompt-{key}", "Test instruction boundaries",
                "A model or agent component consumes prompts and produces instructions or responses.", [key], [],
                "Versioned prompts, model/configuration, responses and deterministic detector results.", LLM,
                "Injecticide endpoint testing")
    for edge in document["edges"]:
        if edge["write"] or edge["untrusted"]:
            add(f"edge-{edge['id']}", "Verify connection data and permissions",
                "The connection is explicitly marked as carrying untrusted content or allowing writes.",
                [edge["source"], edge["target"]], [edge["id"]],
                "Input provenance, effective permissions, authorization decision and downstream action trace.",
                AGENTIC, "Manual scenario / configured endpoint harness")
    return {
        "map_hash": hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
        "planner_version": "1", "status": "modeled_only", "tests": tests,
        "omitted_tests": omitted,
        "summary": {"components": len(nodes), "connections": len(document["edges"]), "suggested_tests": len(tests)},
        "limitations": "User-declared topology; one shortest path per external/retrieval source and action destination. Controls are unverified. No live tests, discovery or vendor integrations have run.",
    }
