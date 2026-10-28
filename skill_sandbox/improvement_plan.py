"""Bounded review plan derived from an already sanitized static scan report.

No source samples, generated patches, runtime calls or compliance certification.
Priority is a work queue based on existing report dispositions, not a risk score.
"""
from __future__ import annotations

import hashlib
import json
from itertools import islice

MAX_ITEMS = 200
MAX_INPUT_ROWS = 10000

FORMAT_ACTIONS = {
    "skill_entrypoint": "Provide the required SKILL.md entrypoint with the exact filename in the intended skill directory.",
    "yaml_frontmatter": "Repair the YAML frontmatter mapping and its opening and closing delimiters.",
    "name_required": "Provide a nonempty string name in the frontmatter.",
    "name_length": "Adjust the name to the specification's supported length.",
    "name_characters": "Use the portable name character set documented by the cited specification.",
    "name_hyphens": "Correct leading, trailing or consecutive hyphens in the name.",
    "name_directory_match": "Align the declared name with the known containing skill directory.",
    "description_required": "Provide a nonempty description that explains the skill and its intended trigger.",
    "description_length": "Adjust the description to the specification's supported length.",
    "compatibility_value": "Correct the compatibility field representation and documented length constraints.",
    "metadata_value": "Represent metadata as a mapping with string keys and string values.",
    "frontmatter_fields": "Move additional skill properties such as version under metadata as string values. Use the selected vendor profile to assess vendor-specific extensions separately.",
    "allowed_tools_value": "Correct allowed-tools to the representation required by the cited portable specification.",
}
SECURITY_ACTIONS = {
    "credential_source_to_network_payload": "Trace the cited credential source and network payload, confirm the destination and authorization, and restrict the transfer to necessary data. Preserve legitimate controls.",
    "dynamic_exec": "Inspect whether the cited expression is executable use or a prose mention. For executable use, review input provenance and whether a constrained alternative preserves the intended behavior.",
    "executable_packaged_as_document": "Review the embedded executable content, its declared purpose and actual upload policy. Keep necessary code clearly declared; establish any applicable restriction before claiming a bypass.",
    "self_modifying_skill": "Review the declared self-modification scope, approval boundary and recovery process before permitting changes.",
    "unverifiable_chunk_marker": "Provide verifiable read-integrity evidence for the declared chunked-reference convention, or clarify the declaration's limits.",
}
RECOMMENDATION_ACTIONS = {
    "body_line_guidance": "Consider moving optional detail into referenced files while retaining essential instructions, approvals and safety controls in SKILL.md. The line guidance is advisory.",
    "body_token_guidance": "Measure the intended loading stages with the selected model's tokenizer before optimizing. Keep essential instructions and controls; a character proxy cannot certify a token limit.",
}
MANUAL_ACTIONS = {
    "description_trigger_quality": "Review whether the description explains when this skill should and should not activate, then evaluate labeled representative requests.",
    "trigger_accuracy": "Run a labeled evaluation of intended triggers and nearby requests that should not trigger the skill; record precision, recall and abstentions.",
    "output_quality": "Evaluate representative tasks against explicit correctness and usefulness criteria with human-reviewed outputs.",
    "script_behavior": "Review script inputs, dependencies and side effects, then test authorized cases in an isolated environment with synthetic data.",
    "runtime_control_enforcement": "Verify the intended permissions and approval boundaries in the selected runtime, including a case that must be denied.",
    "vendor_runtime_compatibility": "Check the selected vendor and installed version's requirements, then validate the skill in that environment.",
    "security_coverage": "Review the scanner's disclosed coverage gaps and the skill's trust boundaries. A clear static scan does not establish safe execution.",
    "evaluation_methodology": "Create realistic test cases and run each with the skill and a no-skill or previous-version baseline in fresh isolated contexts. Grade actual outputs with evidence-backed assertions; record repeated-run timing and token data, critique weak assertions, and obtain human review.",
    "trigger_evaluation_methodology": "Create labeled positive and near-miss prompts, keep a fixed train/validation split, observe repeated real skill activations, and verify the chosen description against fresh prompts.",
    "client_lifecycle": "Verify discovery, precedence, trust checks, activation, on-demand loading and context preservation in the intended client; package text cannot establish those behaviors.",
}
PRIORITY_ORDER = {"required": 0, "high": 1, "normal": 2, "manual": 3}


def _line(value, accuracy=None):
    return value if type(value) is int and value > 0 and accuracy != "file_only" else None


def _sources(row, path, line):
    sources = [{"path": path, "line": line}] if path else []
    for source in (row.get("sources") or [])[:10]:
        if isinstance(source, dict) and isinstance(source.get("url"), str):
            # Only provenance fields; never carry samples or arbitrary source text.
            sources.append({key: source[key] for key in ("url", "section", "revision", "source_sha256") if isinstance(source.get(key), str)})
    return sources


def build_improvement_plan(sanitized_result):
    """Build a reviewable work queue. The caller must redact the report first."""
    candidates, limits, rows_seen = {}, [], 0
    artifact_paths = {entry.get("path") for entry in islice(sanitized_result.get("files", []), MAX_INPUT_ROWS)
                      if isinstance(entry.get("path"), str)}

    def add(rule, category, status, priority, basis, path, line, reason, action, validation, sources):
        key = (rule, path, line)
        row = {"id": "plan_" + hashlib.sha256(json.dumps(key, ensure_ascii=True).encode()).hexdigest()[:16],
               "rule_id": rule, "priority": priority, "priority_basis": basis, "category": category,
               "status": status, "path": path, "line": line, "reason": reason,
               "action": action, "validation": validation, "sources": sources}
        old = candidates.get(key)
        if old is None or PRIORITY_ORDER[priority] < PRIORITY_ORDER[old["priority"]]:
            candidates[key] = row

    def allowed():
        nonlocal rows_seen
        rows_seen += 1
        return rows_seen <= MAX_INPUT_ROWS

    standards = sanitized_result.get("standards_assessment") or {}
    for row in standards.get("requirements", []):
        if not allowed():
            break
        rule, status = row.get("id"), row.get("status")
        if not isinstance(rule, str) or status not in {"fail", "not_assessed"}:
            continue
        path = row.get("path") if isinstance(row.get("path"), str) else None
        line = _line(row.get("line"), row.get("line_accuracy"))
        mandatory = row.get("category") == "format" and row.get("requirement_level") == "mandatory"
        recommendation = row.get("requirement_level") == "recommendation"
        if status == "fail" and mandatory:
            category, state, priority = "mandatory_format", "confirmed_failure", "required"
            reason, basis = "A listed mandatory portable format check failed.", "mandatory format check: fail"
            action = FORMAT_ACTIONS.get(rule, "Review the cited failed requirement and correct the measured constraint according to its cited specification.")
        elif status == "fail" and recommendation:
            category, state, priority = "recommendation", "recommended", "normal"
            reason, basis = "An advisory authoring check needs attention; this is not a mandatory format failure.", "authoring recommendation: fail"
            action = RECOMMENDATION_ACTIONS.get(rule, "Review the cited authoring recommendation and adapt it to the intended workflow without weakening necessary controls.")
        else:
            category, state, priority = "manual_assessment", "not_assessed", "manual"
            reason, basis = "The report does not establish this requirement or behavior.", "assessment status: not_assessed" if status == "not_assessed" else "nonmandatory check: fail"
            action = MANUAL_ACTIONS.get(rule, RECOMMENDATION_ACTIONS.get(rule, "Obtain the missing evidence for the cited requirement; record unknowns until it can be assessed."))
        add(rule, category, state, priority, basis, path, line, reason, action,
            "Re-scan the revised artifact and review the cited check; use separate authorized runtime evidence for behavioral claims.", _sources(row, path, line))

    for entry in sanitized_result.get("files", []):
        if rows_seen > MAX_INPUT_ROWS:
            break
        if not allowed():
            break
        for finding in entry.get("findings", []):
            if not allowed():
                break
            rule, tier = finding.get("id"), finding.get("tier")
            if not isinstance(rule, str) or tier not in {"block", "review"} or finding.get("is_actionable") is False:
                continue
            path = entry.get("path") if isinstance(entry.get("path"), str) else None
            severity = finding.get("severity") if finding.get("severity") in {"critical", "high", "medium", "low", "info"} else "unspecified"
            priority = "high" if tier == "block" or severity in {"critical", "high"} else "normal"
            action = SECURITY_ACTIONS.get(rule, "Review the cited finding in its source context, determine whether the behavior is intended and authorized, and document the decision before changing it.")
            if rule.startswith(("pii_", "phi_")):
                action = "Review disclosure necessity, audience and retention for the cited personal or sensitive data. Minimize unnecessary identifiers while preserving required contacts and legitimate records."
            observations = finding.get("observations") or [{}]
            for observation in observations:
                if not allowed():
                    break
                line = _line(observation.get("line"), observation.get("line_accuracy"))
                sources = _sources({}, path, line)
                for source in (observation.get("sources") or [])[:10]:
                    if not isinstance(source, dict):
                        continue
                    scope = observation.get("evidence_scope")
                    # Legacy origin.path is an operand (e.g. an environment
                    # key), not an artifact name. Only the package contract
                    # assigns artifact identity to origin.path.
                    source_path = (source.get("path") if scope == "package_interprocedural"
                                   and source.get("path") in artifact_paths else path
                                   if scope == "conservative_intraprocedural_value_flow" else None)
                    if source_path:
                        citation = {"path": source_path, "line": _line(source.get("line"), source.get("line_accuracy"))}
                        if citation not in sources:
                            sources.append(citation)
                add(rule, "security_review", "review_required", priority, f"existing tier: {tier}; severity: {severity}", path, line,
                    "A static finding requires contextual review; it is not proof of malicious behavior.", action,
                    "Review the exact cited evidence, retain a rationale for any accepted behavior, and re-scan after an authorized correction.", sources)

    footprint = sanitized_result.get("token_footprint") or {}
    for skill in footprint.get("skills", []):
        if not allowed():
            break
        if skill.get("guidance"):
            path = skill.get("path") if isinstance(skill.get("path"), str) else None
            add("token_loading_optimization", "recommendation", "recommended", "normal", "existing footprint guidance", path, None,
                "The extracted-text footprint suggests reviewing optional loading stages; runtime usage is not measured.",
                RECOMMENDATION_ACTIONS["body_line_guidance"],
                "Measure the selected tokenizer and representative loading scenarios; compare task quality and retained controls before and after.", _sources({}, path, None))
    if not any(row["rule_id"] == "runtime_control_enforcement" for row in candidates.values()):
        add("runtime_control_enforcement", "manual_assessment", "not_assessed", "manual", "static plan scope", None, None,
            "This static improvement plan does not establish runtime enforcement.", MANUAL_ACTIONS["runtime_control_enforcement"],
            "Record authorized runtime tests and their artifact/version binding separately from static scan results.", [])
    if rows_seen > MAX_INPUT_ROWS:
        limits.append({"kind": "input_row_budget", "maximum_rows": MAX_INPUT_ROWS, "remaining_input": "not_assessed"})
    ordered = sorted(candidates.values(), key=lambda row: (PRIORITY_ORDER[row["priority"]], row["path"] or "", row["line"] or 0, row["rule_id"]))
    omitted = max(0, len(ordered) - MAX_ITEMS)
    if omitted:
        limits.append({"kind": "item_budget", "omitted_items": omitted})
    metadata = sanitized_result.get("scanner_metadata") or {}
    artifact = (sanitized_result.get("package_analysis") or {}).get("effect_analysis") or {}
    evidence = sanitized_result.get("governance_evidence") or {}
    return {"schema_version": 1, "artifact_sha256": artifact.get("artifact_sha256") or evidence.get("artifact_sha256"),
            "scanner_version": metadata.get("scanner_version"), "items": ordered[:MAX_ITEMS], "limits": limits,
            "scope": "Deterministic review guidance from sanitized static evidence; no files changed, execution performed, automatic approval, security guarantee or compliance certification.",
            "priority_policy": "Required: confirmed mandatory format failure. High: existing block tier or high/critical severity. Normal: other review findings and advisory guidance. Manual: missing evidence. This orders work, not quantified risk."}
