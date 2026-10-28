"""Shared package analysis used by the web fallback and isolated sandbox."""
from __future__ import annotations

import hashlib

try:
    from .package_formats import inspect_formats, RUNTIMES
    from .package_threats import inspect_threats, embedded_blocks
    from .package_evidence import evidence_profile, coverage_report, scanner_metadata
    from .governance import build_governance_profile
    from .behavior_analysis import analyze_behavior
    from .package_checks import check_results
    from .official_validators import attach_official_validator_results
    from .inspection_evidence import initial_coverage, creator_mitigation
    from .evidence_redaction import redact_result
    from .package_graph import build_package_graph
    from .code_security import analyze_code_security
    from .process_diagram import build_process_diagram, extract_documented_steps
    from .disposition import format_observation_sample
    from .standards_assessment import build_standards_assessment
    from .token_footprint import build_token_footprint
    from .package_effects import analyze_package_effects
    from .improvement_plan import build_improvement_plan
except ImportError:
    from package_formats import inspect_formats, RUNTIMES
    from package_threats import inspect_threats, embedded_blocks
    from package_evidence import evidence_profile, coverage_report, scanner_metadata
    from governance import build_governance_profile
    from behavior_analysis import analyze_behavior
    from package_checks import check_results
    from official_validators import attach_official_validator_results
    from inspection_evidence import initial_coverage, creator_mitigation
    from evidence_redaction import redact_result
    from package_graph import build_package_graph
    from code_security import analyze_code_security
    from process_diagram import build_process_diagram, extract_documented_steps
    from disposition import format_observation_sample
    from standards_assessment import build_standards_assessment
    from token_footprint import build_token_footprint
    from package_effects import analyze_package_effects
    from improvement_plan import build_improvement_plan


def _reconcile_effect_findings(entry, effects, additions):
    """Refine only exact legacy sites with complete package analysis evidence."""
    if effects["status"] != "complete_supported_syntax":
        entry["findings"].extend(additions)
        return []
    path = entry["path"]
    coverage = effects["coverage"]
    sites = {(site["line"], site["operation"]): site["outcome"]
             for site in coverage["modeled_sink_sites"] if site["path"] == path}
    ranges = [row for row in coverage["pruned_ranges"] if row["path"] == path]
    reconciled, retained = [], []
    for finding in entry["findings"]:
        observations = finding.get("observations", [])
        if finding.get("id") != "credential_source_to_network_payload" or not observations:
            retained.append(finding)
            continue
        decisions = []
        for observation in observations:
            if observation.get("evidence_scope") != "conservative_intraprocedural_value_flow":
                decisions.append(None)
                continue
            line, operation = observation.get("line"), observation.get("operation")
            outcome = sites.get((line, operation))
            if isinstance(line, int) and any(row["start_line"] <= line <= row["end_line"] for row in ranges):
                decisions.append("literal_constant_guard")
            elif outcome == "no_source_flow":
                decisions.append("resolved_local_return_has_no_credential_origin")
            elif outcome == "source_flow" and any(any(o.get("line") == line and o.get("operation") == operation for o in new.get("observations", [])) for new in additions):
                decisions.append("replaced_by_package_witness")
            else:
                decisions.append(None)
        if decisions and all(decisions):
            reconciled.append({"path": path, "rule_id": finding["id"], "source_lines": [o.get("line") for o in observations],
                               "reasons": sorted(set(decisions)), "evidence_scope": "complete_modeled_package_python_sites"})
        else:
            retained.append(finding)
    entry["findings"] = retained + additions
    return reconciled


def enrich_result(result, text_sources, upload_bytes, target_runtime="auto", supplied_evidence=None,
                  extraction_root=None, excluded=(), rescan=None):
    entries = result["files"]
    texts = {source["path"]: source["text"] for source in text_sources}
    records = list(entries) + list(excluded)
    for record in records:
        record.setdefault("analysis_coverage", initial_coverage())
        record.setdefault("creator_mitigation", creator_mitigation(record["path"], None))
        if record.get("skipped"):
            record["analysis_coverage"]["extraction"]["reason"] = record.get("reason", "Not extracted")
    analysis = inspect_formats(entries, texts, target_runtime)
    threats = inspect_threats(entries, texts, analysis)
    effects = analyze_package_effects(text_sources, records)
    effect_findings = effects.pop("findings_by_path")
    effects["artifact_sha256"] = hashlib.sha256(upload_bytes).hexdigest()
    effects["reconciled_legacy_sites"] = []
    for entry in entries:
        path = entry["path"]
        content = entry.get("content_analysis", {})
        if path in threats["invoked_paths"] or content.get("code_like"):
            entry["effective_artifact_role"] = "execution_component"
            entry["required_component"] = True
            if rescan and path in texts:
                supplemental = [f for f in entry["findings"] if f.get("subject") in {"package_component", "creator_reading_convention", "asset_structure"}]
                entry["findings"] = rescan(path, texts[path], "active") + supplemental
                for block in embedded_blocks(texts[path]):
                    extension = {"python": ".py", "javascript": ".js", "typescript": ".ts", "powershell": ".ps1",
                                 "shell": ".sh", "ruby": ".rb", "perl": ".pl", "php": ".php", "lua": ".lua",
                                 "batch": ".cmd", "sql": ".sql"}.get(block["language"], ".source")
                    embedded = rescan(path + extension, block["text"], "active")
                    for item in embedded:
                        item["evidence_scope"] = "embedded_source"
                        item["source_language"] = block["language"]
                        item["source_start_line"] = block["line"]
                        # Rescans use block-relative lines; expose physical lines
                        # in the original document, including exported samples.
                        for observation in item.get("observations", []):
                            if isinstance(observation.get("line"), int):
                                observation["embedded_line"] = observation["line"]
                                observation["line"] += block["line"] - 1
                        if item.get("observations"):
                            item["samples"] = [format_observation_sample(o) for o in item["observations"]]
                    entry["findings"].extend(embedded)
            for source in text_sources:
                if source["path"] == path:
                    source["artifact_role"] = "active"
        if path in texts:
            language = content.get("language")
            code_security = analyze_code_security(path, texts[path], declared_language=language)
            entry["findings"].extend(code_security["findings"])
            python_blocks = [block for block in embedded_blocks(texts[path]) if block["language"] == "python"]
            code_security["coverage"]["embedded_python_blocks"] = []
            for block in python_blocks:
                embedded_security = analyze_code_security(path, block["text"], declared_language="python", line_offset=block["line"] - 1)
                for finding in embedded_security["findings"]:
                    finding["evidence_scope"] = "embedded_python_value_flow"
                    finding["source_start_line"] = block["line"]
                entry["findings"].extend(embedded_security["findings"])
                code_security["coverage"]["embedded_python_blocks"].append(embedded_security["coverage"])
            if any(stage["status"] == "partial" for stage in code_security["coverage"]["embedded_python_blocks"]):
                code_security["coverage"]["status"] = "partial"
            elif python_blocks and code_security["coverage"]["status"] in {"partial", "not_performed"}:
                code_security["coverage"].update(status="complete_supported_embedded_syntax", scope="Only recognized Python code fences supplied to value-flow analysis; surrounding prose is outside this detector.")
            entry["analysis_coverage"]["code_security"] = code_security["coverage"]
        effects["reconciled_legacy_sites"].extend(_reconcile_effect_findings(entry, effects, effect_findings.get(path, [])))
        if len(entry["findings"]) > 80:
            entry.setdefault("analysis_coverage", {})["result_display"] = {
                "status": "partial", "findings_before_limit": len(entry["findings"]),
                "findings_displayed": 80, "reason": "Finding display budget reached; analysis and display coverage are separate."}
            entry.update(assessment_state="limited_or_truncated", reason="Finding display budget reached; remaining findings omitted.")
            entry["findings"] = entry["findings"][:80]
        else:
            entry.setdefault("analysis_coverage", {})["result_display"] = {
                "status": "complete", "findings_before_limit": len(entry["findings"]),
                "findings_displayed": len(entry["findings"]), "reason": "No per-file finding display limit reached."}
    coverage = coverage_report(records)
    coverage["package_effects"] = {"status": effects["status"], "limits": effects["limits"], "scope": effects["coverage"]["scope"]}
    if effects["status"] == "partial":
        coverage["status"] = "partial"
    if threats["inventory_limited"]:
        coverage.update(status="partial", component_inventory_limited=True)
    hash_value = hashlib.sha256(upload_bytes).hexdigest()
    evidence = evidence_profile(records, texts, analysis, hash_value, supplied_evidence, extraction_root)
    analysis.pop("configurations")
    # Raw configurations and parsed frontmatter can contain credentials. Do not return them.
    for skill in analysis["skills"]:
        skill.pop("frontmatter", None)
    result["package_analysis"] = {**analysis, "components": (analysis["components"] + threats["components"])[:500],
                                  "format_findings": (analysis["format_findings"] + threats["format_findings"])[:100],
                                  "dependencies": threats["dependencies"], "execution_references": threats["execution_references"],
                                  "permissions": threats["permissions"], "composition_analysis": threats["composition_analysis"]}
    result["package_analysis"]["effect_analysis"] = effects
    graph = build_package_graph(text_sources, records)
    result["package_analysis"]["relationship_graph"] = graph
    result["token_footprint"] = build_token_footprint(text_sources, records, graph)
    coverage["package_relationships"] = {"status": graph["status"], "limits": graph["limits"]}
    if graph["status"] == "partial":
        coverage["status"] = "partial"
    result.update(coverage=coverage, governance_evidence=evidence, scanner_metadata=scanner_metadata(),
                  inventory=[{key: e.get(key) for key in ("path", "size", "sha256", "assessment_state", "reason", "required_component", "analysis_coverage", "asset_inspection", "archive_inspection", "archive_container", "archive_depth", "creator_mitigation", "large_file_tagged_chunked_reference")} for e in records])
    findings = [f for entry in entries for f in entry["findings"]]
    result["summary"].update(flagged_files=sum(any(f.get("severity") != "info" for f in e["findings"]) for e in entries),
                             total_findings=sum(f.get("severity") != "info" for f in findings),
                             info_findings=sum(f.get("severity") == "info" for f in findings),
                             inventory_files=len(records), analyzed_files=coverage["analyzed_files"],
                             upload_policy_review_files=sum(bool(e.get("file_type_policy", {}).get("potential_upload_control_bypass")) for e in entries),
                             unassessed_files=coverage["unassessed_files"])
    result.update(analyze_behavior(text_sources))
    result["governance_profile"] = build_governance_profile(entries, result)
    result["standards_assessment"] = build_standards_assessment(result, text_sources)
    portable_status = result["standards_assessment"]["overall_status"]
    portable_failed = target_runtime == "generic" and portable_status == "fail"
    portable_unknown = target_runtime == "generic" and portable_status == "not_assessed"
    invalid_format = portable_failed or any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"])
    failed_evidence = any(c["status"] == "authenticated_issuer_fail" for c in evidence["controls"])
    failed_evidence = failed_evidence or evidence["evaluation"]["status"] == "failed_by_authenticated_issuer"
    if coverage["status"] == "partial" or invalid_format or failed_evidence or portable_unknown:
        profile = result["governance_profile"]
        reason = "Authenticated external review or evaluation reports a failure." if failed_evidence else "Portable format checks are incomplete; required constraints remain unassessed." if portable_unknown else "Coverage is partial; unassessed material is not certified safe." if coverage["status"] == "partial" else "Package format errors require review before execution."
        profile["decision_reasons"] = [r for r in profile["decision_reasons"] if "read-only" not in r.lower()] + [reason]
        for mode in ("brokered_tokens", "customer_managed_keys"):
            if profile[mode]["decision"] in {"allow", "allow_with_warnings"}:
                profile[mode] = {"decision": "require_further_analysis", "reason": reason}
        profile["approval_required"] = True
        if profile["execution_tier"] == "read_only":
            profile["execution_tier"] = "unassessed"
        profile["recommended_controls"] = ["Review unassessed content before execution."]
    review = any(f.get("severity") != "info" for f in findings)
    result["readiness"] = {"status": "needs_review" if review or invalid_format or failed_evidence else "incomplete" if coverage["status"] == "partial" or portable_unknown else "no_static_findings",
                           "statement": "Static analysis is not deployment approval or a guarantee of safe execution.",
                           "tenant_policy_verified": False, "runtime_evaluation": evidence["evaluation"]["status"]}
    result["readiness"]["upload_policy_review_required"] = result["summary"]["upload_policy_review_files"] > 0
    result["check_results"] = check_results(result)
    result["vendor_verification"] = {
        "status": "unknown", "verification": "STATUS: UNKNOWN — UNVERIFIED",
        "reason": "Static sandbox scan; live vendor requirements are checked by the web service through Research MCP.",
        "live_check": False, "runtime_tested": False, "requirements": [], "documents": []}
    result["readiness"]["vendor_compatibility"] = "unknown"
    result["readiness"]["format_compatibility"] = ({"pass": "explicit_portable_profile_checked", "fail": "portable_format_failed"}.get(portable_status, "unverified") if target_runtime == "generic" else "unverified")
    attach_official_validator_results(result, texts)
    result["documented_process"] = extract_documented_steps(text_sources)
    redact_result(result, texts)
    result["improvement_plan"] = build_improvement_plan(result)
    # Diagram labels and exports derive only from sanitized report evidence.
    # Uploaded content is never executed or sent to a diagram service.
    result["process_diagram"] = build_process_diagram(result)
    return result
