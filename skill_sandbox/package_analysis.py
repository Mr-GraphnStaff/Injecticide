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
except ImportError:
    from package_formats import inspect_formats, RUNTIMES
    from package_threats import inspect_threats, embedded_blocks
    from package_evidence import evidence_profile, coverage_report, scanner_metadata
    from governance import build_governance_profile
    from behavior_analysis import analyze_behavior
    from package_checks import check_results


def enrich_result(result, text_sources, upload_bytes, target_runtime="auto", supplied_evidence=None,
                  extraction_root=None, excluded=(), rescan=None):
    entries = result["files"]
    texts = {source["path"]: source["text"] for source in text_sources}
    records = list(entries) + list(excluded)
    analysis = inspect_formats(entries, texts, target_runtime)
    threats = inspect_threats(entries, texts, analysis)
    for entry in entries:
        path = entry["path"]
        content = entry.get("content_analysis", {})
        if path in threats["invoked_paths"] or content.get("code_like"):
            entry["effective_artifact_role"] = "execution_component"
            entry["required_component"] = True
            if rescan and path in texts:
                supplemental = [f for f in entry["findings"] if f.get("subject") == "package_component"]
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
                    entry["findings"].extend(embedded)
            for source in text_sources:
                if source["path"] == path:
                    source["artifact_role"] = "active"
        if len(entry["findings"]) > 80:
            entry.update(assessment_state="limited_or_truncated", reason="Finding display budget reached; remaining findings omitted.")
            entry["findings"] = entry["findings"][:80]
    coverage = coverage_report(records)
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
    result.update(coverage=coverage, governance_evidence=evidence, scanner_metadata=scanner_metadata(),
                  inventory=[{key: e.get(key) for key in ("path", "size", "sha256", "assessment_state", "reason", "required_component")} for e in records])
    findings = [f for entry in entries for f in entry["findings"]]
    result["summary"].update(flagged_files=sum(any(f.get("severity") != "info" for f in e["findings"]) for e in entries),
                             total_findings=sum(f.get("severity") != "info" for f in findings),
                             info_findings=sum(f.get("severity") == "info" for f in findings),
                             inventory_files=len(records), analyzed_files=coverage["analyzed_files"],
                             upload_policy_review_files=sum(bool(e.get("file_type_policy", {}).get("potential_upload_control_bypass")) for e in entries),
                             unassessed_files=coverage["unassessed_files"])
    result.update(analyze_behavior(text_sources))
    result["governance_profile"] = build_governance_profile(entries, result)
    invalid_format = any(f["severity"] == "error" for f in result["package_analysis"]["format_findings"])
    failed_evidence = any(c["status"] == "authenticated_issuer_fail" for c in evidence["controls"])
    failed_evidence = failed_evidence or evidence["evaluation"]["status"] == "failed_by_authenticated_issuer"
    if coverage["status"] == "partial" or invalid_format or failed_evidence:
        profile = result["governance_profile"]
        reason = "Authenticated external review or evaluation reports a failure." if failed_evidence else "Coverage is partial; unassessed material is not certified safe." if coverage["status"] == "partial" else "Package format errors require review before execution."
        profile["decision_reasons"] = [r for r in profile["decision_reasons"] if "read-only" not in r.lower()] + [reason]
        for mode in ("brokered_tokens", "customer_managed_keys"):
            if profile[mode]["decision"] in {"allow", "allow_with_warnings"}:
                profile[mode] = {"decision": "require_further_analysis", "reason": reason}
        profile["approval_required"] = True
        if profile["execution_tier"] == "read_only":
            profile["execution_tier"] = "unassessed"
        profile["recommended_controls"] = ["Review unassessed content before execution."]
    review = any(f.get("severity") != "info" for f in findings)
    result["readiness"] = {"status": "needs_review" if review or invalid_format or failed_evidence else "incomplete" if coverage["status"] == "partial" else "no_static_findings",
                           "statement": "Static analysis is not deployment approval or a guarantee of safe execution.",
                           "tenant_policy_verified": False, "runtime_evaluation": evidence["evaluation"]["status"]}
    result["readiness"]["upload_policy_review_required"] = result["summary"]["upload_policy_review_files"] > 0
    result["check_results"] = check_results(result)
    result["vendor_verification"] = {
        "status": "unknown", "verification": "STATUS: UNKNOWN — UNVERIFIED",
        "reason": "Static sandbox scan; live vendor requirements are checked by the web service through Research MCP.",
        "live_check": False, "runtime_tested": False, "requirements": [], "documents": []}
    result["readiness"]["vendor_compatibility"] = "unknown"
    return result
