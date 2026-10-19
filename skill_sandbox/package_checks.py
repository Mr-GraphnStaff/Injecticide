"""Source-linked outcomes for the reviewed package scan check set."""
import json
from pathlib import Path


def check_results(result):
    registry = json.loads((Path(__file__).parent / "rules" / "package_checks.json").read_text())
    evidence = result["governance_evidence"]
    controls = {item["control"]: item["status"] for item in evidence["controls"]}
    format_ids = {item["id"] for item in result["package_analysis"]["format_findings"]}
    findings = {item["id"] for entry in result["files"] for item in entry["findings"]}
    issue_map = {
        "FMT-02": {"skill_frontmatter"}, "FMT-03": {"manifest_schema", "unsupported_schema"},
        "FMT-04": {"allowed_tools_type"}, "FMT-05": {"multiple_manifest_profiles"},
        "COMP-02": {"component_path"}, "PERM-01": {"broad_tool_preapproval"},
        "PERM-02": {"literal_credential_declaration", "insecure_component_transport"},
        "CONT-01": {"code_in_text_artifact", "executable_packaged_as_document"}, "CONT-02": {"declared_execution_target"},
    }
    rows = []
    for check in registry["checks"]:
        identifier = check["id"]
        status = "review_needed" if issue_map.get(identifier, set()) & (format_ids | findings) else "completed_static_analysis"
        scope = "Deterministic supported-format inspection; absence of findings is not a safety certification"
        if identifier.startswith("COV-"):
            status = "partial" if result["coverage"]["status"] == "partial" else "complete_supported_content"
        elif identifier == "GOV-01":
            status, scope = "advisory_metadata_inventory", "Optional owner/version/evaluation metadata is a claim, not a required base-spec field"
        elif identifier == "GOV-03":
            status = evidence["signature_verification"]["status"]
        elif identifier == "GOV-04":
            status = controls["independent_review"]
        elif identifier == "GOV-05":
            status = controls["tenant_access"]
        elif identifier == "EVAL-01":
            status, scope = evidence["evaluation"]["status"], "Requires explicit isolated runner and authenticated scenario evidence; static uploads never run code"
        elif identifier == "UPD-01":
            status, scope = "controlled_release", "Source validation CLI, pinned local schemas, regression corpus and human release acceptance"
        rows.append({"id": identifier, "title": check["title"], "source_ids": check["source_ids"], "status": status, "scope": scope})
    return rows
