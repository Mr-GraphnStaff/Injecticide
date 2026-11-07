"""What to fix: findings grouped by cause (``injecticide-fix-summary/v1``).

Built from the finished, redacted result. It copies no samples or source text:
only paths, finding ids, counts and fixed plain-language actions. Grouping is a
fixed id -> cause table, so the same result always gives the same summary.
"""
from __future__ import annotations

import re

SCHEMA = "injecticide-fix-summary/v1"
MAX_FILES_PER_ITEM = 200
PRIORITY_ORDER = {"block": 0, "review": 1, "info": 2}

DISGUISED_SCRIPT_IDS = {"executable_packaged_as_document", "declared_execution_target", "code_in_text_artifact"}

# (cause id, title, plain-language action, finding ids). Order is display order
# within a priority band.
CAUSES = (
    ("disguised_script", "Scripts packaged as documents",
     "Give each script its real file extension (for example .py), keep it in a scripts folder and say in SKILL.md "
     "what runs it and why. Remove the script if the skill does not need it.", DISGUISED_SCRIPT_IDS),
    ("embedded_executable", "Executable content hidden inside data",
     "Remove executable or archive content stored inside databases or data files. Ship any needed program as a "
     "visible, reviewed file.", {"embedded_executable_blob"}),
    ("hardcoded_secrets", "Secrets written into files",
     "Remove the secret from the package, revoke or rotate it, and load credentials at run time from an approved "
     "secret store or environment variable.", {"hardcoded_secret", "literal_credential_declaration"}),
    ("prompt_injection", "Instructions that try to override the model or extract hidden data",
     "Delete or rewrite text that tells the model to ignore its instructions, reveal its system prompt or disclose "
     "secrets. If the text is a deliberate example, mark it clearly as an example.",
     {"prompt_override", "system_exfiltration", "secret_exfiltration", "tool_escape", "unicode_deception"}),
    ("personal_data", "Personal or contact data",
     "Remove personal data the skill does not need, or replace it with synthetic values. Record who approved any "
     "personal data that must stay.",
     {"pii_email_address", "pii_phone_number", "pii_ssn", "pii_date_of_birth", "pii_account_identifier",
      "phi_medical_record_number", "phi_patient_record", "contact_directory"}),
    ("credential_flow", "Credentials sent to the network",
     "Check where each credential is sent. Send only what the destination needs, to an approved destination.",
     {"credential_source_to_network_payload", "sensitive_keywords"}),
    ("enterprise_writes", "Automatic changes to business systems",
     "Add a human approval step before the skill writes to, bulk-changes or chains business systems, and limit it "
     "to the records it needs.",
     {"autonomous_authoritative_write", "bulk_enterprise_modification", "workflow_manipulation", "cross_system_automation"}),
    ("execution", "Running code, installing packages or changing files",
     "Confirm each command, install and file change is needed. Pin dependencies, avoid dynamic code execution and "
     "run the skill in a sandbox with only the permissions it needs.",
     {"dynamic_exec", "subprocess_spawn", "declared_process_launch", "declared_tool_execution", "broad_tool_preapproval",
      "runtime_dependency_install", "dynamic_import_construction", "self_modifying_skill", "filesystem_access",
      "dangerous_file_ops", "home_write", "embedded_browser_script", "shell_command_in_executable_field"}),
    ("network", "Network access and external connectors",
     "List the external services the skill contacts, use HTTPS and only approved, verified servers.",
     {"network_calls", "url_fetch", "insecure_mcp_transport", "unverified_mcp_server", "insecure_component_transport",
      "invalid_endpoint_url"}),
    ("hidden_content", "Encoded or hidden content",
     "Replace encoded or hidden text with plain readable text so reviewers can see what it does.",
     {"base64_usage"}),
    ("database_coverage", "Database content that could not be fully checked",
     "Reduce the database to the rows the skill needs, or provide an unencrypted copy, so all of it can be checked.",
     {"database_not_cleared", "opaque_database"}),
    ("damaged_files", "Damaged or mislabelled files",
     "Replace files whose contents do not match their type, or that are damaged, with clean copies.", set()),
    ("reading_convention", "Unverifiable reading markers",
     "Fix or remove chunked-reading markers that cannot be verified.", {"unverifiable_chunk_marker"}),
)
CAUSE_BY_ID = {finding_id: cause[0] for cause in CAUSES for finding_id in cause[3]}
CAUSE_INFO = {cause[0]: cause for cause in CAUSES}
CAUSE_RANK = {cause[0]: index for index, cause in enumerate(CAUSES)}

FORMAT_TITLE = "Skill format and standards failures"
REFERENCE_STATUSES = {"missing", "case_mismatch", "ambiguous_case_reference", "outside_package",
                      "dynamic_reference_unresolved", "malformed_reference", "document_suffix_variant",
                      "name_only_match", "ambiguous_name_match"}


def _actionable(finding):
    tier = finding.get("tier")
    if tier in {"review", "block"}:
        return True
    if tier == "info":
        return False
    return finding.get("severity") not in {None, "info"}


def _cause_for(finding):
    finding_id = finding.get("id")
    if finding_id in CAUSE_BY_ID:
        return CAUSE_BY_ID[finding_id]
    if finding.get("category") == "asset_structure" or finding.get("finding_category") == "format_integrity":
        return "damaged_files"
    if finding.get("category") == "prompt":
        return "prompt_injection"
    return "other:" + str(finding_id)


def _item(cause, title, priority, action, rows):
    files = sorted({path for path, _, _ in rows if isinstance(path, str)})
    finding_ids = sorted({finding_id for _, finding_id, _ in rows if isinstance(finding_id, str)})
    item = {"id": "fix_" + re.sub(r"[^a-z0-9_]+", "_", cause.lower()).strip("_"), "title": title, "priority": priority,
            "cause": cause, "action": action, "files": files[:MAX_FILES_PER_ITEM], "finding_ids": finding_ids,
            "count": len(rows)}
    if len(files) > MAX_FILES_PER_ITEM:
        item["files_omitted"] = len(files) - MAX_FILES_PER_ITEM
    allowed = [finding for _, _, finding in rows if isinstance(finding, dict)
               and finding.get("policy_disposition") == "allowed_by_policy"]
    if allowed:
        rules = sorted({str(finding.get("policy_rule")) for finding in allowed if finding.get("policy_rule")})
        item["allowed_by_policy"] = len(allowed)
        item["policy_rules"] = rules
        item["policy_note"] = (f"{len(allowed)} of {len(rows)} findings allowed by organisation policy rule"
                               f"{'s' if len(rules) != 1 else ''} {', '.join(rules)}. The scanner's own result is unchanged.")
    return item


def _format_item(result):
    standards = result.get("standards_assessment") or {}
    rows, fields, requirements = [], [], []
    for row in standards.get("requirements") or []:
        if not isinstance(row, dict) or row.get("status") != "fail" or row.get("requirement_level") != "mandatory":
            continue
        requirements.append(str(row.get("id")))
        rows.append((row.get("path"), row.get("id"), None))
        found = re.search(r"Found: ([^\n]{1,800}?)\.$", row.get("message") or "") if row.get("id") == "frontmatter_fields" else None
        if found:
            fields.extend(name.strip() for name in found.group(1).split(",") if name.strip())
    for issue in (result.get("package_analysis") or {}).get("format_findings") or []:
        if isinstance(issue, dict) and issue.get("severity") == "error":
            requirements.append(str(issue.get("id")))
            rows.append((issue.get("path"), issue.get("id"), None))
    if not rows:
        return None
    named = sorted(set(requirements))
    action = "Fix the failed format checks: " + ", ".join(named) + "."
    if fields:
        action += " Move these top-level frontmatter fields under metadata as string values: " + ", ".join(sorted(set(fields))) + "."
    item = _item("format_failures", FORMAT_TITLE, "review", action, rows)
    item["failed_checks"] = named
    if fields:
        item["fields"] = sorted(set(fields))
    return item


def _reference_item(result):
    graph = ((result.get("package_analysis") or {}).get("relationship_graph") or {})
    rows, statuses = [], set()
    for edge in graph.get("edges") or []:
        if isinstance(edge, dict) and edge.get("status") in REFERENCE_STATUSES:
            statuses.add(edge["status"])
            rows.append((edge.get("source"), None, None))
    if not rows:
        return None
    item = _item("unresolved_references", "References to files that do not resolve", "review",
                 "Correct each reference so it names a file that exists in the package with the exact spelling and path, "
                 "or remove it.", rows)
    item["reference_statuses"] = sorted(statuses)
    return item


def _database_gap_rows(result, seen_paths):
    rows = []
    for entry in result.get("files") or []:
        profile = entry.get("database_profile") if isinstance(entry, dict) else None
        if isinstance(profile, dict) and (profile.get("coverage") or {}).get("status") in {"partial", "opaque"}:
            if entry.get("path") not in seen_paths:
                rows.append((entry.get("path"), None, None))
    return rows


def build_fix_summary(result):
    """Group the result's findings by cause into ``result["fix_summary"]``."""
    actionable, informational = {}, []
    per_file = {}
    for entry in result.get("files") or []:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        for finding in entry.get("findings") or []:
            if isinstance(finding, dict) and isinstance(finding.get("id"), str):
                per_file.setdefault(path, []).append(finding)

    for path, findings in per_file.items():
        ids = {finding["id"] for finding in findings}
        # One cause per file: a document-suffixed script with its execution
        # declaration and code-in-text evidence is a single disguised script.
        disguised = bool(ids & {"executable_packaged_as_document", "declared_execution_target"})
        for finding in findings:
            if not _actionable(finding):
                informational.append((path, finding["id"], finding))
                continue
            cause = _cause_for(finding)
            if finding["id"] == "code_in_text_artifact" and not disguised:
                cause = "code_in_documents"
            actionable.setdefault(cause, []).append((path, finding["id"], finding))

    items = []
    for cause, rows in actionable.items():
        priority = "block" if any(f.get("tier") == "block" for _, _, f in rows) else "review"
        if cause in CAUSE_INFO:
            _, title, action, _ = CAUSE_INFO[cause]
        elif cause == "code_in_documents":
            title, action = ("Code stored in documentation files",
                             "Confirm the code is an example only. If anything runs it, move it to a script file with its real extension.")
        else:
            finding_id = cause.split(":", 1)[1]
            title, action = (f"Other finding: {finding_id}",
                             "Review the cited finding in its file and decide whether the behaviour is intended and approved.")
        items.append(_item(cause, title, priority, action, rows))

    if "database_coverage" not in actionable:
        gaps = _database_gap_rows(result, set())
        if gaps:
            _, title, action, _ = CAUSE_INFO["database_coverage"]
            items.append(_item("database_coverage", title, "review", action, gaps))
    for builder in (_format_item, _reference_item):
        item = builder(result)
        if item:
            items.append(item)
    if informational:
        info = _item("informational", "Informational notes", "info",
                     "No change required. These notes describe what was seen; read them if you want more context.",
                     informational)
        info["collapsed"] = True
        items.append(info)

    def rank(item):
        cause = item["cause"]
        order = CAUSE_RANK.get(cause, len(CAUSES) + {"code_in_documents": 0, "format_failures": 1,
                                                       "unresolved_references": 2}.get(cause, 3))
        return (PRIORITY_ORDER[item["priority"]], order, item["id"])
    items.sort(key=rank)
    return {"schema": SCHEMA, "items": items,
            "scope": "Plain-language grouping of this scan's findings by cause. It is a work list, not a risk score "
                     "or proof that fixing these items makes the skill safe."}
