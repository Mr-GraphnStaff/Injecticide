from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import urlparse

if __package__:
    from .scan_rules import load_rule_catalog
else:
    from scan_rules import load_rule_catalog


REFERENCE_TEMPLATE_RULE_IDS = {
    "prompt_override",
    "system_exfiltration",
    "secret_exfiltration",
    "tool_escape",
    "autonomous_authoritative_write",
    "bulk_enterprise_modification",
    "workflow_manipulation",
    "cross_system_automation",
    "dynamic_exec",
    "subprocess_spawn",
    "network_calls",
    "filesystem_access",
    "url_fetch",
    "base64_usage",
    "dangerous_file_ops",
    "home_write",
    "runtime_dependency_install",
    "self_modifying_skill",
    "dynamic_import_construction",
    "insecure_mcp_transport",
    "unverified_mcp_server",
}

REFERENCE_TEMPLATE_MARKERS = (
    "quick-reference",
    "detection patterns",
    "report template",
    "classification guidelines",
    "audit report template",
    "use this template",
    "known trusted",
    "benign patterns",
    "suspicious patterns",
    "malicious patterns",
)

URL_REGEX = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

TRUSTED_MCP_HOSTS = {
    "mcp.atlassian.com",
    "mcp.asana.com",
}
TRUSTED_MCP_SUFFIXES = (
    ".mcp.claude.com",
)


def classify_artifact_role(path: str, text: str) -> str:
    normalized_path = path.replace("\\", "/").lower()
    filename = Path(normalized_path).name
    text_lower = text.lower()
    is_reference = "/references/" in f"/{normalized_path}" or filename.startswith("reference")
    is_template_like = any(marker in text_lower for marker in REFERENCE_TEMPLATE_MARKERS)
    is_audit_policy = (
        filename == "skill.md"
        and "audit" in text_lower
        and any(marker in text_lower for marker in ("risk domains", "automatic high-severity", "detection patterns", "classification guidelines"))
        and any(marker in text_lower for marker in ("inspect", "review", "evaluate"))
    )

    if is_audit_policy:
        return "audit_policy"
    if is_reference and (
        any(token in filename for token in ("template", "pattern", "catalog", "mapping"))
        or is_template_like
    ):
        return "reference_template"
    if is_reference:
        return "reference"
    return "active"


def build_finding(
    rule: Dict[str, object],
    matches: Iterable[str],
    artifact_role: str,
) -> Dict[str, object]:
    normalized_matches = list(matches)
    severity = str(rule["severity"])
    finding_category = str(rule.get("finding_category", "signal"))
    action_state = str(rule.get("action_state", "present"))
    disposition = str(rule.get("disposition", _default_disposition(severity)))

    if artifact_role in {"reference_template", "audit_policy"} and str(rule["id"]) in REFERENCE_TEMPLATE_RULE_IDS:
        severity = "info"
        action_state = "documented"
        disposition = "info"

    return {
        "id": rule["id"],
        "category": rule["category"],
        "severity": severity,
        "description": rule["description"],
        "finding_category": finding_category,
        "subject": rule.get("subject", "unknown"),
        "action_state": action_state,
        "disposition": disposition,
        "count": len(normalized_matches),
        "samples": normalized_matches[:3],
        "status": rule.get("status", "unknown"),
        "sources": rule.get("sources", []),
        "artifact_role": artifact_role,
    }


def detect_special_findings(path: str, text: str, artifact_role: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    catalog = {rule["id"]: rule for rule in load_rule_catalog().get("rules", [])}

    for url in URL_REGEX.findall(text):
        if not _looks_like_mcp_url(url):
            continue

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme.lower() != "https":
            findings.append(build_finding(catalog["insecure_mcp_transport"], [url], artifact_role))
            continue

        if hostname in TRUSTED_MCP_HOSTS or any(hostname.endswith(suffix) for suffix in TRUSTED_MCP_SUFFIXES):
            continue

        findings.append(build_finding(catalog["unverified_mcp_server"], [url], artifact_role))

    return findings


def _looks_like_mcp_url(url: str) -> bool:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    return "mcp" in hostname or "/mcp" in path


def _default_disposition(severity: str) -> str:
    if severity == "high":
        return "block"
    if severity == "medium":
        return "require_approval"
    if severity == "low":
        return "warn"
    return "info"
