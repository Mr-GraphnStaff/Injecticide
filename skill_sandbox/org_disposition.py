"""Separate organization disposition; scanner evidence and legacy decision survive.

Rules are package-wide predicates, but exceptions address individual findings or
identified coverage gaps. Missing exception metadata is valid legacy policy,
not permission. Dates use UTC and expiry is inclusive. Declared approvers are
never authenticated here. No UI evidence limits participate in this decision.
"""
from __future__ import annotations

from datetime import datetime, timezone, date

RANK = {"allow": 0, "require_approval": 1, "block": 2}
PROTECTED = {"hardcoded_secret", "embedded_executable_blob", "opaque_database"}
BLOCK_INSTRUCTIONS = {"prompt_override", "system_exfiltration", "secret_exfiltration", "tool_escape"}


def _requires(node, key, expected=None):
    """Proof over condition structure, not whichever OR branch happened to match."""
    if "all" in node:
        return any(_requires(child, key, expected) for child in node["all"])
    if "any" in node:
        return all(_requires(child, key, expected) for child in node["any"])
    if key not in node:
        return False
    if key == "finding":
        return node[key]["ids"] == [expected]
    return True


def _scanner_disposition(finding, actionable=True):
    if finding.get("tier") == "block" or finding.get("disposition") == "block":
        return "block"
    if finding.get("tier") == "info":
        return "allow"
    if finding.get("disposition") in {"require_approval", "require_admin_approval", "review"}:
        return "require_approval"
    if actionable or finding.get("tier") == "review":
        return "require_approval"
    return "allow"


def _has_finding(node):
    return "finding" in node or any(_has_finding(child) for key in ("all", "any") for child in node.get(key, []))


def _finding_evidence(node, facts, evaluate):
    if not evaluate(node, facts)[0]:
        return []
    if "finding" in node:
        return evaluate(node, facts)[1]
    return [row for key in ("all", "any") for child in node.get(key, [])
            for row in _finding_evidence(child, facts, evaluate)]


def _coverage_evidence(node, facts, evaluate):
    if not evaluate(node, facts)[0]:
        return []
    if "coverage" in node:
        return evaluate(node, facts)[1]
    return [row for key in ("all", "any") for child in node.get(key, [])
            for row in _coverage_evidence(child, facts, evaluate)]


def _gap_matches(gap, rows):
    for row in rows:
        if row.get("path") != gap["path"]:
            continue
        if gap["path"] is None:
            if row.get("signal") == "analysis_coverage:" + gap["status"]:
                return True
        elif row.get("signal") == "database_coverage:" + gap["status"] or row.get("finding_id") in {
                "opaque_database" if gap["status"] == "opaque" else "database_not_cleared"}:
            return True
    return False


def _technical(result):
    """Snapshot real scanner decisions without presenting inferred tiers as a verdict."""
    risk = result.get("risk_classification")
    risk = dict(risk) if isinstance(risk, dict) else None
    governance = result.get("governance_profile") or {}
    routes = {name: dict(governance[name]) for name in ("brokered_tokens", "customer_managed_keys")
              if isinstance(governance.get(name), dict)}
    explicit = result.get("final_verdict", result.get("verdict"))
    decisions = [route.get("decision") for route in routes.values()]
    if isinstance(explicit, str):
        decisions.append(explicit)
    if risk:
        decisions.append(risk.get("recommendation"))
    known = [value for value in decisions if isinstance(value, str)]
    if (risk or {}).get("overall_risk") == "high" or any(value in {"block", "block_by_default"} for value in known):
        baseline = "block"
    elif any(value in {"require_approval", "require_admin_approval", "review"} for value in known) or governance.get("approval_required") is True:
        baseline = "require_approval"
    elif known and all(value in {"allow", "allow_with_warnings"} for value in known):
        baseline = "allow"
    else:
        baseline = "require_approval"
    return {"risk_classification": risk, "governance_decisions": routes,
            "explicit_verdict": explicit, "baseline_disposition": baseline,
            "inputs_status": "known" if known else "unknown"}, baseline


def organization_report(evaluation, result, policy, facts, evaluate, *, today=None):
    """Build an independent decision using validated policy and uncapped facts.

    ``today`` is injectable for deterministic regression tests; production uses
    the current UTC calendar date. A report is emitted even for absent/rejected
    policy, visibly falling back to technical defaults and the coverage floor.
    """
    today = today or datetime.now(timezone.utc).date()
    active = evaluation["status"] == "applied" and policy is not None
    records = []
    for item in facts.findings:
        if len(item) == 3:
            path, finding, actionable = item
        else:
            path, _, actionable, fid = item
            finding = {"id": fid}
        records.append({"path": path, "id": finding["id"],
                        "scanner_disposition": _scanner_disposition(finding, actionable),
                        "protected": finding["id"] in PROTECTED or
                        (finding["id"] in BLOCK_INSTRUCTIONS and _scanner_disposition(finding, actionable) == "block")})
    technical_default = max((row["scanner_disposition"] for row in records), key=RANK.get, default="allow")
    technical, technical_baseline = _technical(result)
    gaps = {}
    for path, status in facts.db_coverage.items():
        if status in {"partial", "opaque"}:
            gaps[path, status] = {"path": path, "status": status, "reason": "Database contents are not fully read.", "accepted_by": []}
    if facts.result_coverage in {"partial", "opaque"}:
        status = facts.result_coverage
        gaps[None, status] = {"path": None, "status": status, "reason": "Package analysis coverage is limited.", "accepted_by": []}
    for row in records:
        if row["id"] in {"database_not_cleared", "opaque_database"}:
            status = "opaque" if row["id"] == "opaque_database" else "partial"
            gaps.setdefault((row["path"], status), {"path": row["path"], "status": status,
                            "reason": row["id"], "accepted_by": []})
    report = {"schema": "injecticide-organization-report/v1", "status": "applied" if active else "fallback",
              "technical_verdict": technical, "organization_disposition": technical_default,
              "policy": dict(evaluation.get("policy") or {}), "authority": "declared_unverified",
              "evaluation_date": today.isoformat(), "exceptions_applied": [], "exceptions_not_applied": [],
              "residual_findings": [], "full_stops": [], "coverage_limits": list(gaps.values()),
              "deciding_rules": [], "not_statically_checkable": list(evaluation.get("not_statically_checkable") or []),
              "fallback_reason": None if active else ("Policy rejected entirely; scanner defaults retained." if evaluation["status"] == "invalid"
                                                     else "No organization policy supplied; scanner defaults retained."),
              "errors": list(evaluation.get("errors") or []), "warnings": [],
              "limits": ["Policy authority and approvers are declared, not verified.",
                         "Exception targets require finding evidence; path-only package signals cannot waive unrelated findings."]}
    report["technical_verdict"]["finding_disposition"] = technical_default
    if active:
        report["policy"]["sources"] = [dict(source) for source in policy["sources"]]
    triggered = []
    mandatory = []
    if active:
        for rule in policy["rules"]:
            hit, evidence, _ = evaluate(rule["when"], facts)
            if not hit and rule["effect"] == "allow":
                report["exceptions_not_applied"].append({"rule_id": rule["id"], "path": None, "finding_id": None,
                    "rationale": rule.get("rationale"), "approver": rule.get("approver"), "expires": rule.get("expires"),
                    "reason": "Rule condition did not match."})
            if hit:
                triggered.append((rule, evidence))
                if rule["enforcement"] == "mandatory" and rule["effect"] in {"block", "require_approval"}:
                    mandatory.append(rule)
                    report["deciding_rules"].append({"id": rule["id"], "effect": rule["effect"], "approver": rule["approver"]})
    accepted = set()
    for rule, evidence in triggered:
        if rule["effect"] != "allow":
            continue
        # A package-wide AND may combine findings from different files with
        # capability evidence. Only finding-clause targets are exception targets
        # whenever a finding clause exists; the union is not blanket permission.
        target_evidence = _finding_evidence(rule["when"], facts, evaluate) if _has_finding(rule["when"]) else evidence
        targets = {(row.get("path"), row.get("finding_id")) for row in target_evidence if row.get("finding_id")}
        matched = [row for row in records if (row["path"], row["id"]) in targets]
        coverage_rows = _coverage_evidence(rule["when"], facts, evaluate)
        matched_gaps = [gap for gap in gaps.values() if _requires(rule["when"], "coverage") and _gap_matches(gap, coverage_rows)]
        reason = None
        if rule["enforcement"] != "mandatory":
            reason = "Advisory rules never change organization disposition."
        elif not rule.get("rationale") or not rule.get("approver"):
            reason = "Exception requires both rationale and a declared approver."
        elif rule.get("expires") and date.fromisoformat(rule["expires"]) < today:
            reason = "Exception expired."
        for row in matched:
            rejected = reason
            if not rejected and row["protected"] and not _requires(rule["when"], "finding", row["id"]):
                rejected = "Full-stop exception must structurally require this exact finding id in every alternative."
            event = {"rule_id": rule["id"], "path": row["path"], "finding_id": row["id"],
                     "rationale": rule.get("rationale"), "approver": rule.get("approver"), "expires": rule.get("expires"),
                     "reason": rejected or "Explicit finding exception accepted; evidence is retained."}
            if rejected:
                report["exceptions_not_applied"].append(event)
            else:
                accepted.add((row["path"], row["id"]))
                report["exceptions_applied"].append(event)
        for gap in matched_gaps:
            event = {"rule_id": rule["id"], "path": gap["path"], "finding_id": None,
                     "coverage": gap["status"], "rationale": rule.get("rationale"), "approver": rule.get("approver"),
                     "expires": rule.get("expires"), "reason": reason or "Explicit coverage gap acceptance; unread contents remain unread."}
            if reason:
                report["exceptions_not_applied"].append(event)
            else:
                gap["accepted_by"].append(dict(event))
                report["exceptions_applied"].append(event)
        if not matched and not matched_gaps:
            report["exceptions_not_applied"].append({"rule_id": rule["id"], "path": None, "finding_id": None,
                "rationale": rule.get("rationale"), "approver": rule.get("approver"), "expires": rule.get("expires"),
                "reason": reason or "No finding or identified coverage gap matched; blanket package exceptions are not supported."})
    residual = [row for row in records if row["scanner_disposition"] != "allow" and (row["path"], row["id"]) not in accepted]
    report["residual_findings"] = residual
    report["full_stops"] = [dict(row, excepted=(row["path"], row["id"]) in accepted) for row in records if row["protected"]]
    dispositions = [row["scanner_disposition"] for row in residual]
    dispositions.extend(rule["effect"] for rule in mandatory)
    if any(not gap["accepted_by"] for gap in gaps.values()):
        dispositions.append("require_approval")
    # A scanner recommendation has force even without retained finding rows.
    # An exception may discharge that baseline only when it accepts an actual
    # scanner finding at that severity. An unrelated/info exception cannot do so.
    discharged = any(row["scanner_disposition"] == technical_baseline and technical_baseline != "allow"
                     and (row["path"], row["id"]) in accepted for row in records)
    if not discharged or technical["inputs_status"] == "unknown":
        dispositions.append(technical_baseline)
    for rule, _ in triggered:
        if rule["enforcement"] == "mandatory" and rule["effect"] == "warn":
            report["warnings"].append({"rule_id": rule["id"], "reason": rule["requirement"]})
    report["organization_disposition"] = max(dispositions, key=RANK.get, default="allow")
    # An accepted exception cannot cancel a mandatory rule, including one in a
    # different file. Keep those rule ids visible beside the residual decision.
    for rule_id in dict.fromkeys(event["rule_id"] for event in report["exceptions_applied"]):
        report["deciding_rules"].append({"id": rule_id, "effect": "allow_exception"})
    return report
