"""Paired organization-report regressions; no live authority or external systems."""
import copy
from datetime import date

import pytest

from skill_sandbox import org_policy as op
from skill_sandbox.org_disposition import organization_report


def rule(rid="R1", when=None, effect="allow", enforcement="mandatory", **extra):
    return {"id": rid, "title": rid, "source": "S1", "requirement": "Synthetic requirement",
            "when": when or {"finding": "hardcoded_secret"}, "effect": effect,
            "enforcement": enforcement, **extra}


def policy(*rules):
    return {"schema": op.POLICY_SCHEMA, "organization": "Fictional organization", "policy_name": "Test",
            "compiled_date": "2026-11-08", "sources": [{"id": "S1", "title": "Test source", "owner": "Declared owner"}],
            "rules": list(rules)}


def scan(*rows, coverage=None):
    result = {"files": [{"path": path, "findings": [{"id": fid, "tier": tier, "severity": "high" if tier == "block" else "medium"}]}
                        for path, fid, tier in rows], "governance_profile": {"policy_capabilities": ["credential_handling", "code_execution"]},
              "risk_classification": {"overall_risk": "low", "recommendation": "allow"}}
    if coverage:
        for path, status in coverage.items():
            result["files"].append({"path": path, "findings": [], "database_profile": {"coverage": {"status": status}}})
    return result


def exception(**extra):
    return rule(rationale="Synthetic documented risk acceptance", approver="Declared reviewer", **extra)


def report(raw, result):
    evaluation = op.evaluate_policy(raw, result)
    assert evaluation["organization_disposition"] == evaluation["organization_report"]["organization_disposition"]
    return evaluation["organization_report"]


def test_unrelated_allow_cannot_lower_residual_secret_and_keeps_legacy_decision():
    result = scan(("secret.txt", "hardcoded_secret", "block"), ("contacts.db", "contact_directory", "info"))
    evaluation = op.evaluate_policy(policy(exception(when={"finding": {"ids": "contact_directory", "include_info": True}})), result)
    assert evaluation["decision"] == "allow"
    assert evaluation["organization_disposition"] == "block"
    assert evaluation["organization_report"]["residual_findings"][0]["id"] == "hardcoded_secret"
    assert result["files"][0]["findings"][0]["tier"] == "block"


@pytest.mark.parametrize("effect", ["block", "require_approval", "warn", "allow"])
def test_advisory_effects_never_change_report(effect):
    baseline = scan(("contacts.db", "contact_directory", "info"))
    r = rule(effect=effect, enforcement="advisory", when={"finding": {"ids": "contact_directory", "include_info": True}},
             approver="Declared reviewer", rationale="Synthetic reason")
    actual = report(policy(r), baseline)
    assert actual["organization_disposition"] == "allow"
    assert actual["deciding_rules"] == []
    assert actual["exceptions_applied"] == []


def test_exact_exception_preserves_scanner_evidence_and_declares_authority():
    result = scan(("secret.txt", "hardcoded_secret", "block"))
    original = copy.deepcopy(result)
    actual = report(policy(exception()), result)
    assert actual["technical_verdict"]["finding_disposition"] == "block"
    assert actual["organization_disposition"] == "allow"
    assert actual["authority"] == "declared_unverified"
    assert actual["policy"]["sha256"] and actual["policy"]["compiled_date"] == "2026-11-08"
    assert actual["policy"]["sources"][0]["owner"] == "Declared owner"
    # Only the pre-existing legacy annotation is additive; technical evidence survives.
    current = copy.deepcopy(result)
    current["files"][0]["findings"][0].pop("policy_disposition", None)
    current["files"][0]["findings"][0].pop("policy_rule", None)
    assert current == original


@pytest.mark.parametrize("condition,expected", [
    ({"capability": "credential_handling"}, "block"),
    ({"any": [{"finding": "hardcoded_secret"}, {"capability": "credential_handling"}]}, "block"),
    ({"all": [{"finding": "hardcoded_secret"}, {"capability": "credential_handling"}]}, "allow"),
    ({"any": [{"finding": "hardcoded_secret"}, {"all": [{"finding": "hardcoded_secret"}, {"capability": "credential_handling"}]}]}, "allow"),
    ({"finding": ["hardcoded_secret", "contact_directory"]}, "block"),
])
def test_full_stop_structural_proof(condition, expected):
    actual = report(policy(exception(when=condition)), scan(("secret.txt", "hardcoded_secret", "block")))
    assert actual["organization_disposition"] == expected


def test_package_wide_all_does_not_waive_other_finding_targets():
    condition = {"all": [{"finding": "contact_directory"}, {"capability": "code_execution"}]}
    actual = report(policy(exception(when=condition)), scan(("directory.db", "contact_directory", "review"),
                                                            ("script.py", "dynamic_exec", "block")))
    assert actual["organization_disposition"] == "block"
    assert {e["finding_id"] for e in actual["exceptions_applied"]} == {"contact_directory"}


@pytest.mark.parametrize("metadata", [{}, {"rationale": "Reason"}, {"approver": "Reviewer"}])
def test_legacy_allow_valid_but_ineligible_without_both_metadata_fields(metadata):
    evaluation = op.evaluate_policy(policy(rule(**metadata)), scan(("secret.txt", "hardcoded_secret", "block")))
    assert evaluation["status"] == "applied"
    assert evaluation["organization_disposition"] == "block"
    assert "requires both" in evaluation["organization_report"]["exceptions_not_applied"][0]["reason"]


@pytest.mark.parametrize("expires,expected", [("2030-01-01", "allow"), ("2029-12-31", "block"), ("2030-01-02", "allow")])
def test_expiry_inclusive_on_evaluation_date(expires, expected):
    raw = policy(exception(expires=expires))
    result = scan(("secret.txt", "hardcoded_secret", "block"))
    validated, errors, _ = op.validate_policy(raw)
    assert not errors
    evaluation = op._evaluate_legacy_policy(raw, result)
    actual = organization_report(evaluation, result, validated, op._Facts(result), op._evaluate, today=date(2030, 1, 1))
    assert actual["organization_disposition"] == expected


@pytest.mark.parametrize("effect", ["block", "require_approval"])
def test_mandatory_effect_cannot_be_cancelled_by_exception(effect):
    raw = policy(exception(), rule("R2", effect=effect, approver="Reviewer"))
    actual = report(raw, scan(("secret.txt", "hardcoded_secret", "block")))
    assert actual["organization_disposition"] == effect
    assert {r["id"] for r in actual["deciding_rules"]} == {"R1", "R2"}


def test_mixed_precedence_block_approval_allow_and_residual():
    raw = policy(exception(), rule("R2", effect="require_approval", approver="Reviewer"), rule("R3", effect="block"))
    assert report(raw, scan(("secret.txt", "hardcoded_secret", "block")))["organization_disposition"] == "block"


def test_coverage_acceptance_only_identified_gap():
    raw = policy(exception(when={"all": [{"coverage": "opaque"}, {"finding": "opaque_database"}]}))
    result = scan(("vault.db", "opaque_database", "block"), coverage={"vault.db": "opaque", "other.db": "partial"})
    actual = report(raw, result)
    assert actual["organization_disposition"] == "require_approval"
    gaps = {g["path"]: g for g in actual["coverage_limits"]}
    assert gaps["vault.db"]["accepted_by"] and not gaps["other.db"]["accepted_by"]


@pytest.mark.parametrize("when,expected", [({"finding": "opaque_database"}, "require_approval"),
                                           ({"coverage": "opaque"}, "block"),
                                           ({"all": [{"coverage": "opaque"}, {"finding": "opaque_database"}]}, "allow")])
def test_opaque_block_requires_both_finding_exception_and_gap_acceptance(when, expected):
    actual = report(policy(exception(when=when)), scan(("vault.db", "opaque_database", "block"), coverage={"vault.db": "opaque"}))
    assert actual["organization_disposition"] == expected


def test_global_coverage_floor_and_explicit_acceptance():
    result = scan()
    result["coverage"] = {"status": "partial"}
    assert report(None, result)["organization_disposition"] == "require_approval"
    assert report(policy(exception(when={"coverage": "partial"})), result)["organization_disposition"] == "allow"


@pytest.mark.parametrize("bad_expiry", ["2030-02-30", "2030-1-01", None])
def test_invalid_policy_rejected_entirely_even_with_valid_exception(bad_expiry):
    raw = policy(exception(), rule("R2", expires=bad_expiry))
    result = scan(("secret.txt", "hardcoded_secret", "block"))
    actual = report(raw, result)
    assert actual["status"] == "fallback" and actual["organization_disposition"] == "block"
    assert actual["errors"] and not actual["exceptions_applied"] and not actual["deciding_rules"]
    assert "policy_disposition" not in result["files"][0]["findings"][0]


def test_object_parser_preserves_bounded_parser_errors():
    raw = policy(exception())
    raw["_comment"] = "x" * (op.MAX_POLICY_CHARS + 1)
    parsed, _, errors = op.parse_policy(raw)
    assert parsed is None and errors


@pytest.mark.parametrize("kind", ["none", "advisory", "unrelated_allow"])
def test_actual_high_risk_verdict_survives_without_actionable_findings(kind):
    result = scan(("contacts.db", "contact_directory", "info"))
    result["risk_classification"] = {"overall_risk": "high", "recommendation": "block_by_default"}
    raw = None if kind == "none" else policy(exception(
        when={"finding": {"ids": "contact_directory", "include_info": True}},
        enforcement="advisory" if kind == "advisory" else "mandatory"))
    actual = report(raw, result)
    assert actual["organization_disposition"] == "block"
    assert actual["technical_verdict"]["risk_classification"] == result["risk_classification"]


def test_governance_block_and_unknown_inputs_are_not_invented_allow():
    result = scan()
    result["governance_profile"]["brokered_tokens"] = {"decision": "block_by_default"}
    assert report(None, result)["organization_disposition"] == "block"
    unknown = report(None, {"files": []})
    assert unknown["organization_disposition"] == "require_approval"
    assert unknown["technical_verdict"]["inputs_status"] == "unknown"


def test_mandatory_warn_reported_without_fourth_disposition():
    actual = report(policy(rule(effect="warn")), scan(("secret.txt", "hardcoded_secret", "block")))
    assert actual["organization_disposition"] == "block"
    assert actual["warnings"][0]["rule_id"] == "R1"


def test_false_all_branch_inside_true_any_cannot_leak_finding_targets():
    condition = {"any": [{"all": [{"finding": "dynamic_exec"}, {"coverage": "opaque"}]},
                         {"finding": "contact_directory"}]}
    actual = report(policy(exception(when=condition)), scan(("script.py", "dynamic_exec", "block"),
                                                            ("directory.db", "contact_directory", "review")))
    assert actual["organization_disposition"] == "block"
    assert {e["finding_id"] for e in actual["exceptions_applied"]} == {"contact_directory"}


def test_company_decision_uses_all_evidence_before_legacy_display_limit():
    result = scan(*[(f"dir-{n}.db", "contact_directory", "review") for n in range(60)])
    evaluation = op.evaluate_policy(policy(exception(when={"finding": "contact_directory"})), result)
    assert len(evaluation["rules"][0]["evidence"]) == op.MAX_EVIDENCE
    assert evaluation["rules"][0]["evidence_omitted"] == 10
    actual = evaluation["organization_report"]
    assert actual["organization_disposition"] == "allow"
    assert len(actual["exceptions_applied"]) == 60 and not actual["residual_findings"]


def test_high_risk_without_any_finding_retains_scanner_block():
    result = scan()
    result["risk_classification"] = {"overall_risk": "high", "recommendation": "block_by_default"}
    actual = report(None, result)
    assert actual["organization_disposition"] == "block"
    assert not actual["residual_findings"]


@pytest.mark.parametrize("metadata", [{}, {"rationale": "Reason"}, {"approver": "Reviewer"},
                                       {"rationale": "Reason", "approver": "Reviewer", "expires": "2000-01-01"}])
def test_coverage_exception_needs_current_reason_and_approver(metadata):
    result = scan(coverage={"db.sqlite": "partial"})
    actual = report(policy(rule(when={"coverage": "partial"}, **metadata)), result)
    assert actual["organization_disposition"] == "require_approval"
    assert not actual["coverage_limits"][0]["accepted_by"]


@pytest.mark.parametrize("fid", ["hardcoded_secret", "embedded_executable_blob", "opaque_database",
                                  "prompt_override", "system_exfiltration", "secret_exfiltration", "tool_escape"])
def test_protected_findings_require_exact_id_in_each_or_branch(fid):
    result = scan(("item", fid, "block"))
    condition = {"any": [{"finding": fid}, {"capability": "code_execution"}]}
    actual = report(policy(exception(when=condition)), result)
    assert actual["organization_disposition"] == "block"
    assert not actual["exceptions_applied"]


def test_real_scan_adds_company_report_without_changing_technical_results():
    from skill_sandbox.app import scan_upload
    data = b"---\nname: policy-report-test\ndescription: Summarize a local note.\n---\n# Note\nRead the note and summarize its purpose.\n"
    original = scan_upload(data, "SKILL.md")
    raw = policy(rule(when={"capability": "read_only"}, effect="block"))
    adjusted = scan_upload(data, "SKILL.md", org_policy=raw)
    assert adjusted["policy_evaluation"]["status"] == "applied"
    assert adjusted["policy_evaluation"]["organization_disposition"] == "block"
    assert adjusted["risk_classification"] == original["risk_classification"]
    assert adjusted["governance_profile"] == original["governance_profile"]
    assert adjusted["files"] == original["files"]
    assert adjusted["policy_evaluation"]["organization_report"]["authority"] == "declared_unverified"
