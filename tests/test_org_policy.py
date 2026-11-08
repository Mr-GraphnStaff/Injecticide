"""Organisation AI policy: hostile and malformed policies first, then evaluation.

All data is synthetic. Results are hand-built dictionaries (so teammates' keys
can be present or absent) plus a few real scans of in-memory packages.
"""
import copy
import io
import json
import pathlib
import sys
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skill_sandbox.org_policy import (evaluate_policy, known_finding_ids, validate_policy, POLICY_SCHEMA,
                                      MAX_CONDITION_DEPTH)
from skill_sandbox.package_evidence import evidence_input_report
from skill_sandbox.app import scan_upload

TEMPLATE = ROOT / "docs" / "org-policy-template.json"


def policy(*rules, **extra):
    base = {"schema": POLICY_SCHEMA, "organization": "Example Org (fictional)", "policy_name": "Test policy",
            "compiled_date": "2026-11-01", "sources": [{"id": "S1", "title": "Example AI standard"}],
            "rules": list(rules)}
    base.update(extra)
    return base


def rule(rule_id="R1", when=None, effect="block", enforcement="mandatory", **extra):
    row = {"id": rule_id, "title": "Rule " + rule_id, "source": "S1", "requirement": "Synthetic requirement.",
           "when": when if when is not None else {"finding": "hardcoded_secret"}, "effect": effect,
           "enforcement": enforcement}
    if effect == "require_approval":
        row["approver"] = "Security team"
    row.update(extra)
    return row


def finding(fid, tier="review", severity="medium", **extra):
    return {"id": fid, "tier": tier, "severity": severity, **extra}


def result(*files, **extra):
    base = {"files": [{"path": path, "findings": list(findings)} for path, findings in files]}
    base.update(extra)
    return base


def messages(evaluation):
    return [error["message"] for error in evaluation["errors"]]


# ---------------------------------------------------------------- hostile input

@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", '"text"', "{\"schema\": 1, \"schema\": 2}",
                                 "{\"a\": NaN}", "﻿"])
def test_malformed_policy_text_is_invalid_not_an_exception(raw):
    evaluation = evaluate_policy(raw, result())
    assert evaluation["status"] in {"invalid", "none"}
    if evaluation["status"] == "invalid":
        assert evaluation["errors"] and evaluation["rules"] == []
        assert len(evaluation["policy"]["sha256"]) == 64


def test_oversized_and_deeply_nested_policies_are_bounded():
    huge = json.dumps(policy(rule(rationale="x" * 200_000)))
    assert evaluate_policy(huge, result())["status"] == "invalid"
    deep = {"finding": "hardcoded_secret"}
    for _ in range(MAX_CONDITION_DEPTH + 2):
        deep = {"all": [deep]}
    evaluation = evaluate_policy(json.dumps(policy(rule(when=deep))), result())
    assert evaluation["status"] == "invalid"
    assert any("nested deeper" in m for m in messages(evaluation))
    nested = "[" * 5000 + "]" * 5000
    assert evaluate_policy(nested, result())["status"] == "invalid"


def test_unknown_finding_suggests_closest_real_id():
    evaluation = evaluate_policy(policy(rule("R3", when={"finding": "secret_in_file"})), result())
    assert evaluation["status"] == "invalid"
    assert "Rule R3: unknown finding 'secret_in_file'; did you mean 'hardcoded_secret'?" in messages(evaluation)
    assert evaluation["errors"][0]["suggestion"] == "hardcoded_secret"
    assert evaluation["errors"][0]["path"] == "rules[0].when.finding"
    typo = evaluate_policy(policy(rule(when={"finding": "hardcoded_secrt"})), result())
    assert typo["errors"][0]["suggestion"] == "hardcoded_secret"


def test_secret_exfiltration_used_for_presence_warns_and_suggests_hardcoded_secret():
    evaluation = evaluate_policy(policy(rule(when={"finding": "secret_exfiltration"})), result())
    assert evaluation["status"] == "applied"
    warning = evaluation["warnings"][0]
    assert warning["suggestion"] == "hardcoded_secret"
    assert "request" in warning["message"] or "instruction" in warning["message"]
    assert "hardcoded_secret" in warning["message"]
    both = evaluate_policy(policy(rule(when={"finding": ["secret_exfiltration", "hardcoded_secret"]})), result())
    assert both["warnings"] == []


def test_condition_shape_errors_name_the_closest_key_and_effect():
    evaluation = evaluate_policy(policy(rule(when={"findings": "hardcoded_secret"}, effect="blok")), result())
    text = " ".join(messages(evaluation))
    assert "did you mean 'finding'?" in text and "did you mean 'block'?" in text
    two_keys = evaluate_policy(policy(rule(when={"finding": "hardcoded_secret", "capability": "network"})), result())
    assert any("exactly one key" in m for m in messages(two_keys))
    bad_capability = evaluate_policy(policy(rule(when={"capability": "netwrok"})), result())
    assert bad_capability["errors"][0]["suggestion"] == "network"


def test_strict_schema_rejects_unknown_fields_missing_fields_and_bad_references():
    raw = policy(rule(surprise=True, source="S9"))
    del raw["compiled_date"]
    raw["extra"] = 1
    evaluation = evaluate_policy(raw, result())
    text = " ".join(messages(evaluation))
    assert "unknown field 'surprise'" in text and "unknown field 'extra'" in text
    assert "missing required field 'compiled_date'" in text
    assert "source 'S9' is not listed" in text
    dup = evaluate_policy(policy(rule("R1"), rule("R1")), result())
    assert any("duplicate rule id" in m for m in messages(dup))
    no_approver = rule(effect="require_approval")
    del no_approver["approver"]
    assert any("must name its approver" in m for m in messages(evaluate_policy(policy(no_approver), result())))
    assert evaluate_policy(policy(rule(), schema="injecticide-org-policy/v2"), result())["errors"][0]["suggestion"] == POLICY_SCHEMA
    assert any("YYYY-MM-DD" in m for m in messages(evaluate_policy(policy(rule(), compiled_date="2026-13-40"), result())))


def test_policy_values_are_never_regex_or_code():
    # Regex and code-like text is rejected as a host pattern, never compiled.
    for pattern in [".*", "(a+)+$", "*.ex*ample.test", "__import__('os')", "a|b"]:
        evaluation = evaluate_policy(policy(rule(when={"external_origin": pattern})), result())
        assert evaluation["status"] == "invalid", pattern
    url = evaluate_policy(policy(rule(when={"external_origin": "https://user@api.example.test:8443/path"})), result())
    assert url["errors"][0]["suggestion"] == "api.example.test"


def test_underscore_keys_are_comments_and_the_template_is_valid():
    commented = policy(rule(_comment="note", when={"finding": "hardcoded_secret", "_why": "x"}), _comment="top")
    assert evaluate_policy(commented, result())["status"] == "applied"
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    normalised, errors, warnings = validate_policy(template)
    assert errors == [] and warnings == [] and normalised["rules"]
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "fictional" in text


def test_invalid_policy_does_not_fail_a_real_scan():
    report = scan_upload(b"# Notes\nNothing here.\n", "notes.md", org_policy="{broken")
    assert report["policy_evaluation"]["status"] == "invalid"
    assert report["summary"]["total_files"] == 1
    assert report["fix_summary"]["schema"] == "injecticide-fix-summary/v1"
    assert scan_upload(b"# Notes\n", "notes.md")["policy_evaluation"]["status"] == "none"


# ---------------------------------------------------------------- evaluation

def test_only_actionable_findings_trigger_unless_rule_asks_for_info():
    scan = result(("a.md", [finding("pii_email_address", tier="info", severity="info")]))
    plain = evaluate_policy(policy(rule(when={"finding": "pii_email_address"})), scan)
    assert plain["rules"][0]["triggered"] is False
    info = evaluate_policy(policy(rule(when={"finding": {"ids": ["pii_email_address"], "include_info": True}})), scan)
    assert info["rules"][0]["triggered"] is True
    assert info["rules"][0]["evidence"] == [{"path": "a.md", "finding_id": "pii_email_address", "count": 1}]


def test_advisory_block_is_never_an_effective_block():
    scan = result(("s.py", [finding("hardcoded_secret", tier="block", severity="high")]))
    evaluation = evaluate_policy(policy(rule(enforcement="advisory")), scan)
    row = evaluation["rules"][0]
    assert row["triggered"] and row["effect"] == "block" and row["effective_effect"] == "advisory_block"
    assert evaluation["effect_summary"]["block"] == 0 and evaluation["effect_summary"]["advisory_block"] == 1
    assert evaluation["decision"] == "warn"
    mandatory = evaluate_policy(policy(rule()), scan)
    assert mandatory["effect_summary"]["block"] == 1 and mandatory["decision"] == "block"


def test_allow_marks_findings_without_hiding_them_or_changing_the_verdict():
    scan = result(("dir.db", [finding("contact_directory", tier="info", severity="info")]),
                  ("s.py", [finding("hardcoded_secret", tier="block", severity="high")]),
                  risk_classification={"overall_risk": "high", "recommendation": "block_by_default"})
    before = copy.deepcopy(scan)
    evaluation = evaluate_policy(policy(rule("R6", when={"finding": {"ids": ["contact_directory"], "include_info": True}},
                                             effect="allow")), scan)
    assert evaluation["effect_summary"]["allow"] == 1 and evaluation["decision"] == "allow"
    marked = scan["files"][0]["findings"][0]
    assert marked["policy_disposition"] == "allowed_by_policy" and marked["policy_rule"] == "R6"
    assert marked["tier"] == "info" and len(scan["files"][0]["findings"]) == 1
    assert scan["files"][1] == before["files"][1]
    assert scan["risk_classification"] == before["risk_classification"]


def test_data_class_reads_database_profile_and_contact_directory_and_tolerates_absence():
    profile = {"schema": "injecticide-db-profile/v1", "tables": [{"name": "people", "columns": [
        {"name": "email", "data_classes": ["personal_email"]}, {"name": "note", "data_classes": ["free_text"]}]}],
        "coverage": {"status": "complete"}}
    scan = result(("hr.db", []), ("staff.db", [finding("contact_directory", tier="info", severity="info")]))
    scan["files"][0]["database_profile"] = profile
    evaluation = evaluate_policy(policy(rule("R1", when={"data_class": "personal_email"}),
                                        rule("R2", when={"data_class": "business_contact_email"}),
                                        rule("R3", when={"data_class": "health"})), scan)
    triggered = {row["id"]: row for row in evaluation["rules"]}
    assert triggered["R1"]["triggered"] and triggered["R1"]["evidence"][0]["path"] == "hr.db"
    assert triggered["R2"]["triggered"] and triggered["R2"]["evidence"][0]["path"] == "staff.db"
    assert not triggered["R3"]["triggered"]
    assert evaluate_policy(policy(rule(when={"data_class": "ssn"})), {})["status"] == "applied"


def test_external_origin_wildcards_and_outside_mode():
    scan = result(package_analysis={"relationship_graph": {"external_references": [
        {"source": "SKILL.md", "url": "https://api.vendor.test"},
        {"source": "ref.md", "url": "https://files.corp.example.test:8443"},
        {"source": "ref.md", "url": "https://corp.example.test"}]}})
    evaluation = evaluate_policy(policy(
        rule("R1", when={"external_origin": "*.example.test"}),
        rule("R2", when={"external_origin": {"outside": ["*.example.test", "corp.example.test"]}}),
        rule("R3", when={"external_origin": "vendor.test"})), scan)
    rows = {row["id"]: row for row in evaluation["rules"]}
    assert [e["signal"] for e in rows["R1"]["evidence"]] == ["external_origin:corp.example.test",
                                                             "external_origin:files.corp.example.test"]
    assert [e["signal"] for e in rows["R2"]["evidence"]] == ["external_origin:api.vendor.test"]
    assert rows["R3"]["triggered"] is False  # '*.' is required to match subdomains


def test_connector_frontmatter_risk_capability_and_coverage_conditions():
    skill_text = ("---\nname: demo\ndescription: Demo.\ncompatibility: Requires the ExampleCRM connector\n"
                  "allowed-tools: Read mcp__ticketdesk__create\nmetadata:\n  owner: Team A\n---\nBody\n")
    profile = {"coverage": {"status": "partial"}, "tables": []}
    scan = result(("demo/SKILL.md", []), ("demo/data.db", []),
                  package_analysis={"skills": [{"path": "demo/SKILL.md", "metadata": {"owner": "Team A"}}]},
                  governance_profile={"policy_capabilities": ["code_execution"]},
                  risk_classification={"overall_risk": "medium"}, coverage={"status": "complete_supported_content"})
    scan["files"][1]["database_profile"] = profile
    sources = [{"path": "demo/SKILL.md", "text": skill_text}]
    evaluation = evaluate_policy(policy(
        rule("C1", when={"connector_mentioned": ["examplecrm", "TicketDesk"]}),
        rule("C2", when={"connector_mentioned": "otherapp"}),
        rule("F1", when={"frontmatter_missing": ["owner"]}),
        rule("F2", when={"frontmatter_missing": ["version", "license"]}),
        rule("K1", when={"risk_at_least": "medium"}),
        rule("K2", when={"risk_at_least": "high"}),
        rule("P1", when={"capability": "code_execution"}),
        rule("V1", when={"coverage": "partial"}),
        rule("V2", when={"coverage": "opaque"}),
        rule("A1", when={"all": [{"risk_at_least": "low"}, {"coverage": "opaque"}]}),
        rule("A2", when={"any": [{"risk_at_least": "high"}, {"coverage": "partial"}]})), scan, sources)
    triggered = {row["id"]: row["triggered"] for row in evaluation["rules"]}
    assert triggered == {"C1": True, "C2": False, "F1": False, "F2": True, "K1": True, "K2": False,
                         "P1": True, "V1": True, "V2": False, "A1": False, "A2": True}


def test_evaluation_is_deterministic_and_carries_contract_shape():
    scan = result(("b.py", [finding("subprocess_spawn")]), ("a.py", [finding("subprocess_spawn")]))
    raw = json.dumps(policy(rule(when={"finding": "subprocess_spawn"}, effect="warn")))
    first, second = evaluate_policy(raw, copy.deepcopy(scan)), evaluate_policy(raw, copy.deepcopy(scan))
    assert first == second
    assert first["schema"] == "injecticide-policy-results/v1" and first["status"] == "applied"
    assert set(first["policy"]) >= {"name", "organization", "sha256"}
    assert set(first["effect_summary"]) >= {"block", "require_approval", "warn", "allow"}
    row = first["rules"][0]
    assert set(row) >= {"id", "title", "effect", "enforcement", "approver", "triggered", "evidence"}
    assert [e["path"] for e in row["evidence"]] == ["a.py", "b.py"]


def _demo_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/SKILL.md", "---\nname: demo\ndescription: Synthetic demo skill.\n---\n# Demo\n"
                         "Run `python scripts/tool.py.md` to start.\nSee https://api.vendor.test/docs\n")
        archive.writestr("demo/scripts/tool.py.md", "import subprocess\nsubprocess.run(['echo', 'hi'])\n"
                         "API_KEY = 'sk_live_" + "Q7w8E9r0T1y2U3i4O5p6A7s8" + "'\n")
    return buffer.getvalue()


def test_real_scan_ids_are_known_and_policy_evaluates_on_the_final_result():
    raw = json.dumps(policy(rule("R1"), rule("R2", when={"external_origin": "*.vendor.test"}, effect="warn"),
                            rule("R3", when={"frontmatter_missing": "owner"}, effect="warn", enforcement="advisory")))
    report = scan_upload(_demo_zip(), "demo.zip", "auto", None, raw)
    emitted = {f["id"] for entry in report["files"] for f in entry["findings"]}
    emitted |= {f["id"] for f in report["package_analysis"]["format_findings"]}
    assert emitted <= known_finding_ids()
    evaluation = report["policy_evaluation"]
    assert evaluation["status"] == "applied"
    rows = {row["id"]: row for row in evaluation["rules"]}
    assert rows["R1"]["triggered"] and rows["R1"]["evidence"][0]["finding_id"] == "hardcoded_secret"
    assert rows["R2"]["triggered"] and rows["R3"]["triggered"]
    # The policy report never copies the secret value.
    assert "sk_live_Q7w8" not in json.dumps(evaluation)


# ---------------------------------------------------------------- evidence input

def test_evidence_input_reports_every_outcome():
    sha = "a" * 64
    assert evidence_input_report(None, sha) == {"status": "none", "reasons": []}
    assert evidence_input_report({}, sha)["status"] == "none"
    assert evidence_input_report([1], sha)["status"] == "rejected"
    missing = evidence_input_report({"source_control": {"status": "pass"}}, sha)
    assert missing["status"] == "ignored" and "No artifact_sha256" in missing["reasons"][0]
    mismatch = evidence_input_report({"artifact_sha256": "b" * 64, "source_control": {}}, sha)
    assert mismatch["status"] == "ignored" and any("hash mismatch" in r for r in mismatch["reasons"])
    unknown = evidence_input_report({"artifact_sha256": sha, "colour": "blue", "zzz": 1}, sha)
    assert unknown["status"] == "ignored"
    assert any("No recognised evidence keys" in r for r in unknown["reasons"])
    assert any("Unknown keys ignored: colour, zzz." == r for r in unknown["reasons"])
    applied = evidence_input_report({"artifact_sha256": sha, "source_control": {}, "extra": 1}, sha)
    assert applied["status"] == "applied" and any("extra" in r for r in applied["reasons"])
    rejected = evidence_input_report({"envelope": {"payload": {}}}, sha, {"status": "not_verified", "reason": "untrusted"})
    assert rejected["status"] == "rejected"


def test_scan_reports_ignored_evidence_instead_of_dropping_it():
    report = scan_upload(b"# Notes\n", "notes.md", "auto", {"artifact_sha256": "0" * 64, "independent_review": {}})
    assert report["evidence_input"]["status"] == "ignored"
    assert any("hash mismatch" in reason for reason in report["evidence_input"]["reasons"])
    assert scan_upload(b"# Notes\n", "notes.md")["evidence_input"]["status"] == "none"


def test_scan_upload_accepts_a_parsed_policy_dict_and_always_reports_sections():
    report = scan_upload(_demo_zip(), "demo.zip", org_policy=policy(rule(when={"finding": "secret_exfiltration"})))
    evaluation = report["policy_evaluation"]
    assert evaluation["status"] == "applied"
    assert any("hardcoded_secret" in warning["message"] for warning in evaluation["warnings"])
    plain = scan_upload(_demo_zip(), "demo.zip")
    assert plain["policy_evaluation"]["schema"] == "injecticide-policy-results/v1"
    assert plain["policy_evaluation"]["status"] == "none"
    assert plain["evidence_input"]["status"] == "none"
    covered = {fid for item in plain["fix_summary"]["items"] if item["priority"] != "info" for fid in item["finding_ids"]}
    actionable = {f["id"] for entry in plain["files"] for f in entry["findings"] if f.get("tier") in {"review", "block"}}
    assert actionable <= covered
    causes = [item["cause"] for item in plain["fix_summary"]["items"]]
    assert len(causes) == len(set(causes))
