"""Static recommendations use report evidence, never executable source samples."""
import copy
import json

from skill_sandbox.improvement_plan import build_improvement_plan


def requirement(rule="name_required", **changes):
    return {"id": rule, "category": "format", "requirement_level": "mandatory", "status": "fail",
            "path": "demo/SKILL.md", "line": 2, "sources": [{"url": "https://agentskills.io/specification.md", "section": "name"}], **changes}


def report(rows=(), findings=()):
    return {"standards_assessment": {"requirements": list(rows)},
            "files": [{"path": "demo/SKILL.md", "findings": list(findings)}],
            "scanner_metadata": {"scanner_version": "test"},
            "governance_evidence": {"artifact_sha256": "a" * 64}}


def test_mandatory_failure_and_advisory_failure_are_separate():
    plan = build_improvement_plan(report([requirement(), requirement("body_line_guidance", requirement_level="recommendation")]))
    required, advisory = plan["items"][:2]
    assert required["category"] == "mandatory_format" and required["priority"] == "required"
    assert advisory["category"] == "recommendation" and advisory["priority"] == "normal"
    assert "advisory" in advisory["action"] and "controls" in advisory["action"]
    assert required["sources"][0] == {"path": "demo/SKILL.md", "line": 2}
    assert plan["artifact_sha256"] == "a" * 64 and plan["scanner_version"] == "test"


def test_unknown_mandatory_check_is_not_a_confirmed_failure_or_invented_fix():
    plan = build_improvement_plan(report([requirement("future_constraint", status="not_assessed")]))
    item = next(row for row in plan["items"] if row["rule_id"] == "future_constraint")
    assert item["category"] == "manual_assessment" and item["priority"] == "manual"
    assert "missing evidence" in item["action"]


def test_security_priorities_follow_existing_tier_and_severity_without_samples():
    findings = [{"id": "dynamic_exec", "tier": "review", "severity": "high", "is_actionable": True,
                 "observations": [{"line": 8, "text": "PRIVATE_EXAMPLE_DO_NOT_REFLECT"}]}]
    plan = build_improvement_plan(report(findings=findings))
    item = plan["items"][0]
    assert item["category"] == "security_review" and item["priority"] == "high"
    assert item["line"] == 8 and "prose mention" in item["action"]
    assert "not proof" in item["reason"] and "PRIVATE_EXAMPLE" not in json.dumps(plan)


def test_contact_review_never_repeats_pii_and_unknown_rule_has_generic_review():
    findings = [{"id": rule, "tier": "review", "observations": [{"line": 4, "text": "person@private.invalid"}]} for rule in ("pii_email_address", "new_future_rule")]
    plan = build_improvement_plan(report(findings=findings))
    assert "person@private.invalid" not in json.dumps(plan)
    actions = {row["rule_id"]: row["action"] for row in plan["items"]}
    assert "disclosure necessity" in actions["pii_email_address"]
    assert "source context" in actions["new_future_rule"]


def test_cross_file_flow_carries_source_origin_without_secret_sample():
    finding = {"id": "credential_source_to_network_payload", "tier": "review", "severity": "high",
               "observations": [{"line": 8, "evidence_scope": "package_interprocedural", "sources": [{"path": "scripts/source.py", "line": 4, "text": "PRIVATE_SAMPLE"}]}]}
    source = report(findings=[finding])
    source["files"].append({"path": "scripts/source.py", "findings": []})
    item = build_improvement_plan(source)["items"][0]
    assert {"path": "scripts/source.py", "line": 4} in item["sources"]
    assert "PRIVATE_SAMPLE" not in json.dumps(item)


def test_legacy_operand_is_never_fabricated_as_a_source_filename():
    finding = {"id": "credential_source_to_network_payload", "tier": "review", "severity": "high",
               "observations": [{"line": 8, "source": "demo/SKILL.md", "evidence_scope": "conservative_intraprocedural_value_flow",
                                 "sources": [{"path": "API_TOKEN", "line": 4}]}]}
    item = build_improvement_plan(report(findings=[finding]))["items"][0]
    assert {"path": "demo/SKILL.md", "line": 4} in item["sources"]
    assert not any(row.get("path") == "API_TOKEN" for row in item["sources"])


def test_documented_info_is_not_automatically_promoted_and_line_accuracy_preserved():
    findings = [{"id": "documented", "tier": "info", "observations": [{"line": 2}]},
                {"id": "other", "tier": "review", "observations": [{"line": 1, "line_accuracy": "file_only"}]}]
    rows = build_improvement_plan(report(findings=findings))["items"]
    assert not any(row["rule_id"] == "documented" for row in rows)
    assert next(row for row in rows if row["rule_id"] == "other")["line"] is None


def test_deduplication_keeps_distinct_physical_locations():
    finding = {"id": "dynamic_exec", "tier": "review", "observations": [{"line": 4}, {"line": 4}, {"line": 7}]}
    rows = build_improvement_plan(report(findings=[finding, finding]))["items"]
    assert [row["line"] for row in rows if row["rule_id"] == "dynamic_exec"] == [4, 7]
    assert len({row["id"] for row in rows}) == len(rows)


def test_bounds_disclose_omitted_items_and_prioritize_required(monkeypatch):
    monkeypatch.setattr("skill_sandbox.improvement_plan.MAX_ITEMS", 2)
    findings = [{"id": "review_" + str(i), "tier": "review"} for i in range(5)]
    plan = build_improvement_plan(report([requirement()], findings))
    assert len(plan["items"]) == 2 and plan["items"][0]["priority"] == "required"
    assert {"kind": "item_budget", "omitted_items": 5} in plan["limits"]


def test_work_budget_is_explicit_and_does_not_claim_all_input_assessed(monkeypatch):
    monkeypatch.setattr("skill_sandbox.improvement_plan.MAX_INPUT_ROWS", 2)
    plan = build_improvement_plan(report([requirement(str(i)) for i in range(20)]))
    assert any(row["kind"] == "input_row_budget" and row["remaining_input"] == "not_assessed" for row in plan["limits"])


def test_token_guidance_is_advisory_and_runtime_questions_remain_explicit():
    source = report()
    source["token_footprint"] = {"skills": [{"path": "demo/SKILL.md", "guidance": ["present"]}]}
    rows = build_improvement_plan(source)["items"]
    assert any(row["rule_id"] == "token_loading_optimization" and row["category"] == "recommendation" and row["line"] is None for row in rows)
    assert any(row["rule_id"] == "runtime_control_enforcement" and row["status"] == "not_assessed" for row in rows)


def test_deterministic_read_only_and_no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("No network")))
    source = report([requirement()])
    before = copy.deepcopy(source)
    assert build_improvement_plan(source) == build_improvement_plan(source)
    assert source == before
