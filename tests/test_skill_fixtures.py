from pathlib import Path

from webapp.skill_scanner import scan_upload


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "skills"


def _scan_fixture(path: Path):
    skill_file = path / "SKILL.md"
    return scan_upload(skill_file.read_bytes(), str(path.name))


def test_clean_read_only_fixture_has_no_findings():
    result = _scan_fixture(FIXTURES_DIR / "clean" / "read_only_reporter.skill")

    assert result["summary"]["flagged_files"] == 0
    assert result["summary"]["total_findings"] == 0
    assert result["risk_classification"]["overall_risk"] == "low"


def test_jira_governance_fixture_has_no_findings():
    result = _scan_fixture(FIXTURES_DIR / "clean" / "jira_infosec_management.skill")

    assert result["summary"]["flagged_files"] == 0
    assert result["summary"]["total_findings"] == 0
    assert result["risk_classification"]["overall_risk"] == "medium"
    assert result["risk_classification"]["recommendation"] == "allow_with_warnings"


def test_security_architect_fixture_has_only_informational_sensitive_topic():
    result = _scan_fixture(FIXTURES_DIR / "clean" / "security_architect.skill")

    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "secret_exfiltration" not in finding_ids
    assert "sensitive_topic" in finding_ids


def test_token_saver_fixture_has_no_secret_exfiltration():
    result = _scan_fixture(FIXTURES_DIR / "clean" / "token_saver.skill")

    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "secret_exfiltration" not in finding_ids
    assert "sensitive_topic" not in finding_ids


def test_borderline_enterprise_audit_fixture_is_unknown_not_flagged():
    result = _scan_fixture(FIXTURES_DIR / "borderline" / "enterprise_audit_helper.skill")

    assert result["summary"]["flagged_files"] == 0
    assert result["summary"]["total_findings"] == 0
    assert result["risk_classification"]["overall_risk"] == "medium"
    assert result["risk_classification"]["recommendation"] in {"allow_with_warnings", "require_admin_approval"}


def test_bad_red_team_fixture_triggers_expected_findings():
    result = _scan_fixture(FIXTURES_DIR / "bad" / "red-team.skill")

    assert result["summary"]["flagged_files"] == 1
    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "prompt_override" in finding_ids
    assert "system_exfiltration" in finding_ids
    assert "tool_escape" in finding_ids
    assert "subprocess_spawn" in finding_ids


def test_bad_autonomous_authoritative_write_fixture_triggers_expected_findings():
    result = _scan_fixture(FIXTURES_DIR / "bad" / "autonomous_authoritative_write.skill")

    assert result["summary"]["flagged_files"] == 1
    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "autonomous_authoritative_write" in finding_ids


def test_bad_bulk_enterprise_modification_fixture_triggers_expected_findings():
    result = _scan_fixture(FIXTURES_DIR / "bad" / "bulk_enterprise_modification.skill")

    assert result["summary"]["flagged_files"] == 1
    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "bulk_enterprise_modification" in finding_ids


def test_bad_workflow_manipulation_fixture_triggers_expected_findings():
    result = _scan_fixture(FIXTURES_DIR / "bad" / "workflow_manipulation.skill")

    assert result["summary"]["flagged_files"] == 1
    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "workflow_manipulation" in finding_ids


def test_bad_cross_system_automation_fixture_triggers_expected_findings():
    result = _scan_fixture(FIXTURES_DIR / "bad" / "cross_system_automation.skill")

    assert result["summary"]["flagged_files"] == 1
    findings = result["files"][0]["findings"]
    finding_ids = {finding["id"] for finding in findings}

    assert "cross_system_automation" in finding_ids
