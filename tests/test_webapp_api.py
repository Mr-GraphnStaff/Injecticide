import pathlib
import sqlite3
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from webapp.api import _session_view, app, cancel_test, get_build_info, test_sessions


def _build_sqlite_bytes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        db_path = handle.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE records (email TEXT, ssn TEXT, dob TEXT, mrn TEXT, diagnosis TEXT)"
        )
        conn.execute(
            "INSERT INTO records (email, ssn, dob, mrn, diagnosis) VALUES (?, ?, ?, ?, ?)",
            ("jane.doe@hospital.org", "123-45-6789", "1984-04-12", "MRN-778899", "diabetes"),
        )
        conn.commit()
        conn.close()

        with open(db_path, "rb") as handle:
            return handle.read()
    finally:
        import os

        os.unlink(db_path)


def test_session_view_includes_progress_total_tests_and_summary():
    session = {
        "session_id": "session-1",
        "status": "running",
        "total_payloads": 4,
        "completed_payloads": 2,
        "results": [
            {"flags": {"system_prompt_leak": True}},
            {"flags": {"system_prompt_leak": False}},
        ],
    }

    view = _session_view(session)

    assert view["progress"] == 2
    assert view["total_tests"] == 4
    assert view["summary"]["total_tests"] == 2
    assert view["summary"]["vulnerabilities_detected"] == 1


@pytest.mark.asyncio
async def test_cancel_test_marks_session_for_cancellation():
    session_id = "session-cancel"
    test_sessions[session_id] = {
        "session_id": session_id,
        "status": "running",
        "cancel_requested": False,
        "results": [],
        "total_payloads": 3,
        "completed_payloads": 1,
    }

    try:
        response = await cancel_test(session_id)
    finally:
        test_sessions.pop(session_id, None)

    assert response["status"] == "cancelling"
    assert response["progress"] == 1
    assert response["total_tests"] == 3


def test_get_build_info_includes_display_version():
    build = get_build_info()

    assert build["app_version"]
    assert build["display_version"]
    assert "git_commit" in build
    assert build["asset_version"]


def test_scan_api_allows_binary_reference_db_upload():
    client = TestClient(app)

    response = client.post(
        "/api/skills/scan",
        files={
            "file": (
                "hub-commercial-lines/references/hub_commercial_lines.db",
                b"SQLite format 3\x00" + b"X" * 256,
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total_files"] == 1
    assert payload["files"][0]["skipped"] is True
    assert payload["files"][0]["reason"] == "Binary or non-text content"


def test_scan_api_allows_upload_above_legacy_limit():
    client = TestClient(app)

    response = client.post(
        "/api/skills/scan",
        files={
            "file": (
                "large-reference.bin",
                b"\x00" * (11 * 1024 * 1024),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total_files"] == 1
    assert payload["files"][0]["skipped"] is True


def test_scan_api_detects_sqlite_pii_phi():
    client = TestClient(app)

    response = client.post(
        "/api/skills/scan",
        files={
            "file": (
                "hub-commercial-lines/references/hub_commercial_lines.db",
                _build_sqlite_bytes(),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["files"][0]["findings"]}
    assert "pii_email_address" in finding_ids
    assert "pii_ssn" in finding_ids
    assert "phi_patient_record" in finding_ids


def test_architecture_options_lists_profiles_and_scenarios():
    client = TestClient(app)

    response = client.get("/api/architecture/options")

    assert response.status_code == 200
    payload = response.json()
    assert any(profile["id"] == "mcp_grouped_agent" for profile in payload["profiles"])
    assert any(
        scenario["id"] == "poisoned_retrieval_to_enterprise_write"
        for scenario in payload["scenarios"]
    )


def test_architecture_analysis_endpoint_returns_trace():
    client = TestClient(app)

    response = client.post(
        "/api/architecture/analyze",
        json={
            "profile_id": "mcp_grouped_agent",
            "scenario_id": "model_output_to_code_exec",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["finding_id"] for finding in payload["trace"]["findings"]}
    assert payload["trace"]["scenario_id"] == "model_output_to_code_exec"
    assert "tool_invocation_abuse" in finding_ids
    assert "memory_contamination" in finding_ids


def _org_policy_text(finding_id="pii_email_address"):
    import json

    return json.dumps({
        "schema": "injecticide-org-policy/v1", "organization": "Example Org (fictional)",
        "policy_name": "API test", "compiled_date": "2026-11-01",
        "sources": [{"id": "S1", "title": "Example standard"}],
        "rules": [{"id": "R1", "title": "Contact data needs review", "source": "S1",
                   "requirement": "Contact data requires approval.", "when": {"finding": finding_id},
                   "effect": "require_approval", "enforcement": "mandatory", "approver": "Privacy team"}],
    })


def test_scan_api_forwards_org_policy_and_returns_policy_and_fix_summary():
    client = TestClient(app)

    response = client.post(
        "/api/skills/scan",
        files={"file": ("records.db", _build_sqlite_bytes(), "application/octet-stream")},
        data={"org_policy": _org_policy_text()},
    )

    assert response.status_code == 200
    payload = response.json()
    evaluation = payload["policy_evaluation"]
    assert evaluation["status"] == "applied"
    assert evaluation["rules"][0]["triggered"] is True
    assert evaluation["effect_summary"]["require_approval"] == 1
    assert payload["fix_summary"]["items"]
    assert payload["evidence_input"] == {"status": "none", "reasons": []}


def test_scan_api_invalid_org_policy_is_reported_not_rejected():
    client = TestClient(app)

    response = client.post(
        "/api/skills/scan",
        files={"file": ("notes.md", b"# Notes\n", "text/markdown")},
        data={"org_policy": _org_policy_text("secret_in_file")},
    )

    assert response.status_code == 200
    evaluation = response.json()["policy_evaluation"]
    assert evaluation["status"] == "invalid"
    assert evaluation["errors"][0]["suggestion"] == "hardcoded_secret"


def test_scan_api_without_org_policy_reports_none():
    client = TestClient(app)

    response = client.post("/api/skills/scan", files={"file": ("notes.md", b"# Notes\n", "text/markdown")})

    assert response.status_code == 200
    assert response.json()["policy_evaluation"]["status"] == "none"


def test_scan_api_sandbox_forwarding_includes_org_policy(monkeypatch):
    from webapp import api as api_module

    captured = {}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"files": [], "summary": {}}

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, files=None, data=None, timeout=None):
            captured.update(data)
            return FakeResponse()

    monkeypatch.setattr(api_module.requests, "Session", FakeSession)
    monkeypatch.setattr(api_module, "attach_vendor_check", lambda result: result)
    api_module._scan_skill_data(b"x", "x.md", "text/markdown", "auto", "{}", "http://sandbox.invalid", "{\"p\": 1}")
    assert captured == {"target_runtime": "auto", "governance_evidence": "{}", "org_policy": "{\"p\": 1}"}
    captured.clear()
    api_module._scan_skill_data(b"x", "x.md", "text/markdown", "auto", "{}", "http://sandbox.invalid")
    assert captured == {"target_runtime": "auto", "governance_evidence": "{}"}
