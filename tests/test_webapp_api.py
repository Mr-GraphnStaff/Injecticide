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
