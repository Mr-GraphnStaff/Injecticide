import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from webapp.api import _session_view, cancel_test, test_sessions


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
