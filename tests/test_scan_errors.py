import json

import pytest

from research_mcp.scan_errors import ScanErrors, SCHEMA
from test_scan_learning import learning


def event(number=1, **changes):
    return {"schema": SCHEMA, "event_id": format(number, "032x"), "http_status": 502,
            "stage": "sandbox", "kind": "Timeout", "scanner_version": "0.17.0", **changes}


def test_issue_deduplication_restart_and_review(learning):
    errors = ScanErrors(learning.catalog)
    first = errors.enqueue(event())
    assert errors.enqueue(event())["duplicate"] is True
    errors.enqueue(event(2))
    reopened = ScanErrors(learning.catalog)
    item = reopened.list()["items"][0]
    assert item["occurrences"] == 2 and item["state"] == "untriaged"
    assert item["confirmed_bug"] is False
    assert len(item["recent_request_ids"]) == 2
    with pytest.raises(ValueError):
        errors.review(first["id"], "confirmed", 1)
    errors.review(first["id"], "resolved", 2)
    errors.enqueue(event(3))
    assert errors.list()["items"][0]["state"] == "untriaged"
    assert errors.list(item["cursor"])["items"][0]["occurrences"] == 3


@pytest.mark.parametrize("change", [{"message": "private source"}, {"http_status": 400},
    {"http_status": 429}, {"stage": "private path"}, {"kind": "private payload"}])
def test_issue_ingest_rejects_content_and_expected_input_errors(learning, change):
    with pytest.raises(ValueError):
        ScanErrors(learning.catalog).enqueue(event(**change))


def test_exception_messages_are_not_submitted(monkeypatch):
    import webapp.scan_feedback as publisher
    seen = []
    monkeypatch.setattr(publisher, "_submit", lambda payload, route: seen.append((payload, route)) or {"status": "recorded"})
    result = publisher.submit_scan_error("a"*32, 502, "sandbox", "Timeout")
    assert result["status"] == "recorded"
    assert seen[0][1] == "/feedback/error"
    assert seen[0][0]["kind"] == "Timeout"
    assert "message" not in seen[0][0]


def test_failed_public_scan_is_reported_and_invalid_upload_is_not(monkeypatch):
    import requests
    import webapp.api as api
    calls = []
    monkeypatch.setattr(api, "submit_scan_error", lambda *args: calls.append(args) or {"status": "recorded"})
    def timeout(*a, **kw):
        raise requests.Timeout("uploaded private data")
    monkeypatch.setattr(api, "_scan_skill_data", timeout)
    status, result = api._execute_skill_scan(b"x", "private.md", "text/plain", "auto", "{}", "", None, "a"*32, 0)
    assert status == 502
    assert len(calls) == 1 and calls[0][-1] == "Timeout"
    assert result["detail"]["bug_report"]["status"] == "recorded"
    assert "private" not in json.dumps(result)
    monkeypatch.setattr(api, "_scan_skill_data", lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad input")))
    assert api._execute_skill_scan(b"x", "private.md", "text/plain", "auto", "{}", "", None, "b"*32, 0)[0] == 400
    assert len(calls) == 1
