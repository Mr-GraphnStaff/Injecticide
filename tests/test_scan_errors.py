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


@pytest.mark.parametrize("failure_point", ["upload", "job_submission"])
def test_submission_failures_record_safe_issue_and_release_slot(monkeypatch,failure_point):
    import asyncio
    from types import SimpleNamespace
    import webapp.api as api
    private="patient-private-4111111111111111"
    calls=[]
    monkeypatch.setattr(api,"submit_scan_error",lambda *args:calls.append(args) or {"status":"recorded"})
    class Upload:
        filename="private-name.md"
        content_type="text/markdown"
        closed=False
        async def read(self,limit):
            if failure_point=="upload":raise OSError(private)
            return b"Read public documentation."
        async def close(self):self.closed=True
    if failure_point=="job_submission":
        def fail_submit(*args):raise RuntimeError(private)
        monkeypatch.setattr(api.SKILL_SCAN_JOBS,"submit",fail_submit)
    upload=Upload()
    response=asyncio.run(api.scan_skill_file(
        SimpleNamespace(state=SimpleNamespace(scan_request_id="c"*32)),
        file=upload,target_runtime="auto",governance_evidence="{}",org_policy="",
        use_local_llm=None,background=failure_point=="job_submission"))
    detail=json.loads(response.body)["detail"]
    assert response.status_code==500 and detail["bug_report"]=={"status":"recorded"}
    assert calls==[("c"*32,500,"upload" if failure_point=="upload" else "analysis",
                    "OSError" if failure_point=="upload" else "RuntimeError")]
    assert private not in response.body.decode() and upload.closed
    assert api.SKILL_SCAN_SLOT.acquire(blocking=False)
    api.SKILL_SCAN_SLOT.release()


@pytest.mark.parametrize("stage",["validation","upload"])
def test_submission_stage_is_accepted_by_publisher_and_ingest(monkeypatch,learning,stage):
    import webapp.scan_feedback as publisher
    errors=ScanErrors(learning.catalog)
    seen=[]
    def submit(payload,route):
        seen.append(payload)
        errors.enqueue(payload)
        return {"status":"recorded"}
    monkeypatch.setattr(publisher,"_submit",submit)
    assert publisher.submit_scan_error("d"*32,500,stage,"OSError")=={"status":"recorded"}
    assert seen[0]["stage"]==stage
    assert errors.list()["items"][0]["occurrences"]==1
