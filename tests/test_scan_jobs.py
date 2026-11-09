import threading
import time

import pytest
import requests
from fastapi.testclient import TestClient

import webapp.api as api
from webapp.scan_jobs import ScanJobs


def wait_for(client, url):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(url)
        if response.status_code != 202:
            return response
        time.sleep(.01)
    raise AssertionError("Background job did not finish")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api, "SKILL_SCAN_JOBS", ScanJobs())
    monkeypatch.setattr(api, "SKILL_SCAN_SLOT", threading.BoundedSemaphore(1))
    return TestClient(api.app)


def submit(client, **extra):
    return client.post("/api/skills/scan", data={"background": "true", **extra},
                       files={"file": ("SKILL.md", b"Read documentation.", "text/markdown")})


def test_background_returns_before_work_and_preserves_receipt(client, monkeypatch):
    started, finish = threading.Event(), threading.Event()
    def scan(*args, **kwargs):
        started.set()
        assert finish.wait(5)
        return {"filename": "SKILL.md", "local_analysis": {"status": "partial"}}
    monkeypatch.setattr(api, "_scan_skill_data", scan)
    try:
        before = time.monotonic()
        response = submit(client)
        assert response.status_code == 202
        assert time.monotonic() - before < 2
        assert started.wait(1)
        assert response.headers["cache-control"] == "no-store"
        receipt = response.json()
        assert len(receipt["job_id"]) == 32
        url = receipt["status_url"]
        assert client.get(url).status_code == 202
        assert submit(client).status_code == 429
        finish.set()
        completed = wait_for(client, url)
        assert completed.status_code == 200
        assert completed.json()["result"]["scan_request_id"] == receipt["scan_request_id"]
        assert completed.json()["result"]["local_analysis"]["status"] == "partial"
        assert client.get(url).json() == completed.json()
    finally:
        finish.set()


def test_background_failure_is_sanitized_and_releases_admission(client, monkeypatch):
    def fail(*args, **kwargs):
        raise requests.Timeout("private source must never escape")
    monkeypatch.setattr(api, "_scan_skill_data", fail)
    receipt = submit(client).json()
    failure = wait_for(client, receipt["status_url"])
    assert failure.json()["status"] == "failed"
    assert failure.json()["http_status"] == 502
    assert "private source" not in failure.text
    monkeypatch.setattr(api, "_scan_skill_data", lambda *a, **kw: {"filename": "SKILL.md"})
    next_job = submit(client)
    assert next_job.status_code == 202
    assert wait_for(client, next_job.json()["status_url"]).json()["status"] == "completed"


def test_job_keys_are_validated_and_unknown_results_are_not_cached(client):
    for key in ["not-a-job", "a" * 32]:
        response = client.get("/api/skills/scan/jobs/" + key)
        assert response.status_code == 404
        assert response.headers["cache-control"] == "no-store"


def test_rejected_input_does_not_consume_scan_slot(client, monkeypatch):
    assert submit(client, target_runtime="unsupported").status_code == 400
    monkeypatch.setattr(api, "_scan_skill_data", lambda *a, **kw: {})
    receipt = submit(client)
    assert receipt.status_code == 202
    assert wait_for(client, receipt.json()["status_url"]).json()["status"] == "completed"


def test_failed_thread_start_returns_slot_and_removes_receipt(client, monkeypatch):
    import webapp.scan_jobs as jobs
    class Broken:
        def __init__(self, **kwargs): pass
        def start(self): raise RuntimeError("private internals")
    with monkeypatch.context() as patch:
        patch.setattr(jobs.threading, "Thread", Broken)
        # TestClient itself needs Thread, so exercise submission directly.
        with pytest.raises(RuntimeError):
            api.SKILL_SCAN_JOBS.submit(lambda: (200, {}), lambda: None)
        assert api.SKILL_SCAN_JOBS.jobs == {}
    monkeypatch.setattr(api, "_scan_skill_data", lambda *a, **kw: {})
    receipt = submit(client)
    assert receipt.status_code == 202
    assert wait_for(client, receipt.json()["status_url"]).json()["status"] == "completed"


def test_completed_receipts_are_bounded_and_expire():
    now = [10.]
    store = ScanJobs(clock=lambda: now[0])
    keys = []
    for _ in range(3):
        released = threading.Event()
        key = store.submit(lambda: (200, {"safe": True}), released.set)
        assert released.wait(2)
        deadline = time.monotonic() + 2
        while store.get(key)["status"] == "running" and time.monotonic() < deadline:
            time.sleep(.01)
        keys.append(key)
    assert store.get(keys[0]) is None
    assert len(store.jobs) == 2
    now[0] += 601
    assert store.get(keys[-1]) is None
    assert store.jobs == {}


def test_handoff_failure_returns_admission_to_next_request(client, monkeypatch):
    def broken(*args):
        raise RuntimeError("private internals")
    with monkeypatch.context() as patch:
        patch.setattr(api.SKILL_SCAN_JOBS, "submit", broken)
        response = submit(client)
        assert response.status_code == 500
        assert "private internals" not in response.text
    monkeypatch.setattr(api, "_scan_skill_data", lambda *a, **kw: {})
    receipt = submit(client)
    assert receipt.status_code == 202
    assert wait_for(client, receipt.json()["status_url"]).json()["status"] == "completed"
