"""Failure/recovery acceptance uses virtual time; no live source or model calls."""
import pytest

from research_mcp.collector import Collector
from research_mcp.recovery import TriageRecovery, health_status


def test_triage_recovers_without_recollecting_or_waiting_a_day(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("research_mcp.collector.time.monotonic", lambda: clock[0])
    worker = Collector(None, interval=86400)
    collections, attempts, failures = [], [], []

    def collect(_):
        collections.append(clock[0])
        return {"attempted": 88}

    def triage():
        attempts.append(clock[0])
        if len(attempts) == 1:
            raise OSError("private source text must not be reported")
        worker.stop_event.set()

    class Wake:
        def clear(self):
            pass

        def wait(self, seconds):
            failures.append(worker.triage.status.copy())
            clock[0] += seconds
            assert clock[0] <= 330, "recovery must not wait for daily collection"

    worker.collect = collect
    worker.after_collection = triage
    worker.wake = Wake()
    worker.run()
    assert collections == [0]
    assert attempts == [0, 300]
    assert any(s["state"] == "retry_wait" and s["last_error"] == "OSError" for s in failures)
    assert worker.triage.status["state"] == "current"
    assert worker.triage.status["last_error"] is None


def test_failed_triage_exhausts_budget_without_busy_loop_or_disclosing_values(caplog):
    clock, attempts = [0.0], []

    def fail():
        attempts.append(clock[0])
        raise ValueError("PRIVATE-CONTACT-123")

    recovery = TriageRecovery(fail, clock=lambda: clock[0])
    recovery.schedule()
    recovery.run_due()
    clock[0] = 299
    recovery.schedule()  # another collection cannot postpone/reset a pending retry
    recovery.run_due()
    assert attempts == [0]
    clock[0] = 300
    recovery.run_due()
    clock[0] = 900
    recovery.run_due()
    clock[0] = 99999
    recovery.run_due()
    assert attempts == [0, 300, 900]
    assert recovery.status["state"] == "exhausted"
    assert recovery.status["last_error"] == "ValueError"
    assert recovery.status["retry_after_seconds"] is None
    assert "PRIVATE-CONTACT-123" not in caplog.text
    assert health_status(True, None, recovery.status, None) == "triage_failed"


@pytest.mark.parametrize("alive,collection,recovery,persisted,expected", [
    (False, None, {}, None, "worker_stopped"),
    (True, "OSError", {}, None, "collection_failed"),
    (True, None, {"last_error": "ValueError"}, None, "triage_failed"),
    (True, None, {"last_error": None}, "ValueError", "triage_failed"),
    (True, None, {"last_error": None}, None, "ok"),
])
def test_health_includes_persisted_failure_after_restart(alive, collection, recovery, persisted, expected):
    assert health_status(alive, collection, recovery, persisted) == expected

def test_http_health_exposes_failure_and_recovers_without_model_calls(tmp_path):
    pytest.importorskip("mcp")
    import json
    from starlette.testclient import TestClient
    from research_mcp.catalog import Catalog
    from research_mcp.server import create_server

    sources = tmp_path / "sources.json"
    sources.write_text(json.dumps({"sources": [{
        "id": "fixture", "ecosystem": "fixture",
        "seeds": ["https://example.org/docs/"],
        "scopes": ["https://example.org/docs/"], "discovery": False,
    }]}))
    catalog = Catalog(tmp_path / "catalog.sqlite3", sources)
    worker = Collector(catalog)
    app = create_server(catalog, worker, start_collector=False)
    with TestClient(app.streamable_http_app(stateless_http=True),
                    base_url="http://127.0.0.1") as client:
        assert client.get("/health").status_code == 200
        with catalog.db() as db:
            db.execute("UPDATE obsession_state SET last_error='ValueError',next_due=0 WHERE singleton=1")
        failed = client.get("/health")
        assert failed.status_code == 503
        assert failed.json()["status"] == "triage_failed"
        assert failed.headers["cache-control"] == "no-store"
        worker.triage.schedule()
        worker.triage.run_due()
        healthy = client.get("/health")
        assert healthy.status_code == 200
        assert healthy.json()["triage_last_error"] is None
        assert healthy.json()["triage_recovery"]["state"] == "current"


def test_deferred_triage_wakes_when_due_between_daily_collections(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("research_mcp.collector.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("research_mcp.recovery.time.time", lambda: 1000 + clock[0])
    worker = Collector(None, interval=86400)
    collections, attempts, states = [], [], []

    def collect(_):
        collections.append(clock[0])
        return {"attempted": 0}

    def triage():
        attempts.append(clock[0])
        if len(attempts) == 1:
            return {"status": "not_due_or_locked", "next_due": 1050}
        worker.stop_event.set()
        return {"status": "completed"}

    class Wake:
        def clear(self):
            pass

        def wait(self, seconds):
            states.append(worker.triage.status.copy())
            clock[0] += seconds
            assert clock[0] <= 80, "a deferred due time must not wait for tomorrow's capture"

    worker.collect = collect
    worker.after_collection = triage
    worker.wake = Wake()
    worker.run()
    assert collections == [0]
    assert attempts == [0, 50]
    assert any(s["state"] == "deferred" and s["last_success"] is None for s in states)
    assert worker.triage.status["state"] == "current"
    assert worker.triage.status["attempts"] == 1


@pytest.mark.parametrize("next_due", [None, float("nan"), float("inf"), "future"])
def test_invalid_deferred_schedule_fails_visibly_without_a_busy_loop(next_due):
    recovery = TriageRecovery(lambda: {"status": "not_due_or_locked", "next_due": next_due}, clock=lambda: 0)
    recovery.schedule()
    recovery.run_due()
    assert recovery.status["last_error"] == "ValueError"
    assert recovery.status["state"] == "retry_wait"
    assert recovery.wait_seconds() == 300


def test_held_triage_lease_is_revisited_without_burning_failure_attempts(monkeypatch):
    clock, calls = [0], []
    monkeypatch.setattr("research_mcp.recovery.time.time", lambda: 1000)
    def locked():
        calls.append(clock[0])
        return {"status": "not_due_or_locked", "next_due": 999}
    recovery = TriageRecovery(locked, clock=lambda: clock[0])
    recovery.schedule()
    recovery.run_due()
    recovery.run_due()
    assert calls == [0]
    clock[0] = 30
    recovery.run_due()
    assert calls == [0, 30]
    assert recovery.status["attempts"] == 0
    assert recovery.status["state"] == "deferred"
    assert recovery.status["last_success"] is None
