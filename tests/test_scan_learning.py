import json
import time
from pathlib import Path

import pytest

from research_mcp.catalog import Catalog
from research_mcp.fetch import Response
from research_mcp.scan_learning import ScanLearning, SCHEMA
from webapp.scan_feedback import statistics

URL = "https://example.org/research/"
TEXT = "Prompt injection uses untrusted instructions. Review source boundaries."


def event(number=1):
    return {"schema": SCHEMA, "event_id": format(number, "032x"),
            "coverage": "partial", "rules": {"prompt_override": 1},
            "scanner_version": "0.18.0", "engine_sha256": None}


@pytest.fixture
def learning(tmp_path, monkeypatch):
    monkeypatch.setenv("INJECTICIDE_RESEARCH_LLM_ENABLED", "1")
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": [{"id": "test", "ecosystem": "test",
        "seeds": [URL], "scopes": [URL]}]}))
    catalog = Catalog(tmp_path / "catalog.sqlite3", config)
    page = catalog.due_pages("test", 1)[0]
    catalog.record(page, Response(URL, 200, {"content-type": "text/plain"}, TEXT.encode()), TEXT, [])
    return ScanLearning(catalog)


def response(proposals=None):
    return {"done": True, "done_reason": "stop", "_local_model_digest": "a"*64,
            "message": {"content": json.dumps({"proposals": proposals or []})}}


def proposal():
    return {"snapshot_id": 1, "quote": "Prompt injection uses untrusted instructions.",
            "summary": "Review source-boundary regression coverage."}


def test_metadata_never_serializes_uploaded_evidence_or_unknown_rule_ids():
    secret = "private_customer_password"
    report = {"filename": secret, "policy": secret, "coverage": {"status": "partial"},
        "files": [{"path": secret, "findings": [
            {"id": "prompt_override", "evidence_excerpt": secret},
            {"id": secret, "detail": secret}]}]}
    value = statistics(report, event()["event_id"])
    assert value == event()
    assert secret not in json.dumps(value)
    assert "artifact_sha256" not in value


def test_durable_dedup_conflict_and_monotonic_pagination(learning):
    learning.enqueue(event(10))
    assert learning.enqueue(event(10))["duplicate"] is True
    learning.enqueue(event(1))
    items = learning.list(limit=1)["items"]
    assert items[0]["event_id"] == event(10)["event_id"]
    assert learning.list(items[0]["cursor"])["items"][0]["event_id"] == event(1)["event_id"]
    with pytest.raises(ValueError):
        learning.enqueue(dict(event(10), coverage="unknown"))
    reopened = ScanLearning(learning.catalog)
    assert sum(reopened.status()["states"].values()) == 2


@pytest.mark.parametrize("extra", [{"text": "uploaded content"}, {"label": "confirmed_safe"},
    {"rules": {"bad": True}}, {"coverage": "safe"}, {"event_id": "not-an-event"}])
def test_strict_ingest_cannot_accept_content_or_training_labels(learning, extra):
    with pytest.raises((ValueError, TypeError)):
        learning.enqueue(dict(event(), **extra))


def test_capacity_preserves_old_records(learning, monkeypatch):
    monkeypatch.setattr("research_mcp.scan_learning.MAX_ITEMS", 1)
    learning.enqueue(event())
    with pytest.raises(OverflowError):
        learning.enqueue(event(2))
    assert learning.list()["items"][0]["event_id"] == event()["event_id"]


def test_sourced_proposal_is_unverified_and_never_activates_rules(learning):
    calls = []
    learning.transport = lambda endpoint, payload: calls.append(payload) or response([proposal()])
    learning.enqueue(event())
    assert learning.cycle()["status"] == "review"
    item = learning.list()["items"][0]
    record = item["proposal"]
    assert record["scanner_rules_updated"] is False
    assert record["model_weights_updated"] is False
    assert record["model"]["digest"] == "a"*64
    assert record["proposals"][0]["url"] == URL
    assert record["proposals"][0]["verification"] == "STATUS: UNKNOWN — UNVERIFIED"
    assert learning.cycle()["status"] == "idle"
    assert len(calls) == 1


def test_fabricated_quote_rejected_with_bounded_durable_retry(learning):
    learning.enqueue(event())
    learning.transport = lambda *a: response([dict(proposal(), quote="Invented source quote")])
    for attempt in range(3):
        assert learning.cycle()["status"] == "unavailable"
        with learning.catalog.db() as db:
            db.execute("UPDATE scan_learning SET retry_at=0")
    item = learning.list()["items"][0]
    assert item["state"] == "failed" and item["attempts"] == 3
    assert item["proposal"] is None
    assert learning.cycle()["status"] == "idle"


def test_no_sources_no_inference_and_model_off_does_not_claim(learning):
    learning.enqueue(event())
    learning.enabled = False
    learning.transport = lambda *a: pytest.fail("model must not be called")
    assert learning.cycle()["status"] == "disabled"
    assert learning.list()["items"][0]["attempts"] == 0
    learning.enabled = True
    learning.catalog.sources["test"]["enabled"] = False
    assert learning.cycle()["status"] == "unavailable"
    assert learning.list()["items"][0]["state"] == "retry"


def test_source_changed_during_inference_rejects_proposal(learning):
    learning.enqueue(event())
    def transport(*a):
        text = "Changed public source without the previous quote."
        page = learning.catalog.due_pages("test", 1)[0]
        learning.catalog.record(page, Response(URL, 200, {"content-type": "text/plain"}, text.encode()), text, [])
        return response([proposal()])
    learning.transport = transport
    assert learning.cycle()["status"] == "unavailable"
    assert learning.list()["items"][0]["proposal"] is None


def test_live_lease_not_claimed_and_exhausted_lease_recovers(learning):
    learning.enqueue(event())
    with learning.catalog.db() as db:
        db.execute("UPDATE scan_learning SET state='processing',retry_at=?,attempts=1", (time.time()+100,))
    assert learning.cycle()["status"] == "idle"
    with learning.catalog.db() as db:
        db.execute("UPDATE scan_learning SET retry_at=0,attempts=3")
    assert learning.cycle()["status"] == "idle"
    assert learning.list()["items"][0]["state"] == "failed"


def test_public_scan_never_calls_model_even_with_old_enable_flags(monkeypatch):
    from skill_sandbox.app import scan_upload
    monkeypatch.setenv("INJECTICIDE_LOCAL_LLM_ENABLED", "1")
    monkeypatch.setattr("skill_sandbox.local_analysis._chat", lambda *a: pytest.fail("scan called model"))
    for flag in (None, True, False):
        report = scan_upload(b"Read documentation.", "SKILL.md", use_local_llm=flag)
        assert not report.get("local_analysis", {}).get("findings")


def test_remote_model_config_rejected_before_content_is_sent(monkeypatch):
    from research_mcp.local_model import complete
    monkeypatch.setenv("INJECTICIDE_LOCAL_LLM_URL", "https://remote.example")
    with pytest.raises(ValueError):
        complete("system", {"private": "data"}, {}, transport=lambda *a: pytest.fail("network"))


def test_feedback_outage_never_changes_scan_result(monkeypatch):
    from webapp.scan_feedback import submit_feedback
    monkeypatch.setenv("INJECTICIDE_SCAN_FEEDBACK_ENABLED", "1")
    monkeypatch.setenv("RESEARCH_MCP_URL", "https://remote.example")
    report = {"files": [], "verdict": "review"}
    assert submit_feedback(report)["status"] == "unavailable"
    assert report == {"files": [], "verdict": "review"}


def test_feedback_publisher_sends_only_statistics(monkeypatch):
    import webapp.scan_feedback as publisher
    captured = []
    class Response:
        status_code = 202
        def __enter__(self): return self
        def __exit__(self, *a): pass
    class Session:
        trust_env = True
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, **kwargs):
            assert self.trust_env is False
            assert url == "http://research_mcp:8200/feedback/scan"
            assert kwargs["allow_redirects"] is False
            captured.append(kwargs["json"])
            return Response()
    monkeypatch.setenv("INJECTICIDE_SCAN_FEEDBACK_ENABLED", "1")
    monkeypatch.setenv("RESEARCH_MCP_URL", "http://research_mcp:8200")
    monkeypatch.setattr(publisher.requests, "Session", Session)
    report = {"filename": "private", "coverage": {"status": "partial"},
              "files": [{"path": "private", "findings": [{"id": "prompt_override", "text": "private"}]}]}
    assert publisher.submit_feedback(report, event()["event_id"])["status"] == "queued"
    assert captured == [event()]


def test_storage_failure_does_not_escape_cycle(learning, monkeypatch):
    from contextlib import contextmanager
    import sqlite3
    @contextmanager
    def broken():
        raise sqlite3.OperationalError("private database path")
        yield
    monkeypatch.setattr(learning.catalog, "db", broken)
    assert learning.cycle()["status"] == "unavailable"
    assert learning.last_error == "OperationalError"
    assert not learning.lock.locked()


def test_internal_queue_route_and_read_only_mcp(learning, monkeypatch):
    pytest.importorskip("mcp")
    import asyncio
    import research_mcp.server as module
    from research_mcp.collector import Collector
    from starlette.requests import Request
    original = module.MCPServer
    captured = {}
    class Capture(original):
        def custom_route(self, path, **kwargs):
            decorate = super().custom_route(path, **kwargs)
            def wrap(fn):
                captured[path] = fn
                return decorate(fn)
            return wrap
    monkeypatch.setattr(module, "MCPServer", Capture)
    server = module.create_server(learning.catalog, Collector(learning.catalog), start_collector=False)
    async def post(value, path='/feedback/scan'):
        async def receive():
            return {"type": "http.request", "body": json.dumps(value).encode(), "more_body": False}
        request = Request({"type": "http", "method": "POST", "path": "/feedback/scan", "headers": []}, receive)
        return await captured[path](request)
    monkeypatch.delenv("INJECTICIDE_SCAN_FEEDBACK_ENABLED", raising=False)
    assert asyncio.run(post(event())).status_code == 404
    monkeypatch.setenv("INJECTICIDE_SCAN_FEEDBACK_ENABLED", "1")
    assert asyncio.run(post(event())).status_code == 202
    assert asyncio.run(post(dict(event(), text="not accepted"))).status_code == 400
    assert asyncio.run(post(dict(event(), rules={"bad": 1}, extra="x"*20000))).status_code == 413
    error = {"schema": "injecticide.scan-error.v1", "event_id": "f"*32, "http_status": 502,
             "stage": "sandbox", "kind": "Timeout", "scanner_version": "0.18.0"}
    assert asyncio.run(post(error, "/feedback/error")).status_code == 202
    assert asyncio.run(post(dict(error, text="private"), "/feedback/error")).status_code == 400
    from mcp.client import Client
    async def tools():
        async with Client(server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert {"research_get_learning_status", "research_list_learning_proposals", "research_list_scan_errors"} <= names
            result = await client.call_tool("research_list_learning_proposals", {})
            assert not result.is_error
            assert result.structured_content["items"][0]["statistics"] == event()
    asyncio.run(tools())



def test_recent_source_revalidation_keeps_old_snapshot_eligible(learning):
    from datetime import datetime, timezone
    learning.enqueue(event())
    old = datetime.fromtimestamp(time.time()-900000, timezone.utc).isoformat()
    with learning.catalog.db() as db:
        db.execute("UPDATE snapshots SET retrieved=?", (old,))
    learning.transport = lambda *a: response([proposal()])
    assert learning.cycle()["status"] == "review"
