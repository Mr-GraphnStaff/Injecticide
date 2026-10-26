import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from research_mcp.catalog import Catalog, STATUS
from research_mcp.fetch import Response
from research_mcp.requirements import Requirements
from webapp.vendor_requirements import attach_vendor_check, check_vendor, _validate

ROOT = Path(__file__).resolve().parents[1]
URL = "https://support.claude.com/en/articles/12512198-how-to-create-custom-skills"
BODY = b"Description maximum 200 characters"


@pytest.fixture
def service(tmp_path):
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": [{"id": "requirements-claude-upload",
        "seeds": [URL], "scopes": [URL], "discovery": False}]}))
    catalog = Catalog(tmp_path / "research.db", config)
    registry = tmp_path / "requirements.json"
    registry.write_text(json.dumps({"profiles": {"claude-upload": {
        "vendor": "Anthropic", "product": "Claude custom skill uploads",
        "source_id": "requirements-claude-upload", "documents": [{"url": URL,
            "reviewed_on": "2026-10-26", "reviewed_sha256": hashlib.sha256(BODY).hexdigest()}],
        "requirements": {
            "description_max_characters": {"value": 200, "source_url": URL, "note": "Upload limit"},
            "package_max_bytes": {"value": None, "source_url": URL, "note": "Not reviewed"}}}}}))
    class FakeCollector:
        def collect(self, ids):
            page = catalog.due_pages(ids[0], 1)[0]
            catalog.record(page, Response(URL, 200, {}, BODY), BODY.decode(), [])
            return {"attempted": 1, "changed": 1, "failures": 0}
    return Requirements(catalog, registry, FakeCollector())


def test_live_unchanged_document_exposes_only_reviewed_known_values(service):
    result = service.check("claude-upload")
    assert result["live_check"] and result["status"] == "current_documented_requirements"
    assert result["requirements"][0]["value"] == 200
    assert result["requirements"][1]["verification"] == STATUS
    assert result["runtime_tested"] is False
    assert result["documents"][0]["snapshot_id"]


def test_offline_query_is_unknown_until_collected(service):
    assert service.check("claude-upload", refresh=False)["status"] == "unknown"


def test_304_revalidates_retained_reviewed_snapshot(service):
    service.check("claude-upload")
    class NotModified:
        def collect(self, ids):
            page = service.catalog.due_pages(ids[0], 1)[0]
            service.catalog.record(page, Response(URL, 304, {}, b""), "", [])
            return {"attempted": 1, "failures": 0}
    service.collector = NotModified()
    result = service.check("claude-upload")
    assert result["live_check"] and result["documents"][0]["state"] == "unchanged"


def test_changed_vendor_document_does_not_activate_new_limits(service):
    service.check("claude-upload")
    page = service.catalog.due_pages("requirements-claude-upload", 1)[0]
    service.catalog.record(page, Response(URL, 200, {}, b"Now 300 characters"), "Now 300", [])
    result = service.check("claude-upload", refresh=False)
    assert result["status"] == "unknown"
    assert result["documents"][0]["state"] == "changed_review_required"
    assert all(r["value"] is None for r in result["requirements"])


def test_html_decoration_changes_do_not_hide_documentation_text_changes(service):
    profile = service.profiles["claude-upload"]
    profile["documents"][0].update(fingerprint_scope="projected_text",
        reviewed_sha256=hashlib.sha256(BODY).hexdigest())
    page = service.catalog.due_pages("requirements-claude-upload", 1)[0]
    service.catalog.record(page, Response(URL, 200, {}, b"<html>new timestamp</html>"), BODY.decode(), [])
    assert service.check("claude-upload", False)["documents"][0]["state"] == "unchanged"
    service.catalog.record(page, Response(URL, 200, {}, b"<html>new limit</html>"), "Description 300 characters", [])
    assert service.check("claude-upload", False)["documents"][0]["state"] == "changed_review_required"


def test_failed_refresh_never_reuses_last_good_pass(service):
    service.check("claude-upload")
    class Failed:
        def collect(self, ids):
            service.catalog.failure(service.catalog.due_pages(ids[0], 1)[0], TimeoutError())
            return {"attempted": 1, "failures": 1}
    service.collector = Failed()
    result = service.check("claude-upload")
    assert result["status"] == "unknown" and not result["live_check"]
    assert result["documents"][0]["state"] == "fetch_error"
    assert result["documents"][0]["snapshot_id"]  # Last good evidence is preserved.


def test_stale_disabled_and_busy_checks_are_unknown(service):
    service.check("claude-upload")
    with service.catalog.db() as db:
        db.execute("UPDATE pages SET successful=?", ((datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),))
    assert service.check("claude-upload", False)["documents"][0]["state"] == "stale"
    service.check("claude-upload")
    with service.lock:
        result = service.check("claude-upload")
    assert result["refresh_state"] == "busy" and result["status"] == "unknown"
    service.catalog.sources["requirements-claude-upload"]["enabled"] = False
    assert service.check("claude-upload")["documents"][0]["state"] == "disabled"


def test_scope_is_four_platform_families_and_no_arbitrary_targets(service):
    registry = json.loads((ROOT / "research_mcp/requirements.json").read_text())
    assert {p["vendor"] for p in registry["profiles"].values()} == {"OpenAI", "Anthropic", "Google", "GitHub"}
    for target in ("auto", "cursor", "https://evil.example/", "generic"):
        assert service.check(target)["verification"] == STATUS


def test_web_enforces_upload_limit_without_certifying_entire_package(monkeypatch, service):
    evidence = service.check("claude-upload")
    monkeypatch.setattr("webapp.vendor_requirements.check_vendor", lambda runtime: dict(evidence))
    result = attach_vendor_check({"package_analysis": {"target_runtime": "claude-upload",
        "skills": [{"path": "demo/SKILL.md", "field_lengths": {"description": 201}}]}})
    assert result["vendor_verification"]["checks"][0]["status"] == "fail"
    assert result["readiness"]["vendor_compatibility"] == "fails_documented_requirement"
    result["package_analysis"]["skills"][0]["field_lengths"]["description"] = 200
    assert attach_vendor_check(result)["readiness"]["vendor_compatibility"] == "unknown"


def test_web_ambiguous_auto_target_requires_selection(monkeypatch):
    seen = []
    monkeypatch.setattr("webapp.vendor_requirements.check_vendor", lambda runtime: seen.append(runtime) or {"status": "unknown"})
    attach_vendor_check({"package_analysis": {"target_runtime": "auto", "runtime_targets": [
        {"runtime": "openai"}, {"runtime": "claude-code"}]}})
    assert seen == ["auto"]


def test_mcp_import_limits_are_scoped_and_measured_from_complete_inventory(monkeypatch):
    rules = json.loads((ROOT / "research_mcp/requirements.json").read_text())["profiles"]["openai-mcp-import"]["requirements"]
    monkeypatch.setattr("webapp.vendor_requirements.check_vendor", lambda runtime: {
        "status": "current_documented_requirements", "requirements": [dict(r, field=f, status="vendor_documented") for f,r in rules.items()]})
    result = attach_vendor_check({"package_analysis": {"target_runtime": "openai-mcp-import",
        "skills": [{"path": ".agents/skills/demo/SKILL.md", "root": ".agents/skills/demo"}]},
        "inventory": [{"path": ".agents/skills/demo/SKILL.md", "size": 100},
                      {"path": ".agents/skills/demo/assets/data.bin", "size": 1048577}]})
    checks = result["vendor_verification"]["checks"]
    assert any(c["field"] == "supporting_file_max_bytes" and c["status"] == "fail" for c in checks)
    assert any(c["field"] == "skill_max_files" and c["observed"] == 2 for c in checks)
    assert any(c["field"] == "generated_archives_max_bytes" and c["status"] == "unknown" for c in checks)
    assert any(c["field"] == "skill_resources_max_bytes" and c["status"] == "unknown" for c in checks)
    result["coverage"] = {"status": "complete_supported_content"}
    checks = attach_vendor_check(result)["vendor_verification"]["checks"]
    assert any(c["field"] == "skill_resources_max_bytes" and c["status"] == "pass" for c in checks)


def test_web_missing_service_and_invalid_evidence_fail_explicitly(monkeypatch, service):
    monkeypatch.delenv("RESEARCH_MCP_URL", raising=False)
    assert check_vendor("claude-upload")["verification"] == STATUS
    evidence = service.check("claude-upload")
    evidence["live_check"] = False
    with pytest.raises(ValueError):
        _validate(evidence, "claude-upload")
    evidence["live_check"] = True
    evidence["documents"][0]["url"] = "https://evil.example/"
    with pytest.raises(ValueError):
        _validate(evidence, "claude-upload")


def test_web_sends_only_product_identifier(monkeypatch, service):
    evidence = service.check("claude-upload")
    class Reply:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_content(self, size): yield json.dumps(evidence).encode()
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            assert url == "http://research.internal/requirements/check"
            assert kwargs["json"] == {"runtime": "claude-upload"}
            assert not ({"data", "files", "headers"} & set(kwargs))
            assert kwargs["allow_redirects"] is False
            return Reply()
    monkeypatch.setenv("RESEARCH_MCP_URL", "http://research.internal")
    monkeypatch.setattr("webapp.vendor_requirements.requests.Session", Session)
    assert check_vendor("claude-upload")["live_check"] is True


def test_http_route_bounds_input_and_refreshes_only_registered_product(service, monkeypatch):
    pytest.importorskip("mcp")
    from fastapi.testclient import TestClient
    from research_mcp.collector import Collector
    from research_mcp.server import create_server
    monkeypatch.setattr("research_mcp.server.Requirements", lambda catalog: service)
    server = create_server(service.catalog, Collector(service.catalog), False)
    with TestClient(server.streamable_http_app(stateless_http=True), base_url="http://127.0.0.1") as client:
        result = client.post("/requirements/check", json={"runtime": "claude-upload"})
        assert result.status_code == 200 and result.json()["live_check"] is True
        assert client.post("/requirements/check", json={"url": "https://evil.example/"}).status_code == 400
        assert client.post("/requirements/check", content=b"x"*1025).status_code == 413
        assert client.get("/requirements/check").status_code == 405


def test_mcp_exposes_requirements_tool(service):
    pytest.importorskip("mcp")
    from mcp.client import Client
    from research_mcp.collector import Collector
    from research_mcp.server import create_server
    async def exercise():
        async with Client(create_server(service.catalog, Collector(service.catalog), False)) as client:
            tools = await client.list_tools()
            assert "research_check_requirements" in {t.name for t in tools.tools}
            result = await client.call_tool("research_check_requirements", {"runtime": "cursor"})
            assert not result.is_error
            assert result.structured_content["verification"] == STATUS
    asyncio.run(exercise())
