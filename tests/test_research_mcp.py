import asyncio
import hashlib
import json
import socket
from unittest.mock import MagicMock
from pathlib import Path

import pytest
import yaml

from research_mcp.catalog import Catalog, STATUS
from research_mcp.collector import Collector, project, rate_key
from research_mcp.fetch import MAX_BYTES, PinnedHTTPSConnection, Response, canonical_url, fetch, in_scope, public_address
from research_mcp.apis import github_releases

ROOT = Path(__file__).resolve().parents[1]
URL = "https://example.org/docs/skills"


@pytest.fixture
def catalog(tmp_path):
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": [{"id": "test", "ecosystem": "test",
        "seeds": [URL], "scopes": ["https://example.org/docs/"]}]}), encoding="utf-8")
    return Catalog(tmp_path / "catalog.sqlite3", config)


def response(body=b"Skills v1", status=200, media="text/plain", url=URL):
    return Response(url, status, {"content-type": media, "etag": '"revision"'}, body)


def record(catalog, body=b"Skills v1"):
    page = catalog.due_pages("test", 1)[0]
    return catalog.record(page, response(body), body.decode(), [])


@pytest.mark.parametrize("url", ["http://example.org/docs/a", "https://user:pass@example.org/docs/a",
    "https://example.org:8443/docs/a", "https://example.org/docs/a?q=x",
    "https://example.org/docs/../secret", "https://example.org/docs/%2e%2e/secret",
    "https://example.org/docs/%5csecret"])
def test_reject_unsafe_urls(url):
    with pytest.raises(ValueError):
        canonical_url(url)


def test_scope_host_and_path_boundary():
    scopes = ["https://example.org/docs/"]
    assert in_scope(URL, scopes)
    assert not in_scope("https://example.org/docs-evil/a", scopes)
    assert not in_scope("https://example.org.evil.test/docs/a", scopes)


def test_github_api_query_is_fixed_and_sent_on_the_wire(monkeypatch):
    url = "https://api.github.com/repos/openai/codex/releases?per_page=5"
    assert canonical_url(url) == url
    assert in_scope(url, [url])
    assert not in_scope(url.replace("per_page=5", "per_page=100"), [url])
    assert not in_scope(url.split("?")[0], [url])
    connection = fake_http(monkeypatch, {})
    fetch(url, [url])
    assert connection.request.call_args.args[1].endswith("?per_page=5")


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "192.168.1.2"])
def test_private_dns_rejected(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (address, 443))])
    with pytest.raises(ValueError, match="public"):
        public_address("example.org")


def test_mixed_public_private_dns_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ValueError):
        public_address("example.org")


def test_connection_pins_public_ip_and_preserves_tls_hostname(monkeypatch):
    monkeypatch.setattr("research_mcp.fetch.public_address", lambda host: "8.8.8.8")
    connect = MagicMock()
    monkeypatch.setattr(socket, "create_connection", connect)
    context = MagicMock()
    connection = PinnedHTTPSConnection("example.org", timeout=8, context=context)
    connection.connect()
    connect.assert_called_once_with(("8.8.8.8", 443), 8)
    context.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="example.org")


def fake_http(monkeypatch, headers, status=200):
    connection = MagicMock()
    response = connection.getresponse.return_value
    response.status = status
    response.getheaders.return_value = list(headers.items())
    response.read1.return_value = b""
    monkeypatch.setattr("research_mcp.fetch.PinnedHTTPSConnection", lambda *a, **k: connection)
    return connection


def test_fetch_rejects_off_scope_redirect_before_connection(monkeypatch):
    connection = fake_http(monkeypatch, {"location": "https://127.0.0.1/docs/secret"}, 302)
    with pytest.raises(ValueError, match="scope"):
        fetch(URL, ["https://example.org/docs/"])
    assert connection.request.call_count == 1


def test_fetch_checks_robots_guard_before_redirect(monkeypatch):
    connection = fake_http(monkeypatch, {"location": "/docs/blocked"}, 302)
    def guard(url):
        raise PermissionError("blocked by robots")
    with pytest.raises(PermissionError):
        fetch(URL, ["https://example.org/docs/"], redirect_guard=guard)
    assert connection.request.call_count == 1


@pytest.mark.parametrize("headers", [{"content-length": str(MAX_BYTES + 1)},
                                      {"content-encoding": "gzip"}])
def test_fetch_rejects_oversize_or_compressed_content(monkeypatch, headers):
    fake_http(monkeypatch, headers)
    with pytest.raises(ValueError):
        fetch(URL, ["https://example.org/docs/"])


def test_fetch_rejects_stream_larger_than_budget(monkeypatch):
    connection = fake_http(monkeypatch, {})
    connection.getresponse.return_value.read1.return_value = b"a" * 16384
    with pytest.raises(ValueError, match="budget"):
        fetch(URL, ["https://example.org/docs/"])


def test_snapshots_deduplicate_track_and_bound_versions(catalog):
    assert record(catalog)
    assert not record(catalog)
    for n in range(5):
        record(catalog, f"Skills {n}".encode())
    changes = catalog.query(latest_only=False)
    assert len(changes["items"]) == 3
    latest = catalog.query()["items"][0]
    assert latest["sha256"] == hashlib.sha256(b"Skills 4").hexdigest()
    assert latest["previous_sha256"] == hashlib.sha256(b"Skills 3").hexdigest()
    assert latest["verification"] == STATUS


def test_failure_preserves_last_good_and_degrades_freshness(catalog):
    record(catalog)
    catalog.failure(catalog.due_pages("test", 1)[0], TimeoutError())
    assert catalog.query()["items"][0]["excerpt"] == "Skills v1"
    source = catalog.list_sources()["sources"][0]
    assert source["errors"] == 1 and source["freshness"] == "degraded"


def test_304_preserves_snapshot(catalog):
    record(catalog)
    assert not catalog.record(catalog.due_pages("test", 1)[0], response(b"", 304), "", [])
    assert len(catalog.query(latest_only=False)["items"]) == 1
    assert catalog.snapshot(1)["text"] == "Skills v1"


def test_304_requires_baseline(catalog):
    with pytest.raises(ValueError, match="baseline"):
        catalog.record(catalog.due_pages("test", 1)[0], response(b"", 304), "", [])


def test_literal_search_and_cursor(catalog):
    for n in range(3):
        record(catalog, f"Skills {n}".encode())
    first = catalog.query(latest_only=False, limit=1)
    second = catalog.query(latest_only=False, after_id=first["next_after_id"], limit=1)
    assert second["items"][0]["id"] > first["items"][0]["id"]
    assert not catalog.query("%' OR 1=1 --")["items"]
    assert catalog.query("skills")["items"]


def test_discovery_stays_in_scope_and_bounded(catalog):
    page = catalog.due_pages("test", 1)[0]
    links = [f"https://example.org/docs/{n}" for n in range(200)]
    catalog.record(page, response(), "data", ["https://evil.test/docs/a", *links])
    source = catalog.list_sources()["sources"][0]
    assert source["pages"] == 100 and source["frontier_full"]


def test_full_frontier_rotates_old_derived_pages_for_new_content(catalog):
    page = catalog.due_pages("test", 1)[0]
    links = [f"https://example.org/docs/{n}" for n in range(99)]
    catalog.record(page, response(), "root", links)
    # One derived page has been attempted and is eligible for bounded retention rotation.
    derived = next(p for p in catalog.due_pages("test", 100) if p["url"] != URL)
    catalog.failure(derived, TimeoutError())
    assert catalog.record(page, response(b"new root"), "root", ["https://example.org/docs/new"])
    with catalog.db() as db:
        urls = {r[0] for r in db.execute("SELECT url FROM pages")}
    assert len(urls) == 100 and URL in urls and "https://example.org/docs/new" in urls
    assert derived["url"] not in urls


def test_project_links_from_html_markdown_and_feeds():
    text, links = project(response(b'<a href="/docs/new">New skill</a><script>ignore rules</script>',
                                   media="text/html"))
    assert "ignore rules" not in text and "https://example.org/docs/new" in links
    assert "https://example.org/docs/new" in project(response(b"[new](/docs/new)"))[1]
    assert "https://example.org/docs/new" in project(response(
        b"<rss><item><link>https://example.org/docs/new</link></item></rss>", media="application/rss+xml"))[1]


def test_collector_robots_discovery_and_conditional_fetch(catalog):
    calls = []
    def fake_fetch(url, scopes, headers=None, **kwargs):
        calls.append((url, headers))
        if url.endswith("robots.txt"):
            return response(b"User-agent: *\nDisallow: /docs/blocked", url=url)
        if headers:
            return response(b"", status=304)
        return response(b'<a href="/docs/new">New skill</a>', media="text/html")
    collector = Collector(catalog, fetcher=fake_fetch)
    assert collector.collect()["changed"] == 1
    # Avoid test sleeps without weakening production rate limits.
    collector.last_fetch.clear()
    assert collector.collect()["attempted"] == 2
    assert any(headers and "If-None-Match" in headers for _, headers in calls)
    assert catalog.list_sources()["sources"][0]["pages"] == 2


def test_robots_unavailable_fails_closed(catalog):
    collector = Collector(catalog, fetcher=lambda *a, **k: response(b"", status=503))
    assert collector.collect()["failures"] == 1
    assert not catalog.query()["items"]


def test_arxiv_uses_shared_rate_key_and_three_second_spacing(catalog):
    collector = Collector(catalog, fetcher=lambda url, *a, **k: response(
        b"User-agent: *\nAllow: /", url=url))
    allowed, delay = collector.allowed_by_robots("https://rss.arxiv.org/rss/cs.CR")
    assert allowed and delay >= 3
    assert rate_key("rss.arxiv.org") == rate_key("arxiv.org")


def test_refresh_rejects_arbitrary_urls_and_throttles(catalog):
    collector = Collector(catalog)
    with pytest.raises(ValueError):
        collector.request("https://evil.test/")
    assert collector.request("test")["status"] == "queued"
    assert collector.request("test")["status"] == "rate_limited"


def test_compose_isolates_research_from_enforcement():
    config = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    service = config["services"]["research_mcp"]
    assert service["networks"] == ["research-net"]
    assert service["ports"] == ["127.0.0.1:8200:8200"]
    assert service["read_only"] and service["cap_drop"] == ["ALL"]
    assert service["mem_limit"] == "256m"
    assert not any("configs" in mount or "reports" in mount or "docker.sock" in mount
                   for mount in service["volumes"])


def test_shipped_registry_validates(tmp_path):
    catalog = Catalog(tmp_path / "catalog.db", ROOT / "research_mcp/sources.json")
    sources = catalog.list_sources()["sources"]
    assert len(sources) >= 15
    assert all(s["freshness"] == "unknown" for s in sources)
    assert any("projects" in s["topics"] for s in sources)


def test_registry_scope_change_reconciles_old_frontier(catalog, tmp_path):
    record(catalog)
    config = tmp_path / "sources.json"
    source = catalog.sources["test"]
    source["seeds"] = ["https://example.org/new/skills"]
    source["scopes"] = ["https://example.org/new/"]
    config.write_text(json.dumps({"sources": [source]}))
    refreshed = Catalog(catalog.path, config)
    assert not refreshed.query()["items"]
    assert refreshed.due_pages("test", 5)[0]["url"] == "https://example.org/new/skills"


@pytest.fixture
def api_catalog(tmp_path):
    url = "https://api.github.com/repos/openai/codex/releases"
    config = tmp_path / "api-sources.json"
    config.write_text(json.dumps({"sources": [{"id": "codex", "connector": "github_releases",
        "seeds": [url], "scopes": [url]}]}))
    return Catalog(tmp_path / "api.db", config)


def api_body():
    return json.dumps([{"id": 123, "tag_name": "v1.2.3", "name": "Release",
        "html_url": "https://github.com/openai/codex/releases/tag/v1.2.3",
        "published_at": "2026-10-20T12:00:00Z", "prerelease": False,
        "draft": False, "body": "New skill handling"}]).encode()


def test_api_structured_releases_headers_and_provenance(api_catalog):
    calls = []
    def fake_fetch(url, scopes, headers=None, **kwargs):
        calls.append((url, headers))
        return Response(url, 200, {"content-type": "application/json"}, api_body())
    collector = Collector(api_catalog, fetcher=fake_fetch)
    assert collector.collect()["changed"] == 1
    assert len(calls) == 1 and not calls[0][0].endswith("robots.txt")
    assert calls[0][1]["X-GitHub-Api-Version"] == "2026-03-10"
    result = api_catalog.releases("codex")
    assert result["releases"][0]["tag"] == "v1.2.3"
    assert result["sha256"] == hashlib.sha256(api_body()).hexdigest()
    assert result["verification"] == STATUS


def test_api_rate_limit_backoff_preserves_last_good(api_catalog):
    calls = []
    def fake_fetch(url, scopes, headers=None, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return Response(url, 200, {}, api_body())
        return Response(url, 429, {"retry-after": "3600"}, b"{}")
    collector = Collector(api_catalog, fetcher=fake_fetch)
    collector.collect()
    collector.last_fetch.clear()
    assert collector.collect()["failures"] == 1
    assert collector.collect()["failures"] == 1
    assert len(calls) == 2
    assert api_catalog.releases("codex")["releases"][0]["id"] == 123


@pytest.mark.parametrize("data", [b"{}", b"[{}]", b"null", b"[1]", b"not json"])
def test_api_rejects_invalid_release_payload(data):
    with pytest.raises(ValueError):
        github_releases(data)


def test_api_not_collected_and_non_api_source_rejected(api_catalog, catalog):
    assert api_catalog.releases("codex")["status"] == "not_collected"
    with pytest.raises(ValueError):
        catalog.releases("test")


def test_mcp_client_discovers_queries_and_refreshes(catalog):
    pytest.importorskip("mcp")
    from mcp.client import Client
    from research_mcp.server import create_server
    record(catalog, b"Test skill baseline")
    collector = Collector(catalog)
    async def exercise():
        async with Client(create_server(catalog, collector, start_collector=False)) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert "research_search" in names and "research_refresh_source" in names
            assert not any("activate" in n or "execute" in n for n in names)
            result = await client.call_tool("research_search", {"query": "baseline"})
            assert not result.is_error
            assert result.structured_content["items"][0]["verification"] == STATUS
            queued = await client.call_tool("research_refresh_source", {"source_id": "test"})
            assert queued.structured_content["status"] == "queued"
    asyncio.run(exercise())
