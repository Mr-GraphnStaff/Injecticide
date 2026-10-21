"""Independent acceptance checks for API-first collection boundaries.

These tests exercise the collector and persisted evidence, not live providers.
Live collection and restart/rollback evidence remain separate release gates.
"""
import io
import json
from email.utils import formatdate
from unittest.mock import MagicMock

import pytest

from research_mcp.catalog import Catalog
from research_mcp.apis import normalize_api
from research_mcp.collector import Collector, project, retry_seconds
from research_mcp.fetch import MAX_BYTES, Response, canonical_url, fetch, in_scope


DOC = "https://example.org/docs/skills"
RELEASES = "https://api.github.com/repos/openai/codex/releases?per_page=1"


def make_catalog(tmp_path, sources):
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": sources}), encoding="utf-8")
    return Catalog(tmp_path / "catalog.sqlite3", config), config


def source(sid="docs", **overrides):
    return {"id": sid, "ecosystem": "fixture", "seeds": [DOC],
            "scopes": ["https://example.org/docs/"], **overrides}


def reply(body, url=DOC, status=200, **headers):
    return Response(url, status, {"content-type": "text/html", **headers}, body)


def release_body():
    return json.dumps([{"id": 71, "tag_name": "v1", "html_url":
        "https://github.com/openai/codex/releases/tag/v1", "draft": False,
        "prerelease": False, "published_at": "2026-10-21T12:00:00Z"}]).encode()


def wire(monkeypatch, body, headers=None, status=200):
    stream = io.BytesIO(body)
    connection = MagicMock()
    response = connection.getresponse.return_value
    response.status = status
    response.getheaders.return_value = list((headers or {}).items())
    response.read1.side_effect = stream.read
    monkeypatch.setattr("research_mcp.fetch.PinnedHTTPSConnection", lambda *a, **kw: connection)
    return connection


def test_html_discovers_documents_without_script_fragments_or_static_assets():
    body = b'''<a href="/docs/real">Real documentation</a>
      <script>const a="https://example.org/docs/async(";
      const b="[fake](https://example.org/docs/not-a-link)";</script>
      <style>.x{background:url(https://example.org/docs/style-fake)}</style>
      <link rel="stylesheet" href="/docs/site.css">
      <a href="/docs/icon.png">icon</a><a href="/docs/app.js">script</a>'''
    text, links = project(reply(body))
    assert links == ["https://example.org/docs/real"]
    assert "const a" not in text


@pytest.mark.parametrize("suffix", [".png", ".jpg", ".css", ".js", ".woff2", ".svg"])
def test_markdown_asset_links_are_not_collected(suffix):
    response = reply(f"[asset](/docs/file{suffix}) [page](/docs/reference.md)".encode(),
                     **{"content-type": "text/markdown"})
    assert project(response)[1] == ["https://example.org/docs/reference.md"]


def test_large_document_uses_explicit_bounded_allowance(monkeypatch):
    body = b"x" * (MAX_BYTES + 17)
    wire(monkeypatch, body, {"content-length": str(len(body))})
    response = fetch(DOC, ["https://example.org/docs/"], max_bytes=2 * MAX_BYTES)
    assert response.body == body


@pytest.mark.parametrize("declared", [False, True])
def test_custom_response_limit_rejects_header_and_stream_overflow(monkeypatch, declared):
    limit = 2 * MAX_BYTES
    body = b"x" * (limit + 1)
    wire(monkeypatch, body, {"content-length": str(len(body))} if declared else {})
    with pytest.raises(ValueError):
        fetch(DOC, ["https://example.org/docs/"], max_bytes=limit)


@pytest.mark.parametrize("limit", [0, -1, 8 * 1024 * 1024 + 1, True])
def test_invalid_source_budget_is_rejected_at_admission(tmp_path, limit):
    with pytest.raises(ValueError):
        make_catalog(tmp_path, [source(max_response_bytes=limit)])


@pytest.mark.parametrize("url", [
    "https://api.github.com/advisories?per_page=100000",
    "https://api.github.com/advisories?per_page=5&url=https://127.0.0.1/",
    "https://api.crossref.org/works?query=prompt&rows=999999",
    "https://registry.modelcontextprotocol.io/v0.1/servers?limit=100000",
    "https://example.org/docs/a?next=https://127.0.0.1/",
])
def test_unapproved_api_query_shapes_are_rejected(url):
    with pytest.raises(ValueError):
        canonical_url(url)


def test_approved_api_query_does_not_widen_source_scope():
    assert in_scope(RELEASES, [RELEASES])
    assert not in_scope(RELEASES.replace("per_page=1", "per_page=5"), [RELEASES])


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/openai/codex/releases?per_page=1&per_page=5",
    "https://api.crossref.org/works?query=prompt%20injection&rows=5&rows=100",
    "https://registry.modelcontextprotocol.io/v0.1/servers?limit=10&cursor=unapproved",
])
def test_duplicate_or_unapproved_pagination_parameters_are_rejected(url):
    with pytest.raises(ValueError):
        canonical_url(url)


@pytest.mark.parametrize("connector,payload", [
    ("github_advisories", {}), ("github_advisories", [{}]),
    ("github_advisories", [{"ghsa_id": 123}]),
    ("mcp_registry", []), ("mcp_registry", {"servers": [{}]}),
    ("mcp_registry", {"servers": [{"server": {"name": "test"}}]}),
    ("crossref", {"message": []}), ("crossref", {"message": {"items": [{}]}}),
    ("crossref", {"message": {"items": [{"DOI": 123}]}}),
])
def test_invalid_api_schema_does_not_create_normalized_records(connector, payload):
    with pytest.raises(ValueError):
        normalize_api(connector, json.dumps(payload).encode())


@pytest.mark.parametrize("connector,payload", [
    ("github_advisories", []), ("mcp_registry", {"servers": []}),
    ("crossref", {"message": {"items": []}}),
])
def test_valid_empty_api_results_explicitly_report_bounded_coverage(connector, payload):
    result = normalize_api(connector, json.dumps(payload).encode())
    assert result["records"] == []
    assert "first page" in result["coverage"]


def test_api_redirect_cannot_connect_to_arbitrary_destination(monkeypatch):
    connection = wire(monkeypatch, b"", {"location": "https://127.0.0.1/private"}, 302)
    with pytest.raises(ValueError):
        fetch(RELEASES, [RELEASES])
    assert connection.request.call_count == 1


def test_provider_failure_keeps_last_good_evidence_and_backoff(tmp_path):
    catalog, _ = make_catalog(tmp_path, [source("release", connector="github_releases",
        seeds=[RELEASES], scopes=[RELEASES])])
    calls = []
    def provider(url, scopes, headers=None, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return reply(release_body(), url, **{"content-type": "application/json"})
        return reply(b"{}", url, 429, **{"retry-after": "3600"})
    collector = Collector(catalog, fetcher=provider)
    assert collector.collect()["changed"] == 1
    original = catalog.query()["items"][0]["sha256"]
    collector.last_fetch.clear()
    assert collector.collect()["failures"] == 1
    collector.collect()
    assert len(calls) == 2
    assert catalog.query()["items"][0]["sha256"] == original
    assert catalog.list_sources()["sources"][0]["errors"] == 1


def test_json_shaped_challenge_page_is_not_accepted_as_api_evidence(tmp_path):
    catalog, _ = make_catalog(tmp_path, [source("release", connector="github_releases",
        seeds=[RELEASES], scopes=[RELEASES])])
    responses = iter([
        reply(release_body(), RELEASES, **{"content-type": "application/json"}),
        reply(release_body(), RELEASES, **{"content-type": "text/html"}),
    ])
    collector = Collector(catalog, fetcher=lambda *a, **kw: next(responses))
    assert collector.collect()["changed"] == 1
    original = catalog.query()["items"][0]["sha256"]
    collector.last_fetch.clear()
    failed = collector.collect()
    assert failed["changed"] == 0 and failed["failures"] == 1
    assert catalog.query()["items"][0]["sha256"] == original
    assert catalog.list_sources()["sources"][0]["errors"] == 1


@pytest.mark.parametrize("header", [None, "not-a-date", "nan", "inf", "-inf", "-100"])
def test_invalid_retry_header_uses_conservative_fallback(header):
    assert retry_seconds(header) >= 3600


def test_retry_http_date_does_not_retry_before_provider_time(monkeypatch):
    monkeypatch.setattr("research_mcp.collector.time.time", lambda: 1800000000)
    assert retry_seconds(formatdate(1800007200, usegmt=True)) >= 7200


def test_valid_long_retry_delay_is_not_shortened_to_one_hour():
    assert retry_seconds("172800") >= 172800


def test_registry_removal_preserves_evidence_on_disk(tmp_path):
    catalog, config = make_catalog(tmp_path, [source("retire"), source("keep")])
    catalog.record(catalog.due_pages("retire", 1)[0], reply(b"retained"), "retained", [])
    config.write_text(json.dumps({"sources": [source("keep")]}), encoding="utf-8")
    current = Catalog(catalog.path, config)
    assert not current.query()["items"]
    with current.db() as db:
        assert db.execute("SELECT count(*) FROM snapshots WHERE source='retire'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM pages WHERE source='retire'").fetchone()[0] == 1


def test_disabled_source_retains_queryable_history_without_collection(tmp_path):
    catalog, config = make_catalog(tmp_path, [source()])
    catalog.record(catalog.due_pages("docs", 1)[0], reply(b"history"), "history", [])
    config.write_text(json.dumps({"sources": [source(enabled=False)]}), encoding="utf-8")
    current = Catalog(catalog.path, config)
    assert current.due_pages("docs", 1) == []
    assert current.snapshot(1)["text"] == "history"
