"""Synthetic source records verify the public feed's evidence boundaries."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
import yaml
from fastapi.testclient import TestClient

from research_mcp.catalog import Catalog
from research_mcp.fetch import Response
from research_mcp.news import build_news
from webapp.research_news import ResearchNewsClient, sanitize_news

ROOT = Path(__file__).resolve().parents[1]
API = 'https://api.github.com/repos/openai/codex/releases?per_page=1'
STANDARD = 'https://www.nist.gov/itl/ai-risk-management-framework'


def release(**changes):
    return dict(id=1, tag_name='v1.2', html_url='https://github.com/openai/codex/releases/tag/v1.2',
                published_at=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat(),
                draft=False, prerelease=False, body='<script>remote notes</script>', **changes)


def news_catalog(tmp_path):
    config = tmp_path / 'sources.json'
    config.write_text(json.dumps({'sources': [
        {'id':'codex-releases', 'ecosystem':'Codex', 'connector':'github_releases', 'seeds':[API], 'scopes':[API]},
        {'id':'nist-ai', 'ecosystem':'NIST AI RMF', 'seeds':[STANDARD], 'scopes':[STANDARD]},
    ]}))
    return Catalog(tmp_path / 'news.sqlite3', config)


def record(catalog, sid, body):
    page = catalog.due_pages(sid, 1)[0]
    catalog.record(page, Response(page['url'], 200, {'content-type':'application/json'}, body), '', [])


def worker():
    return SimpleNamespace(thread=SimpleNamespace(is_alive=lambda:True), interval=3600,
                           status={'running':False,'last_cycle':None,'last_error':None})


def test_news_filters_drafts_old_dates_foreign_links_and_prose(tmp_path):
    catalog = news_catalog(tmp_path)
    records = [release()]
    for index, changes in enumerate([
        {'draft':True}, {'published_at': '2000-01-01T00:00:00Z'},
        {'published_at':'invalid'}, {'html_url':'https://github.com/evil/repo/releases/tag/v1'},
        {'html_url':'https://github.com/openai/codex/releases.evil/v1'},
        {'published_at': (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()},
    ], 2):
        record_data = release()
        record_data.update(id=index, **changes)
        records.append(record_data)
    record(catalog, 'codex-releases', json.dumps(records).encode())
    record(catalog, 'nist-ai', b'baseline')
    feed = build_news(catalog, worker())
    assert len(feed['items']) == 1
    assert feed['items'][0]['title'] == 'OpenAI Codex v1.2'
    assert 'remote notes' not in json.dumps(feed)
    assert feed['collection']['source_count'] == 2
    assert feed['collection']['retained_snapshots'] == 2
    assert feed['collection']['worker_alive'] is True


def test_changed_reference_is_observed_not_new_standard(tmp_path):
    catalog = news_catalog(tmp_path)
    record(catalog, 'nist-ai', b'baseline')
    assert build_news(catalog, worker())['items'] == []
    record(catalog, 'nist-ai', b'changed navigation')
    item = build_news(catalog, worker())['items'][0]
    assert item['kind'] == 'source_change'
    assert item['date_label'] == 'Observed'
    assert item['title'] == 'NIST AI RMF reference page changed'


def test_news_is_bounded_sorted_and_preview_labeled(tmp_path):
    catalog = news_catalog(tmp_path)
    records = []
    for i in range(12):
        item = release()
        item.update(id=i, prerelease=True, published_at=(datetime.now(timezone.utc)-timedelta(hours=i+1)).isoformat())
        records.append(item)
    record(catalog, 'codex-releases', json.dumps(records).encode())
    items = build_news(catalog, worker())['items']
    assert len(items) == 8
    assert [i['id'] for i in items] == [f'codex-releases:{i}' for i in range(8)]
    assert all(i['preview'] for i in items)


def test_public_projection_rejects_malformed_and_unapproved_urls():
    data = {'items':[{'url':url, 'body':'secret'} for url in [
        'javascript:alert(1)', 'https://github.com.evil.test/a', 'https://user:pass@github.com/a',
        'https://github.com:wat/a', None, 'https://github.com:8443/a',
        'https://github.com/openai/codex/releases/tag/v1',
    ]], 'collection':{}, 'private':'secret'}
    safe = sanitize_news(data)
    assert len(safe['items']) == 1
    assert 'secret' not in json.dumps(safe)


def mock_response(monkeypatch, body):
    session = MagicMock()
    session.__enter__.return_value = session
    response = session.get.return_value.__enter__.return_value
    response.status_code = 200
    response.iter_content.return_value = [body]
    monkeypatch.setattr('webapp.research_news.requests.Session', lambda:session)
    return session


def test_proxy_caches_then_retains_last_good_on_failure(monkeypatch):
    clock = [0]
    monkeypatch.setattr('webapp.research_news.time.monotonic', lambda:clock[0])
    monkeypatch.setenv('RESEARCH_MCP_URL', 'http://research_mcp:8200')
    session = mock_response(monkeypatch, b'{"items":[],"collection":{"source_count":24}}')
    client = ResearchNewsClient()
    assert client.get()['collection']['source_count'] == 24
    assert client.get()['available'] is True
    assert session.get.call_count == 1
    assert session.trust_env is False
    assert session.get.call_args.kwargs['allow_redirects'] is False
    clock[0] = 61
    session.get.side_effect = requests.ConnectionError('fixture')
    saved = client.get()
    assert saved['feed_stale'] is True
    assert saved['collection']['source_count'] == 24
    saved['collection']['source_count'] = 0
    assert client.get()['collection']['source_count'] == 24


def test_oversized_response_has_unavailable_fallback(monkeypatch):
    monkeypatch.setenv('RESEARCH_MCP_URL','http://research_mcp:8200')
    mock_response(monkeypatch, b' ' * 131073)
    assert ResearchNewsClient().get() == {'available':False,'feed_stale':True,'items':[],'collection':{}}


def test_web_news_failure_does_not_block_home_and_version_matches(monkeypatch):
    from webapp.api import app, news_client
    import tomllib
    monkeypatch.setenv('RESEARCH_MCP_URL','')
    monkeypatch.setattr(news_client, 'cache', None)
    with TestClient(app) as client:
        assert client.get('/').status_code == 200
        assert client.get('/api/research/news').json()['available'] is False
        assert app.version == tomllib.loads((ROOT/'pyproject.toml').read_text())['project']['version']


def test_research_network_has_web_read_path_but_no_scanner_or_shared_files():
    services = yaml.safe_load((ROOT/'docker-compose.yml').read_text())['services']
    assert 'research-net' in services['injecticide']['networks']
    assert 'research-net' not in services['skill_sandbox']['networks']
    assert services['research_mcp']['networks'] == ['research-net']
    assert all('configs' not in volume and 'reports' not in volume for volume in services['research_mcp']['volumes'])

def test_research_http_news_route_is_read_only_and_no_store(tmp_path):
    pytest.importorskip('mcp')
    from research_mcp.collector import Collector
    from research_mcp.server import create_server
    catalog = news_catalog(tmp_path)
    record(catalog, 'codex-releases', json.dumps([release()]).encode())
    collector = Collector(catalog)
    server = create_server(catalog, collector, start_collector=False)
    with TestClient(server.streamable_http_app(stateless_http=True), base_url='http://127.0.0.1') as client:
        response = client.get('/news')
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store'
        assert response.json()['items'][0]['title'] == 'OpenAI Codex v1.2'
        assert client.post('/news').status_code == 405
        assert collector.status['running'] is False


def test_source_health_separates_worker_from_pending_and_failed_evidence(tmp_path):
    catalog = news_catalog(tmp_path)
    record(catalog, 'codex-releases', json.dumps([release()]).encode())
    pending = build_news(catalog, worker())
    assert pending['collection']['worker_alive'] is True
    assert pending['collection']['coverage_incomplete'] is True
    assert pending['collection']['sources_current'] == 1
    assert pending['collection']['sources_pending'] == 1
    catalog.failure(catalog.due_pages('nist-ai', 1)[0], ValueError('private diagnostic'))
    failed = build_news(catalog, worker())
    assert failed['collection']['sources_with_errors'] == 1
    assert failed['collection']['source_health'][1]['state'] == 'fetch_error'
    assert 'private diagnostic' not in json.dumps(failed)


def test_stale_source_is_distinct_from_successful_feed_connection(tmp_path):
    catalog = news_catalog(tmp_path)
    record(catalog, 'codex-releases', json.dumps([release()]).encode())
    record(catalog, 'nist-ai', b'baseline')
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    with catalog.db() as db:
        db.execute('UPDATE pages SET successful=? WHERE source=?', (old, 'nist-ai'))
    feed = sanitize_news(build_news(catalog, worker()))
    assert feed['feed_stale'] is False
    assert feed['collection']['sources_stale'] == 1
    assert feed['collection']['coverage_incomplete'] is True
    assert feed['collection']['source_health'][1]['state'] == 'stale'


def test_source_health_projection_rejects_unknown_states_and_bounds_fields():
    source = {'id':'a' * 500, 'name':'Example', 'state':'fetch_error', 'errors':True,
              'pending':-1, 'coverage':'b' * 500, 'diagnostic':'private'}
    data = {'items':[], 'collection':{'source_health':[source, {'state':'invented'}]}}
    safe = sanitize_news(data)['collection']['source_health']
    assert len(safe) == 1
    assert len(safe[0]['id']) == 200
    assert len(safe[0]['coverage']) == 200
    assert safe[0]['errors'] == safe[0]['pending'] == 0
    assert 'private' not in json.dumps(safe)
