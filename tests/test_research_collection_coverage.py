"""Collection coverage regressions use synthetic sources without network I/O."""
import json
from pathlib import Path

import pytest

from research_mcp.catalog import Catalog
from research_mcp.collector import Collector
from research_mcp.fetch import Response


def catalog_with_counts(tmp_path, counts):
    sources = []
    for number, count in enumerate(counts):
        origin = f"https://source{number:03d}.example.org/docs/"
        sources.append({"id": f"source-{number:03d}", "ecosystem": "fixture",
                        "seeds": [origin + str(i) for i in range(count)],
                        "scopes": [origin], "discovery": False})
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": sources}), encoding="utf-8")
    return Catalog(tmp_path / "catalog.sqlite3", config)


def synthetic_fetch(url, *args, **kwargs):
    return Response(url, 200, {"content-type": "text/plain"}, b"Synthetic reviewed source")


def collector(catalog, **kwargs):
    worker = Collector(catalog, fetcher=synthetic_fetch, **kwargs)
    worker.allowed_by_robots = lambda url: (True, 0)
    return worker


def test_all_52_sources_and_88_configured_urls_fit_daily_cycle(tmp_path):
    # Mirrors the observed registry shape, including its 12-seed source.
    catalog = catalog_with_counts(tmp_path, [12] + [3] * 5 + [2] * 15 + [1] * 31)
    result = collector(catalog, interval=86400, page_budget=100, cycle_seconds=600).collect()
    assert result["attempted"] == result["planned_pages"] == 88
    assert result["unattempted_pages"] == result["failures"] == 0
    assert not result["cycle_budget_reached"] and not result["deadline_reached"]
    statuses = catalog.list_sources()["sources"]
    assert len(statuses) == 52
    assert all(s["freshness"] == "current" and not s["is_stale"] for s in statuses)


def test_twelve_seed_source_is_not_permanently_capped_at_eight(tmp_path):
    catalog = catalog_with_counts(tmp_path, [12])
    assert collector(catalog, page_budget=100).collect()["attempted"] == 12
    assert catalog.list_sources()["sources"][0]["freshness"] == "current"


def test_small_budget_resumes_after_last_serviced_source(tmp_path):
    catalog = catalog_with_counts(tmp_path, [1, 1, 1, 1])
    worker = collector(catalog, page_budget=2)
    first = worker.collect()
    assert first["attempted"] == 2 and first["unattempted_pages"] == 2
    second = worker.collect()
    assert second["attempted"] == 2
    assert all(s["freshness"] == "current" for s in catalog.list_sources()["sources"])


def test_manual_refresh_does_not_reset_periodic_resume_position(tmp_path):
    catalog = catalog_with_counts(tmp_path, [1, 1, 1, 1])
    worker = collector(catalog, page_budget=2)
    worker.collect()
    saved = worker.source_cursor
    worker.collect(["source-000"])
    assert worker.source_cursor == saved


def test_configured_cycle_deadline_remains_bounded(tmp_path, monkeypatch):
    catalog = catalog_with_counts(tmp_path, [1] * 6)
    clock = [0.0]
    monkeypatch.setattr("research_mcp.collector.time.monotonic", lambda: clock[0])
    def fetch(url, *args, **kwargs):
        clock[0] += 125
        return synthetic_fetch(url)
    worker = collector(catalog, interval=86400, page_budget=100, cycle_seconds=600)
    worker.fetcher = fetch
    result = worker.collect()
    assert result["attempted"] == 5 and result["unattempted_pages"] == 1
    assert result["deadline_reached"]


@pytest.mark.parametrize("seconds", [0, 29, 901, True])
def test_invalid_cycle_deadline_rejected(seconds):
    with pytest.raises(ValueError, match="deadline"):
        Collector(None, cycle_seconds=seconds)


def test_cycle_deadline_cannot_exceed_schedule_interval():
    with pytest.raises(ValueError, match="deadline"):
        Collector(None, interval=300, cycle_seconds=600)


def test_periodic_start_does_not_drift_by_collection_duration(monkeypatch):
    clock = [0.0]
    starts = []
    worker = Collector(None, interval=300)
    class Wake:
        def clear(self): pass
        def wait(self, seconds): clock[0] += seconds
    worker.wake = Wake()
    def collect(_):
        starts.append(clock[0])
        clock[0] += 100
        if len(starts) == 2: worker.stop_event.set()
        return {"attempted": 0}
    worker.collect = collect
    monkeypatch.setattr("research_mcp.collector.time.monotonic", lambda: clock[0])
    worker.run()
    assert starts == [0, 300]


def test_shipped_capacity_and_deadline_cover_current_seed_registry():
    import yaml
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    env = compose["services"]["research_mcp"]["environment"]
    assert "RESEARCH_PAGE_BUDGET=${INJECTICIDE_RESEARCH_PAGE_BUDGET:-100}" in env
    assert "RESEARCH_CYCLE_SECONDS=${INJECTICIDE_RESEARCH_CYCLE_SECONDS:-600}" in env
    enabled = [s for s in json.loads((root / "research_mcp/sources.json").read_text())["sources"] if s.get("enabled", True)]
    assert sum(len(s["seeds"]) for s in enabled) <= 100
