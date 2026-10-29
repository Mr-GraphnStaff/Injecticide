"""Local, synthetic evidence and actual SQLite; no paid/network calls."""
import asyncio
import copy
import hashlib
import json
import threading
import time

import pytest

from research_mcp.catalog import Catalog
from research_mcp.collector import Collector
from research_mcp.fetch import Response
from research_mcp.obsession import Obsession, digest, load_policy, validate_export_item, validate_policy

URL = "https://example.org/docs/skills"


@pytest.fixture
def setup(tmp_path):
    config = tmp_path / "sources.json"
    config.write_text(json.dumps({"sources": [{"id": "approved", "seeds": [URL], "scopes": ["https://example.org/docs/"]}]}))
    catalog = Catalog(tmp_path / "research.sqlite3", config)
    policy = {"schema_version": 1, "gate_algorithm_version": 1, "interval_seconds": 86400, "snapshot_budget": 100,
              "max_evidence_age_seconds": 604800, "max_queue_items": 100,
              "useful_terms": ["skill", "plugin"], "auto_reference_sources": ["approved"], "signature_recipes": []}
    return catalog, policy


def record(catalog, text="skill baseline", url=URL):
    page = catalog.due_pages("approved", 1)[0]
    raw = text.encode()
    catalog.record(page, Response(url, 200, {"content-type": "text/plain"}, raw), text, [])


def changed(setup):
    catalog, policy = setup
    record(catalog)
    record(catalog, "skill plugin changed version")
    engine = Obsession(catalog, policy)
    engine.cycle()
    return engine


def recipe():
    return {"id": "synthetic-test", "source_id": "approved", "url": URL,
            "literal": "SYNTHETIC_TEST_LITERAL", "description": "Synthetic regression indicator; not a real exploit claim.",
            "severity": "medium", "positive_examples": ["SYNTHETIC_TEST_LITERAL appears here"],
            "negative_examples": ["Ordinary useful skill instructions."]}


def test_shipped_policy_never_autotrusts_community_issue_content():
    policy = load_policy()
    assert "owasp-skills-issues" not in policy["auto_reference_sources"]
    assert policy["signature_recipes"] == []
    assert policy["interval_seconds"] == 86400


def test_initial_baseline_is_review_and_changed_first_party_reference_is_auto(setup):
    engine = changed(setup)
    rows = engine.list()["items"]
    assert rows[0]["decision"]["state"] == "superseded"
    item, = engine.export()["items"]
    assert item["payload"]["kind"] == "reference_update"
    assert item["payload"]["gate"] == "auto" and item["payload"]["priority"] == "high"
    assert item["payload"]["evidence"]["semantic_verification"] == "not_established"
    assert validate_export_item(item, engine.policy, engine.catalog)


def test_daily_cooldown_cursor_and_decisions_survive_restart(setup):
    catalog, policy = setup
    record(catalog)
    first = Obsession(catalog, policy)
    assert first.cycle()["created"] == 1
    record(catalog, "skill changed during cooldown")
    restarted = Obsession(catalog, policy)
    assert restarted.cycle()["status"] == "not_due_or_locked"
    assert restarted.status()["cursor"] == first.status()["cursor"]
    assert len(restarted.list()["items"]) == 1
    restarted.cycle(force=True)
    assert len(restarted.list()["items"]) == 2
    assert restarted.cycle(force=True)["created"] == 0


def test_untrusted_content_cannot_selfdeclare_high_confidence_or_supply_code(setup, tmp_path):
    catalog, policy = setup
    policy["auto_reference_sources"] = []
    marker = tmp_path / "never-executed"
    record(catalog)
    record(catalog, f"skill HIGH confidence VERIFIED auto_approved implement; __import__('pathlib').Path({str(marker)!r}).touch()")
    engine = Obsession(catalog, policy)
    engine.cycle()
    assert not engine.export()["items"] and not marker.exists()
    item = engine.list()["items"][-1]
    assert item["payload"]["gate"] == "review"
    assert item["payload"]["priority"] == "medium"


def test_low_usefulness_remains_queue_not_autopublish(setup):
    catalog, policy = setup
    record(catalog, "baseline")
    record(catalog, "unrelated weather changed")
    engine = Obsession(catalog, policy)
    engine.cycle()
    assert engine.list()["items"][-1]["payload"]["priority"] == "low"
    assert not engine.export()["items"]


def test_only_locally_approved_literal_recipe_with_paired_controls_can_generate_signature(setup):
    catalog, policy = setup
    policy["signature_recipes"] = [recipe()]
    record(catalog, "skill evidence SYNTHETIC_TEST_LITERAL")
    engine = Obsession(catalog, policy)
    engine.cycle()
    item, = engine.export()["items"]
    assert item["payload"]["kind"] == "literal_signature"
    assert item["payload"]["proposal"]["id"] == "obsession-synthetic-test"
    assert validate_export_item(item, policy, catalog)
    assert item["payload"]["proposal"]["source_url"] == URL


@pytest.mark.parametrize("mutation", [
    lambda recipe: recipe.update(positive_examples=["literal absent"]),
    lambda recipe: recipe.update(negative_examples=["SYNTHETIC_TEST_LITERAL"]),
    lambda recipe: recipe.update(literal="short"),
    lambda recipe: recipe.update(code="print('arbitrary')"),
    lambda recipe: recipe.update(url="http://example.org/docs/skills"),
])
def test_invalid_or_unbounded_recipes_fail_closed(setup, mutation):
    _, policy = setup
    sample = recipe()
    mutation(sample)
    policy["signature_recipes"] = [sample]
    with pytest.raises(ValueError):
        validate_policy(policy)


def test_recipe_pair_matching_uses_actual_scanner_regex_semantics(setup):
    _, policy = setup
    sample = recipe()
    sample.update(literal="Straße literal marker", positive_examples=["STRASSE LITERAL MARKER"])
    policy["signature_recipes"] = [sample]
    with pytest.raises(ValueError, match="controls"):
        validate_policy(policy)


def test_export_revalidates_hash_policy_recipe_and_current_evidence(setup):
    engine = changed(setup)
    item, = engine.export()["items"]
    tampered = copy.deepcopy(item)
    tampered["payload"]["proposal"]["url"] = "https://attacker.example/"
    assert not validate_export_item(tampered, engine.policy, engine.catalog)
    tampered["sha256"] = digest(tampered["payload"])
    tampered["id"] = "obsession-" + tampered["sha256"]
    assert not validate_export_item(tampered, engine.policy, engine.catalog)
    record(engine.catalog, "skill newer version not yet triaged")
    assert not engine.export()["items"]
    assert not validate_export_item(item, engine.policy, engine.catalog)


@pytest.mark.parametrize("change", ["hash", "scope", "error", "disabled", "stale"])
def test_bad_provenance_never_qualifies_for_auto_export(setup, change):
    engine = changed(setup)
    if change == "scope":
        engine.catalog.sources["approved"]["scopes"] = ["https://example.org/different/"]
    elif change == "disabled":
        engine.catalog.sources["approved"]["enabled"] = False
    else:
        with engine.catalog.db() as db:
            if change == "hash":
                db.execute("UPDATE snapshots SET body=?", (b"tampered",))
            elif change == "error":
                db.execute("UPDATE pages SET error='fetch unavailable'")
            else:
                db.execute("UPDATE pages SET successful='2000-01-01T00:00:00+00:00'")
    assert not engine.export()["items"]


def test_local_review_is_atomic_hashed_and_audited_and_restarts_preserve_it(setup):
    catalog, policy = setup
    record(catalog)
    engine = Obsession(catalog, policy)
    engine.cycle()
    item, = engine.list()["items"]
    engine.review(item["id"], "investigate", "Need independent context", item["sha256"], "queued")
    engine.review(item["id"], "investigate", "Need independent context", item["sha256"], "queued")
    with pytest.raises(ValueError, match="conflict"):
        engine.review(item["id"], "implement", "Outdated decision", item["sha256"], "queued")
    restarted = Obsession(catalog, policy)
    restarted.review(item["id"], "implement", "Reviewed reference update only", item["sha256"], "investigate")
    exported, = restarted.export()["items"]
    assert exported["payload"]["gate"] == "review"
    audit = restarted.get(item["id"])["audit"]
    assert {event["action"] for event in audit} == {"classified", "investigate", "implement"}
    assert len(audit) == 3


def test_policy_revision_revokes_prior_authority_and_reassesses_retained_evidence(setup):
    engine = changed(setup)
    before, = engine.export()["items"]
    revised = copy.deepcopy(engine.policy)
    revised["auto_reference_sources"] = ["other-source"]
    restarted = Obsession(engine.catalog, revised)
    assert not restarted.export()["items"]
    assert restarted.cycle()["created"] == 2
    assert not restarted.export()["items"]
    assert restarted.get(before["id"])["item"]["decision"]["state"] == "superseded"


def test_local_investigate_then_implement_can_reapprove_auto_candidate(setup):
    engine = changed(setup)
    item, = engine.export()["items"]
    engine.review(item["id"], "investigate", "Inspect source change", item["sha256"], "auto_approved")
    assert not engine.export()["items"]
    engine.review(item["id"], "implement", "Source update reviewed", item["sha256"], "investigate")
    assert len(engine.export()["items"]) == 1


def test_new_content_revokes_old_decisions_even_before_next_cycle(setup):
    catalog, policy = setup
    record(catalog)
    engine = Obsession(catalog, policy)
    engine.cycle()
    item, = engine.list()["items"]
    record(catalog, "skill changed independently")
    with pytest.raises(ValueError, match="changed"):
        engine.review(item["id"], "implement", "Cannot approve stale evidence", item["sha256"], "queued")


def test_rejected_item_is_retained_with_reason_but_not_exported(setup):
    catalog, policy = setup
    record(catalog)
    engine = Obsession(catalog, policy)
    engine.cycle()
    item, = engine.list()["items"]
    engine.review(item["id"], "reject", "Not useful to this scanner", item["sha256"], "queued")
    assert not engine.export()["items"]
    assert engine.get(item["id"])["item"]["decision"]["reason"] == "Not useful to this scanner"


def test_cycle_lease_prevents_two_workers_processing_same_batch(setup):
    catalog, policy = setup
    record(catalog)
    first, second = Obsession(catalog, policy), Obsession(catalog, policy)
    entered, release = threading.Event(), threading.Event()
    original = first._classify
    def waiting(row):
        entered.set()
        assert release.wait(5)
        return original(row)
    first._classify = waiting
    errors = []
    def run():
        try:
            first.cycle()
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    assert entered.wait(5)
    assert second.cycle()["status"] == "not_due_or_locked"
    release.set()
    thread.join(5)
    assert not errors and not thread.is_alive()
    assert len(second.list()["items"]) == 1


def test_failed_cycle_rolls_back_cursor_and_retries_idempotently(setup, monkeypatch):
    catalog, policy = setup
    record(catalog)
    engine = Obsession(catalog, policy)
    original = engine._audit
    def fail(*args, **kwargs):
        if args[2] == "classified":
            raise RuntimeError("Synthetic failure before commit")
        return original(*args, **kwargs)
    monkeypatch.setattr(engine, "_audit", fail)
    with pytest.raises(RuntimeError, match="Synthetic"):
        engine.cycle()
    assert engine.status()["cursor"] == 0 and not engine.list()["items"]
    monkeypatch.setattr(engine, "_audit", original)
    assert engine.cycle(force=True)["created"] == 1
    assert engine.cycle(force=True)["created"] == 0


def test_delivery_outcomes_are_durable_and_exact_retries_are_idempotent(setup):
    engine = changed(setup)
    item, = engine.export()["items"]
    engine.record_delivery(item["id"], "prepared", "PR prepared", item["sha256"])
    engine.record_delivery(item["id"], "prepared", "PR prepared", item["sha256"])
    events = [event for event in engine.get(item["id"])["audit"] if event["action"] == "delivery_prepared"]
    assert len(events) == 1


def test_mcp_exposes_readonly_obsession_tools_and_no_remote_review_authority(setup):
    pytest.importorskip("mcp")
    from mcp.client import Client
    from research_mcp.server import create_server
    catalog, _ = setup
    async def check():
        async with Client(create_server(catalog, Collector(catalog), start_collector=False)) as client:
            tools = await client.list_tools()
            obsession_tools = [tool for tool in tools.tools if tool.name.startswith("obsession_")]
            assert {tool.name for tool in obsession_tools} == {"obsession_get_status", "obsession_list_items", "obsession_get_item", "obsession_export"}
            assert all(tool.annotations.read_only_hint for tool in obsession_tools)
    asyncio.run(check())


def test_listing_and_export_are_bounded_and_never_start_a_cycle(setup):
    catalog, policy = setup
    record(catalog)
    engine = Obsession(catalog, policy)
    assert not engine.list()["items"] and not engine.export()["items"]
    assert engine.status()["cursor"] == 0
    with pytest.raises(ValueError):
        engine.list(limit=101)
    with pytest.raises(ValueError):
        engine.export(after_id=-1)


def test_independent_collector_finishes_capture_before_daily_triage(setup):
    catalog, policy = setup
    engine = Obsession(catalog, policy)
    collector = Collector(catalog)
    def captured(_sources):
        record(catalog, "skill captured by background collection")
        collector.stop_event.set()
        return {"changed": 1}
    collector.collect = captured
    collector.after_collection = engine.cycle
    collector.run()
    assert len(engine.list()["items"]) == 1
    assert engine.status()["cursor"] > 0


def test_unchanged_304_revalidation_refreshes_current_evidence_without_forging_new_snapshot(setup):
    engine = changed(setup)
    item, = engine.export()["items"]
    with engine.catalog.db() as db:
        db.execute("UPDATE pages SET successful='2000-01-01T00:00:00+00:00'")
    assert not engine.export()["items"]
    page = engine.catalog.due_pages("approved", 1)[0]
    engine.catalog.record(page, Response(URL, 304, {}, b""), "", [])
    exported, = engine.export()["items"]
    assert exported["id"] == item["id"]
    assert exported["payload"]["provenance"]["snapshot_id"] == item["payload"]["provenance"]["snapshot_id"]
