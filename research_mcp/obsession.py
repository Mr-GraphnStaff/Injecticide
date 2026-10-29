"""Durable, bounded research triage. Network content never supplies authority.

The collector obtains evidence independently. This worker consumes its SQLite
snapshots daily; scanner requests neither start a cycle nor execute research.
Review mutations are trusted local CLI operations, never public MCP tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .catalog import Catalog, active_page
from .fetch import canonical_url, in_scope

LOG = logging.getLogger(__name__)
POLICY_PATH = Path(__file__).with_name("obsession_policy.json")
GATE_ALGORITHM_VERSION = 1
STATES = {"queued", "auto_approved", "implement", "investigate", "reject", "superseded"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds")


def load_policy(path=POLICY_PATH):
    if Path(path).stat().st_size > 262144:
        raise ValueError("Obsession policy exceeds 256 KiB")
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_policy(policy)
    return policy


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("Unsupported Obsession policy schema")
    if policy.get("gate_algorithm_version") != GATE_ALGORITHM_VERSION:
        raise ValueError("Unsupported local gate algorithm version")
    for key, minimum, maximum in (("interval_seconds", 86400, 604800),
                                   ("snapshot_budget", 1, 100),
                                   ("max_evidence_age_seconds", 3600, 604800),
                                   ("max_queue_items", 100, 10000)):
        if type(policy.get(key)) is not int or not minimum <= policy[key] <= maximum:
            raise ValueError("Invalid bounded policy field: " + key)
    for key in ("useful_terms", "auto_reference_sources"):
        values = policy.get(key)
        minimum = 0 if key == "auto_reference_sources" else 1
        if not isinstance(values, list) or not minimum <= len(values) <= 100 or any(
                not isinstance(value, str) or not 1 <= len(value) <= 160 for value in values):
            raise ValueError("Invalid local policy list: " + key)
    recipes = policy.get("signature_recipes")
    if not isinstance(recipes, list) or len(recipes) > 50:
        raise ValueError("Use at most 50 locally reviewed signature recipes")
    seen = set()
    for recipe in recipes:
        required = {"id", "source_id", "url", "literal", "description", "severity", "positive_examples", "negative_examples"}
        if not isinstance(recipe, dict) or set(recipe) != required:
            raise ValueError("Recipe fields must match the reviewed literal template")
        if not isinstance(recipe["id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", recipe["id"]) or recipe["id"] in seen:
            raise ValueError("Recipe IDs must be unique local identifiers")
        seen.add(recipe["id"])
        if not isinstance(recipe["source_id"], str) or not recipe["source_id"]:
            raise ValueError("Recipe source_id is required")
        canonical_url(recipe["url"])
        literal = recipe["literal"]
        if not isinstance(literal, str) or not 12 <= len(literal) <= 160 or any(ord(char) < 32 for char in literal):
            raise ValueError("Recipe literal must be 12–160 printable characters")
        if not isinstance(recipe["description"], str) or not 1 <= len(recipe["description"]) <= 300 or recipe["severity"] not in {"medium", "high"}:
            raise ValueError("Invalid signature description/severity")
        for key in ("positive_examples", "negative_examples"):
            values = recipe[key]
            if not isinstance(values, list) or not 1 <= len(values) <= 5 or any(
                    not isinstance(value, str) or not 1 <= len(value) <= 1000 for value in values):
                raise ValueError("Recipes require bounded positive and negative examples")
        pattern = re.compile(re.escape(literal), re.IGNORECASE)
        if any(not pattern.search(value) for value in recipe["positive_examples"]) or any(
                pattern.search(value) for value in recipe["negative_examples"]):
            raise ValueError("Recipe fails its literal positive/negative controls")


def _recipe_proposal(recipe):
    return {"id": "obsession-" + recipe["id"], **{key: recipe[key] for key in (
        "literal", "description", "severity", "positive_examples", "negative_examples")}, "source_url": recipe["url"]}


def _snapshot_current(catalog, provenance, clock, max_age=604800):
    source = catalog.sources.get(provenance["source_id"])
    if not source or not source.get("enabled", True):
        return False
    if not active_page(source, provenance["url"]) or not in_scope(provenance["final_url"], source["scopes"]):
        return False
    with catalog.db() as db:
        row = db.execute("""SELECT s.*,p.error,p.successful FROM snapshots s JOIN pages p
            ON p.source=s.source AND p.url=s.url WHERE s.source=? AND s.url=?
            ORDER BY s.id DESC LIMIT 1""", (provenance["source_id"], provenance["url"])).fetchone()
    if row is None or row["error"] or row["sha256"] != provenance["source_sha256"] or row["id"] != provenance["snapshot_id"]:
        return False
    return (row["final_url"] == provenance["final_url"] and row["retrieved"] == provenance["retrieved"]
            and hashlib.sha256(row["body"]).hexdigest() == row["sha256"]
            and 0 <= clock - datetime.fromisoformat(row["retrieved"]).timestamp()
            and row["successful"] is not None
            and 0 <= clock - datetime.fromisoformat(row["successful"]).timestamp() <= max_age)


def validate_export_item(item, policy=None, catalog=None):
    """Validate immutable template/authority, optionally against live local evidence.

    Without Catalog this is structural/local-policy validation only. A delivery
    consumer MUST also match the digest against a fresh trusted local export;
    an internet-supplied object with a valid checksum is not approved evidence.
    """
    try:
        policy = load_policy() if policy is None else policy
        validate_policy(policy)
        if not isinstance(item, dict) or set(item) != {"sequence", "id", "sha256", "payload", "decision"}:
            return False
        payload, decision = item["payload"], item["decision"]
        if set(payload) != {"schema_version", "kind", "gate", "priority", "policy_sha256", "provenance", "proposal", "evidence"}:
            return False
        if payload["schema_version"] != 1 or payload["policy_sha256"] != digest(policy):
            return False
        if item["sha256"] != digest(payload) or item["id"] != "obsession-" + item["sha256"]:
            return False
        if type(item["sequence"]) is not int or item["sequence"] < 1:
            return False
        provenance, evidence = payload["provenance"], payload["evidence"]
        if set(provenance) != {"source_id", "url", "final_url", "snapshot_id", "source_sha256", "retrieved", "previous_sha256"}:
            return False
        canonical_url(provenance["url"])
        canonical_url(provenance["final_url"])
        if not re.fullmatch(r"[a-f0-9]{64}", provenance["source_sha256"]):
            return False
        if provenance["previous_sha256"] is not None and not re.fullmatch(r"[a-f0-9]{64}", provenance["previous_sha256"]):
            return False
        if type(provenance["snapshot_id"]) is not int or provenance["snapshot_id"] < 1:
            return False
        if set(evidence) - {"excerpt", "fetch_verified", "semantic_verification", "authority"} or evidence.get("semantic_verification") != "not_established":
            return False
        if type(evidence.get("fetch_verified")) is not bool or evidence.get("authority", "local_policy_only") != "local_policy_only":
            return False
        if set(decision) != {"state", "reason", "updated"} or not isinstance(decision["reason"], str) or not 1 <= len(decision["reason"]) <= 500:
            return False
        datetime.fromisoformat(decision["updated"])
        if not isinstance(evidence.get("excerpt"), str) or len(evidence["excerpt"]) > 2000:
            return False
        if payload["gate"] not in {"auto", "review"} or payload["priority"] not in {"high", "medium", "low"}:
            return False
        if payload["gate"] == "auto":
            if payload["priority"] != "high" or evidence.get("fetch_verified") is not True or decision.get("state") not in {"auto_approved", "implement"}:
                return False
        elif decision.get("state") != "implement":
            return False
        if payload["kind"] == "reference_update":
            expected = {"source_id": provenance["source_id"], "url": provenance["final_url"],
                        "source_sha256": provenance["source_sha256"], "previous_sha256": provenance["previous_sha256"],
                        "change_type": "source_content_changed" if provenance["previous_sha256"] else "initial_baseline"}
            if payload["proposal"] != expected:
                return False
            if payload["gate"] == "auto" and (provenance["source_id"] not in policy["auto_reference_sources"] or not provenance["previous_sha256"]):
                return False
        elif payload["kind"] == "literal_signature":
            recipe = next((r for r in policy["signature_recipes"] if _recipe_proposal(r) == payload["proposal"]), None)
            if not recipe or recipe["source_id"] != provenance["source_id"] or recipe["url"] != provenance["final_url"]:
                return False
            if not re.search(re.escape(recipe["literal"]), evidence["excerpt"], re.I):
                return False
        else:
            return False
        age = time.time() - datetime.fromisoformat(provenance["retrieved"]).timestamp()
        if age < 0:
            return False
        if catalog is not None and not _snapshot_current(catalog, provenance, time.time(), policy["max_evidence_age_seconds"]):
            return False
        return True
    except (KeyError, ValueError, TypeError, AttributeError, StopIteration, OverflowError):
        return False


class Obsession:
    def __init__(self, catalog, policy=None, clock=time.time):
        self.catalog, self.policy, self.clock = catalog, load_policy() if policy is None else policy, clock
        validate_policy(self.policy)
        self.owner = uuid.uuid4().hex
        self.driver_thread = None
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="obsession-research", daemon=True)
        with catalog.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS obsession_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),cursor INTEGER NOT NULL,
                    next_due REAL NOT NULL,lease_until REAL NOT NULL,owner TEXT,last_cycle TEXT,last_error TEXT,policy_sha256 TEXT);
                INSERT OR IGNORE INTO obsession_state(singleton,cursor,next_due,lease_until) VALUES(1,0,0,0);
                CREATE TABLE IF NOT EXISTS obsession_items (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL,source TEXT NOT NULL,url TEXT NOT NULL,snapshot_id INTEGER NOT NULL,
                    state TEXT NOT NULL,reason TEXT NOT NULL,updated TEXT NOT NULL,delivery TEXT);
                CREATE TABLE IF NOT EXISTS obsession_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,item_id TEXT,action TEXT NOT NULL,
                    reason TEXT NOT NULL,actor TEXT NOT NULL,created TEXT NOT NULL,details TEXT NOT NULL);
            """)
            if "policy_sha256" not in {row["name"] for row in db.execute("PRAGMA table_info(obsession_state)")}:
                db.execute("ALTER TABLE obsession_state ADD COLUMN policy_sha256 TEXT")

    def _audit(self, db, item_id, action, reason, actor="local_worker", details=None):
        db.execute("INSERT INTO obsession_audit(item_id,action,reason,actor,created,details) VALUES(?,?,?,?,?,?)",
                   (item_id, action, reason, actor, timestamp(self.clock()), canonical(details or {})))

    def _classify(self, row):
        source = self.catalog.sources.get(row["source"])
        if not source or not source.get("enabled", True) or not active_page(source, row["url"]):
            return []
        text = row["text"]
        relevant = any(re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text, re.I) for term in self.policy["useful_terms"])
        provenance = {"source_id": row["source"], "url": row["url"], "final_url": row["final_url"],
                      "snapshot_id": row["id"], "source_sha256": row["sha256"], "retrieved": row["retrieved"],
                      "previous_sha256": row["previous_sha256"]}
        verified = _snapshot_current(self.catalog, provenance, self.clock(), self.policy["max_evidence_age_seconds"])
        auto = verified and relevant and bool(row["previous_sha256"]) and row["source"] in self.policy["auto_reference_sources"]
        payload = {"schema_version": 1, "kind": "reference_update", "gate": "auto" if auto else "review",
                   "priority": "high" if auto else "medium" if relevant else "low", "policy_sha256": digest(self.policy),
                   "provenance": provenance,
                   "proposal": {"source_id": row["source"], "url": row["final_url"], "source_sha256": row["sha256"],
                                "previous_sha256": row["previous_sha256"], "change_type": "source_content_changed" if row["previous_sha256"] else "initial_baseline"},
                   "evidence": {"excerpt": text[:2000], "fetch_verified": verified,
                                "semantic_verification": "not_established", "authority": "local_policy_only"}}
        payloads = [payload]
        for recipe in self.policy["signature_recipes"]:
            match = re.search(re.escape(recipe["literal"]), text, re.I)
            if verified and recipe["source_id"] == row["source"] and recipe["url"] == row["final_url"] and match:
                candidate = json.loads(canonical(payload))
                candidate.update(kind="literal_signature", gate="auto", priority="high", proposal=_recipe_proposal(recipe))
                candidate["evidence"]["excerpt"] = text[max(0, match.start() - 200):match.start() + 1800]
                payloads.append(candidate)
        return payloads

    def cycle(self, force=False):
        current = self.clock()
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            state = db.execute("SELECT * FROM obsession_state WHERE singleton=1").fetchone()
            policy_changed = state["policy_sha256"] != digest(self.policy)
            if state["lease_until"] > current or not force and not policy_changed and state["next_due"] > current:
                return {"status": "not_due_or_locked", "next_due": state["next_due"]}
            if policy_changed:
                for item in db.execute("SELECT id FROM obsession_items WHERE state!='superseded'").fetchall():
                    db.execute("UPDATE obsession_items SET state='superseded',reason=?,updated=? WHERE id=?",
                               ("Local policy changed; prior authority revoked", timestamp(current), item["id"]))
                    self._audit(db, item["id"], "superseded", "Local policy changed; prior authority revoked")
                db.execute("UPDATE obsession_state SET cursor=0,policy_sha256=? WHERE singleton=1", (digest(self.policy),))
            db.execute("UPDATE obsession_state SET lease_until=?,owner=? WHERE singleton=1", (current + 300, self.owner))
            cursor = 0 if policy_changed else state["cursor"]
        try:
            # No write transaction while verifying evidence via Catalog reads.
            with self.catalog.db() as db:
                rows = list(db.execute("SELECT * FROM snapshots WHERE id>? ORDER BY id LIMIT ?", (cursor, self.policy["snapshot_budget"])))
            candidates = [(row, self._classify(row)) for row in rows]
            created = 0
            with self.catalog.db() as db:
                db.execute("BEGIN IMMEDIATE")
                state = db.execute("SELECT * FROM obsession_state WHERE singleton=1").fetchone()
                if state["owner"] != self.owner or state["lease_until"] <= self.clock():
                    raise RuntimeError("Obsession cycle lease expired")
                for row, payloads in candidates:
                    for payload in payloads:
                        checksum = digest(payload)
                        item_id = "obsession-" + checksum
                        if db.execute("SELECT 1 FROM obsession_items WHERE id=?", (item_id,)).fetchone():
                            continue
                        if db.execute("SELECT count(*) FROM obsession_items WHERE state NOT IN ('reject','superseded')").fetchone()[0] >= self.policy["max_queue_items"]:
                            raise ValueError("Durable queue capacity reached; review/archive policy required")
                        old = db.execute("SELECT id FROM obsession_items WHERE source=? AND url=? AND snapshot_id<? AND state!='superseded'",
                                         (row["source"], row["url"], row["id"])).fetchall()
                        for previous in old:
                            db.execute("UPDATE obsession_items SET state='superseded',reason=?,updated=? WHERE id=?",
                                       ("New source content superseded this evidence", timestamp(self.clock()), previous["id"]))
                            self._audit(db, previous["id"], "superseded", "New source content superseded this evidence")
                        decision = "auto_approved" if payload["gate"] == "auto" else "queued"
                        reason = "Locally approved deterministic gate passed" if decision == "auto_approved" else "Requires local Implement, Investigate or Reject decision"
                        db.execute("INSERT INTO obsession_items(id,sha256,payload,source,url,snapshot_id,state,reason,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (item_id, checksum, canonical(payload), row["source"], row["url"], row["id"], decision, reason, timestamp(self.clock())))
                        self._audit(db, item_id, "classified", reason, details={"gate": payload["gate"], "policy_sha256": digest(self.policy)})
                        created += 1
                cursor = rows[-1]["id"] if rows else cursor
                db.execute("UPDATE obsession_state SET cursor=?,next_due=?,lease_until=0,owner=NULL,last_cycle=?,last_error=NULL WHERE singleton=1",
                           (cursor, self.clock() + self.policy["interval_seconds"], timestamp(self.clock())))
                self._audit(db, None, "cycle_completed", "Bounded snapshot cycle completed", details={"cursor": cursor, "created": created})
            return {"status": "completed", "processed": len(rows), "created": created, "cursor": cursor}
        except Exception as error:
            with self.catalog.db() as db:
                db.execute("UPDATE obsession_state SET lease_until=0,owner=NULL,next_due=?,last_error=? WHERE singleton=1 AND owner=?",
                           (self.clock() + 300, type(error).__name__, self.owner))
                self._audit(db, None, "cycle_failed", type(error).__name__)
            raise

    @staticmethod
    def _item(row):
        return {"sequence": row["sequence"], "id": row["id"], "sha256": row["sha256"],
                "payload": json.loads(row["payload"]), "decision": {"state": row["state"], "reason": row["reason"], "updated": row["updated"]}}

    def status(self):
        with self.catalog.db() as db:
            state = dict(db.execute("SELECT * FROM obsession_state WHERE singleton=1").fetchone())
            counts = {row["state"]: row["count"] for row in db.execute("SELECT state,count(*) AS count FROM obsession_items GROUP BY state")}
        state.pop("owner", None)
        return {"schema_version": 1, **state, "counts": counts, "worker_alive": (self.driver_thread or self.thread).is_alive(),
                "interval_seconds": self.policy["interval_seconds"], "policy_sha256": digest(self.policy),
                "authority": "local_policy_and_local_review_only", "external_paid_calls": False}

    def list(self, after_id=0, limit=20, state=""):
        if type(after_id) is not int or after_id < 0 or type(limit) is not int or not 1 <= limit <= 100 or state and state not in STATES:
            raise ValueError("Use nonnegative cursor, limit 1–100 and a known state")
        with self.catalog.db() as db:
            rows = list(db.execute("SELECT * FROM obsession_items WHERE sequence>? AND (?='' OR state=?) ORDER BY sequence LIMIT ?",
                                   (after_id, state, state, limit + 1)))
        return {"schema_version": 1, "items": [self._item(row) for row in rows[:limit]],
                "next_after_id": rows[limit-1]["sequence"] if len(rows) > limit else None, "untrusted_content": True}

    def get(self, item_id):
        with self.catalog.db() as db:
            row = db.execute("SELECT * FROM obsession_items WHERE id=?", (item_id,)).fetchone()
            audit = [dict(row) for row in db.execute("SELECT sequence,action,reason,actor,created,details FROM obsession_audit WHERE item_id=? ORDER BY sequence DESC LIMIT 100", (item_id,))]
        if row is None:
            raise ValueError("Unknown Obsession item")
        return {"item": self._item(row), "audit": audit, "audit_limit": 100, "untrusted_content": True}

    def export(self, after_id=0, limit=20):
        self.list(after_id, limit)  # Validate the bounded pagination contract.
        with self.catalog.db() as db:
            rows = list(db.execute("SELECT * FROM obsession_items WHERE sequence>? AND state IN ('auto_approved','implement') ORDER BY sequence LIMIT ?", (after_id, limit + 1)))
        page = {"schema_version": 1, "items": [self._item(row) for row in rows[:limit]],
                "next_after_id": rows[limit-1]["sequence"] if len(rows) > limit else None, "untrusted_content": True}
        page["items"] = [item for item in page["items"] if validate_export_item(item, self.policy, self.catalog)]
        page["admission"] = "Match against this fresh local export and independently validate policy; publication still requires the delivery pipeline gates."
        return page

    def review(self, item_id, decision, reason, expected_sha256, expected_state, actor="local_cli"):
        if decision not in {"implement", "investigate", "reject"} or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
            raise ValueError("Choose Implement, Investigate or Reject and supply a reason up to 500 characters")
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM obsession_items WHERE id=?", (item_id,)).fetchone()
            retry = row is not None and row["state"] == decision and row["reason"] == reason.strip()
            if row is None or row["sha256"] != expected_sha256 or row["state"] != expected_state and not retry or row["state"] == "superseded":
                raise ValueError("Review conflict: refresh the immutable item and decision state")
            payload = json.loads(row["payload"])
            if payload["policy_sha256"] != digest(self.policy):
                raise ValueError("Local policy changed; evidence must be reassessed")
            # A known newer source revision revokes old review authority.
            latest = db.execute("SELECT id,sha256 FROM snapshots WHERE source=? AND url=? ORDER BY id DESC LIMIT 1", (row["source"], row["url"])).fetchone()
            if latest is None or latest["id"] != row["snapshot_id"] or latest["sha256"] != payload["provenance"]["source_sha256"]:
                raise ValueError("Source changed or was pruned; refresh evidence before reviewing")
            if not retry:
                db.execute("UPDATE obsession_items SET state=?,reason=?,updated=? WHERE id=?", (decision, reason.strip(), timestamp(self.clock()), item_id))
                self._audit(db, item_id, decision, reason.strip(), actor, {"previous_state": expected_state, "sha256": expected_sha256})
        return self.get(item_id)

    def record_delivery(self, item_id, outcome, reason, expected_sha256):
        if outcome not in {"prepared", "published", "failed"} or not 1 <= len(reason) <= 500:
            raise ValueError("Use a bounded delivery outcome and reason")
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM obsession_items WHERE id=? AND sha256=?", (item_id, expected_sha256)).fetchone()
            if row is None:
                raise ValueError("Delivery digest does not identify a retained item")
            outcome_record = {"outcome": outcome, "reason": reason, "sha256": expected_sha256}
            encoded = canonical(outcome_record)
            prior = db.execute("SELECT 1 FROM obsession_audit WHERE item_id=? AND action=? AND details=?", (item_id, "delivery_" + outcome, encoded)).fetchone()
            if prior is None:
                db.execute("UPDATE obsession_items SET delivery=? WHERE id=?", (encoded, item_id))
                self._audit(db, item_id, "delivery_" + outcome, reason, "local_delivery_cli", outcome_record)
        return {"recorded": True, "id": item_id, "outcome": outcome}

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.cycle()
            except Exception:
                LOG.exception("Obsession cycle failed; durable cursor retained")
            self.stop_event.wait(30)

    def close(self):
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=25)


def main():
    parser = argparse.ArgumentParser(description="Trusted local Obsession review/control; no remote write API")
    parser.add_argument("--db", type=Path, default=Path(os.environ.get("RESEARCH_DB", "/data/research.sqlite3")))
    parser.add_argument("--sources", type=Path, default=Path(__file__).with_name("sources.json"))
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("command", choices=["status", "list", "get", "cycle", "export", "review", "delivery"])
    parser.add_argument("--id", default="")
    parser.add_argument("--decision", default="")
    parser.add_argument("--reason", default="")
    parser.add_argument("--sha256", default="")
    parser.add_argument("--expected-state", default="queued")
    parser.add_argument("--after-id", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    engine = Obsession(Catalog(args.db, args.sources), load_policy(args.policy))
    if args.command in {"status", "cycle"}:
        result = getattr(engine, args.command)()
    elif args.command in {"list", "export"}:
        result = getattr(engine, args.command)(args.after_id, args.limit)
    elif args.command == "get":
        result = engine.get(args.id)
    elif args.command == "review":
        result = engine.review(args.id, args.decision, args.reason, args.sha256, args.expected_state)
    else:
        result = engine.record_delivery(args.id, args.decision, args.reason, args.sha256)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
