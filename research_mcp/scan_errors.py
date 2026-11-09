"""Durable untriaged operational issues; never model training labels."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from .catalog import Catalog, now

SCHEMA = "injecticide.scan-error.v1"
KINDS = {"Timeout", "ConnectionError", "HTTPError", "RuntimeError", "KeyError",
         "TypeError", "IndexError", "MemoryError", "OSError", "other"}
STATES = {"untriaged", "investigating", "confirmed", "rejected", "resolved"}
MAX_EVENTS = 10000


def validate(event):
    required = {"schema", "event_id", "http_status", "stage", "kind", "scanner_version"}
    if (not isinstance(event, dict) or set(event) != required or event["schema"] != SCHEMA
            or not isinstance(event["event_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", event["event_id"])
            or type(event["http_status"]) is not int or event["http_status"] not in {500, 502, 503, 504}
            or event["stage"] not in {"analysis", "sandbox"}
            or event["kind"] not in KINDS or not isinstance(event["scanner_version"], str)
            or not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", event["scanner_version"])):
        raise ValueError("Invalid operational error metadata")
    return event


class ScanErrors:
    def __init__(self, catalog):
        self.catalog = catalog
        with catalog.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS scan_error_groups (
                    id TEXT PRIMARY KEY, signature TEXT NOT NULL, occurrences INTEGER NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_event INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'untriaged');
                CREATE TABLE IF NOT EXISTS scan_error_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
                    group_id TEXT NOT NULL, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scan_error_reviews (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL,
                    old_state TEXT NOT NULL, new_state TEXT NOT NULL,
                    occurrences INTEGER NOT NULL, reviewed TEXT NOT NULL);
            """)

    def enqueue(self, event):
        validate(event)
        signature = {key: event[key] for key in ("http_status", "stage", "kind", "scanner_version")}
        encoded = json.dumps(signature, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(encoded.encode()).hexdigest()
        timestamp = now()
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT group_id FROM scan_error_events WHERE event_id=?",
                                  (event["event_id"],)).fetchone()
            if previous:
                if previous[0] != fingerprint:
                    raise ValueError("Error event identity conflict")
                return {"status": "recorded", "id": fingerprint, "duplicate": True}
            if db.execute("SELECT count(*) FROM scan_error_events").fetchone()[0] >= MAX_EVENTS:
                raise OverflowError("Issue capacity reached; evidence preserved")
            cursor = db.execute("INSERT INTO scan_error_events(event_id,group_id,created) VALUES (?,?,?)",
                                (event["event_id"], fingerprint, timestamp)).lastrowid
            db.execute("""INSERT INTO scan_error_groups
                (id,signature,occurrences,first_seen,last_seen,last_event) VALUES (?,?,1,?,?,?)
                ON CONFLICT(id) DO UPDATE SET occurrences=occurrences+1,last_seen=excluded.last_seen,
                last_event=excluded.last_event,
                state=CASE WHEN state='resolved' THEN 'untriaged' ELSE state END""",
                (fingerprint, encoded, timestamp, timestamp, cursor))
        return {"status": "recorded", "id": fingerprint, "duplicate": False}

    def list(self, after_id=0, limit=20, state=""):
        if (type(after_id) is not int or after_id < 0 or type(limit) is not int or not 1 <= limit <= 100
                or state and state not in STATES):
            raise ValueError("Invalid issue page")
        with self.catalog.db() as db:
            rows = db.execute("""SELECT * FROM scan_error_groups WHERE last_event>?
                AND (?='' OR state=?) ORDER BY last_event LIMIT ?""",
                (after_id, state, state, limit)).fetchall()
            items = []
            for row in rows:
                samples = [r[0] for r in db.execute("""SELECT event_id FROM scan_error_events
                    WHERE group_id=? ORDER BY seq DESC LIMIT 5""", (row["id"],))]
                items.append({"id": row["id"], "cursor": row["last_event"], "state": row["state"],
                    "signature": json.loads(row["signature"]), "occurrences": row["occurrences"],
                    "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                    "recent_request_ids": samples, "confirmed_bug": row["state"] == "confirmed"})
        return {"schema": SCHEMA, "classification": "operational_issues_not_training_labels",
                "content_retained": False, "items": items}

    def review(self, issue_id, state, expected_count, expected_state="untriaged"):
        if (not re.fullmatch(r"[a-f0-9]{64}", issue_id) or state not in STATES
                or expected_state not in STATES or type(expected_count) is not int or expected_count < 1):
            raise ValueError("Invalid local review")
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scan_error_groups WHERE id=?", (issue_id,)).fetchone()
            if not row or row["occurrences"] != expected_count or row["state"] != expected_state:
                raise ValueError("Issue changed; read it again before reviewing")
            db.execute("UPDATE scan_error_groups SET state=? WHERE id=?", (state, issue_id))
            db.execute("""INSERT INTO scan_error_reviews
                (group_id,old_state,new_state,occurrences,reviewed) VALUES (?,?,?,?,?)""",
                (issue_id, expected_state, state, expected_count, now()))
        return {"id": issue_id, "state": state, "reviewed": True}


def main():
    parser = argparse.ArgumentParser(description="Trusted local scan issue review; no remote write tool")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--sources", type=Path, default=Path(__file__).with_name("sources.json"))
    parser.add_argument("command", choices=["list", "review"])
    parser.add_argument("--id", default="")
    parser.add_argument("--state", default="untriaged")
    parser.add_argument("--expected-state", default="untriaged")
    parser.add_argument("--expected-count", type=int, default=0)
    args = parser.parse_args()
    errors = ScanErrors(Catalog(args.db, args.sources))
    result = errors.list(state=args.state) if args.command == "list" else errors.review(
        args.id, args.state, args.expected_count, args.expected_state)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
