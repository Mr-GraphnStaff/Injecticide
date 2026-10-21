"""SQLite evidence catalog. Retrieved content is unverified research data."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .fetch import HARD_MAX_BYTES, MAX_BYTES, canonical_url, in_scope
from .apis import API_CONNECTORS, api_connector, github_releases, is_github_releases_url

STATUS = "STATUS: UNKNOWN — UNVERIFIED"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def active_page(source: dict, url: str) -> bool:
    return in_scope(url, source["scopes"]) and (
        source.get("discovery", True) or url in source["seeds"])


class Catalog:
    def __init__(self, path: Path, config: Path):
        self.path = path
        sources = json.loads(config.read_text(encoding="utf-8"))["sources"]
        if not sources or len(sources) > 100:
            raise ValueError("Configure between 1 and 100 sources")
        self.sources = {}
        for source in sources:
            sid = source["id"]
            if sid in self.sources or not sid.replace("-", "").isalnum():
                raise ValueError("Source IDs must be unique alphanumeric/hyphen identifiers")
            if not 1 <= len(source["seeds"]) <= 20 or not 1 <= len(source["scopes"]) <= 20:
                raise ValueError("Each source needs 1–20 seeds and scopes")
            for scope in source["scopes"]:
                canonical_url(scope)
            for url in source["seeds"]:
                if not in_scope(url, source["scopes"]):
                    raise ValueError(f"Seed outside source scope: {sid}")
            connector = source.get("connector", "web")
            if connector not in {"web", *API_CONNECTORS}:
                raise ValueError("Unsupported source connector")
            if type(source.get("enabled", True)) is not bool:
                raise ValueError("enabled must be a boolean")
            if type(source.get("discovery", True)) is not bool:
                raise ValueError("discovery must be a boolean")
            size = source.get("max_response_bytes", MAX_BYTES)
            if type(size) is not int or not 1 <= size <= HARD_MAX_BYTES:
                raise ValueError("max_response_bytes must be between 1 byte and 8 MiB")
            if connector in API_CONNECTORS and any(api_connector(url) != connector for url in source["seeds"]):
                raise ValueError("API seed does not match its provider contract")
            if connector == "github_releases" and (
                len(source["seeds"]) != 1 or not is_github_releases_url(source["seeds"][0])
            ):
                raise ValueError("GitHub connector requires one public repository releases endpoint")
            self.sources[sid] = source
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS pages (
                    source TEXT NOT NULL, url TEXT NOT NULL, checked TEXT,
                    successful TEXT, error TEXT, etag TEXT, modified TEXT,
                    PRIMARY KEY(source, url));
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL, url TEXT NOT NULL, final_url TEXT NOT NULL,
                    retrieved TEXT NOT NULL, sha256 TEXT NOT NULL, media TEXT NOT NULL,
                    body BLOB NOT NULL, text TEXT NOT NULL, previous_sha256 TEXT);
                CREATE INDEX IF NOT EXISTS snapshot_lookup ON snapshots(source,url,id);
            """)
            # Registry migration retires collection targets without deleting evidence.
            # Current queries/scheduling filter scope; archived rows remain recoverable.
            for sid, source in self.sources.items():
                for url in source["seeds"]:
                    db.execute("INSERT OR IGNORE INTO pages(source,url) VALUES (?,?)",
                               (sid, canonical_url(url)))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        # Cap the database at 256 MiB; snapshots are independently bounded/pruned.
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={268435456 // page_size}")
        try:
            with db:
                yield db
        finally:
            db.close()

    def due_pages(self, source_id: str, limit: int) -> list[dict]:
        if not self.sources[source_id].get("enabled", True):
            return []
        with self.db() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM pages WHERE source=? ORDER BY checked IS NOT NULL, checked, url",
                (source_id,)) if active_page(self.sources[source_id], r["url"])][:limit]

    def record(self, page: dict, response, text: str, links: list[str]) -> bool:
        sid, url = page["source"], page["url"]
        timestamp = now()
        with self.db() as db:
            if not db.execute("SELECT 1 FROM pages WHERE source=? AND url=?", (sid, url)).fetchone():
                return False  # This page rotated out while a bounded cycle was in flight.
            previous = db.execute(
                "SELECT sha256 FROM snapshots WHERE source=? AND url=? ORDER BY id DESC LIMIT 1",
                (sid, url)).fetchone()
            if response.status == 304 and previous is None:
                raise ValueError("304 without a retained baseline")
            if response.status not in (200, 304):
                raise ValueError(f"HTTP {response.status}")
            digest = hashlib.sha256(response.body).hexdigest()
            changed = response.status == 200 and (previous is None or previous[0] != digest)
            if changed:
                db.execute("""INSERT INTO snapshots
                    (source,url,final_url,retrieved,sha256,media,body,text,previous_sha256)
                    VALUES (?,?,?,?,?,?,?,?,?)""", (sid, url, response.url, timestamp, digest,
                    response.headers.get("content-type", ""), response.body, text[:100000],
                    previous[0] if previous else None))
                db.execute("""DELETE FROM snapshots WHERE source=? AND url=? AND id NOT IN
                    (SELECT id FROM snapshots WHERE source=? AND url=? ORDER BY id DESC LIMIT 3)""",
                    (sid, url, sid, url))
            db.execute("""UPDATE pages SET checked=?, successful=?, error=NULL,
                etag=COALESCE(?,etag), modified=COALESCE(?,modified) WHERE source=? AND url=?""",
                (timestamp, timestamp, response.headers.get("etag"),
                 response.headers.get("last-modified"), sid, url))
            # A per-source ceiling stops one vendor consuming the whole frontier.
            count = db.execute("SELECT count(*) FROM pages WHERE source=?", (sid,)).fetchone()[0]
            rotations = 0
            seeds = {canonical_url(seed) for seed in self.sources[sid]["seeds"]}
            for link in links:
                if not self.sources[sid].get("discovery", True):
                    break
                if in_scope(link, self.sources[sid]["scopes"]):
                    link = canonical_url(link)
                    if db.execute("SELECT 1 FROM pages WHERE source=? AND url=?", (sid, link)).fetchone():
                        continue
                    if count >= 100:
                        # Preserve discovery roots; rotate only already-attempted derived pages.
                        # Retention is bounded research storage, never a permanent audit ledger.
                        if rotations >= 8:
                            break
                        victim = next((r["url"] for r in db.execute(
                            "SELECT url FROM pages WHERE source=? AND checked IS NOT NULL ORDER BY checked,url",
                            (sid,)) if r["url"] not in seeds and r["url"] != url), None)
                        if victim is None:
                            continue
                        db.execute("DELETE FROM pages WHERE source=? AND url=?", (sid, victim))
                        db.execute("DELETE FROM snapshots WHERE source=? AND url=?", (sid, victim))
                        count -= 1
                        rotations += 1
                    count += db.execute("INSERT OR IGNORE INTO pages(source,url) VALUES (?,?)",
                                        (sid, link)).rowcount
            return changed

    def failure(self, page: dict, error: Exception):
        # Store a bounded diagnostic as untrusted metadata; operational logs omit it.
        with self.db() as db:
            db.execute("UPDATE pages SET checked=?, error=? WHERE source=? AND url=?",
                       (now(), f"{type(error).__name__}: {str(error)[:160]}", page["source"], page["url"]))

    def list_sources(self) -> dict:
        result = []
        with self.db() as db:
            for sid, source in self.sources.items():
                all_rows = list(db.execute("SELECT * FROM pages WHERE source=?", (sid,)))
                rows = [r for r in all_rows if active_page(source, r["url"])]
                successes = [r["successful"] for r in rows if r["successful"]]
                oldest = min(successes) if successes else None
                stale = oldest is None or (datetime.now(timezone.utc) -
                    datetime.fromisoformat(oldest)).total_seconds() > 86400
                errors = sum(r["error"] is not None for r in rows)
                pending = sum(r["successful"] is None for r in rows)
                freshness = "stale" if stale else "current"
                if errors or pending:
                    freshness = "degraded" if successes else "unknown"
                result.append({**source, "pages": len(rows), "frontier_full": len(rows) >= 100,
                    "enabled": source.get("enabled", True),
                    "archived_pages": len(all_rows) - len(rows),
                    "coverage": "bounded first page only; not complete synchronization" if source.get("connector") in API_CONNECTORS else "bounded approved-source collection",
                    "pending": sum(r["checked"] is None for r in rows),
                    "errors": errors,
                    "failure_examples": [{"url": r["url"], "diagnostic": r["error"],
                                          "untrusted_metadata": True}
                                         for r in rows if r["error"]][:3],
                    "is_stale": stale,
                    "oldest_success": oldest, "freshness": freshness,
                    "verification": STATUS})
        return {"sources": result, "coverage": "bounded approved-source crawl, not exhaustive internet coverage"}

    def query(self, query: str = "", source_id: str = "", after_id: int = 0,
              limit: int = 20, latest_only: bool = True) -> dict:
        if not 1 <= limit <= 50 or after_id < 0 or len(query) > 200:
            raise ValueError("Use limit 1–50, nonnegative after_id, and query up to 200 characters")
        if source_id and source_id not in self.sources:
            raise ValueError("Unknown source_id; use research_list_sources")
        clauses, values = ["s.id > ?"], [after_id]
        # Sources removed from operator config must not remain query-visible.
        clauses.append("s.source IN (" + ",".join("?" for _ in self.sources) + ")")
        values.extend(self.sources)
        if latest_only:
            clauses.append("s.id=(SELECT max(x.id) FROM snapshots x WHERE x.source=s.source AND x.url=s.url)")
        if source_id:
            clauses.append("s.source=?")
            values.append(source_id)
        if query:
            clauses.append("instr(lower(s.text || ' ' || s.url),lower(?))>0")
            values.append(query)
        with self.db() as db:
            db.create_function("current_scope", 2, lambda sid, url: int(
                sid in self.sources and active_page(self.sources[sid], url)))
            clauses.append("current_scope(s.source,s.url)=1")
            rows = list(db.execute("""SELECT s.id,s.source,s.url,s.final_url,s.retrieved,
                s.sha256,s.previous_sha256,s.media,substr(s.text,1,1200) AS excerpt,p.checked,p.successful,p.error
                FROM snapshots s JOIN pages p ON p.source=s.source AND p.url=s.url WHERE """ +
                " AND ".join(clauses) + " ORDER BY s.id LIMIT ?", (*values, limit + 1)))
        more = len(rows) > limit
        return {"items": [{**dict(r), "verification": STATUS} for r in rows[:limit]],
                "next_after_id": rows[limit-1]["id"] if more else None,
                "untrusted_content": True,
                "retention": "latest 3 versions per tracked URL; derived pages rotate at frontier capacity"}

    def snapshot(self, snapshot_id: int, offset: int = 0) -> dict:
        if offset < 0 or offset > 100000:
            raise ValueError("offset must be between 0 and 100000")
        with self.db() as db:
            row = db.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if (row is None or row["source"] not in self.sources
                or not active_page(self.sources[row["source"]], row["url"])):
            raise ValueError("Snapshot unavailable or pruned; query the current catalog")
        return {k: row[k] for k in ("id", "source", "url", "final_url", "retrieved", "sha256", "media")} | {
            "text": row["text"][offset:offset+8000], "offset": offset,
            "next_offset": offset+8000 if len(row["text"]) > offset+8000 else None,
            "verification": STATUS, "untrusted_content": True,
            "text_projection_limit": 100000, "raw_bytes": len(row["body"])}

    def releases(self, source_id: str, limit: int = 10) -> dict:
        source = self.sources.get(source_id)
        if source is None or source.get("connector") != "github_releases" or not 1 <= limit <= 30:
            raise ValueError("Select a github_releases source from research_list_sources and limit 1–30")
        with self.db() as db:
            row = db.execute("SELECT * FROM snapshots WHERE source=? AND url IN (" +
                             ",".join("?" for _ in source["seeds"]) + ") ORDER BY id DESC LIMIT 1",
                             (source_id, *source["seeds"])).fetchone()
        if row is None:
            return {"source_id": source_id, "status": "not_collected", "releases": []}
        return {"source_id": source_id, "snapshot_id": row["id"], "url": row["url"],
                "retrieved": row["retrieved"], "sha256": row["sha256"],
                "releases": github_releases(row["body"])[:limit],
                "verification": STATUS, "untrusted_content": True,
                "coverage": "first API page only (1 or 5 releases in shipped sources); no assets downloaded"}
