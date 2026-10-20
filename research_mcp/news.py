"""Small attributed public projection of collected evidence, without fetched prose."""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .apis import github_releases
from .catalog import now
from .fetch import canonical_url

RELEASE_NAMES = {
    "codex-releases": "OpenAI Codex", "claude-code-releases": "Claude Code",
    "gemini-cli-releases": "Gemini CLI", "skillspector-releases": "NVIDIA SkillSpector",
    "agent-scan-releases": "Snyk Agent Scan",
}


def recent_date(value):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        current = datetime.now(timezone.utc)
        return date.tzinfo is not None and current - timedelta(days=30) <= date <= current
    except (AttributeError, TypeError, ValueError):
        return False


def build_news(catalog, collector) -> dict:
    items = []
    with catalog.db() as db:
        for sid, label in RELEASE_NAMES.items():
            source = catalog.sources.get(sid)
            if not source or source.get("connector") != "github_releases":
                continue
            row = db.execute("SELECT * FROM snapshots WHERE source=? ORDER BY id DESC LIMIT 1", (sid,)).fetchone()
            if row is None:
                continue
            repo = urlsplit(source["seeds"][0]).path.split("/")[2:4]
            prefix = f"https://github.com/{'/'.join(repo)}/releases/".lower()
            for release in github_releases(row["body"]):
                if (release["draft"] is not False or type(release["prerelease"]) is not bool
                        or not recent_date(release["published_at"])):
                    continue
                try:
                    url = canonical_url(release["url"])
                except ValueError:
                    continue
                if not url.lower().startswith(prefix):
                    continue
                items.append({"id": f"{sid}:{release['id']}", "kind": "release",
                    "title": f"{label} {release['tag'][:120]}", "source": label, "url": url,
                    "date": release["published_at"], "date_label": "Published",
                    "preview": release["prerelease"], "observed_at": row["retrieved"]})
        # Only changed discovery roots for standards; first retrieval is not news.
        for sid in ("owasp-genai", "owasp-skills", "nist-ai"):
            source = catalog.sources.get(sid)
            if not source:
                continue
            for seed in source["seeds"]:
                row = db.execute("""SELECT * FROM snapshots WHERE source=? AND url=?
                    ORDER BY id DESC LIMIT 1""", (sid, canonical_url(seed))).fetchone()
                if row and row["previous_sha256"] and recent_date(row["retrieved"]):
                    items.append({"id": f"source:{row['id']}", "kind": "source_change",
                        "title": f"{source['ecosystem']} reference page changed",
                        "source": source["ecosystem"], "url": canonical_url(seed),
                        "date": row["retrieved"], "date_label": "Observed", "preview": False,
                        "observed_at": row["retrieved"]})
        snapshots = db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
    sources = catalog.list_sources()["sources"]
    items.sort(key=lambda item: datetime.fromisoformat(item["date"].replace("Z", "+00:00")), reverse=True)
    return {"generated_at": now(), "feed_stale": False, "available": True,
        "items": items[:8], "collection": {
            "worker_alive": collector.thread.is_alive(), "collecting": collector.status["running"],
            "last_cycle": collector.status["last_cycle"], "last_error": collector.status["last_error"],
            "interval_seconds": collector.interval, "source_count": len(sources),
            "sources_with_errors": sum(s["errors"] > 0 for s in sources),
            "retained_snapshots": snapshots, "last_result": collector.status.get("last_result")},
        "notice": "Automated source watch. A page change is not a verified new standard or vulnerability."}
