"""Read-only public API adapters; no provider credentials or remote code loading.

GitHub contract: https://docs.github.com/en/rest/releases/releases#list-releases
Rate policy: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
"""
import json
import re
from urllib.parse import urlsplit

GITHUB_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}


def is_github_releases_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.hostname == "api.github.com" and bool(re.fullmatch(
        r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases", parts.path))


def github_releases(body: bytes) -> list[dict]:
    data = json.loads(body)
    if not isinstance(data, list) or len(data) > 30:
        raise ValueError("Expected a bounded GitHub releases list (at most 30)")
    records = []
    for item in data:
        if not isinstance(item, dict) or type(item.get("id")) is not int:
            raise ValueError("Invalid GitHub release record")
        for field in ("tag_name", "html_url"):
            if not isinstance(item.get(field), str):
                raise ValueError("Invalid GitHub release fields")
        records.append({"id": item["id"], "tag": item["tag_name"],
            "name": item.get("name"), "published_at": item.get("published_at"),
            "prerelease": item.get("prerelease"), "draft": item.get("draft"),
            "url": item["html_url"], "notes": str(item.get("body") or "")[:6000]})
    return records
