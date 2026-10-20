"""Bounded read-only connection to the research service, with last-good caching."""
import copy
import json
import os
import threading
import time
from urllib.parse import urlsplit

import requests

PUBLIC_HOSTS = {"github.com", "genai.owasp.org", "owasp.github.io", "www.nist.gov"}


def sanitize_news(data):
    if not isinstance(data, dict) or not isinstance(data.get("items"), list) or not isinstance(data.get("collection"), dict):
        raise ValueError("Invalid research news response")
    items = []
    for item in data["items"][:8]:
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        if not isinstance(url, str):
            continue
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            continue
        if (parsed.scheme != "https" or parsed.hostname not in PUBLIC_HOSTS or parsed.username
                or parsed.password or port not in (None, 443)):
            continue
        items.append({key: str(item.get(key, ""))[:300] for key in
                      ("id", "kind", "title", "source", "url", "date", "date_label", "observed_at")} |
                     {"preview": item.get("preview") is True})
    collection = data["collection"]
    safe = {key: collection.get(key) for key in ("worker_alive", "collecting", "last_cycle",
        "last_error", "interval_seconds", "source_count", "sources_with_errors", "retained_snapshots", "last_result")}
    return {"available": True, "feed_stale": False, "generated_at": data.get("generated_at"),
            "items": items, "collection": safe}


class ResearchNewsClient:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache, self.checked, self.origin = None, 0, None

    def get(self):
        origin = os.environ.get("RESEARCH_MCP_URL", "").rstrip("/")
        with self.lock:
            if origin != self.origin:
                self.cache, self.checked, self.origin = None, 0, origin
            if self.cache is not None and time.monotonic() - self.checked < 60:
                return copy.deepcopy(self.cache)
            self.checked = time.monotonic()
            try:
                if not origin:
                    raise ValueError("Research service is not configured")
                with requests.Session() as session:
                    session.trust_env = False
                    with session.get(origin + "/news", timeout=(2, 3), stream=True, allow_redirects=False) as response:
                        if response.status_code != 200:
                            raise ValueError("Research service unavailable")
                        deadline = time.monotonic() + 5
                        chunks, count = [], 0
                        for block in response.iter_content(chunk_size=8192):
                            count += len(block)
                            if count > 131072 or time.monotonic() > deadline:
                                raise ValueError("Research response exceeds its budget")
                            chunks.append(block)
                        self.cache = sanitize_news(json.loads(b"".join(chunks)))
            except (requests.RequestException, ValueError, TypeError):
                if self.cache is None:
                    self.cache = {"available": False, "feed_stale": True, "items": [], "collection": {}}
                else:
                    self.cache["feed_stale"] = True
            return copy.deepcopy(self.cache)


news_client = ResearchNewsClient()
