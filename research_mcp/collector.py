"""Recurring approved-source discovery. No LLM, shell or package execution."""
from __future__ import annotations

import logging
import json
import re
import threading
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from .catalog import Catalog, now
from .fetch import USER_AGENT, canonical_url, fetch, in_scope
from .apis import GITHUB_HEADERS, github_releases, is_github_releases_url

LOG = logging.getLogger(__name__)


def rate_key(host: str) -> str:
    return "arxiv.org" if host == "arxiv.org" or host.endswith(".arxiv.org") else host


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links = [], []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        for key, value in attrs:
            if len(self.links) < 1000 and value and (
                tag in ("a", "link") and key == "href"
            ):
                self.links.append(value)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def project(response) -> tuple[str, list[str]]:
    media = response.headers.get("content-type", "").split(";")[0].lower()
    if media not in ("text/html", "application/xhtml+xml", "text/plain", "text/markdown",
                     "application/json", "application/xml", "text/xml", "application/rss+xml",
                     "application/atom+xml"):
        raise ValueError("Unsupported media; binary documents need a separate approved extractor")
    raw = response.body.decode("utf-8", errors="replace")
    parser = PageParser()
    parser.feed(raw)
    # RSS/Atom/sitemaps, Markdown and llms.txt indexes, without XML entity expansion.
    links = parser.links + re.findall(r"https://[^\s<>\"')\]]+", raw)[:1000]
    if "xml" in media:
        links += re.findall(r"<(?:link|loc)>\s*([^<]+)\s*</", raw)[:1000]
    links += re.findall(r"\]\(([^\s)]+)\)", raw)[:1000]
    canonical = []
    for link in links[:2000]:
        try:
            canonical.append(canonical_url(urljoin(response.url, link)))
        except ValueError:
            continue
    text = " ".join(" ".join(parser.text).split()) if "html" in media else raw
    return text, list(dict.fromkeys(canonical))


class Collector:
    def __init__(self, catalog: Catalog, interval: int = 3600, page_budget: int = 40,
                 fetcher=fetch):
        if interval < 300 or not 1 <= page_budget <= 100:
            raise ValueError("Interval must be >=300 seconds and page budget 1–100")
        self.catalog, self.interval, self.page_budget = catalog, interval, page_budget
        self.fetcher = fetcher
        self.stop_event, self.wake = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.pending: set[str] = set()
        self.last_requested: dict[str, float] = {}
        self.robots: dict[str, tuple[float, RobotFileParser]] = {}
        self.last_fetch: dict[str, float] = {}
        self.api_blocked_until: dict[str, float] = {}
        self.status = {"last_cycle": None, "last_error": None, "running": False}
        self.thread = threading.Thread(target=self.run, name="research-collector", daemon=True)
        self.source_cursor = 0

    def request(self, source_id: str) -> dict:
        if source_id not in self.catalog.sources:
            raise ValueError("Unknown source_id; use research_list_sources")
        with self.lock:
            if time.monotonic() - self.last_requested.get(source_id, -1000) < 60:
                return {"status": "rate_limited", "retry_after_seconds": 60}
            self.last_requested[source_id] = time.monotonic()
            self.pending.add(source_id)
        self.wake.set()
        return {"status": "queued", "source_id": source_id}

    def allowed_by_robots(self, url: str) -> tuple[bool, float]:
        origin = "https://" + urlsplit(url).hostname
        cached = self.robots.get(origin)
        if cached is None or time.monotonic() - cached[0] > 3600:
            key = rate_key(urlsplit(url).hostname)
            spacing = 3 if key == "arxiv.org" else 1
            remaining = spacing - (time.monotonic() - self.last_fetch.get(key, 0))
            if remaining > 0 and self.stop_event.wait(remaining):
                raise InterruptedError("Collector stopping")
            response = self.fetcher(origin + "/robots.txt", [origin + "/robots.txt"])
            self.last_fetch[key] = time.monotonic()
            parser = RobotFileParser()
            if response.status in (404, 410):
                parser.parse([])
            elif response.status == 200:
                parser.parse(response.body.decode("utf-8", errors="replace").splitlines())
            else:
                raise ValueError("robots.txt unavailable; source deferred")
            self.robots[origin] = time.monotonic(), parser
        parser = self.robots[origin][1]
        delay = max(3 if rate_key(urlsplit(url).hostname) == "arxiv.org" else 1,
                    parser.crawl_delay(USER_AGENT) or 0)
        rate = parser.request_rate(USER_AGENT)
        if rate and rate.requests > 0:
            delay = max(delay, rate.seconds / rate.requests)
        if delay > 60:
            raise ValueError("robots crawl delay exceeds this collector's request budget")
        return parser.can_fetch(USER_AGENT, url), delay

    def collect(self, source_ids: list[str] | None = None) -> dict:
        ids = source_ids if source_ids is not None else list(self.catalog.sources)
        # Rotate the starting source when the global cycle budget is exhausted.
        ids = ids[self.source_cursor % len(ids):] + ids[:self.source_cursor % len(ids)] if ids else []
        self.source_cursor += 1
        pages = {sid: self.catalog.due_pages(sid, 8) for sid in ids}
        attempted, changed, failures = 0, 0, 0
        started = time.monotonic()
        while attempted < self.page_budget and not self.stop_event.is_set():
            worked = False
            for sid in ids:
                if attempted >= self.page_budget or time.monotonic() - started > 240:
                    break
                if not pages[sid] or self.stop_event.is_set():
                    continue
                worked = True
                page = pages[sid].pop(0)
                attempted += 1
                try:
                    api = self.catalog.sources[sid].get("connector") == "github_releases"
                    host = rate_key(urlsplit(page["url"]).hostname)
                    if api and self.api_blocked_until.get(host, 0) > time.time():
                        raise ValueError("GitHub API rate-limit backoff active; last-good evidence retained")
                    # Documented API contracts use API limits; web crawling uses robots.txt.
                    allowed, delay = (True, 1) if api else self.allowed_by_robots(page["url"])
                    if not allowed:
                        raise PermissionError("robots.txt disallows this page")
                    remaining = delay - (time.monotonic() - self.last_fetch.get(host, 0))
                    if remaining > 0 and self.stop_event.wait(remaining):
                        break
                    headers = dict(GITHUB_HEADERS) if api else {}
                    if page["etag"]:
                        headers["If-None-Match"] = page["etag"]
                    if page["modified"]:
                        headers["If-Modified-Since"] = page["modified"]
                    self.last_fetch[host] = time.monotonic()
                    def redirect_guard(url):
                        if api:
                            if not is_github_releases_url(url):
                                raise ValueError("API redirect must remain a public GitHub releases endpoint")
                            return
                        permitted, redirect_delay = self.allowed_by_robots(url)
                        if not permitted:
                            raise PermissionError("robots.txt disallows redirect destination")
                        if self.stop_event.wait(redirect_delay):
                            raise InterruptedError("Collector stopping")
                    response = self.fetcher(page["url"], self.catalog.sources[sid]["scopes"],
                                            headers, redirect_guard=redirect_guard)
                    if api:
                        if response.headers.get("x-ratelimit-remaining") == "0":
                            self.api_blocked_until[host] = max(time.time() + 60,
                                float(response.headers.get("x-ratelimit-reset", time.time() + 3600)))
                        if response.status in (403, 429):
                            self.api_blocked_until[host] = max(self.api_blocked_until.get(host, 0),
                                time.time() + min(86400, max(60, int(response.headers.get("retry-after", "3600")))))
                        if response.status not in (200, 304):
                            raise ValueError(f"GitHub API HTTP {response.status}")
                        text, links = ("", []) if response.status == 304 else (
                            json.dumps(github_releases(response.body), ensure_ascii=False, sort_keys=True), [])
                    else:
                        text, links = ("", []) if response.status == 304 else project(response)
                    changed += self.catalog.record(page, response, text, links)
                except Exception as error:
                    failures += 1
                    self.catalog.failure(page, error)
                    LOG.warning("Research fetch failed: source=%s kind=%s", sid, type(error).__name__)
            if not worked or time.monotonic() - started > 240:
                break
        return {"attempted": attempted, "changed": changed, "failures": failures,
                "cycle_budget_reached": attempted >= self.page_budget,
                "deadline_reached": time.monotonic() - started > 240}

    def run(self):
        next_cycle = 0
        while not self.stop_event.is_set():
            self.wake.clear()
            with self.lock:
                requested = sorted(self.pending)
                self.pending.clear()
            periodic = time.monotonic() >= next_cycle
            if periodic or requested:
                self.status["running"] = True
                try:
                    self.status["last_result"] = self.collect(None if periodic else requested)
                    self.status["last_error"] = None
                except Exception as error:
                    self.status["last_error"] = type(error).__name__
                    LOG.exception("Research cycle failed")
                finally:
                    self.status["last_cycle"] = now()
                    self.status["running"] = False
                if periodic:
                    next_cycle = time.monotonic() + self.interval
            self.wake.wait(min(30, max(0, next_cycle - time.monotonic())))

    def close(self):
        self.stop_event.set()
        self.wake.set()
        if self.thread.is_alive():
            self.thread.join(timeout=25)
