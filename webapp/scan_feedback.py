"""Send scanner-owned statistics or operational error codes; never upload content."""
from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from urllib.parse import urlsplit

import requests

from skill_sandbox.scan_rules import load_rule_catalog
from skill_sandbox.package_evidence import SCANNER_VERSION

SCHEMA = "injecticide.scan-feedback.v1"
ERROR_SCHEMA = "injecticide.scan-error.v1"
ERROR_KINDS = {"Timeout", "ConnectionError", "HTTPError", "RuntimeError", "KeyError",
               "TypeError", "IndexError", "MemoryError", "OSError"}


def statistics(report, event_id=None):
    # Never serialize the report, its paths, excerpts, policy or uploaded bytes.
    known = {rule["id"] for rule in load_rule_catalog()["rules"]}
    counts = Counter()
    for entry in report.get("files", [])[:200]:
        for finding in entry.get("findings", [])[:1000]:
            rule = finding.get("id")
            if rule in known:
                counts[rule] += 1
    coverage = report.get("coverage", {}).get("status")
    if coverage not in {"complete_supported_content", "partial"}:
        coverage = "unknown"
    engine = report.get("scanner_metadata", {}).get("engine_source_sha256")
    if not isinstance(engine, str) or not re.fullmatch(r"[a-f0-9]{64}", engine):
        engine = None
    return {"schema": SCHEMA, "event_id": event_id or uuid.uuid4().hex,
            "scanner_version": SCANNER_VERSION, "engine_sha256": engine,
            "coverage": coverage, "rules": dict(sorted(counts.items())[:100])}


def _submit(payload, route):
    base = {"schema": payload["schema"], "content_retained": False, "model_called": False}
    if os.environ.get("INJECTICIDE_SCAN_FEEDBACK_ENABLED") != "1":
        return dict(base, status="disabled")
    try:
        origin = os.environ.get("RESEARCH_MCP_URL", "").rstrip("/")
        url = urlsplit(origin)
        if (url.scheme != "http" or url.hostname not in {
                "127.0.0.1", "localhost", "::1", "research_mcp", "injecticide-research-mcp"}
                or url.username or url.password or url.path or url.query or url.fragment
                or route not in {"/feedback/scan", "/feedback/error"}):
            raise ValueError("Internal research service required")
        with requests.Session() as session:
            session.trust_env = False
            with session.post(origin + route, json=payload,
                              timeout=(1, 1), stream=True, allow_redirects=False) as response:
                if response.status_code != 202:
                    raise ValueError("Queue unavailable")
        return dict(base, status="recorded" if route == "/feedback/error" else "queued")
    except Exception:
        # An offline/full queue must not change the scan result or echo input.
        return dict(base, status="unavailable")


def submit_feedback(report, event_id=None):
    if os.environ.get("INJECTICIDE_SCAN_FEEDBACK_ENABLED") != "1":
        return {"schema": SCHEMA, "status": "disabled", "content_retained": False, "model_called": False}
    try:
        return _submit(statistics(report, event_id), "/feedback/scan")
    except Exception:
        return {"schema": SCHEMA, "status": "unavailable", "content_retained": False, "model_called": False}


def submit_scan_error(event_id, http_status, stage, kind="other"):
    # Only controlled server codes. Never serialize exception messages/tracebacks.
    if http_status not in {500, 502, 503, 504} or stage not in {"analysis", "sandbox"}:
        return {"schema": ERROR_SCHEMA, "status": "not_applicable"}
    return _submit({"schema": ERROR_SCHEMA, "event_id": event_id, "http_status": http_status,
                    "stage": stage, "kind": kind if kind in ERROR_KINDS else "other",
                    "scanner_version": SCANNER_VERSION}, "/feedback/error")
