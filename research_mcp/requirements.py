"""Reviewed vendor requirements backed by fresh, unchanged official documents.

Retrieval never edits this registry or scanner rules. A changed page needs review.
Only product profiles of the four selected major platforms are covered.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .catalog import STATUS, active_page, now
from .collector import Collector

REGISTRY = Path(__file__).with_name("requirements.json")
MAX_AGE_SECONDS = 3600


class Requirements:
    def __init__(self, catalog, registry=REGISTRY, collector=None):
        self.catalog = catalog
        self.profiles = json.loads(registry.read_text(encoding="utf-8"))["profiles"]
        # Separate collector state avoids racing the recurring worker's rate/robots state.
        self.collector = collector or Collector(catalog)
        self.lock = threading.Lock()

    def check(self, runtime: str, refresh: bool = True) -> dict:
        if runtime not in self.profiles:
            return {"status": "unknown", "verification": STATUS, "runtime": runtime,
                    "reason": "Select a supported product runtime: " + ", ".join(self.profiles),
                    "checked_at": now(), "requirements": [], "documents": [],
                    "runtime_tested": False, "live_check": False}
        profile = self.profiles[runtime]
        source_id = profile["source_id"]
        live = False
        refresh_state = "not_requested"
        if refresh:
            if self.lock.acquire(blocking=False):
                try:
                    if source_id not in self.catalog.sources:
                        refresh_state = "source_not_configured"
                    elif not self.catalog.sources[source_id].get("enabled", True):
                        refresh_state = "disabled"
                    elif (set(self.catalog.sources[source_id]["seeds"]) != {d["url"] for d in profile["documents"]}
                          or self.catalog.sources[source_id].get("discovery", True)):
                        refresh_state = "source_configuration_changed"
                    else:
                        result = self.collector.collect([source_id])
                        live = result["attempted"] == len(profile["documents"]) and result["failures"] == 0
                        refresh_state = "completed" if live else "incomplete"
                finally:
                    self.lock.release()
            else:
                refresh_state = "busy"
        documents = []
        with self.catalog.db() as db:
            for reference in profile["documents"]:
                url = reference["url"]
                row = db.execute("""SELECT p.checked,p.successful,p.error,s.id,s.sha256,s.text,s.final_url
                    FROM pages p LEFT JOIN snapshots s ON s.id=(SELECT max(x.id) FROM snapshots x
                    WHERE x.source=p.source AND x.url=p.url) WHERE p.source=? AND p.url=?""",
                    (source_id, url)).fetchone()
                state = "not_collected"
                if source_id not in self.catalog.sources or not self.catalog.sources[source_id].get("enabled", True):
                    state = "disabled"
                elif not active_page(self.catalog.sources[source_id], url):
                    state = "outside_active_scope"
                elif row and row["error"]:
                    state = "fetch_error"
                elif row and row["id"]:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(row["successful"])).total_seconds() if row["successful"] else -1
                    digest = hashlib.sha256(row["text"].encode("utf-8")).hexdigest() if reference.get("fingerprint_scope") == "projected_text" else row["sha256"]
                    state = "stale" if not 0 <= age <= MAX_AGE_SECONDS else (
                        "unchanged" if digest == reference.get("reviewed_sha256") else "changed_review_required")
                documents.append({"url": url, "state": state,
                    "checked_at": row["checked"] if row else None,
                    "last_success": row["successful"] if row else None,
                    "snapshot_id": row["id"] if row else None,
                    "sha256": row["sha256"] if row else None,
                    "final_url": row["final_url"] if row else None,
                    "fingerprint_scope": reference.get("fingerprint_scope", "response_bytes"),
                    "reviewed_on": reference["reviewed_on"]})
        current = all(d["state"] == "unchanged" for d in documents)
        # A failed/busy requested refresh never inherits a cached verified verdict.
        verified = current and (not refresh or live)
        reason = "" if verified else (
            "Another vendor check is running; this run has no confirmed live verification." if refresh_state == "busy" else
            "Vendor documentation changed since review; review the requirements before relying on them." if any(d["state"] == "changed_review_required" for d in documents) else
            "Official vendor documentation could not be revalidated against the reviewed baseline; inspect source states.")
        requirements = []
        for field, claim in profile["requirements"].items():
            known = verified and claim["value"] is not None
            requirements.append({"field": field, "value": claim["value"] if known else None,
                "status": "vendor_documented" if known else "unknown",
                "note": claim["note"], "source_url": claim["source_url"],
                "verification": "reviewed_document_unchanged" if known else STATUS})
        return {"status": "current_documented_requirements" if verified else "unknown",
            "verification": "reviewed_documents_unchanged" if verified else STATUS,
            "runtime": runtime, "product": profile["product"], "vendor": profile["vendor"],
            "reason": reason,
            "checked_at": now(), "max_age_seconds": MAX_AGE_SECONDS,
            "live_check": live, "refresh_state": refresh_state,
            "requirements": requirements, "documents": documents, "runtime_tested": False,
            "coverage": "Only listed reviewed requirements; unknown values are not unlimited or allowed",
            "authority": "vendor_documentation_evidence_not_active_scanner_rules"}
