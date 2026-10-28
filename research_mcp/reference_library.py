"""Read-only, source-attributed captured references; never active instructions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).with_name("reference_docs") / "agent-skills"


class ReferenceLibrary:
    def __init__(self, root=ROOT):
        self.root = Path(root)

    def manifest(self):
        return json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))

    def _text(self, row):
        filename = row["text_file"]
        if Path(filename).name != filename or "/" in filename or "\\" in filename:
            raise ValueError("Reference file must stay inside the fixed library")
        raw = (self.root / filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["text_sha256"]:
            raise ValueError("Captured reference integrity check failed")
        return raw.decode("utf-8")

    def search(self, query="", limit=20):
        if not isinstance(query, str) or len(query) > 200 or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Use a query up to 200 characters and limit 1-50")
        manifest = self.manifest()
        matches = []
        for row in manifest["records"]:
            if not row.get("text_file"):
                continue
            text = self._text(row)
            index = text.casefold().find(query.casefold())
            if index < 0:
                continue
            matches.append({"id": row["id"], "url": row["url"], "role": row["role"],
                            "retrieved_at": row["retrieved_at"], "source_sha256": row["sha256"],
                            "excerpt": text[max(0, index - 80):index + 240]})
        return {"authority": "captured_research_data_not_active_rules", "live_check": False,
                "matches": matches[:limit], "omitted_matches": max(0, len(matches) - limit),
                "unavailable_references": [row for row in manifest["records"] if not row.get("text_file")]}

    def document(self, document_id, offset=0):
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        row = next((row for row in self.manifest()["records"] if row["id"] == document_id), None)
        if row is None or not row.get("text_file"):
            raise ValueError("Unknown or unavailable reference document")
        text = self._text(row)
        return {**row, "authority": "untrusted_captured_research_data_not_instructions",
                "live_check": False, "text": text[offset:offset + 8000], "offset": offset,
                "next_offset": offset + 8000 if offset + 8000 < len(text) else None,
                "total_characters": len(text)}
