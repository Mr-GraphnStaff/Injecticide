"""Bounded literal-only update template. No downloaded code or regex executes.

New indicators request review; a source-text match alone does not establish a
malicious action. Publication authority is checked separately by the delivery
gate. A running process retains its release's cached catalog.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

MANIFEST = Path(__file__).with_name("rules") / "obsession_signatures.json"
MAX_MANIFEST_BYTES = 1024 * 1024
FIELDS = {"id", "literal", "description", "severity", "positive_examples", "negative_examples", "source_url"}


def validate_manifest(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "signatures"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Expected literal signature manifest schema 1")
    records = value["signatures"]
    if not isinstance(records, list) or len(records) > 128:
        raise ValueError("Literal signature count exceeds budget")
    seen = set()
    for item in records:
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise ValueError("Unexpected signature fields; code and regex are unsupported")
        identifier, literal = item["id"], item["literal"]
        if not isinstance(identifier, str) or not re.fullmatch(r"obsession-[a-z0-9][a-z0-9-]{0,79}", identifier) or identifier in seen:
            raise ValueError("Invalid or duplicate signature identity")
        seen.add(identifier)
        if not isinstance(literal, str) or not 12 <= len(literal) <= 160 or any(ord(c) < 32 for c in literal):
            raise ValueError("Literal must contain 12-160 printable characters")
        if not isinstance(item["description"], str) or not 1 <= len(item["description"]) <= 300 or item["severity"] not in {"medium", "high"}:
            raise ValueError("Invalid signature description or source severity")
        url = item["source_url"]
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError("Invalid signature source")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ValueError("Signature source must be public HTTPS provenance")
        matcher = re.compile(re.escape(literal), re.IGNORECASE)
        for name, expected in (("positive_examples", True), ("negative_examples", False)):
            examples = item[name]
            if not isinstance(examples, list) or not 1 <= len(examples) <= 5:
                raise ValueError("Paired examples are required")
            for example in examples:
                if not isinstance(example, str) or not 1 <= len(example) <= 1000:
                    raise ValueError("Example exceeds budget")
                if bool(matcher.search(example)) != expected:
                    raise ValueError("Paired literal regression failed")
    return value


def load_rules(path=None):
    path = Path(path) if path is not None else MANIFEST
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Signature manifest exceeds budget")
    manifest = validate_manifest(json.loads(raw))
    return [{"id": item["id"], "category": "prompt", "severity": "medium",
             "description": item["description"] + " Literal indicator requires contextual review; source severity is not a malware verdict.",
             "finding_category": "research_indicator", "subject": "skill_plugin_source",
             "action_state": "observed", "status": "indicator_match",
             "patterns": [re.escape(item["literal"])], "exclude_patterns": [],
             "sources": [{"name": "Obsession reviewed literal recipe", "url": item["source_url"]}]}
            for item in manifest["signatures"]]
