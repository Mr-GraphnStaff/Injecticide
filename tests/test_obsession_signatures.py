"""Authored controls for the bounded signature template and production matcher."""
import json
import re

import pytest

from skill_sandbox import scan_rules
from skill_sandbox.finding_enrichment import build_finding
from skill_sandbox.obsession_signatures import load_rules, validate_manifest


def signature(**changes):
    return {"id": "obsession-authored-control", "literal": "authored literal [a-z]+",
            "description": "Authored template control", "severity": "high",
            "positive_examples": ["An AUTHORED LITERAL [A-Z]+ example"],
            "negative_examples": ["authored literal abcdef"],
            "source_url": "https://example.org/research", **changes}


def test_literal_regex_punctuation_is_data_and_novel_indicator_requests_review(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "signatures": [signature()]}))
    rules = load_rules(path)
    assert re.search(rules[0]["patterns"][0], "authored literal [a-z]+", re.I)
    assert not re.search(rules[0]["patterns"][0], "authored literal abcdef", re.I)
    finding = build_finding(rules[0], [{"text": "authored literal [a-z]+", "context_tag": "pattern_match"}], "active")
    assert finding["tier"] == "review" and not finding["counts_for_governance"]
    assert finding["status"] == "indicator_match"
    monkeypatch.setattr(scan_rules, "load_obsession_rules", lambda: rules)
    scan_rules.load_rule_catalog.cache_clear()
    try:
        assert any(rule["id"] == signature()["id"] for rule in scan_rules.compile_patterns())
    finally:
        scan_rules.load_rule_catalog.cache_clear()


@pytest.mark.parametrize("changes", [
    {"literal": "short"}, {"literal": "line\nbreak forbidden"},
    {"id": "../rules"}, {"source_url": "http://example.org/"},
    {"source_url": "https://user:pass@example.org/"},
    {"negative_examples": ["authored literal [a-z]+"]},
    {"positive_examples": ["not a matching example"]},
    {"regex": "(a+)+$"}, {"severity": "critical"},
    {"literal": "credential Straße", "positive_examples": ["credential STRASSE"]},
])
def test_invalid_or_non_reproducible_templates_fail_closed(changes):
    with pytest.raises(ValueError):
        validate_manifest({"schema_version": 1, "signatures": [signature(**changes)]})


def test_duplicate_rules_and_manifest_schema_are_rejected():
    with pytest.raises(ValueError):
        validate_manifest({"schema_version": 1, "signatures": [signature(), signature()]})
    with pytest.raises(ValueError):
        validate_manifest({"schema_version": True, "signatures": []})
