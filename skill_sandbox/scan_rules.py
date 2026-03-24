from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple


RULE_CATALOG_PATH = Path(__file__).resolve().parent / "rules" / "violations.json"


@lru_cache(maxsize=1)
def load_rule_catalog() -> Dict[str, object]:
    """Load the local structured rule catalog used for skill scanning."""

    with RULE_CATALOG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def compile_patterns() -> Tuple[Dict[str, object], ...]:
    """Compile the local rule catalog into regex-backed matcher definitions."""

    catalog = load_rule_catalog()
    compiled: List[Dict[str, object]] = []

    for rule in catalog.get("rules", []):
        compiled.append(
            {
                **rule,
                "compiled_patterns": tuple(
                    re.compile(pattern, re.IGNORECASE)
                    for pattern in rule.get("patterns", [])
                ),
                "compiled_excludes": tuple(
                    re.compile(pattern, re.IGNORECASE)
                    for pattern in rule.get("exclude_patterns", [])
                ),
            }
        )

    return tuple(compiled)


def find_rule_matches(rule: Dict[str, object], text: str) -> List[str]:
    """Return normalized match samples when a compiled rule applies."""

    if any(pattern.search(text) for pattern in rule.get("compiled_excludes", ())):
        return []

    compiled_patterns = rule.get("compiled_patterns", ())
    if not compiled_patterns:
        return []

    mode = rule.get("match_mode", "any")

    if mode == "all":
        grouped_matches: List[str] = []
        for pattern in compiled_patterns:
            matches = _normalize_matches(pattern.findall(text))
            if not matches:
                return []
            grouped_matches.extend(matches[:1])
        return grouped_matches[:3]

    positive_matches: List[str] = []
    for pattern in compiled_patterns:
        positive_matches.extend(_normalize_matches(pattern.findall(text)))

    return positive_matches[:3]


def _normalize_matches(matches: List[object]) -> List[str]:
    normalized: List[str] = []
    for match in matches:
        if isinstance(match, tuple):
            text = " ".join(str(item) for item in match if item)
        else:
            text = str(match)
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            normalized.append(text)
    return normalized
