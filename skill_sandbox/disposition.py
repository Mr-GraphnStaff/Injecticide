from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List


DISPOSITION_CATALOG_PATH = Path(__file__).resolve().parent / "rules" / "dispositions.json"
TIER_RANK = {"block": 0, "review": 1, "info": 2}


@lru_cache(maxsize=1)
def load_disposition_catalog() -> Dict[str, object]:
    with DISPOSITION_CATALOG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def apply_disposition(
    detector_id: str,
    observations: Iterable[Dict[str, object]],
    artifact_role: str,
) -> Dict[str, object]:
    catalog = load_disposition_catalog()
    observation_list = list(observations)
    dispositions = [
        _disposition_for_observation(catalog, detector_id, observation, artifact_role)
        for observation in observation_list
    ]

    if not dispositions:
        dispositions = [dict(catalog["default"])]

    selected = min(dispositions, key=lambda item: TIER_RANK.get(str(item.get("tier")), 9))
    tier = str(selected.get("tier", "review"))

    return {
        "tier": tier,
        "severity": str(selected.get("severity", "medium")),
        "disposition": str(selected.get("disposition", "require_approval")),
        "is_actionable": bool(selected.get("is_actionable", tier != "info")),
        "counts_for_governance": bool(selected.get("counts_for_governance", tier == "block")),
        "observation_count": len(observation_list),
    }


def normalize_observations(matches: Iterable[object]) -> List[Dict[str, object]]:
    observations: List[Dict[str, object]] = []
    for match in matches:
        if isinstance(match, dict):
            observations.append(
                {
                    "text": str(match.get("text", "")).strip(),
                    "line": match.get("line"),
                    "context_tag": str(match.get("context_tag", "pattern_match")),
                    "confidence": str(match.get("confidence", "medium")),
                }
            )
            continue

        text = str(match).strip()
        if text:
            observations.append(
                {
                    "text": text,
                    "line": None,
                    "context_tag": "pattern_match",
                    "confidence": "medium",
                }
            )

    return [observation for observation in observations if observation["text"]]


def format_observation_sample(observation: Dict[str, object]) -> str:
    text = str(observation.get("text", "")).strip()
    line = observation.get("line")
    if isinstance(line, int) and line > 0:
        return f"line {line}: {text}"
    return text


def _disposition_for_observation(
    catalog: Dict[str, object],
    detector_id: str,
    observation: Dict[str, object],
    artifact_role: str,
) -> Dict[str, object]:
    for override in catalog.get("role_overrides", []):
        if artifact_role in override.get("artifact_roles", []):
            return dict(override)

    context_tag = str(observation.get("context_tag", "pattern_match"))
    detector_rule = _rule_for_detector(catalog, detector_id)
    if detector_rule:
        contexts = detector_rule.get("contexts", {})
        if context_tag in contexts:
            return dict(contexts[context_tag])

    return dict(catalog["default"])


def _rule_for_detector(catalog: Dict[str, object], detector_id: str) -> Dict[str, object] | None:
    for rule in catalog.get("rules", []):
        if rule.get("detector_id") == detector_id:
            return rule
    return None
