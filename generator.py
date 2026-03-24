"""Payload generation utilities for Injecticide."""

from typing import Dict, Iterable, List, Sequence, Tuple

from payloads import (
    BASELINE_PAYLOADS,
    ESF_PAYLOADS,
    POLICY_VIOLATION_PAYLOADS,
    get_all_payloads,
)


def generate_payloads() -> List[str]:
    """Return a baseline list of prompt-injection payloads."""

    return list(BASELINE_PAYLOADS)


def policy_violation_payloads() -> List[str]:
    """Return payloads that probe for policy-violation enforcement."""

    return list(POLICY_VIOLATION_PAYLOADS)


def esf_payloads() -> List[str]:
    """Return payloads that probe epistemic stress handling."""

    return list(ESF_PAYLOADS)


def payload_registry() -> Dict[str, List[str]]:
    """Return a copy of the payload registry keyed by category id."""

    return {
        category: list(items)
        for category, items in get_all_payloads().items()
    }


def build_payload_suite(
    categories: Sequence[str],
    custom_payloads: Iterable[str] | None = None,
) -> List[Tuple[str, str]]:
    """Expand category ids into the payloads that should be executed."""

    registry = payload_registry()
    unknown_categories = [category for category in categories if category not in registry]
    if unknown_categories:
        unknown = ", ".join(sorted(set(unknown_categories)))
        raise ValueError(f"Unsupported payload categories: {unknown}")

    suite: List[Tuple[str, str]] = []
    for category in categories:
        suite.extend((payload, category) for payload in registry[category])

    for payload in custom_payloads or ():
        suite.append((payload, "custom"))

    return suite
