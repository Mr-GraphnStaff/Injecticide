"""Payload generation utilities for Injecticide."""

from typing import List

from payloads import BASELINE_PAYLOADS, POLICY_VIOLATION_PAYLOADS


def generate_payloads() -> List[str]:
    """Return a baseline list of prompt-injection payloads."""

    return list(BASELINE_PAYLOADS)


def policy_violation_payloads() -> List[str]:
    """Return payloads that probe for policy-violation enforcement."""

    return list(POLICY_VIOLATION_PAYLOADS)
