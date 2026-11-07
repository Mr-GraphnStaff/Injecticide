"""Typed stress-test result rows and execution coverage.

Contract: items 362/363/364/365, result/error/coverage contract v2 (agreed
between the Claude and Codex partners, 2026-11-06).

Rules this module enforces:
- Only ``assessed`` rows carry lexical signals.
- A failed, timed-out, cancelled or not-run row never reads as clean.
- Keyword flags are lexical *signals*, never verified findings.
- ``verified`` stays ``None`` unless an executed check supplied evidence.
- Coverage counts add up, and a session is ``complete`` only when every
  planned row was assessed.

This module is pure and deterministic. It sends nothing and reads nothing.
"""

from __future__ import annotations

import html
from typing import Any, Dict, Iterable, List, Mapping, Optional

ASSESSED = "assessed"
FAILED = "failed"
TIMED_OUT = "timed_out"
CANCELLED = "cancelled"
NOT_RUN = "not_run"

OUTCOMES = (ASSESSED, FAILED, TIMED_OUT, CANCELLED, NOT_RUN)
ATTEMPTED_OUTCOMES = (ASSESSED, FAILED, TIMED_OUT, CANCELLED)

# Closed reason codes and the outcomes each may accompany.
REASON_OUTCOMES: Dict[str, frozenset] = {
    "provider_error": frozenset({FAILED}),
    "analysis_error": frozenset({FAILED}),
    "unrecorded_outcome": frozenset({FAILED}),
    "timeout": frozenset({TIMED_OUT}),
    "cancelled_by_user": frozenset({CANCELLED, NOT_RUN}),
    "session_failed": frozenset({NOT_RUN}),
    "max_requests_reached": frozenset({NOT_RUN}),
    # Live snapshots only; forbidden once coverage is finalized.
    "pending": frozenset({NOT_RUN}),
}
REASONS = tuple(REASON_OUTCOMES)

SIGNAL_KIND = "lexical"
DETAIL_LIMIT = 500

LABEL_SIGNALS = "LEXICAL SIGNALS"
LABEL_NO_SIGNALS = "NO SIGNALS (lexical only)"

DEPRECATED_SUMMARY_FIELDS = {
    "total_tests": "planned",
    "vulnerabilities_detected": "rows_with_signals",
    "detection_rate": "lexical_signal_rate",
}


class ContractError(ValueError):
    """A row or coverage request violates the result contract."""


def cap_detail(detail: Any, limit: int = DETAIL_LIMIT) -> Optional[str]:
    """Return untrusted detail text as a capped string (``None`` stays ``None``)."""

    if detail is None:
        return None
    text = str(detail)
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def _check_verified(verified: Any) -> Optional[Dict[str, Any]]:
    if verified is None:
        return None
    if not isinstance(verified, Mapping):
        raise ContractError("verified must be None or a mapping")
    check = verified.get("check")
    provenance = verified.get("provenance")
    leaked = verified.get("leaked")
    if not isinstance(check, str) or not check:
        raise ContractError("verified.check must name the executed check")
    if not isinstance(provenance, str) or not provenance:
        raise ContractError("verified.provenance is required")
    if not isinstance(leaked, bool):
        raise ContractError("verified.leaked must be a bool")
    return {"check": check, "provenance": provenance, "leaked": leaked}


def make_assessed_row(
    row_id: Any,
    payload: str,
    category: str,
    response: Any,
    signals: Mapping[str, Any],
    *,
    verified: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the row for a payload whose response was received and analyzed."""

    if not isinstance(signals, Mapping):
        raise ContractError("signals must be a mapping of flag -> bool")
    clean_signals = {str(name): bool(value) for name, value in signals.items()}
    detected = any(clean_signals.values())
    return {
        "row_id": str(row_id),
        "payload": payload,
        "category": category,
        "outcome": ASSESSED,
        "reason": None,
        "detail": None,
        "signals": clean_signals,
        "signal_kind": SIGNAL_KIND,
        "verified": _check_verified(verified),
        "response_length": len(str(response)),
        # Compatibility keys for existing report and UI consumers.
        "flags": dict(clean_signals),
        "detected": detected,
    }


def make_unassessed_row(
    row_id: Any,
    payload: str,
    category: str,
    outcome: str,
    reason: str,
    detail: Any = None,
) -> Dict[str, Any]:
    """Build a failed, timed-out, cancelled or not-run row (never clean)."""

    if outcome not in OUTCOMES or outcome == ASSESSED:
        raise ContractError(f"unassessed outcome must be one of {OUTCOMES[1:]}, got {outcome!r}")
    allowed = REASON_OUTCOMES.get(reason) if isinstance(reason, str) else None
    if allowed is None:
        raise ContractError(f"unknown reason {reason!r}")
    if outcome not in allowed:
        raise ContractError(f"reason {reason!r} is not allowed with outcome {outcome!r}")
    capped = cap_detail(detail)
    return {
        "row_id": str(row_id),
        "payload": payload,
        "category": category,
        "outcome": outcome,
        "reason": reason,
        "detail": capped,
        "signals": None,
        "signal_kind": SIGNAL_KIND,
        "verified": None,
        "response_length": None,
        # Compatibility keys: no flags, never detected, error text visible.
        "flags": {},
        "detected": False,
        "error": capped if capped is not None else reason,
    }


def is_unrecorded(row: Mapping[str, Any]) -> bool:
    """True for a converted legacy row whose dispatch was never recorded."""

    return row.get("reason") == "unrecorded_outcome"


def validate_row(row: Mapping[str, Any]) -> None:
    """Reject a row that is incomplete or contradicts the contract.

    Nothing is repaired: an inconsistent row must not turn into an apparently
    clean assessment or into complete coverage.
    """

    if not isinstance(row, Mapping):
        raise ContractError("row must be a mapping")
    rid = row.get("row_id")
    if not isinstance(rid, str) or not rid:
        raise ContractError("row_id is required")
    outcome = row.get("outcome")
    if outcome not in OUTCOMES:
        raise ContractError(f"unknown outcome {outcome!r}")
    if outcome == ASSESSED:
        if row.get("reason") is not None:
            raise ContractError("assessed row must not carry a failure reason")
        if row.get("detail") is not None or row.get("error") is not None:
            raise ContractError("assessed row must not carry failure detail or error text")
        signals = row.get("signals")
        if not isinstance(signals, Mapping):
            raise ContractError("assessed row is missing signals")
        if not all(isinstance(value, bool) for value in signals.values()):
            raise ContractError("signal values must be bool")
        _check_verified(row.get("verified"))
        return
    reason = row.get("reason")
    allowed = REASON_OUTCOMES.get(reason) if isinstance(reason, str) else None
    if allowed is None or outcome not in allowed:
        raise ContractError(f"reason {reason!r} is not allowed with outcome {outcome!r}")
    if row.get("signals"):
        raise ContractError(f"{outcome} row must not carry signals")
    if row.get("verified") is not None:
        raise ContractError(f"{outcome} row must not carry verified evidence")


def normalize_row(row: Mapping[str, Any], row_id: Any = None) -> Dict[str, Any]:
    """Return a validated contract row; convert legacy rows without inventing facts.

    A legacy row (no ``outcome``) is never normalized into ``assessed`` and is
    never counted as an attempt: the record shows neither that the request was
    dispatched nor that a response was analyzed. It becomes
    ``failed`` / ``unrecorded_outcome``; ``build_coverage`` reports it under
    ``unrecorded``, outside ``attempted``. Original flags are kept only under
    ``legacy_flags``.

    A typed row is validated, not repaired: a contradictory or incomplete row
    raises ``ContractError``.
    """

    if not isinstance(row, Mapping):
        raise ContractError("row must be a mapping")
    rid = row.get("row_id", row_id)
    if rid is None:
        raise ContractError("row_id is required")
    payload = row.get("payload", "")
    category = row.get("category", "unknown")
    outcome = row.get("outcome")

    if outcome is None:
        detail = row.get("error") or "legacy row without a recorded outcome"
        normalized = make_unassessed_row(rid, payload, category, FAILED, "unrecorded_outcome", detail)
        legacy_flags = row.get("flags")
        if legacy_flags:
            if isinstance(legacy_flags, Mapping):
                kept = {str(k): bool(v) for k, v in legacy_flags.items()}
            elif isinstance(legacy_flags, (list, tuple)) and all(isinstance(k, str) for k in legacy_flags):
                kept = {k: True for k in legacy_flags}
            else:
                raise ContractError("legacy flags must be a mapping or a list of names")
            normalized["legacy_flags"] = kept
        return normalized

    validate_row(dict(row, row_id=str(rid)))
    if outcome == ASSESSED:
        normalized = make_assessed_row(rid, payload, category, "", row["signals"], verified=row.get("verified"))
        normalized["response_length"] = row.get("response_length")
        return normalized
    # Keep the diagnostic: fall back to compatibility ``error`` text when
    # ``detail`` is missing.
    detail = row.get("detail")
    if detail is None:
        detail = row.get("error")
    return make_unassessed_row(rid, payload, category, outcome, row["reason"], detail)


def signal_names(row: Mapping[str, Any]) -> List[str]:
    """Names of true lexical signals; always empty for non-assessed rows."""

    if row.get("outcome") != ASSESSED:
        return []
    return [name for name, value in (row.get("signals") or {}).items() if value]


def row_label(row: Mapping[str, Any]) -> str:
    """Human label for a row. Never ``SAFE``; non-assessed rows name the reason."""

    outcome = row.get("outcome")
    if outcome == ASSESSED:
        return LABEL_SIGNALS if signal_names(row) else LABEL_NO_SIGNALS
    if outcome in OUTCOMES:
        return f"{outcome.upper()}: {row.get('reason') or 'unknown'}"
    return "FAILED: unrecorded_outcome"


def escape_html(value: Any) -> str:
    """Escape any untrusted value for HTML text or attribute context."""

    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _rate(numerator: int, denominator: int) -> Dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": (numerator / denominator) if denominator else None,
    }


def build_coverage(
    rows: Iterable[Mapping[str, Any]],
    *,
    planned: Optional[int] = None,
    in_flight: int = 0,
    final: bool = True,
) -> Dict[str, Any]:
    """Aggregate typed rows into the coverage object.

    ``rows`` are terminal rows (``not_run`` included); every row is validated
    and an invalid row raises ``ContractError``. Converted legacy rows
    (``unrecorded_outcome``) are counted under ``unrecorded``, never under
    ``attempted`` or ``failed``, because their dispatch is unknown. For a final
    coverage, ``planned`` defaults to ``len(rows)``, ``in_flight`` must be
    zero, no row may still be ``pending``, and
    ``planned == attempted + not_run + unrecorded``. For a live snapshot
    (``final=False``) the remainder ``planned - len(rows) - in_flight`` is
    reported as ``pending`` and no terminal outcome is invented for it.
    """

    typed = [dict(row) for row in rows]
    seen = set()
    for row in typed:
        validate_row(row)
        if row["row_id"] in seen:
            raise ContractError(f"duplicate row_id {row['row_id']!r}")
        seen.add(row["row_id"])
    counts = {outcome: 0 for outcome in OUTCOMES}
    unrecorded = 0
    for row in typed:
        if row.get("reason") == "pending":
            continue  # reported under ``pending``, not as a terminal not_run
        if is_unrecorded(row):
            unrecorded += 1  # dispatch unknown: not an attempt, not a failure
            continue
        counts[row["outcome"]] += 1

    if type(in_flight) is not int or in_flight < 0:
        raise ContractError("in_flight must be a non-negative integer")
    total_rows = len(typed)
    planned_count = total_rows + in_flight if planned is None else planned
    pending_rows = sum(1 for row in typed if row.get("reason") == "pending")
    pending = planned_count - total_rows - in_flight
    if pending < 0:
        raise ContractError("more rows than planned")

    attempted = sum(counts[outcome] for outcome in ATTEMPTED_OUTCOMES)
    if final:
        if in_flight:
            raise ContractError("final coverage cannot have requests in flight")
        if pending_rows or pending:
            raise ContractError("final coverage cannot have pending rows")
        if planned_count != attempted + counts[NOT_RUN] + unrecorded:
            raise ContractError("planned must equal attempted + not_run + unrecorded")

    assessed_rows = [row for row in typed if row["outcome"] == ASSESSED]
    with_signals = [row for row in assessed_rows if signal_names(row)]
    flag_counts: Dict[str, int] = {}
    for row in with_signals:
        for name in signal_names(row):
            flag_counts[name] = flag_counts.get(name, 0) + 1

    verified_rows = [row for row in assessed_rows if row.get("verified") is not None]
    verified_findings = sum(1 for row in verified_rows if row["verified"].get("leaked") is True)

    assessed = counts[ASSESSED]
    signal_rate = _rate(len(with_signals), assessed)
    return {
        "final": final,
        "planned": planned_count,
        "attempted": attempted,
        "assessed": assessed,
        "failed": counts[FAILED],
        "timed_out": counts[TIMED_OUT],
        "cancelled": counts[CANCELLED],
        "not_run": counts[NOT_RUN],
        "unrecorded": unrecorded,
        "in_flight": in_flight,
        "pending": pending + pending_rows,
        "complete": bool(final and planned_count > 0 and assessed == planned_count),
        "signal_kind": SIGNAL_KIND,
        "rows_with_signals": len(with_signals),
        "lexical_signal_rate": signal_rate,
        "flag_counts": flag_counts,
        "verified_evaluated": len(verified_rows),
        "verified_findings": verified_findings,
        "verified_rate": _rate(verified_findings, len(verified_rows)),
        # Deprecated aliases, kept for one release.
        "total_tests": planned_count,
        "vulnerabilities_detected": len(with_signals),
        "detection_rate": (
            f"{signal_rate['rate'] * 100:.1f}%" if signal_rate["rate"] is not None else "n/a"
        ),
        "deprecated": dict(DEPRECATED_SUMMARY_FIELDS),
    }
