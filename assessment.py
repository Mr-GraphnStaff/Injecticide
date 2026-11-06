"""Typed result rows and coverage counts for stress-tester sessions.

A row records what happened to one planned payload. Only an ``assessed`` row may
carry lexical signals. A failed, timed-out, cancelled or not-run row never
renders as "no signals" or SAFE, and the counts below keep separate
denominators so partial coverage is always visible.
"""

from typing import Any, Dict, Iterable, List, Optional

OUTCOMES = ("assessed", "failed", "timed_out", "cancelled", "not_run")
REASONS = (
    "provider_error",
    "timeout",
    "rate_limit_exhausted",
    "cancelled_by_user",
    "session_failed",
    "unknown_error",
)
MAX_DETAIL_CHARS = 300


def _clean_detail(detail: Any) -> str:
    return str(detail or "")[:MAX_DETAIL_CHARS]


def make_assessed_row(
    payload: str,
    category: str,
    signals: Dict[str, bool],
    response_length: int = 0,
    verified: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """Row for a payload whose response was received and analyzed.

    ``signals`` are deterministic lexical flags. They are not verified findings;
    ``verified`` is set only by a check that compared a canary.
    """
    signals = {name: bool(value) for name, value in signals.items()}
    return {
        "payload": payload,
        "category": category,
        "outcome": "assessed",
        "reason": None,
        "detail": "",
        "signals": signals,
        "signal_kind": "lexical",
        "verified": verified,
        "response_length": response_length,
        # Legacy keys, kept for one release so existing consumers keep working.
        "flags": dict(signals),
        "detected": any(signals.values()),
    }


def make_unassessed_row(
    payload: str,
    category: str,
    outcome: str,
    reason: str = "unknown_error",
    detail: Any = "",
) -> Dict[str, Any]:
    """Row for a payload that was not assessed (failed, timed out, cancelled, not run)."""
    if outcome == "assessed" or outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of the unassessed outcomes, got {outcome!r}")
    if reason not in REASONS:
        reason = "unknown_error"
    return {
        "payload": payload,
        "category": category,
        "outcome": outcome,
        "reason": reason,
        "detail": _clean_detail(detail),
        "signals": {},
        "signal_kind": "lexical",
        "verified": None,
        "response_length": 0,
        "flags": {},
        "detected": False,
    }


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return a typed row for a legacy row that has no ``outcome`` key.

    A legacy row with an ``error`` becomes ``failed``; any other legacy row is
    treated as ``assessed``.
    """
    if row.get("outcome") in OUTCOMES:
        return row
    if row.get("error"):
        return make_unassessed_row(
            row.get("payload", ""),
            row.get("category", "unknown"),
            "failed",
            "unknown_error",
            row.get("error"),
        )
    return make_assessed_row(
        row.get("payload", ""),
        row.get("category", "unknown"),
        row.get("flags", {}) or {},
        row.get("response_length", 0),
    )


def build_coverage(rows: Iterable[Dict[str, Any]], planned: Optional[int] = None) -> Dict[str, Any]:
    """Counts with separate denominators.

    ``planned`` is the number of payloads the session intended to send. Rows the
    session never reached are counted as ``not_run`` when ``planned`` exceeds the
    rows seen.
    """
    typed: List[Dict[str, Any]] = [normalize_row(row) for row in rows]
    counts = {name: 0 for name in OUTCOMES}
    flag_counts: Dict[str, int] = {}
    rows_with_signals = 0
    verified_findings = 0
    verified_checked = 0
    for row in typed:
        counts[row["outcome"]] += 1
        if row["outcome"] != "assessed":
            continue
        signals = row.get("signals", {})
        if any(signals.values()):
            rows_with_signals += 1
        for name, value in signals.items():
            if value:
                flag_counts[name] = flag_counts.get(name, 0) + 1
        verified = row.get("verified")
        if verified is not None:
            verified_checked += 1
            if verified.get("canary_leaked"):
                verified_findings += 1

    seen = len(typed)
    planned_total = max(planned if planned is not None else seen, seen)
    not_run = counts["not_run"] + (planned_total - seen)
    attempted = counts["assessed"] + counts["failed"] + counts["timed_out"] + counts["cancelled"]
    incomplete = counts["failed"] + counts["timed_out"] + counts["cancelled"] + not_run
    return {
        "planned": planned_total,
        "attempted": attempted,
        "assessed": counts["assessed"],
        "failed": counts["failed"],
        "timed_out": counts["timed_out"],
        "cancelled": counts["cancelled"],
        "not_run": not_run,
        "complete": incomplete == 0,
        "rows_with_signals": rows_with_signals,
        "verified_findings": verified_findings,
        "verified_checked": verified_checked,
        "flag_counts": flag_counts,
    }


def row_label(row: Dict[str, Any]) -> str:
    """Plain label for a row. Never says SAFE; never says "no signals" for an unassessed row."""
    row = normalize_row(row)
    if row["outcome"] != "assessed":
        reason = row.get("reason") or "unknown_error"
        return f"NOT ASSESSED ({row['outcome']}: {reason})"
    if any(row.get("signals", {}).values()):
        return "SIGNALS (lexical)"
    return "NO SIGNALS (lexical only)"
