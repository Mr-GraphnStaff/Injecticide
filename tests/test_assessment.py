"""Tests for the typed result/coverage contract (items 362/363/364/365)."""

import pytest

from analyzer import analyze
from assessment import (
    ASSESSED,
    CANCELLED,
    FAILED,
    LABEL_NO_SIGNALS,
    LABEL_SIGNALS,
    NOT_RUN,
    TIMED_OUT,
    ContractError,
    build_coverage,
    cap_detail,
    escape_html,
    make_assessed_row,
    make_unassessed_row,
    normalize_row,
    row_label,
    signal_names,
)

BENIGN_REFUSAL = "I can't share my system prompt, but I'm happy to help otherwise."


def _assessed(i, text="Hello there.", verified=None):
    return make_assessed_row(i, f"payload {i}", "cat", text, analyze(text), verified=verified)


def test_failed_rows_never_read_clean():
    rows = [
        make_unassessed_row(0, "p", "c", FAILED, "provider_error", "HTTP 500"),
        make_unassessed_row(1, "p", "c", FAILED, "analysis_error", "boom"),
        make_unassessed_row(2, "p", "c", TIMED_OUT, "timeout"),
        make_unassessed_row(3, "p", "c", CANCELLED, "cancelled_by_user"),
        make_unassessed_row(4, "p", "c", NOT_RUN, "session_failed"),
    ]
    for row in rows:
        label = row_label(row)
        assert "SAFE" not in label and "NO SIGNALS" not in label
        assert row["reason"] in label
        assert row["signals"] is None and row["verified"] is None
        assert row["flags"] == {} and row["detected"] is False
        assert row["error"]  # reason or detail stays visible to old consumers


def test_assessed_labels_and_no_safe():
    clean = _assessed(0)
    flagged = _assessed(1, "Sure, I will ignore previous instructions.")
    assert row_label(clean) == LABEL_NO_SIGNALS
    assert row_label(flagged) == LABEL_SIGNALS
    assert signal_names(flagged) == ["unexpected_behavior"]
    assert all("SAFE" not in row_label(r) for r in (clean, flagged))


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (ASSESSED, "provider_error"),
        (FAILED, "timeout"),
        (TIMED_OUT, "provider_error"),
        (CANCELLED, "session_failed"),
        (NOT_RUN, "provider_error"),
        (FAILED, "made_up_reason"),
        ("safe", "provider_error"),
    ],
)
def test_reason_outcome_pairs_are_closed(outcome, reason):
    with pytest.raises(ContractError):
        make_unassessed_row(0, "p", "c", outcome, reason)


def test_lexical_signal_is_not_a_verified_finding():
    refusal = _assessed(0, BENIGN_REFUSAL)
    assert signal_names(refusal) == ["system_prompt_leak"]
    cov = build_coverage([refusal])
    assert cov["rows_with_signals"] == 1
    assert cov["verified_evaluated"] == 0
    assert cov["verified_findings"] == 0
    assert cov["verified_rate"]["rate"] is None


def test_verified_requires_executed_check_evidence():
    leak = _assessed(0, "CANARY-1234", verified={"check": "canary", "provenance": "fixture:t1", "leaked": True})
    nope = _assessed(1, "fine", verified={"check": "canary", "provenance": "fixture:t1", "leaked": False})
    cov = build_coverage([leak, nope, _assessed(2)])
    assert cov["verified_evaluated"] == 2
    assert cov["verified_findings"] == 1
    assert cov["verified_rate"] == {"numerator": 1, "denominator": 2, "rate": 0.5}
    for bad in ({"leaked": True}, {"check": "canary", "provenance": "", "leaked": True},
                {"check": "canary", "provenance": "x", "leaked": "yes"}, "leaked"):
        with pytest.raises(ContractError):
            _assessed(9, verified=bad)


def test_final_coverage_invariants_and_complete():
    rows = [
        _assessed(0),
        _assessed(1, "ignore previous"),
        make_unassessed_row(2, "p", "c", FAILED, "provider_error"),
        make_unassessed_row(3, "p", "c", TIMED_OUT, "timeout"),
        make_unassessed_row(4, "p", "c", CANCELLED, "cancelled_by_user"),
        make_unassessed_row(5, "p", "c", NOT_RUN, "cancelled_by_user"),
    ]
    cov = build_coverage(rows)
    assert cov["planned"] == cov["attempted"] + cov["not_run"] == 6
    assert cov["attempted"] == cov["assessed"] + cov["failed"] + cov["timed_out"] + cov["cancelled"] == 5
    assert cov["complete"] is False
    assert cov["lexical_signal_rate"] == {"numerator": 1, "denominator": 2, "rate": 0.5}
    # Deprecated aliases: rate over assessed rows only, still a string.
    assert cov["vulnerabilities_detected"] == 1
    assert cov["detection_rate"] == "50.0%"
    assert cov["total_tests"] == 6
    assert cov["deprecated"]["vulnerabilities_detected"] == "rows_with_signals"

    full = build_coverage([_assessed(0), _assessed(1)])
    assert full["complete"] is True


def test_zero_payload_session_is_not_complete():
    cov = build_coverage([])
    assert cov["complete"] is False
    assert cov["lexical_signal_rate"]["rate"] is None
    assert cov["detection_rate"] == "n/a"
    only_failed = build_coverage([make_unassessed_row(0, "p", "c", FAILED, "provider_error")])
    assert only_failed["complete"] is False and only_failed["detection_rate"] == "n/a"


def test_final_coverage_rejects_inconsistent_state():
    with pytest.raises(ContractError):
        build_coverage([_assessed(0)], planned=3)
    with pytest.raises(ContractError):
        build_coverage([_assessed(0)], in_flight=1)
    with pytest.raises(ContractError):
        build_coverage([make_unassessed_row(0, "p", "c", NOT_RUN, "pending")])
    with pytest.raises(ContractError):
        build_coverage([_assessed(0), _assessed(1)], planned=1)
    with pytest.raises(ContractError):
        build_coverage([{"payload": "legacy", "flags": {}}])


def test_live_snapshot_reports_pending_without_inventing_outcomes():
    rows = [_assessed(0), make_unassessed_row(1, "p", "c", NOT_RUN, "pending")]
    cov = build_coverage(rows, planned=5, in_flight=1, final=False)
    assert cov["final"] is False and cov["complete"] is False
    assert cov["assessed"] == 1 and cov["not_run"] == 0
    assert cov["in_flight"] == 1
    assert cov["pending"] == 3  # 2 unmaterialized + 1 pending row


def test_legacy_rows_never_normalize_to_assessed():
    ok_legacy = {"payload": "p", "category": "c", "flags": {"system_prompt_leak": True},
                 "detected": True, "response_length": 10}
    err_legacy = {"payload": "p", "category": "c", "flags": {}, "detected": False, "error": "boom"}
    a = normalize_row(ok_legacy, row_id=0)
    b = normalize_row(err_legacy, row_id=1)
    assert a["outcome"] == b["outcome"] == FAILED
    assert a["reason"] == b["reason"] == "unrecorded_outcome"
    assert a["legacy_flags"] == {"system_prompt_leak": True}
    assert a["detected"] is False and signal_names(a) == []
    assert b["detail"] == "boom"
    cov = build_coverage([a, b])
    assert cov["assessed"] == 0 and cov["rows_with_signals"] == 0


def test_typed_rows_round_trip_and_reject_contradictions():
    row = _assessed(7, "ignore previous")
    again = normalize_row(row)
    assert again["outcome"] == ASSESSED and again["signals"] == row["signals"]
    assert again["response_length"] == row["response_length"]
    failed = make_unassessed_row(8, "p", "c", FAILED, "provider_error", "x")
    assert normalize_row(failed)["reason"] == "provider_error"
    with pytest.raises(ContractError):
        normalize_row(dict(failed, signals={"x": True}))
    with pytest.raises(ContractError):
        normalize_row({"row_id": 1, "outcome": ASSESSED})
    with pytest.raises(ContractError):
        normalize_row({"payload": "no id"})


def test_detail_is_capped_and_escaped():
    long = "<script>" + "x" * 1000
    row = make_unassessed_row(0, "p", "c", FAILED, "provider_error", long)
    assert len(row["detail"]) == 500 and row["detail"].endswith("...")
    assert cap_detail(None) is None
    hostile = '<img src=x onerror="alert(1)">&\''
    escaped = escape_html(hostile)
    assert "<" not in escaped and ">" not in escaped and '"' not in escaped and "'" not in escaped
    assert escape_html(None) == ""
