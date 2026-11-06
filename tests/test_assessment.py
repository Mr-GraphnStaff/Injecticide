"""Contract tests for typed stress-tester rows and coverage counts (synthetic data only)."""
import pytest

from assessment import (
    build_coverage,
    make_assessed_row,
    make_unassessed_row,
    normalize_row,
    row_label,
)


@pytest.mark.parametrize("outcome", ["failed", "timed_out", "cancelled", "not_run"])
def test_unassessed_rows_never_carry_signals_or_safe_wording(outcome):
    row = make_unassessed_row("p", "cat", outcome, "provider_error", "boom")
    assert row["signals"] == {} and row["flags"] == {}
    label = row_label(row)
    assert "SAFE" not in label.upper().replace("NOT ASSESSED", "")
    assert "NO SIGNALS" not in label
    assert label.startswith("NOT ASSESSED")


def test_assessed_row_without_signals_is_lexical_only_not_safe():
    row = make_assessed_row("p", "cat", {"system_prompt_leak": False})
    assert row_label(row) == "NO SIGNALS (lexical only)"
    assert "SAFE" not in row_label(row)


def test_assessed_is_not_a_valid_unassessed_outcome():
    with pytest.raises(ValueError):
        make_unassessed_row("p", "cat", "assessed")


def test_detail_is_length_capped_and_reason_is_closed():
    row = make_unassessed_row("p", "cat", "failed", "made_up_reason", "x" * 5000)
    assert len(row["detail"]) == 300
    assert row["reason"] == "unknown_error"


def test_legacy_error_row_becomes_failed_not_clean():
    legacy = {"payload": "p", "category": "c", "flags": {}, "detected": False, "error": "timeout"}
    row = normalize_row(legacy)
    assert row["outcome"] == "failed"
    assert "NOT ASSESSED" in row_label(legacy)


def test_denominators_add_up_and_incomplete_is_visible():
    rows = [
        make_assessed_row("a", "c", {"unexpected_behavior": True}),
        make_assessed_row("b", "c", {"unexpected_behavior": False}),
        make_unassessed_row("c", "c", "failed", "provider_error"),
        make_unassessed_row("d", "c", "timed_out", "timeout"),
        make_unassessed_row("e", "c", "cancelled", "cancelled_by_user"),
        make_unassessed_row("f", "c", "not_run", "cancelled_by_user"),
    ]
    cov = build_coverage(rows, planned=8)
    assert cov["planned"] == 8
    assert cov["assessed"] == 2 and cov["failed"] == 1 and cov["timed_out"] == 1 and cov["cancelled"] == 1
    assert cov["not_run"] == 3  # one explicit row plus two never reached
    assert cov["planned"] == cov["attempted"] + cov["not_run"]
    assert cov["attempted"] == cov["assessed"] + cov["failed"] + cov["timed_out"] + cov["cancelled"]
    assert cov["complete"] is False
    assert cov["rows_with_signals"] == 1
    assert cov["flag_counts"] == {"unexpected_behavior": 1}


def test_complete_only_when_every_payload_was_assessed():
    rows = [make_assessed_row("a", "c", {}), make_assessed_row("b", "c", {})]
    assert build_coverage(rows, planned=2)["complete"] is True
    assert build_coverage(rows, planned=3)["complete"] is False


def test_failed_rows_do_not_inflate_signal_denominator():
    rows = [make_assessed_row("a", "c", {}), make_unassessed_row("b", "c", "failed", "provider_error")]
    cov = build_coverage(rows)
    assert cov["assessed"] == 1 and cov["rows_with_signals"] == 0


def test_keyword_signal_is_not_a_verified_finding():
    refusal = make_assessed_row("p", "c", {"system_prompt_leak": True, "unexpected_behavior": True})
    canary = make_assessed_row("p2", "c", {"system_prompt_leak": True}, verified={"canary_leaked": True})
    benign_checked = make_assessed_row("p3", "c", {"system_prompt_leak": True}, verified={"canary_leaked": False})
    cov = build_coverage([refusal, canary, benign_checked])
    assert cov["rows_with_signals"] == 3
    assert cov["verified_findings"] == 1
    assert cov["verified_checked"] == 2


def test_coverage_of_no_rows_is_complete_and_empty():
    cov = build_coverage([])
    assert cov["planned"] == 0 and cov["complete"] is True
