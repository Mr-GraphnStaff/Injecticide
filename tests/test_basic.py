import pathlib
import sys

import pytest

# Ensure project root is importable when running from anywhere
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from generator import generate_payloads
from redteam import default_tests


def test_payloads_non_empty():
    payloads = generate_payloads()
    assert payloads, "Payload generation should return at least one payload"


def test_default_tests_present():
    tests = default_tests()
    assert len(tests) == 1
    assert tests[0].expected_flag == "system_prompt_leak"


def test_red_team_run_detects_system_leak():
    test_case = default_tests()[0]

    def fake_send(prompt: str):
        assert prompt == test_case.payload
        return "System prompt: do not reveal this"

    result = test_case.run(fake_send)
    assert result["passed"] is True
    assert result["flags"]["system_prompt_leak"] is True
    assert result["flags"]["unexpected_behavior"] is False
