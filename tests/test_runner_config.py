import argparse
import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from endpoints import create_endpoint
from generator import build_payload_suite
from main import apply_cli_overrides
from payloads import BASELINE_PAYLOADS, POLICY_VIOLATION_PAYLOADS
from config import TestConfig as InjecticideTestConfig


def test_build_payload_suite_expands_categories_and_custom_payloads():
    suite = build_payload_suite(
        ["baseline", "policy"],
        custom_payloads=["custom payload"],
    )

    assert len(suite) == len(BASELINE_PAYLOADS) + len(POLICY_VIOLATION_PAYLOADS) + 1
    assert suite[0][1] == "baseline"
    assert suite[-1] == ("custom payload", "custom")


def test_build_payload_suite_rejects_unknown_categories():
    with pytest.raises(ValueError, match="Unsupported payload categories"):
        build_payload_suite(["baseline", "unknown-category"])


def test_apply_cli_overrides_preserves_config_values_when_args_are_unset():
    config = InjecticideTestConfig(
        payload_categories=["baseline", "roleplay"],
        max_requests=17,
        output_format="html",
    )
    args = argparse.Namespace(
        service=None,
        api_key=None,
        model=None,
        delay=None,
        max_requests=None,
        verbose=False,
        format=None,
        output=None,
        categories=None,
        mode=None,
    )

    updated = apply_cli_overrides(config, args)

    assert updated.payload_categories == ["baseline", "roleplay"]
    assert updated.max_requests == 17
    assert updated.output_format == "html"


def test_create_endpoint_applies_configured_rate_limits():
    endpoint = create_endpoint(
        "anthropic",
        api_key="test-key",
        requests_per_minute=7,
        requests_per_hour=21,
    )

    assert endpoint.rate_limiter.requests_per_minute == 7
    assert endpoint.rate_limiter.requests_per_hour == 21
