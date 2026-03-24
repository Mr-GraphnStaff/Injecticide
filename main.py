"""Enhanced entry point for Injecticide with config support."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Callable, List, Dict, Any

from analyzer import analyze
from config import TestConfig
from endpoints import create_endpoint
from generator import build_payload_suite
from reporter import ReportGenerator


def build_sender(config: TestConfig) -> Callable[[str], str]:
    """Create a send function based on configuration."""

    service = config.target_service
    api_key = config.api_key or os.environ.get(f"{service.upper()}_API_KEY")

    if not api_key:
        raise ValueError(f"API key required for {service}")

    endpoint = create_endpoint(
        service,
        api_key=api_key,
        model=config.model,
        endpoint_url=config.endpoint_url,
        requests_per_minute=config.requests_per_minute,
        requests_per_hour=config.requests_per_hour,
    )

    def rate_limited_send(prompt: str) -> str:
        if config.delay_between_requests > 0:
            time.sleep(config.delay_between_requests)
        return endpoint.send_with_rate_limit(prompt)

    return rate_limited_send


def run_test_suite(config: TestConfig) -> List[Dict[str, Any]]:
    """Run the complete test suite based on configuration."""

    send_fn = build_sender(config)
    results = []
    request_count = 0

    payloads = build_payload_suite(config.payload_categories, config.custom_payloads)

    for payload, category in payloads:
        if request_count >= config.max_requests:
            print(f"⚠️  Reached maximum request limit ({config.max_requests})")
            break

        try:
            if config.verbose:
                print(f"Testing [{category}]: {payload[:60]}...")

            response = send_fn(payload)
            flags = analyze(response)

            result = {
                "payload": payload,
                "category": category,
                "flags": flags,
                "response_length": len(str(response)),
                "detected": any(flags.values()),
            }

            results.append(result)

            if config.stop_on_detection and result["detected"]:
                print("🛑 Detection found, stopping execution")
                break

        except Exception as e:
            results.append({
                "payload": payload,
                "category": category,
                "error": str(e),
                "flags": {},
                "detected": False,
            })

        request_count += 1

    return results


def apply_cli_overrides(config: TestConfig, args: argparse.Namespace) -> TestConfig:
    """Apply CLI overrides without clobbering config file values by default."""

    if args.service:
        config.target_service = args.service
    if args.api_key:
        config.api_key = args.api_key
    if args.model:
        config.model = args.model
    if args.delay is not None:
        config.delay_between_requests = args.delay
    if args.max_requests is not None:
        config.max_requests = args.max_requests
    if args.verbose:
        config.verbose = True
    if args.format is not None:
        config.output_format = args.format
    if args.output:
        config.output_file = args.output

    if args.categories:
        config.payload_categories = args.categories
    elif args.mode:
        config.payload_categories = (
            ["baseline"] if args.mode == "baseline" else
            ["policy"] if args.mode == "policy" else
            [
                "baseline",
                "policy",
                "extraction",
                "jailbreak",
                "encoding",
                "context",
                "roleplay",
                "insurance_us_ca",
                "esf",
            ]
        )

    return config


def main():
    """Main entry point."""

    parser = argparse.ArgumentParser(
        description="Injecticide - LLM Security Testing Framework"
    )

    # Config
    parser.add_argument("--config", help="Path to config file (YAML/JSON)")
    parser.add_argument("--service", choices=["anthropic", "openai", "azure_openai"])
    parser.add_argument("--api-key")
    parser.add_argument("--model")

    # Execution control
    parser.add_argument(
        "--mode",
        choices=["baseline", "policy", "all"],
        default=None,
        help="Legacy mode selector (overridden by --categories)"
    )

    parser.add_argument(
        "--categories",
        nargs="+",
        help="Explicit payload categories to run (overrides --mode)"
    )

    # Output
    parser.add_argument("--output")
    parser.add_argument("--format", choices=["json", "html", "csv"], default=None)
    parser.add_argument("--verbose", action="store_true")

    # Safety
    parser.add_argument("--max-requests", type=int, default=None)
    parser.add_argument("--delay", type=float, default=None)

    args = parser.parse_args()

    # Load config
    config = TestConfig.from_file(args.config) if args.config else TestConfig()

    config = apply_cli_overrides(config, args)

    # Validate API key
    if not config.api_key and not os.environ.get(f"{config.target_service.upper()}_API_KEY"):
        print(f"❌ API key required for {config.target_service}")
        sys.exit(1)

    print("🚀 Starting Injecticide Security Assessment")
    print(f"   Target: {config.target_service}")
    print(f"   Categories: {', '.join(config.payload_categories)}")

    results = run_test_suite(config)

    print("\n📊 Assessment Complete")
    print(f"   Total tests: {len(results)}")
    print(f"   Detections: {sum(1 for r in results if r.get('detected'))}")

    if config.output_file:
        generator = ReportGenerator(results, config.to_dict())
        generator.generate(config.output_format, config.output_file)
        print(f"   Report saved: {config.output_file}")


if __name__ == "__main__":
    main()
