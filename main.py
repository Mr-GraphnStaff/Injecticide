"""Entry point for running Injecticide prompt-injection suites."""

from __future__ import annotations

import argparse
import os
from typing import Callable

from analyzer import analyze
from endpoints import AnthropicEndpoint, Endpoint
from generator import generate_payloads, policy_violation_payloads
from redteam import run_suite


def build_sender(service: str, api_key: str, model: str | None = None) -> Callable[[str], str]:
    """Create a send function for the requested service."""

    if service == "anthropic":
        endpoint: Endpoint = AnthropicEndpoint(
            api_key=api_key,
            model=model or "claude-3-opus-20240229",
        )
        return endpoint.send

    raise ValueError(f"Unsupported service: {service}")


def run_payloads(service: str, api_key: str, model: str | None = None) -> None:
    """Send baseline payloads and print analyzer flags for quick checks."""

    send_fn = build_sender(service, api_key, model)
    for payload in generate_payloads():
        response = send_fn(payload)
        flags = analyze(response)
        print({"payload": payload, "flags": flags})


def run_policy_violation_probes(service: str, api_key: str, model: str | None = None) -> None:
    """Send policy-violation probes tailored to the service."""

    send_fn = build_sender(service, api_key, model)
    for payload in policy_violation_payloads():
        response = send_fn(payload)
        flags = analyze(response)
        print({"payload": payload, "flags": flags})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Injecticide against an LLM endpoint")
    parser.add_argument("service", choices=["anthropic"], help="Target service name")
    parser.add_argument("--api-key", dest="api_key", default=os.environ.get("ANTHROPIC_API_KEY"))
    parser.add_argument("--model", dest="model", default=os.environ.get("MODEL", "claude-3-opus-20240229"))
    parser.add_argument(
        "--mode",
        choices=["baseline", "policy-violations", "suite"],
        default="baseline",
        help="Which checks to run",
    )
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("API key required via --api-key or ANTHROPIC_API_KEY")

    if args.mode == "baseline":
        run_payloads(args.service, args.api_key, args.model)
    elif args.mode == "policy-violations":
        run_policy_violation_probes(args.service, args.api_key, args.model)
    else:
        send_fn = build_sender(args.service, args.api_key, args.model)
        for result in run_suite(send_fn):
            print(result)


if __name__ == "__main__":
    main()
