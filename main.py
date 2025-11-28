"""Enhanced entry point for Injecticide with config support."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Callable, Optional, List, Dict, Any

from analyzer import analyze
from config import TestConfig
from reporter import ReportGenerator
from endpoints import (
    AnthropicEndpoint, 
    OpenAIEndpoint, 
    AzureOpenAIEndpoint,
)
from generator import generate_payloads, policy_violation_payloads
from redteam import run_suite


def build_sender(config: TestConfig) -> Callable[[str], str]:
    """Create a send function based on configuration."""
    
    service = config.target_service
    api_key = config.api_key or os.environ.get(f"{service.upper()}_API_KEY")
    
    if not api_key:
        raise ValueError(f"API key required for {service}")
    
    if service == "anthropic":
        endpoint = AnthropicEndpoint(
            api_key=api_key,
            model=config.model or "claude-3-opus-20240229",
        )
    elif service == "openai":
        endpoint = OpenAIEndpoint(
            api_key=api_key,
            model=config.model or "gpt-4",
        )
    elif service == "azure_openai":
        if not config.endpoint_url:
            raise ValueError("Azure OpenAI requires endpoint_url in config")
        endpoint = AzureOpenAIEndpoint(
            api_key=api_key,
            endpoint=config.endpoint_url,
            deployment_name=config.model,
        )
    else:
        raise ValueError(f"Unsupported service: {service}")
    
    # Create rate-limited wrapper
    def rate_limited_send(prompt: str) -> str:
        if config.delay_between_requests > 0:
            time.sleep(config.delay_between_requests)
        return endpoint.send(prompt)
    
    return rate_limited_send


def run_test_suite(config: TestConfig) -> List[Dict[str, Any]]:
    """Run the complete test suite based on configuration."""
    
    send_fn = build_sender(config)
    results = []
    request_count = 0
    
    # Get payloads based on categories
    payloads = []
    if "baseline" in config.payload_categories:
        payloads.extend([(p, "baseline") for p in generate_payloads()])
    if "policy" in config.payload_categories:
        payloads.extend([(p, "policy") for p in policy_violation_payloads()])
    
    # Add custom payloads
    for custom in config.custom_payloads:
        payloads.append((custom, "custom"))
    
    # Execute tests with safety limits
    for payload, category in payloads:
        if request_count >= config.max_requests:
            print(f"⚠️  Reached maximum request limit ({config.max_requests})")
            break
        
        try:
            if config.verbose:
                print(f"Testing: {payload[:50]}...")
            
            response = send_fn(payload)
            flags = analyze(response)
            
            result = {
                "payload": payload,
                "category": category,
                "flags": flags,
                "response_length": len(str(response)),
                "detected": any(flags.values())
            }
            results.append(result)
            
            if config.verbose and result["detected"]:
                print(f"  ✓ Detection: {[k for k,v in flags.items() if v]}")
            
            if config.stop_on_detection and result["detected"]:
                print(f"🛑 Stopping: Detection found")
                break
                
        except Exception as e:
            print(f"❌ Error testing payload: {e}")
            results.append({
                "payload": payload,
                "category": category,
                "error": str(e),
                "flags": {},
                "detected": False
            })
        
        request_count += 1
    
    return results


def main():
    """Enhanced main entry point with config support."""
    
    parser = argparse.ArgumentParser(
        description="Injecticide - LLM Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with config file
  python main.py --config configs/anthropic.yaml

  # Quick test against OpenAI
  python main.py --service openai --api-key sk-... --mode baseline

  # Generate HTML report
  python main.py --config configs/test.yaml --output report.html --format html
        """
    )
    
    # Config file option
    parser.add_argument("--config", help="Path to configuration file (YAML/JSON)")
    
    # Direct options (override config)
    parser.add_argument("--service", choices=["anthropic", "openai", "azure_openai"])
    parser.add_argument("--api-key")
    parser.add_argument("--model")
    parser.add_argument("--mode", choices=["baseline", "policy", "all"], default="baseline")
    
    # Output options
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--format", choices=["json", "html", "csv"], default="json")
    parser.add_argument("--verbose", action="store_true")
    
    # Safety options
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    
    args = parser.parse_args()
    
    # Load or create config
    if args.config:
        config = TestConfig.from_file(args.config)
    else:
        config = TestConfig()
    
    # Override config with command line args
    if args.service:
        config.target_service = args.service
    if args.api_key:
        config.api_key = args.api_key
    if args.model:
        config.model = args.model
    if args.mode:
        config.payload_categories = ["baseline"] if args.mode == "baseline" else \
                                   ["policy"] if args.mode == "policy" else \
                                   ["baseline", "policy"]
    if args.max_requests:
        config.max_requests = args.max_requests
    if args.delay:
        config.delay_between_requests = args.delay
    if args.verbose:
        config.verbose = True
    if args.format:
        config.output_format = args.format
    if args.output:
        config.output_file = args.output
    
    # Validate config
    if not config.api_key and not os.environ.get(f"{config.target_service.upper()}_API_KEY"):
        print(f"❌ Error: API key required for {config.target_service}")
        print(f"   Set via --api-key or {config.target_service.upper()}_API_KEY environment variable")
        sys.exit(1)
    
    # Run tests
    print(f"🚀 Starting Injecticide Security Assessment")
    print(f"   Target: {config.target_service} / {config.model or 'default model'}")
    print(f"   Categories: {', '.join(config.payload_categories)}")
    print()
    
    results = run_test_suite(config)
    
    # Generate report
    print(f"\n📊 Assessment Complete")
    print(f"   Total tests: {len(results)}")
    print(f"   Detections: {sum(1 for r in results if r.get('detected'))}")
    
    if config.output_file or args.output:
        generator = ReportGenerator(results, config.to_dict())
        report = generator.generate(
            format=config.output_format,
            output_file=config.output_file or args.output
        )
        print(f"   Report saved: {config.output_file or args.output}")
    else:
        # Print results to console
        for result in results:
            if result.get("detected"):
                print(f"\n🔍 Detection: {result['payload'][:50]}...")
                print(f"   Flags: {result['flags']}")


if __name__ == "__main__":
    main()
