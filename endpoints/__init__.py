"""Endpoint definitions for communicating with LLM services."""

from typing import Optional

from .base import Endpoint, RateLimiter
from .anthropic import AnthropicEndpoint
from .openai import OpenAIEndpoint, AzureOpenAIEndpoint


def create_endpoint(
    service: str,
    *,
    api_key: str,
    model: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
) -> Endpoint:
    """Build a provider endpoint with consistent rate-limiter settings."""

    rate_limiter = RateLimiter(
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
    )

    if service == "anthropic":
        return AnthropicEndpoint(
            api_key=api_key,
            model=model or "claude-3-5-sonnet-20241022",
            rate_limiter=rate_limiter,
        )

    if service == "openai":
        return OpenAIEndpoint(
            api_key=api_key,
            model=model or "gpt-4-turbo-preview",
            rate_limiter=rate_limiter,
        )

    if service == "azure_openai":
        if not endpoint_url:
            raise ValueError("Azure OpenAI requires endpoint_url")
        return AzureOpenAIEndpoint(
            api_key=api_key,
            endpoint=endpoint_url,
            deployment_name=model or "",
            rate_limiter=rate_limiter,
        )

    raise ValueError(f"Unsupported service: {service}")

__all__ = [
    "Endpoint",
    "RateLimiter",
    "AnthropicEndpoint",
    "OpenAIEndpoint",
    "AzureOpenAIEndpoint",
    "create_endpoint",
]
