"""Compatibility imports for older code paths.

Prefer importing from the ``endpoints`` package directly.
"""

from endpoints import Endpoint, AnthropicEndpoint, OpenAIEndpoint, AzureOpenAIEndpoint

__all__ = [
    "Endpoint",
    "AnthropicEndpoint",
    "OpenAIEndpoint",
    "AzureOpenAIEndpoint",
]
