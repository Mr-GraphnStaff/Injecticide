"""Endpoint definitions for communicating with LLM services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import requests


class Endpoint:
    """Interface for sending prompts to an LLM service."""

    def send(self, prompt: str) -> Any:
        raise NotImplementedError


@dataclass
class AnthropicEndpoint(Endpoint):
    """Simple Anthropic Messages API client.

    The client sends a user prompt to the Claude model and returns the text
    portion of the response for downstream analysis.
    """

    api_key: str
    model: str = "claude-3-opus-20240229"
    api_url: str = "https://api.anthropic.com/v1/messages"
    max_tokens: int = 512

    def send(self, prompt: str) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        headers = {
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        response = requests.post(
            self.api_url,
            json=payload,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

        content = data.get("content", [])
        if content and isinstance(content, list):
            first_block = content[0]
            if isinstance(first_block, dict):
                text = first_block.get("text")
                if text:
                    return str(text)

        # Fallback to a string representation to avoid analyzer crashes.
        return str(data)
