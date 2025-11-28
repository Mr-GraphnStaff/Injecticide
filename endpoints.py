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


@dataclass
class OpenAIEndpoint(Endpoint):
    """OpenAI API client for GPT models."""
    
    api_key: str
    model: str = "gpt-4"
    api_url: str = "https://api.openai.com/v1/chat/completions"
    max_tokens: int = 512
    
    def send(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        response = requests.post(
            self.api_url,
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text from OpenAI response format
        if "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            if "message" in choice and "content" in choice["message"]:
                return choice["message"]["content"]
        
        return str(data)


@dataclass 
class AzureOpenAIEndpoint(Endpoint):
    """Azure OpenAI API client."""
    
    api_key: str
    endpoint_url: str  # e.g., https://your-resource.openai.azure.com
    deployment_name: str  # Your deployment name
    api_version: str = "2023-05-15"
    max_tokens: int = 512
    
    def send(self, prompt: str) -> str:
        url = f"{self.endpoint_url}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        
        payload = {
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0
        }
        
        headers = {
            "Content-Type": "application/json",
            "api-key": self.api_key
        }
        
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text from Azure OpenAI response
        if "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            if "message" in choice and "content" in choice["message"]:
                return choice["message"]["content"]
        
        return str(data)
