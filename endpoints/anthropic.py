"""Anthropic Claude endpoint implementation."""

from dataclasses import dataclass
from typing import Any, Dict, Optional
import requests
from .base import Endpoint, RateLimiter


@dataclass
class AnthropicEndpoint(Endpoint):
    """Anthropic Messages API client for Claude models."""
    
    api_key: str
    model: str = "claude-3-5-sonnet-20241022"
    api_url: str = "https://api.anthropic.com/v1/messages"
    max_tokens: int = 512
    temperature: float = 0
    
    def __init__(self, api_key: str, model: Optional[str] = None, 
                 rate_limiter: Optional[RateLimiter] = None):
        super().__init__(rate_limiter)
        self.api_key = api_key
        if model:
            self.model = model
    
    def send(self, prompt: str) -> str:
        """Send prompt to Claude and return response text."""
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}]
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
        
        # Extract text content
        content = data.get("content", [])
        if content and isinstance(content, list):
            first_block = content[0]
            if isinstance(first_block, dict):
                text = first_block.get("text")
                if text:
                    return str(text)
        
        return str(data)
