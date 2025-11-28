"""OpenAI and Azure OpenAI endpoint implementations."""

from dataclasses import dataclass
from typing import Any, Dict, Optional
import requests
from .base import Endpoint, RateLimiter


@dataclass
class OpenAIEndpoint(Endpoint):
    """OpenAI API client for GPT models."""
    
    api_key: str
    model: str = "gpt-4-turbo-preview"
    api_url: str = "https://api.openai.com/v1/chat/completions"
    max_tokens: int = 512
    temperature: float = 0
    
    def __init__(self, api_key: str, model: Optional[str] = None,
                 rate_limiter: Optional[RateLimiter] = None):
        super().__init__(rate_limiter)
        self.api_key = api_key
        if model:
            self.model = model
    
    def send(self, prompt: str) -> str:
        """Send prompt to OpenAI and return response text."""
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        response = self._send_request(
            lambda: requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=30,
            )
        )
        data = response.json()
        
        # Extract text content
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if content:
                return str(content)
        
        return str(data)


@dataclass
class AzureOpenAIEndpoint(Endpoint):
    """Azure OpenAI Service client."""
    
    api_key: str
    endpoint: str  # e.g., "https://myresource.openai.azure.com"
    deployment_name: str  # e.g., "gpt-4"
    api_version: str = "2024-02-15-preview"
    max_tokens: int = 512
    temperature: float = 0
    
    def __init__(self, api_key: str, endpoint: str, deployment_name: str,
                 api_version: Optional[str] = None,
                 rate_limiter: Optional[RateLimiter] = None):
        super().__init__(rate_limiter)
        self.api_key = api_key
        self.endpoint = endpoint
        self.deployment_name = deployment_name
        if api_version:
            self.api_version = api_version
    
    def send(self, prompt: str) -> str:
        """Send prompt to Azure OpenAI and return response text."""
        url = f"{self.endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        
        payload: Dict[str, Any] = {
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        headers = {
            "Content-Type": "application/json",
            "api-key": self.api_key,
        }

        response = self._send_request(
            lambda: requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )
        )
        data = response.json()
        
        # Extract text content (same structure as OpenAI)
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if content:
                return str(content)
        
        return str(data)
