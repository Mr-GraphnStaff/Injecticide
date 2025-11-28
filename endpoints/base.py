"""Base endpoint interface for LLM services."""

from abc import ABC, abstractmethod
from typing import Any, Optional
import time
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    """Simple rate limiter for API calls."""
    
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    _minute_timestamps: list = field(default_factory=list)
    _hour_timestamps: list = field(default_factory=list)
    
    def check_and_wait(self) -> None:
        """Check rate limits and wait if necessary."""
        current_time = time.time()
        
        # Clean old timestamps
        self._minute_timestamps = [
            t for t in self._minute_timestamps 
            if current_time - t < 60
        ]
        self._hour_timestamps = [
            t for t in self._hour_timestamps 
            if current_time - t < 3600
        ]
        
        # Check minute limit
        if len(self._minute_timestamps) >= self.requests_per_minute:
            wait_time = 60 - (current_time - self._minute_timestamps[0])
            if wait_time > 0:
                print(f"Rate limit: waiting {wait_time:.1f}s (minute limit)")
                time.sleep(wait_time)
        
        # Check hour limit
        if len(self._hour_timestamps) >= self.requests_per_hour:
            wait_time = 3600 - (current_time - self._hour_timestamps[0])
            if wait_time > 0:
                print(f"Rate limit: waiting {wait_time:.1f}s (hour limit)")
                time.sleep(wait_time)
        
        # Record this request
        self._minute_timestamps.append(current_time)
        self._hour_timestamps.append(current_time)


class Endpoint(ABC):
    """Interface for sending prompts to an LLM service."""
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        self.rate_limiter = rate_limiter or RateLimiter()
    
    @abstractmethod
    def send(self, prompt: str) -> Any:
        """Send a prompt to the LLM and return the response."""
        raise NotImplementedError
    
    def send_with_rate_limit(self, prompt: str) -> Any:
        """Send with rate limiting."""
        self.rate_limiter.check_and_wait()
        return self.send(prompt)
