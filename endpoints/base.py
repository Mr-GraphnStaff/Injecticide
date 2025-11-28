"""Base endpoint interface for LLM services."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
import time

import requests


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

    def compute_retry_delay(
        self,
        retry_after: Optional[str],
        attempt: int,
        *,
        backoff_factor: float = 1.0,
    ) -> float:
        """Determine how long to wait before retrying after a 429."""

        if retry_after:
            try:
                retry_seconds = float(retry_after)
                if retry_seconds >= 0:
                    return retry_seconds
            except ValueError:
                pass

        return max(backoff_factor * (attempt + 1), 0)


class Endpoint(ABC):
    """Interface for sending prompts to an LLM service."""

    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_retries = 3
        self.backoff_factor = 1.0
    
    @abstractmethod
    def send(self, prompt: str) -> Any:
        """Send a prompt to the LLM and return the response."""
        raise NotImplementedError

    def send_with_rate_limit(self, prompt: str) -> Any:
        """Send with rate limiting."""
        return self.send(prompt)

    def _handle_rate_limit(self, response: requests.Response, attempt: int) -> None:
        """Wait an appropriate interval when we hit a 429."""

        wait_time = self.rate_limiter.compute_retry_delay(
            response.headers.get("Retry-After"),
            attempt,
            backoff_factor=self.backoff_factor,
        )
        if wait_time > 0:
            print(
                f"Rate limited (status 429). Waiting {wait_time:.1f}s before retrying"
            )
            time.sleep(wait_time)

    def _send_request(self, request_fn: Callable[[], requests.Response]) -> requests.Response:
        """Perform an HTTP request with basic rate-limit handling."""

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            self.rate_limiter.check_and_wait()

            try:
                response = request_fn()
            except requests.RequestException as exc:  # network-level issues
                last_error = exc
                break

            if response.status_code == 429:
                if attempt >= self.max_retries - 1:
                    response.raise_for_status()

                self._handle_rate_limit(response, attempt)
                continue

            try:
                response.raise_for_status()
                return response
            except requests.HTTPError as exc:
                last_error = exc
                break

        if last_error:
            raise last_error

        raise RuntimeError("Request failed without raising an exception")
