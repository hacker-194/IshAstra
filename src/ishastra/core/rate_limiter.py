"""Per-job token bucket rate limiter for Rules of Engagement enforcement.

Provides an in-memory token bucket implementation that can be shared across
adapters within a single job to enforce the engagement's rate_limit_rps.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    limit: int
    remaining: int
    retry_after: float


class TokenBucket:
    """Thread-safe token bucket rate limiter for a single job."""

    def __init__(self, rate_limit_rps: float) -> None:
        """Initialize token bucket with the given rate limit in requests per second.

        Args:
            rate_limit_rps: Maximum requests per second (0 = unlimited)
        """
        self.rate_limit_rps = rate_limit_rps
        self._capacity = max(1, int(rate_limit_rps)) if rate_limit_rps > 0 else 0
        self._tokens = float(self._capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        if self.rate_limit_rps <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self.rate_limit_rps)
        self._last_refill = now

    def try_consume(self, tokens: int = 1) -> RateLimitResult:
        """Try to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume (default: 1)

        Returns:
            RateLimitResult with allowed status and retry information
        """
        if self.rate_limit_rps <= 0:
            return RateLimitResult(
                allowed=True,
                limit=0,
                remaining=0,
                retry_after=0.0,
            )

        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return RateLimitResult(
                    allowed=True,
                    limit=self._capacity,
                    remaining=int(self._tokens),
                    retry_after=0.0,
                )
            # Calculate retry time
            needed = tokens - self._tokens
            retry_after = needed / self.rate_limit_rps
            return RateLimitResult(
                allowed=False,
                limit=self._capacity,
                remaining=int(self._tokens),
                retry_after=retry_after,
            )

    def consume(self, tokens: int = 1) -> float:
        """Consume tokens, blocking until available.

        Args:
            tokens: Number of tokens to consume (default: 1)

        Returns:
            Time waited in seconds
        """
        if self.rate_limit_rps <= 0:
            return 0.0

        waited = 0.0
        while True:
            result = self.try_consume(tokens)
            if result.allowed:
                return waited
            time.sleep(result.retry_after)
            waited += result.retry_after

    def reset(self) -> None:
        """Reset the bucket to full capacity."""
        with self._lock:
            self._tokens = float(self._capacity)
            self._last_refill = time.monotonic()


class JobRateLimiter:
    """Rate limiter for a job that can be shared across adapters.

    This wraps a TokenBucket and provides a simple interface for adapters
    to respect the engagement's rate limit.
    """

    def __init__(self, rate_limit_rps: float) -> None:
        self._bucket = TokenBucket(rate_limit_rps)
        self._enabled = rate_limit_rps > 0

    def pace(self) -> None:
        """Block until a request can be made."""
        if not self._enabled:
            return
        self._bucket.consume(1)

    def try_pace(self) -> RateLimitResult:
        """Try to pace without blocking.

        Returns:
            RateLimitResult indicating if request is allowed and retry time
        """
        if not self._enabled:
            return RateLimitResult(
                allowed=True,
                limit=0,
                remaining=0,
                retry_after=0.0,
            )
        return self._bucket.try_consume(1)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def rate_limit_rps(self) -> float:
        return self._bucket.rate_limit_rps