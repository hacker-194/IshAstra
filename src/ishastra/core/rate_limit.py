"""Distributed rate limiting with Redis-backed token bucket.

Provides atomic Redis token bucket using Lua scripts for multi-worker deployments.
Fails closed if Redis is unavailable when ISHASTRA_REDIS_REQUIRED=1 or workers > 1.
"""

from __future__ import annotations

import logging
import time

import redis.asyncio as redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

log = logging.getLogger(__name__)


TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local per = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local refill_per_sec = rate / per

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    tokens = rate
    last_refill = now
else
    local elapsed = now - last_refill
    tokens = math.min(rate, tokens + elapsed * refill_per_sec)
    last_refill = now
end

local allowed = 0
local retry_after = 0
if tokens >= 1 then
    tokens = tokens - 1
    allowed = 1
else
    retry_after = math.ceil((1 - tokens) / refill_per_sec)
end

redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
redis.call('EXPIRE', key, math.ceil(per * 2))
return {allowed, rate, retry_after}
"""


class RedisTokenBucket:
    """Redis-backed token bucket rate limiter for multi-worker deployments.

    Uses Lua scripts for atomic operations to ensure consistency across workers.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        *,
        key_prefix: str = "ratelimit",
    ) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._token_bucket_sha: str | None = None

    def _script(self) -> str:
        """The loaded token-bucket SHA, or a clear failure when Redis refused it."""
        if self._token_bucket_sha is None:
            raise RuntimeError("redis token bucket script is not loaded")
        return self._token_bucket_sha

    async def _ensure_scripts_loaded(self) -> None:
        """Load the Lua script into Redis if not already loaded."""
        if self._token_bucket_sha is None:
            self._token_bucket_sha = await self.redis.script_load(TOKEN_BUCKET_LUA)

    def _bucket_key(self, identifier: str) -> str:
        """Generate the Redis key for a bucket."""
        return f"{self.key_prefix}:{identifier}"

    async def allow(
        self,
        identifier: str,
        rate: int,
        per_seconds: float,
    ) -> tuple[bool, int, int]:
        """
        Consume one request from the token bucket.

        Args:
            identifier: Unique identifier for this bucket (e.g., "tenant:123", "address:1.2.3.4")
            rate: Maximum requests allowed per window
            per_seconds: Time window in seconds

        Returns:
            Tuple of (allowed, limit, retry_after_seconds)
        """
        await self._ensure_scripts_loaded()
        now = time.monotonic()
        bucket_key = self._bucket_key(identifier)

        try:
            result = await self.redis.evalsha(
                self._script(),
                1,
                bucket_key,
                str(rate),
                str(per_seconds),
                str(now),
            )  # type: ignore[misc]
            allowed = bool(result[0])
            limit = int(result[1])
            retry_after = int(result[2])
            return allowed, limit, retry_after
        except (RedisConnectionError, RedisTimeoutError, RedisError) as e:
            log.warning("Redis rate limiter error: %s", e)
            raise
        except Exception as e:
            if "NOSCRIPT" in str(e):
                self._token_bucket_sha = None
                await self._ensure_scripts_loaded()
                try:
                    result = await self.redis.evalsha(
                        self._script(),
                        1,
                        bucket_key,
                        str(rate),
                        str(per_seconds),
                        str(now),
                    )  # type: ignore[misc]
                    allowed = bool(result[0])
                    limit = int(result[1])
                    retry_after = int(result[2])
                    return allowed, limit, retry_after
                except Exception:
                    raise
            raise


TIER_RATE_LIMITS = {
    "free": (5, 60.0),
    "pro": (60, 60.0),
    "enterprise": (300, 60.0),
    "standard": (5, 60.0),
    "elevated": (60, 60.0),
    "unlimited": (300, 60.0),
}
ASSESS_RATE_LIMITS = {
    "free": (5, 60.0),
    "pro": (20, 60.0),
    "enterprise": (60, 60.0),
    "standard": (5, 60.0),
    "elevated": (20, 60.0),
    "unlimited": (60, 60.0),
}
AUTH_RATE_LIMIT = (10, 60.0)
ANONYMOUS_RATE_LIMIT = (120, 60.0)


KEY_CREATE_RATE_LIMIT = (5, 300.0)
KEY_ROTATE_RATE_LIMIT = (3, 300.0)
USER_CREATE_RATE_LIMIT = (10, 300.0)


class DistributedRateLimiter:
    """High-level distributed rate limiter with tiered limits."""

    def __init__(self, redis_client: redis.Redis) -> None:
        self.bucket = RedisTokenBucket(redis_client)

    def _limit_for(self, route_class: str, tier: str) -> tuple[int, float]:
        if tier == "anon":
            return ANONYMOUS_RATE_LIMIT
        if route_class == "auth":
            return AUTH_RATE_LIMIT
        if route_class == "assessment":
            return ASSESS_RATE_LIMITS.get(tier, ASSESS_RATE_LIMITS["standard"])
        return TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["standard"])

    async def allow(
        self,
        route_class: str,
        identity: str,
        tier: str,
    ) -> tuple[bool, int, int]:
        """Check if request is allowed under rate limit."""
        rate, per = self._limit_for(route_class, tier)
        return await self.bucket.allow(f"{route_class}:{identity}", rate, per)


_rate_limiter: DistributedRateLimiter | None = None


async def get_distributed_rate_limiter() -> DistributedRateLimiter:
    """Dependency: Get or create the distributed rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        from ishastra.api.deps import get_redis

        redis_client = await get_redis()
        _rate_limiter = DistributedRateLimiter(redis_client)
    return _rate_limiter
