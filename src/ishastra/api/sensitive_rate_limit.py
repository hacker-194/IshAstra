"""Dedicated rate limiting for sensitive endpoints.

Provides stricter, per-IP rate limits for authentication and key management
endpoints that are targets for brute-force and abuse.
"""

from __future__ import annotations

import logging

from fastapi import Request, status
from fastapi.responses import Response
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError
from starlette.middleware.base import BaseHTTPMiddleware

from ishastra.core.rate_limit import (
    KEY_CREATE_RATE_LIMIT,
    KEY_ROTATE_RATE_LIMIT,
    USER_CREATE_RATE_LIMIT,
    get_distributed_rate_limiter,
)

log = logging.getLogger(__name__)


SENSITIVE_PATHS = {
    "/api/keys/create": (KEY_CREATE_RATE_LIMIT, "key_create"),
    "/api/users": (USER_CREATE_RATE_LIMIT, "user_create"),
    "/api/keys/rotate": (KEY_ROTATE_RATE_LIMIT, "key_rotate"),
}


SENSITIVE_PREFIXES = {
    "/api/keys/revoke": KEY_ROTATE_RATE_LIMIT,
    "/api/users/": USER_CREATE_RATE_LIMIT,
}


EXEMPT_PATHS = {
    "/",
    "/api/health",
    "/api/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/static/",
}


class SensitiveRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that applies stricter per-IP rate limits to sensitive endpoints.

    Uses Redis-backed rate limiting for distributed deployments.
    Fails closed if Redis is unavailable when required.
    """

    def __init__(self, app) -> None:
        super().__init__(app)

    def _get_sensitive_limit(self, path: str) -> tuple[tuple[int, float], str] | None:
        """Get the rate limit config for a sensitive path."""

        if path in SENSITIVE_PATHS:
            return SENSITIVE_PATHS[path]

        for prefix, limit in SENSITIVE_PREFIXES.items():
            if path.startswith(prefix):
                return (limit, prefix.rstrip("/"))

        return None

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP for rate limiting (respects trusted proxies)."""
        peer = request.client.host if request.client else ""
        if not peer:
            return "unknown"

        return f"ip:{peer}"

    async def dispatch(self, request: Request, call_next):
        path = request.scope["path"]

        if any(path.startswith(p) for p in EXEMPT_PATHS):
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        sensitive_config = self._get_sensitive_limit(path)
        if not sensitive_config:
            return await call_next(request)

        (rate, per_seconds), limit_name = sensitive_config
        client_ip = self._get_client_ip(request)
        identifier = f"{limit_name}:{client_ip}"

        try:
            rate_limiter = await get_distributed_rate_limiter()
            allowed, limit, retry = await rate_limiter.bucket.allow(identifier, rate, per_seconds)
        except (TimeoutError, RedisConnectionError, RedisTimeoutError, RedisError) as exc:
            from ishastra.api.deps import get_settings

            settings = get_settings()
            if settings.redis_required or settings.workers > 1:
                log.error(
                    "Redis rate limiter unavailable for sensitive endpoint %s "
                    "(multi-worker/REDIS_REQUIRED): %s",
                    path,
                    exc,
                )
                return Response(
                    content='{"detail":"Rate limiting unavailable — try again shortly"}',
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    media_type="application/json",
                )

            log.warning(
                "Redis rate limiter unavailable for %s, allowing in degraded mode: %s",
                path,
                exc,
            )
            allowed, limit, retry = True, 0, 0
        except Exception as exc:
            from ishastra.api.deps import get_settings

            settings = get_settings()
            if settings.redis_required or settings.workers > 1:
                log.error(
                    "Unexpected error in sensitive rate limiter for %s (multi-worker/REDIS_REQUIRED): %s",
                    path,
                    exc,
                )
                return Response(
                    content='{"detail":"Rate limiting unavailable — try again shortly"}',
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    media_type="application/json",
                )
            log.exception(
                "Unexpected error in sensitive rate limiter for %s: %s",
                path,
                exc,
            )
            allowed, limit, retry = True, 0, 0

        if not allowed:
            from ishastra.metrics import record_rate_limit_exceeded

            record_rate_limit_exceeded(limit_name, "ip", "address")
            return Response(
                content='{"detail":"Rate limit exceeded for this endpoint"}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json",
                headers={
                    "Retry-After": str(retry),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        return response
