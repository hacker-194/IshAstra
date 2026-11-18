"""FastAPI dependencies: shared HTTP client, Redis, and lazy global services.

Module-level singletons are lazy-initialized to allow test overrides.
Access via get_settings(), get_audit_log(), get_audit_chain(), get_monitor().

Database connections live in ``strix.core.store`` (one pool, used by every
router); this module deliberately does not keep a second one.
"""

from __future__ import annotations

import logging
import os

import httpx
import redis.asyncio as redis

from strix import __version__
from strix.audit import AuditChain, AuditLog
from strix.config import Settings
from strix.config import get_settings as config_settings
from strix.config import reset_settings as config_reset_settings
from strix.monitor import Monitor

_audit_log: AuditLog | None = None
_audit_chain: AuditChain | None = None
_monitor: Monitor | None = None


def get_settings() -> Settings:
    """The process settings.

    Delegates to ``strix.config`` so the API, the CLI and the core modules share
    one object instead of each reading the environment for itself.
    """
    return config_settings()


def reset_settings() -> None:
    """Reset the cached settings (for test isolation)."""
    config_reset_settings()


def get_audit_log() -> AuditLog:
    """Lazy-initialized audit log."""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog(max_entries=get_settings().audit_max_entries, persistent=True)
    return _audit_log


def get_audit_chain() -> AuditChain:
    """Lazy-initialized audit chain."""
    global _audit_chain
    if _audit_chain is None:
        _audit_chain = AuditChain(persistent=True, hmac_key=get_settings().audit_hmac_key)
    return _audit_chain


def get_monitor() -> Monitor:
    """Lazy-initialized monitor."""
    global _monitor
    if _monitor is None:
        _monitor = Monitor(
            audit_chain=get_audit_chain(),
            scope_mode=get_settings().scope_mode,
            webhook_secret=get_settings().webhook_secret,
            encryption_key=get_settings().encryption_key,
        )
    return _monitor


# Module-level __getattr__ for lazy attribute access.
def __getattr__(name: str):
    if name == "settings":
        return get_settings()
    if name == "audit_log":
        return get_audit_log()
    if name == "audit_chain":
        return get_audit_chain()
    if name == "monitor":
        return get_monitor()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Global async resources (initialized on startup)
_http_client: httpx.AsyncClient | None = None
_redis_client: redis.Redis | None = None


async def init_http_client() -> httpx.AsyncClient:
    """Initialize the shared async HTTP client with connection pooling."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
            headers={"User-Agent": f"strix/{__version__} (+authorized-testing)"},
        )
    return _http_client


async def close_http_client() -> None:
    """Close the shared HTTP client on shutdown."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


async def get_http_client() -> httpx.AsyncClient:
    """Dependency: shared async HTTP client with connection pooling."""
    if _http_client is None:
        await init_http_client()
    assert _http_client is not None
    return _http_client


async def init_redis() -> redis.Redis:
    """Initialize the Redis client for rate limiting and caching."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        # Fail fast if Redis is required but no URL is explicitly configured
        if settings.redis_required and not os.environ.get("STRIX_REDIS_URL"):
            raise RuntimeError(
                "STRIX_REDIS_REQUIRED=1 but STRIX_REDIS_URL not set; "
                "refusing to start with implicit localhost fallback"
            )
        _redis_client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        # Test connection and log warning if unavailable
        try:
            await _redis_client.ping()
        except (redis.ConnectionError, redis.TimeoutError, redis.RedisError) as e:
            logging.getLogger(__name__).warning(
                "Redis unavailable at startup (%s): %s",
                type(e).__name__,
                e,
            )
            if settings.redis_required:
                raise RuntimeError("Redis required but unreachable") from e
    return _redis_client


async def close_redis() -> None:
    """Close the Redis client on shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


async def get_redis() -> redis.Redis:
    """Dependency: Redis client for rate limiting and caching."""
    if _redis_client is None:
        await init_redis()
    assert _redis_client is not None
    return _redis_client


# The authorization dependencies live in `strix.api.deps`. They are deliberately
# not re-exported here: this module used to set them to None "for backward
# compatibility", so `from strix.api.dependencies import require_admin` handed
# callers None, which FastAPI silently accepted as a dependency that always
# allowed the request.
