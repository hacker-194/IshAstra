from __future__ import annotations

import asyncio
import contextvars
import logging
from collections.abc import AsyncGenerator
from typing import Any

import aiosqlite
import httpx
import redis.asyncio as redis

from strix.audit import AuditChain, AuditLog
from strix.config import Settings
from strix.monitor import Monitor

"""FastAPI dependencies: async database, HTTP client, Redis, and shared services."""

settings = Settings.from_env()
audit_log = AuditLog(max_entries=settings.audit_max_entries, persistent=True)
audit_chain = AuditChain(persistent=True, hmac_key=settings.audit_hmac_key)
monitor = Monitor(audit_chain=audit_chain, scope_mode=settings.scope_mode,
                  webhook_secret=settings.webhook_secret)

Tenant = dict[str, Any]


# Global async resources (initialized on startup)
_http_client: httpx.AsyncClient | None = None
_redis_client: redis.Redis | None = None
# Database pool per event loop (ContextVar propagates across async boundaries)
_db_pool: contextvars.ContextVar[asyncio.Queue | None] = contextvars.ContextVar("_db_pool", default=None)
_db_pool_size = 10  # Max connections in pool


async def init_http_client() -> httpx.AsyncClient:
    """Initialize the shared async HTTP client with connection pooling."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
            headers={"User-Agent": "strix/3.6.0 (+authorized-testing)"},
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
        _redis_client = redis.from_url(
            settings.redis_url if hasattr(settings, 'redis_url') else "redis://localhost:6379/0",
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def close_redis() -> None:
    """Close the Redis client on shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


def _get_db_pool() -> asyncio.Queue:
    """Get or create the database pool for the current event loop."""
    pool = _db_pool.get()
    if pool is not None:
        return pool
    # Create new pool for this event loop
    pool = asyncio.Queue(maxsize=_db_pool_size)
    _db_pool.set(pool)
    return pool


def _cleanup_pool_sync(pool: asyncio.Queue) -> None:
    """Close all connections in a pool synchronously.

    Note: This is a fallback for edge cases (e.g., test cleanup). Normal
    cleanup should use the async close_db_pool() which properly awaits.
    """
    import contextlib
    while not pool.empty():
        try:
            db = pool.get_nowait()
            # Close the underlying sqlite3 connection synchronously
            # aiosqlite.Connection doesn't expose a public sync close,
            # but we can close the underlying connection if available.
            if hasattr(db, '_conn') and db._conn is not None:
                with contextlib.suppress(Exception):
                    db._conn.close()
        except Exception:
            pass


async def _create_pool_connections(pool: asyncio.Queue) -> None:
    """Create and populate pool connections."""
    from strix.core.store_async import _restrict_permissions, current_path, migrate_async
    db_path = current_path() or settings.db_path
    # Create first connection and run migrations
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA busy_timeout = 10000")
    await db.execute("PRAGMA foreign_keys = ON")
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA synchronous = NORMAL")
    # Run migrations on first connection
    await migrate_async(db)
    # Restrict database file permissions to owner only (0o600)
    _restrict_permissions(db_path)
    await pool.put(db)
    # Pre-populate the rest of the pool
    for _ in range(_db_pool_size - 1):
        db = await aiosqlite.connect(db_path)
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA busy_timeout = 10000")
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute("PRAGMA journal_mode = WAL")
        await db.execute("PRAGMA synchronous = NORMAL")
        await pool.put(db)


async def init_db_pool() -> asyncio.Queue:
    """Initialize the SQLite connection pool for the current event loop."""
    pool = _get_db_pool()
    if pool.empty():
        # Pool exists but is empty (just created or cleared), populate it
        await _create_pool_connections(pool)
    return pool


async def close_db_pool() -> None:
    """Close all connections in the SQLite pool for the current event loop."""
    pool = _db_pool.get()
    if pool is not None:
        while not pool.empty():
            db = await pool.get()
            await db.close()
        _db_pool.set(None)


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Dependency: async SQLite database connection from pool."""
    pool = await init_db_pool()
    db = await pool.get()
    try:
        yield db
    finally:
        await pool.put(db)


async def get_db_pool() -> asyncio.Queue:
    """Get the SQLite connection pool (for direct use by store_async)."""
    return await init_db_pool()


def cleanup_db_pool_for_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Clean up the database pool for a specific event loop.

    With ContextVar-based storage, pools are isolated per event loop
    automatically. This function is kept for compatibility but is a no-op.
    """
    # ContextVar automatically isolates per event loop; nothing to do.


def reset_db_pool() -> None:
    """Reset the database pool for the current event loop (for test isolation when db path changes)."""
    pool = _db_pool.get()
    if pool is not None:
        # Schedule cleanup in the current event loop
        try:
            current_loop = asyncio.get_running_loop()
            async def _cleanup():
                while not pool.empty():
                    db = await pool.get()
                    await db.close()
            current_loop.call_soon_threadsafe(asyncio.create_task, _cleanup())
        except RuntimeError:
            # No running loop - just clear the reference
            pass
    _db_pool.set(None)


async def get_redis() -> redis.Redis:
    """Dependency: Redis client for rate limiting and caching."""
    if _redis_client is None:
        await init_redis()
    assert _redis_client is not None
    return _redis_client




# Rate limiter using Redis
class RedisRateLimiter:
    """Redis-backed token bucket rate limiter for multi-worker deployments."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)

    async def allow(self, key: str, rate: int, per_seconds: float) -> tuple[bool, int, int]:
        """
        Consume one request from the token bucket.
        Returns (allowed, limit, retry_after_seconds).
        """
        now = asyncio.get_event_loop().time()
        bucket_key = f"ratelimit:{key}"

        # Lua script for atomic token bucket operation
        lua_script = """
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

        try:
            result = await self.redis.eval(  # type: ignore[misc]
                lua_script, 1, bucket_key,
                str(rate), str(per_seconds), str(now)
            )
            allowed = bool(result[0])
            limit = int(result[1])
            retry_after = int(result[2])
            return allowed, limit, retry_after
        except redis.RedisError as e:
            self.logger.warning("Redis rate limiter error, propagating to fallback: %s", e)
            # Propagate to allow middleware fallback to in-memory limiter
            raise

    async def reset(self, key: str) -> None:
        """Reset a specific rate limit bucket."""
        await self.redis.delete(f"ratelimit:{key}")


async def get_rate_limiter() -> RedisRateLimiter:
    """Dependency: Redis-backed rate limiter."""
    redis_client = await get_redis()
    return RedisRateLimiter(redis_client)


# Backward-compatible exports for existing code (set by security module at runtime)
require_auth = None
tenant_scope = None
audit = None
deny = None
require_admin = None
owns = None
tenant_filter = None
check_target_or_raise = None
check_scope_or_raise = None
managed_mode = None
SEALED_EVENTS: frozenset[str] = frozenset()
