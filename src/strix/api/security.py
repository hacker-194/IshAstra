"""Security layer for Strix SOC Command Center.
Provides API-key authentication, per-tenant rate limiting, and security-header middleware.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security.utils import get_authorization_scheme_param
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from strix.config import Settings
from strix.core import store
from strix.core.rate_limit import (
    ANONYMOUS_RATE_LIMIT,
    ASSESS_RATE_LIMITS,
    AUTH_RATE_LIMIT,
    TIER_RATE_LIMITS,
    get_distributed_rate_limiter,
)
from strix.metrics import record_rate_limit_check, record_rate_limit_exceeded

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory Rate Limiter (for single-worker test mode only)
# ---------------------------------------------------------------------------
class _TokenBucket:
    """Per-key token bucket for test mode only."""

    def __init__(
        self,
        rate: int,
        per_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50_000,
    ) -> None:
        self.rate = rate
        self.per = per_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._refill_per_second = rate / per_seconds
        self.tokens: dict[str, float] = {}
        self.timestamps: dict[str, float] = {}
        self.last_access: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        idle_threshold = self.per * 2
        for key in [
            k for k, seen in self.last_access.items() if now - seen >= idle_threshold
        ]:
            self.tokens.pop(key, None)
            self.timestamps.pop(key, None)
            self.last_access.pop(key, None)
        excess = len(self.tokens) - (self.max_keys - 1)
        if excess > 0:
            for key in sorted(self.last_access, key=self.last_access.__getitem__)[:excess]:
                self.tokens.pop(key, None)
                self.timestamps.pop(key, None)
                self.last_access.pop(key, None)

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens = self.tokens.get(key)
        if tokens is None:
            if len(self.tokens) >= self.max_keys:
                self._prune(now)
            tokens = float(self.rate)
        else:
            tokens = min(
                float(self.rate),
                tokens + (now - self.timestamps[key]) * self._refill_per_second,
            )
        self.timestamps[key] = now
        self.last_access[key] = now
        allowed = tokens >= 1.0
        self.tokens[key] = tokens - 1.0 if allowed else tokens
        return allowed

    def retry_after(self, key: str) -> int:
        tokens = self.tokens.get(key, 0.0)
        return max(1, math.ceil((1.0 - tokens) / self._refill_per_second))


class _RateLimiter:
    """In-memory rate limiter for test mode (STRIX_TEST_MODE=1, single worker)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[tuple[str, str], _TokenBucket] = {}

    @staticmethod
    def _limit_for(route_cls: str, tier: str) -> tuple[int, float]:
        if tier == "anon":
            return ANONYMOUS_RATE_LIMIT
        if route_cls == "auth":
            return AUTH_RATE_LIMIT
        if route_cls == "assessment":
            return ASSESS_RATE_LIMITS.get(tier, ASSESS_RATE_LIMITS["free"])
        return TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])

    def allow(self, route_cls: str, identity: str, tier: str) -> tuple[bool, int, int]:
        rate, per = self._limit_for(route_cls, tier)
        bucket = self._buckets.get((route_cls, tier))
        if bucket is None:
            bucket = self._buckets[(route_cls, tier)] = _TokenBucket(rate, per, self._clock)
        if bucket.allow(identity):
            return True, rate, 0
        return False, rate, bucket.retry_after(identity)

    def reset(self) -> None:
        self._buckets.clear()


# Test-mode rate limiter instance (only used when STRIX_TEST_MODE=1)
_test_rate_limiter = _RateLimiter()


# Backward-compatible export for tests
rate_limiter = _test_rate_limiter

# ---------------------------------------------------------------------------
# API Key Authentication
# ---------------------------------------------------------------------------
class APIKeyStore:
    """Thread-safe API key registry with durable, single-key-per-tenant state.

    Only SHA-256 hashes are held or stored (keys are high-entropy random
    values, so a fast hash is appropriate). State changes are persisted before
    becoming visible in memory, so a storage error cannot silently grant or
    revoke credentials only in one of the two stores.
    """

    def __init__(self, *, persistent: bool = False) -> None:
        self._persistent = persistent
        self._keys: dict[str, dict[str, Any]] = {}
        self._hash_to_tenant: dict[str, str] = {}
        self._lock = threading.RLock()

    def reset(self) -> None:
        """Clear all in-memory keys (for test isolation)."""
        with self._lock:
            self._keys.clear()
            self._hash_to_tenant.clear()

    @staticmethod
    def _records_from_rows(
        rows: list[dict[str, Any]],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        records: dict[str, dict[str, Any]] = {}
        hashes: dict[str, str] = {}
        for row in rows:
            record = {
                "key_hash": row["key_hash"],
                "tier": row["tier"],
                "admin": bool(row["admin"]),
                "active": bool(row["active"]),
                "created_at": row["created_at"],
                "last_used": row["last_used"],
                "expires_at": row["expires_at"],
                "rotated_at": row["rotated_at"],
            }
            tenant_id = row["tenant_id"]
            records[tenant_id] = record
            if record["active"]:
                owner = hashes.get(record["key_hash"])
                if owner is not None and owner != tenant_id:
                    raise RuntimeError(
                        "database contains an API key hash assigned to multiple tenants"
                    )
                hashes[record["key_hash"]] = tenant_id
        return records, hashes

    # -- persistence -------------------------------------------------------
    def load(self) -> int:
        """Replace the in-memory registry with what the database holds (sync version)."""
        with self._lock:

            rows = (
                store._run_async(store.load_api_keys())
                if self._persistent
                else []
            )
            self._keys, self._hash_to_tenant = self._records_from_rows(rows)
            return len(self._keys)

    async def load_async(self) -> int:
        """Async version of load (for async callers)."""
        if not self._persistent:
            return 0
        rows = await store.load_api_keys()
        with self._lock:
            self._keys, self._hash_to_tenant = self._records_from_rows(rows)
            return len(self._keys)

    def _persist_record(self, tenant_id: str, record: dict[str, Any]) -> None:
        if not self._persistent:
            return

        store._run_async(
            store.save_api_key(
                tenant_id=tenant_id,
                key_hash=record["key_hash"],
                tier=record["tier"],
                admin=record["admin"],
                active=record["active"],
                created_at=record["created_at"],
                expires_at=record.get("expires_at"),
                last_used=record.get("last_used"),
                rotated_at=record.get("rotated_at"),
                ai_enabled=record.get("ai_enabled", False),
            )
        )

    async def _persist_record_async(
        self, tenant_id: str, record: dict[str, Any]
    ) -> None:
        if not self._persistent:
            return
        await store.save_api_key(
            tenant_id=tenant_id,
            key_hash=record["key_hash"],
            tier=record["tier"],
            admin=record["admin"],
            active=record["active"],
            created_at=record["created_at"],
            expires_at=record.get("expires_at"),
            last_used=record.get("last_used"),
            rotated_at=record.get("rotated_at"),
            ai_enabled=record.get("ai_enabled", False),
        )

    def _persist(self, tenant_id: str) -> None:
        record = self._keys[tenant_id]
        self._persist_record(tenant_id, record)

    async def _persist_async(self, tenant_id: str) -> None:
        record = self._keys[tenant_id]
        await self._persist_record_async(tenant_id, record)

    def _install(
        self,
        tenant_id: str,
        raw_key: str,
        tier: str,
        admin: bool,
        *,
        expires_at: float | None = None,
    ) -> None:
        """Make ``raw_key`` the tenant's one valid key, retiring any previous one."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        existing_owner = self._hash_to_tenant.get(key_hash)
        if existing_owner is not None and existing_owner != tenant_id:
            raise ValueError("API key is already assigned to another tenant")
        previous = self._keys.get(tenant_id)
        now = time.time()
        record = {
            "key_hash": key_hash,
            "tier": tier,
            "admin": admin,
            "active": True,
            "created_at": now,
            "last_used": None,
            "expires_at": expires_at,
            "rotated_at": now if previous else None,
            "ai_enabled": False,
        }
        # Persist the replacement first. If SQLite fails, the old in-memory key
        # remains authoritative and usable instead of creating split-brain state.
        self._persist_record(tenant_id, record)
        self._keys[tenant_id] = record
        if previous:
            self._hash_to_tenant.pop(previous["key_hash"], None)
        self._hash_to_tenant[key_hash] = tenant_id

    async def _install_async(
        self,
        tenant_id: str,
        raw_key: str,
        tier: str,
        admin: bool,
        *,
        expires_at: float | None = None,
    ) -> None:
        """Async version of _install."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        existing_owner = self._hash_to_tenant.get(key_hash)
        if existing_owner is not None and existing_owner != tenant_id:
            raise ValueError("API key is already assigned to another tenant")
        previous = self._keys.get(tenant_id)
        now = time.time()
        record = {
            "key_hash": key_hash,
            "tier": tier,
            "admin": admin,
            "active": True,
            "created_at": now,
            "last_used": None,
            "expires_at": expires_at,
            "rotated_at": now if previous else None,
            "ai_enabled": False,
        }
        await self._persist_record_async(tenant_id, record)
        self._keys[tenant_id] = record
        if previous:
            self._hash_to_tenant.pop(previous["key_hash"], None)
        self._hash_to_tenant[key_hash] = tenant_id

    # -- lifecycle ---------------------------------------------------------
    def register(
        self,
        tenant_id: str,
        tier: str = "free",
        *,
        admin: bool = False,
        ttl_days: int | None = None,
    ) -> str:
        """Issue a new key for a tenant (shown once). A positive TTL expires it."""
        if ttl_days is not None and (
            isinstance(ttl_days, bool) or ttl_days < 1 or ttl_days > 3650
        ):
            raise ValueError("ttl_days must be between 1 and 3650")
        raw_key = f"strix_{secrets.token_urlsafe(32)}"
        expires_at = time.time() + ttl_days * 86400.0 if ttl_days is not None else None
        with self._lock:
            self._install(tenant_id, raw_key, tier, admin, expires_at=expires_at)
        return raw_key

    async def register_async(
        self,
        tenant_id: str,
        tier: str = "free",
        *,
        admin: bool = False,
        ttl_days: int | None = None,
    ) -> str:
        """Async version of register."""
        if ttl_days is not None and (
            isinstance(ttl_days, bool) or ttl_days < 1 or ttl_days > 3650
        ):
            raise ValueError("ttl_days must be between 1 and 3650")
        raw_key = f"strix_{secrets.token_urlsafe(32)}"
        expires_at = time.time() + ttl_days * 86400.0 if ttl_days is not None else None
        with self._lock:
            await self._install_async(
                tenant_id, raw_key, tier, admin, expires_at=expires_at
            )
        return raw_key

    def rotate(self, tenant_id: str, *, ttl_days: int | None = None) -> str | None:
        """Rotate an active key, preserving its absolute expiry unless a TTL is supplied.

        Unknown, revoked, or expired keys cannot be revived by the rotate
        endpoint; use an explicit key-create operation for deliberate reissue.
        """
        if ttl_days is not None and (
            isinstance(ttl_days, bool) or ttl_days < 1 or ttl_days > 3650
        ):
            raise ValueError("ttl_days must be between 1 and 3650")
        with self._lock:
            record = self._keys.get(tenant_id)
            if record is None or not record["active"]:
                return None
            now = time.time()
            expires_at = record.get("expires_at")
            if expires_at is not None and now >= float(expires_at):
                return None
            new_expiry = (
                (now + ttl_days * 86400.0) if ttl_days is not None else expires_at
            )
            raw_key = f"strix_{secrets.token_urlsafe(32)}"
            self._install(
                tenant_id,
                raw_key,
                record["tier"],
                bool(record["admin"]),
                expires_at=new_expiry,
            )
            return raw_key

    async def rotate_async(
        self, tenant_id: str, *, ttl_days: int | None = None
    ) -> str | None:
        """Async version of rotate."""
        if ttl_days is not None and (
            isinstance(ttl_days, bool) or ttl_days < 1 or ttl_days > 3650
        ):
            raise ValueError("ttl_days must be between 1 and 3650")
        with self._lock:
            record = self._keys.get(tenant_id)
            if record is None or not record["active"]:
                return None
            now = time.time()
            expires_at = record.get("expires_at")
            if expires_at is not None and now >= float(expires_at):
                return None
            new_expiry = (
                (now + ttl_days * 86400.0) if ttl_days is not None else expires_at
            )
            raw_key = f"strix_{secrets.token_urlsafe(32)}"
            await self._install_async(
                tenant_id,
                raw_key,
                record["tier"],
                bool(record["admin"]),
                expires_at=new_expiry,
            )
            return raw_key

    def adopt(
        self, tenant_id: str, tier: str, raw_key: str, *, admin: bool = True
    ) -> None:
        """Register an operator-supplied key verbatim (STRIX_API_KEY cold start)."""
        if len(raw_key) < 16:
            raise ValueError("STRIX_API_KEY must be at least 16 characters")
        with self._lock:
            self._install(tenant_id, raw_key, tier, admin, expires_at=None)

    async def adopt_async(
        self, tenant_id: str, tier: str, raw_key: str, *, admin: bool = True
    ) -> None:
        """Async version of adopt."""
        if len(raw_key) < 16:
            raise ValueError("STRIX_API_KEY must be at least 16 characters")
        with self._lock:
            await self._install_async(tenant_id, raw_key, tier, admin, expires_at=None)

    def revoke(self, tenant_id: str) -> bool:
        with self._lock:
            record = self._keys.get(tenant_id)
            if not record or not record["active"]:
                return False
            revoked = dict(record)
            revoked["active"] = False
            self._persist_record(tenant_id, revoked)
            self._keys[tenant_id] = revoked
            self._hash_to_tenant.pop(record["key_hash"], None)
            return True

    async def revoke_async(self, tenant_id: str) -> bool:
        with self._lock:
            record = self._keys.get(tenant_id)
            if not record or not record["active"]:
                return False
            revoked = dict(record)
            revoked["active"] = False
            await self._persist_record_async(tenant_id, revoked)
            self._keys[tenant_id] = revoked
            self._hash_to_tenant.pop(record["key_hash"], None)
            return True

    # -- queries -----------------------------------------------------------
    def validate(self, api_key: str | None) -> dict[str, Any] | None:
        if not api_key:
            return None
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        with self._lock:
            owner = self._hash_to_tenant.get(digest)
            record = self._keys.get(owner) if owner is not None else None
            if (
                owner is None
                or not record
                or not record["active"]
                or not secrets.compare_digest(digest, record["key_hash"])
            ):
                return None
            tenant_id: str = owner
            expires_at = record.get("expires_at")
            if expires_at is not None and time.time() >= float(expires_at):
                revoked = dict(record)
                revoked["active"] = False
                # Persist FIRST, then update in-memory state.
                # If persistence fails, exception propagates and in-memory state is unchanged.
                self._persist_record(tenant_id, revoked)
                self._keys[tenant_id] = revoked
                self._hash_to_tenant.pop(record["key_hash"], None)
                return None
            record["last_used"] = time.time()
            return {
                "tenant_id": tenant_id,
                "tier": record["tier"],
                "admin": bool(record["admin"]),
                "record": dict(record),
            }

    async def validate_async(self, api_key: str | None) -> dict[str, Any] | None:
        """Async version of validate."""
        if not api_key:
            return None
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        with self._lock:
            owner = self._hash_to_tenant.get(digest)
            record = self._keys.get(owner) if owner is not None else None
            if (
                owner is None
                or not record
                or not record["active"]
                or not secrets.compare_digest(digest, record["key_hash"])
            ):
                return None
            tenant_id: str = owner
            expires_at = record.get("expires_at")
            if expires_at is not None and time.time() >= float(expires_at):
                revoked = dict(record)
                revoked["active"] = False
                # Persist FIRST, then update in-memory state.
                # If persistence fails, exception propagates and in-memory state is unchanged.
                await self._persist_record_async(tenant_id, revoked)
                self._keys[tenant_id] = revoked
                self._hash_to_tenant.pop(record["key_hash"], None)
                return None
            record["last_used"] = time.time()
            return {
                "tenant_id": tenant_id,
                "tier": record["tier"],
                "admin": bool(record["admin"]),
                "record": dict(record),
            }

    def tenants(self) -> list[dict[str, Any]]:
        """Every tenant that holds a key."""
        with self._lock:
            return [
                {
                    "tenant_id": tenant_id,
                    "tier": record["tier"],
                    "admin": bool(record["admin"]),
                    "active": bool(record["active"]),
                }
                for tenant_id, record in self._keys.items()
            ]

    def is_admin(self, tenant_id: str) -> bool:
        with self._lock:
            record = self._keys.get(tenant_id)
            return bool(record and record["admin"])

    def status(self, tenant_id: str) -> dict[str, Any] | None:
        """Non-secret key state for the owner (or an administrator)."""
        with self._lock:
            record = self._keys.get(tenant_id)
            if not record:
                return None
            expires_at = record.get("expires_at")
            remaining = None
            if expires_at is not None:
                remaining = max(0.0, float(expires_at) - time.time())
            return {
                "tenant_id": tenant_id,
                "tier": record["tier"],
                "active": bool(record["active"]),
                "admin": bool(record["admin"]),
                "ai_enabled": bool(record.get("ai_enabled", False)),
                "created_at": record["created_at"],
                "expires_at": expires_at,
                "days_remaining": (
                    round(remaining / 86400.0, 2) if remaining is not None else None
                ),
                "last_used": record.get("last_used"),
                "rotated_at": record.get("rotated_at"),
            }


api_keys = APIKeyStore(persistent=True)

security = HTTPBearer(auto_error=False)


async def get_current_tenant(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """Dependency: resolve and validate the caller's API key."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer <api-key>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    tenant = await api_keys.validate_async(credentials.credentials)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return tenant


# Rate-limit values live in strix.core.rate_limit, shared by both limiters.
AUTH_PATHS = ("/api/keys/",)
ASSESSMENT_PATHS = {"/api/assess", "/api/probe"}
# Liveness probes, docs and the static shell are never rate-limited. /api/metrics
# is deliberately absent: it requires an admin key and a scraper that holds one
# can be counted like any other caller.
UNLIMITED_PATHS = {
    "/",
    "/api/health",
    "/api/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
}


def route_class(path: str) -> str:
    """Which limit table applies to this request path."""
    if path.startswith(AUTH_PATHS):
        return "auth"
    if path in ASSESSMENT_PATHS:
        return "assessment"
    return "default"


# X-Forwarded-For is honored only when the peer is a proxy listed in
# STRIX_TRUSTED_PROXIES (comma separated). Anything else cannot influence the
# identity a limit is counted against, so rotating headers never resets a bucket.


def _get_settings() -> Settings:
    """Lazy settings accessor to avoid importing config at module load time."""
    from strix.config import Settings

    return Settings.from_env()


def _get_limits_disabled() -> bool:
    return _get_settings().rate_limit_disabled


def _get_redis_required() -> bool:
    return _get_settings().redis_required


def _get_worker_count() -> int:
    return _get_settings().workers


def _limits_disabled() -> bool:
    """Lazy accessor for limits disabled flag."""
    return _get_limits_disabled()


def _redis_required() -> bool:
    """Lazy accessor for redis required flag."""
    return _get_redis_required()


def _worker_count() -> int:
    """Lazy accessor for worker count."""
    return _get_worker_count()


async def resolve_identity(request: Request) -> tuple[str | None, str]:
    """(tenant_id or None, tier) from the validated bearer key only.

    Shared by the tenant-state and rate-limit middlewares so the identity used
    for authorization and the one used for accounting cannot drift. Identity is
    never read from X-Tenant-* headers: trusting those let any caller claim any
    tenant, tier, or fresh rate-limit bucket.
    """
    scheme, raw = get_authorization_scheme_param(request.headers.get("Authorization"))
    tenant = await api_keys.validate_async(raw) if scheme.lower() == "bearer" else None
    return (tenant["tenant_id"], tenant["tier"]) if tenant else (None, "free")


def _is_trusted_proxy(peer: str) -> bool:
    try:
        address = ipaddress.ip_address(peer.split("%")[0])
    except ValueError:
        return False
    return any(address in network for network in _get_settings().trusted_proxies)


def client_address(request: Request) -> str:
    """Peer address to count unauthenticated requests against."""
    peer = request.client.host if request.client else ""
    if peer and _is_trusted_proxy(peer):
        hops = [
            hop.strip()
            for hop in request.headers.get("X-Forwarded-For", "").split(",")
            if hop.strip()
        ]
        if hops:
            return hops[-1]  # appended by our trusted proxy: the peer it saw
    return peer or "unknown"


# Tier ordering used for authorization: a principal may never grant a tier above
# its own, so a free tenant cannot mint itself an enterprise key.
TIER_ORDER = {"free": 0, "pro": 1, "enterprise": 2}


def tier_rank(tier: str) -> int:
    return TIER_ORDER.get(tier, -1)


class TenantStateMiddleware(BaseHTTPMiddleware):
    """Set request.state.tenant_id / tier from the validated API key only.

    Identity is never read from request headers: trusting X-Tenant-ID /
    X-Tenant-Tier let any caller claim any tenant and tier, which is a
    privilege escalation for every consumer of request.state (quotas,
    rate limits, per-tenant accounting).
    """

    async def dispatch(self, request: Request, call_next):
        tenant_id, tier = await resolve_identity(request)
        # Missing, malformed or revoked keys get the lowest tier as anonymous.
        request.state.tenant_id = tenant_id or "anonymous"
        request.state.tier = tier
        return await call_next(request)


# Rate limiter instance is now provided by strix.core.rate_limit.get_distributed_rate_limiter()
# In-memory RateLimiter and TokenBucket classes removed - use Redis-backed DistributedRateLimiter

# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
            "accelerometer=(), gyroscope=(), magnetometer=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        # Remove potentially revealing server headers if present
        if "server" in response.headers:
            del response.headers["server"]
        return response


# ---------------------------------------------------------------------------
# In-memory Rate Limit Middleware (for single-worker test mode only)
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limiter for single-worker deployments (test mode only).

    Uses the legacy TokenBucket implementation. All workers must share the same
    Redis state for production use.
    """

    def __init__(self, app, limiter: _RateLimiter | None = None) -> None:
        super().__init__(app)
        self.limiter = limiter if limiter is not None else _test_rate_limiter

    async def dispatch(self, request: Request, call_next):
        path = request.scope["path"]
        if (
            _limits_disabled()
            or request.method == "OPTIONS"
            or path in UNLIMITED_PATHS
            or path.startswith("/static/")
        ):
            return await call_next(request)

        tenant_id, tier = await resolve_identity(request)
        if tenant_id:
            identity, tier = f"tenant:{tenant_id}", tier
        else:
            identity, tier = f"address:{client_address(request)}", "anon"

        allowed, limit, retry = self.limiter.allow(route_class(path), identity, tier)
        if not allowed:
            return Response(
                content='{"detail":"Rate limit exceeded"}',
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


# ---------------------------------------------------------------------------
# Request ID / correlation middleware
# ---------------------------------------------------------------------------
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        supplied = request.headers.get("X-Request-ID", "")
        request_id = (
            supplied if _REQUEST_ID.fullmatch(supplied) else secrets.token_hex(8)
        )
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Redis-backed Rate Limiter (for multi-worker deployments)
# ---------------------------------------------------------------------------
class RedisRateLimitMiddleware(BaseHTTPMiddleware):
    """Redis-backed rate limiter for multi-worker deployments.

    Uses DistributedRateLimiter from strix.core.rate_limit for distributed rate limiting.
    Fails closed if Redis is unavailable when REDIS_REQUIRED=1 or workers > 1.
    No in-memory fallback - all workers must share the same Redis state.
    """

    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.scope["path"]
        if (
            _limits_disabled()
            or request.method == "OPTIONS"
            or path in UNLIMITED_PATHS
            or path.startswith("/static/")
        ):
            return await call_next(request)

        tenant_id, tier = await resolve_identity(request)
        if tenant_id:
            identity, tier = f"tenant:{tenant_id}", tier
        else:
            identity, tier = f"address:{client_address(request)}", "anon"

        route_cls = route_class(path)

        try:
            rate_limiter = await get_distributed_rate_limiter()
            allowed, limit, retry = await rate_limiter.allow(route_cls, identity, tier)
            record_rate_limit_check(route_cls, tier, allowed)
        except (
            TimeoutError,
            RedisConnectionError,
            RedisTimeoutError,
            RedisError,
        ) as exc:
            # Redis unavailable: if REDIS_REQUIRED is set OR we're in multi-worker mode,
            # fail closed (503) because we cannot safely rate limit without shared state.
            if _redis_required() or _worker_count() > 1:
                log.error(
                    "Redis rate limiter unavailable and multi-worker/REDIS_REQUIRED: %s",
                    exc,
                )
                return Response(
                    content='{"detail":"Rate limiting unavailable — try again shortly"}',
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    media_type="application/json",
                )
            # Single worker without REDIS_REQUIRED: allow request (degraded mode)
            log.warning(
                "Redis rate limiter unavailable (%s), allowing request in degraded mode: %s",
                type(exc).__name__,
                exc,
            )
            allowed, limit, retry = True, 0, 0
        except Exception as exc:
            # Unexpected error - if Redis required or multi-worker, fail closed
            if _redis_required() or _worker_count() > 1:
                log.error(
                    "Unexpected error in Redis rate limiter with multi-worker/REDIS_REQUIRED: %s",
                    exc,
                )
                return Response(
                    content='{"detail":"Rate limiting unavailable — try again shortly"}',
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    media_type="application/json",
                )
            log.exception(
                "Unexpected error in Redis rate limiter (%s): %s",
                type(exc).__name__,
                exc,
            )
            allowed, limit, retry = True, 0, 0

        if not allowed:
            record_rate_limit_exceeded(route_cls, tier, "tenant" if ":" in identity else "address")
            return Response(
                content='{"detail":"Rate limit exceeded"}',
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
