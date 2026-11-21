"""Process-wide services and the FastAPI dependencies shared by every router.

Module-level singletons are lazy-initialized to allow test overrides. Access
them via ``get_settings()``, ``get_audit_log()``, ``get_audit_chain()``,
``get_monitor()``, ``get_http_client()`` and ``get_redis()``; the historical
attribute style (``deps.settings``, ``deps.monitor``) still resolves through
``__getattr__``.

Database connections live in ``ishastra.core.store`` (one pool, used by every
router); this module deliberately does not keep a second one.

The authorization dependencies used to live in a separate
``ishastra.api.deps`` module, which once re-exported them as ``None`` and
silently disabled authorization. One module means one place to audit.
"""

from __future__ import annotations

import logging
import os
from typing import Any, NoReturn

import httpx
import redis.asyncio as redis
from fastapi import Depends, HTTPException, Request, status

from ishastra import __version__
from ishastra.api.security import get_current_tenant
from ishastra.audit import AuditChain, AuditLog
from ishastra.config import Settings
from ishastra.config import get_settings as config_settings
from ishastra.config import reset_settings as config_reset_settings
from ishastra.core import policies, scope
from ishastra.core.scope import Scope
from ishastra.monitor import Monitor

Tenant = dict[str, Any]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_audit_log: AuditLog | None = None
_audit_chain: AuditChain | None = None
_monitor: Monitor | None = None


def get_settings() -> Settings:
    """The process settings.

    Delegates to ``ishastra.config`` so the API, the CLI and the core modules share
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
            headers={"User-Agent": f"ishastra/{__version__} (+authorized-testing)"},
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
    if _http_client is None:
        raise RuntimeError("HTTP client not initialized")
    return _http_client


async def init_redis() -> redis.Redis:
    """Initialize the Redis client for rate limiting and caching."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()

        if settings.redis_required and not os.environ.get("ISHASTRA_REDIS_URL"):
            raise RuntimeError(
                "ISHASTRA_REDIS_REQUIRED=1 but ISHASTRA_REDIS_URL not set; "
                "refusing to start with implicit localhost fallback"
            )
        _redis_client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )

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
    if _redis_client is None:
        raise RuntimeError("Redis client not initialized")
    return _redis_client


async def require_auth(request: Request, tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
    """Authenticate, then refuse writes from a read-scoped key."""
    if request.method not in SAFE_METHODS and tenant.get("scope") != "write":
        await deny_async(
            tenant,
            "write_scope_required",
            "This API key is read-only; use a write-scoped key for this request",
        )
    return tenant


SEALED_EVENTS = frozenset(
    {
        "api_key_created",
        "api_key_rotated",
        "api_key_revoked",
        "user_created",
        "user_revoked",
        "security_denied",
        "webhook_added",
        "monitor_configured",
        "policy_created",
        "policy_updated",
        "policy_revoked",
        "finding_status_changed",
        "finding_exception_requested",
        "finding_exception_approved",
        "finding_exception_rejected",
        "finding_resolution_verified",
        "report_generated",
    }
)


async def managed_mode_async() -> bool:
    """True when per-tenant engagement policies govern authorization (async version).

    ``ISHASTRA_SCOPE_MODE=global`` keeps the single-organization scope file;
    ``managed`` always defers to policies; ``auto`` (default) is managed as
    soon as one policy exists in the database, global before that.
    """
    s = get_settings()
    if s.scope_mode == "managed":
        return True
    if s.scope_mode == "global":
        return False
    if s.scope_mode != "auto":
        return True
    policy_list = await policies.registry.list_async()
    return bool(policy_list)


async def tenant_scope_async(tenant: Tenant, policy_id: str | None = None) -> Scope | None:
    """The authorization judging this caller's requests (None = global mode).

    ``policy_id`` pins a specific engagement policy (it must belong to the
    caller); without it the tenant's newest valid policy is used.
    """
    if not await managed_mode_async():
        if policy_id:
            await deny_async(
                tenant,
                "policy_unavailable",
                "policy_id requires managed authorization mode",
            )
        return None
    snapshot, reason = await policies.tenant_scope_snapshot_async(tenant["tenant_id"], policy_id)
    if snapshot is None:
        await deny_async(tenant, "no_authorization_policy", reason)
    return snapshot


async def audit_async(tenant: Tenant, entry: dict[str, Any]) -> None:
    """Record an audit event stamped with the tenant that caused it.

    Security-relevant events are also sealed in the tamper-evident chain.
    """
    await get_audit_log().record_async({**entry, "tenant": tenant["tenant_id"]})
    if entry.get("event") in SEALED_EVENTS:
        await get_audit_chain().append_async({**entry, "tenant": tenant["tenant_id"]})


async def deny_async(
    tenant: Tenant,
    action: str,
    detail: str,
    status_code: int = status.HTTP_403_FORBIDDEN,
) -> NoReturn:
    """Refuse, record the refusal, and reveal nothing else."""
    await audit_async(tenant, {"event": "security_denied", "action": action, "detail": detail})
    raise HTTPException(status_code=status_code, detail=detail)


async def require_admin(tenant: Tenant = Depends(require_auth)) -> Tenant:
    """Cross-tenant operations are administrator-only."""
    if not tenant.get("global_admin") and not tenant.get("admin"):
        await deny_async(tenant, "admin_required", "Administrator privileges required")
    return tenant


async def require_tenant_admin(tenant: Tenant = Depends(require_auth)) -> Tenant:
    """Tenant-scoped administration (users, risk-exception decisions)."""
    if not tenant.get("global_admin") and not tenant.get("admin") and tenant.get("role") != "admin":
        await deny_async(tenant, "tenant_admin_required", "Tenant administrator privileges required")
    return tenant


def owns(tenant: Tenant, owner_id: str) -> bool:
    return bool(tenant.get("global_admin") or tenant.get("admin")) or tenant["tenant_id"] == owner_id


def tenant_filter(tenant: Tenant) -> str | None:
    """Storage scope for a caller: ``None`` (everything) only for global administrators."""
    return None if (tenant.get("global_admin") or tenant.get("admin")) else tenant["tenant_id"]


def check_target_or_raise(target: str, snapshot: Scope | None) -> None:
    """Refuse a target the authorization does not cover: 400 malformed, 403 out of scope.

    ``snapshot`` is the engagement policy bound to this request; ``None`` means
    the global scope document judges it. The target must be judged against
    *that* snapshot: re-resolving the tenant's default policy could check a
    different policy than the caller explicitly selected.
    """
    denial, reason = snapshot.check(target) if snapshot is not None else scope.check(target)
    if denial:
        raise HTTPException(status_code=400 if denial == "invalid_target" else 403, detail=reason)


async def check_scope_or_raise_async(target: str, tenant: Tenant | None = None) -> None:
    """Check if target is within the authorized scope (async version)."""
    if tenant is not None and await managed_mode_async():
        snapshot = await tenant_scope_async(tenant)
        if snapshot is None:
            raise HTTPException(status_code=403, detail="no authorized scope configured")
        check_target_or_raise(target, snapshot)
    else:
        check_target_or_raise(target, None)
