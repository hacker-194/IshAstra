"""Process-wide services and the FastAPI dependencies shared by every router."""

from __future__ import annotations

from typing import Any, NoReturn

from fastapi import Depends, HTTPException, status

from strix.api.dependencies import (
    audit_chain,
    audit_log,
    monitor,  # noqa: F401  (re-exported for routers)
    settings,
)
from strix.api.security import get_current_tenant
from strix.core import policies, scope
from strix.core.scope import Scope

Tenant = dict[str, Any]


def require_auth(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
    return tenant


# Events whose history must be provable: they change who can do what.
SEALED_EVENTS = frozenset(
    {
        "api_key_created",
        "api_key_rotated",
        "api_key_revoked",
        "security_denied",
        "webhook_added",
        "monitor_configured",
        "policy_created",
        "policy_updated",
        "policy_revoked",
        "finding_status_changed",
        "report_generated",
    }
)


def managed_mode() -> bool:
    """True when per-tenant engagement policies govern authorization (sync version).

    Checks only the scope_mode setting without database access.
    Use managed_mode_async() when database access is needed.
    """
    if settings.scope_mode == "managed":
        return True
    if settings.scope_mode == "global":
        return False
    # Fail closed for invalid values; auto mode defaults to global (conservative)
    return settings.scope_mode != "auto"


async def managed_mode_async() -> bool:
    """True when per-tenant engagement policies govern authorization (async version).

    ``STRIX_SCOPE_MODE=global`` keeps the single-organization scope file;
    ``managed`` always defers to policies; ``auto`` (default) is managed as
    soon as one policy exists in the database, global before that.
    """
    if settings.scope_mode == "managed":
        return True
    if settings.scope_mode == "global":
        return False
    if settings.scope_mode != "auto":
        # Fail closed if Settings was constructed outside from_env() or is
        # changed by a deployment/test harness to an invalid value.
        return True
    policy_list = await policies.registry.list_async()
    return bool(policy_list)


async def tenant_scope_async(
    tenant: Tenant, policy_id: str | None = None
) -> Scope | None:
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
    snapshot, reason = await policies.tenant_scope_snapshot_async(
        tenant["tenant_id"], policy_id
    )
    if snapshot is None:
        await deny_async(tenant, "no_authorization_policy", reason)
    return snapshot


async def audit_async(tenant: Tenant, entry: dict[str, Any]) -> None:
    """Record an audit event stamped with the tenant that caused it.

    Security-relevant events are also sealed in the tamper-evident chain.
    """
    await audit_log.record_async({**entry, "tenant": tenant["tenant_id"]})
    if entry.get("event") in SEALED_EVENTS:
        await audit_chain.append_async({**entry, "tenant": tenant["tenant_id"]})


async def deny_async(
    tenant: Tenant,
    action: str,
    detail: str,
    status_code: int = status.HTTP_403_FORBIDDEN,
) -> NoReturn:
    """Refuse, record the refusal, and reveal nothing else."""
    await audit_async(
        tenant, {"event": "security_denied", "action": action, "detail": detail}
    )
    raise HTTPException(status_code=status_code, detail=detail)


async def require_admin(tenant: Tenant = Depends(require_auth)) -> Tenant:
    """Cross-tenant operations are administrator-only."""
    if not tenant.get("admin"):
        await deny_async(tenant, "admin_required", "Administrator privileges required")
    return tenant


def owns(tenant: Tenant, owner_id: str) -> bool:
    return bool(tenant.get("admin")) or tenant["tenant_id"] == owner_id


def tenant_filter(tenant: Tenant) -> str | None:
    """Storage scope for a caller: ``None`` (everything) only for administrators."""
    return None if tenant.get("admin") else tenant["tenant_id"]


def check_target_or_raise(target: str, snapshot: Scope | None) -> None:
    """Refuse a target the authorization does not cover: 400 malformed, 403 out of scope.

    ``snapshot`` is the engagement policy bound to this request; ``None`` means
    the global scope document judges it. The target must be judged against
    *that* snapshot: re-resolving the tenant's default policy could check a
    different policy than the caller explicitly selected.
    """
    denial, reason = (
        snapshot.check(target) if snapshot is not None else scope.check(target)
    )
    if denial:
        raise HTTPException(
            status_code=400 if denial == "invalid_target" else 403, detail=reason
        )


async def check_scope_or_raise_async(target: str, tenant: Tenant | None = None) -> None:
    """Check if target is within the authorized scope (async version)."""
    if tenant is not None and await managed_mode_async():
        snapshot = await tenant_scope_async(tenant)
        if snapshot is None:
            raise HTTPException(
                status_code=403, detail="no authorized scope configured"
            )
        check_target_or_raise(target, snapshot)
    else:
        check_target_or_raise(target, None)


# Re-export for backward compatibility
