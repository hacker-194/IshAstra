"""API-key management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ishastra.api.csrf import validate_csrf_token
from ishastra.api.deps import (
    Tenant,
    audit_async,
    deny_async,
    owns,
    require_auth,
    require_tenant_admin,
)
from ishastra.api.schemas import APIKeyCreateRequest, UserCreateRequest
from ishastra.api.security import TIER_ORDER, api_keys, tier_rank
from ishastra.core.key_scopes import (
    create_project_key,
    deactivate_project_key,
    get_project_key,
    list_project_keys,
    rotate_project_key,
)

router = APIRouter(prefix="/api")


@router.get("/tenants")
async def list_tenants(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Tenants holding a key — only the caller's own unless administrator."""
    visible = {
        record["tenant_id"]: {
            "tier": record["tier"],
            "active": record["active"],
            "admin": record["admin"],
            "scope": record["scope"],
        }
        for record in api_keys.tenants()
        if owns(tenant, record["tenant_id"])
    }
    return {
        "requesting_tenant": tenant["tenant_id"],
        "tiers": list(TIER_ORDER),
        "tenants": visible,
    }


@router.post("/keys/create")
async def create_api_key(
    req: APIKeyCreateRequest,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    if not owns(tenant, req.tenant):
        await deny_async(tenant, "key_create", "Cannot manage API keys for another tenant")
    if req.tier not in TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}")
    if not tenant.get("admin") and tier_rank(req.tier) > tier_rank(tenant["tier"]):
        await deny_async(tenant, "key_create", "Cannot mint a key above your own tier")

    raw_key = await api_keys.register_async(
        req.tenant,
        req.tier,
        admin=api_keys.is_admin(req.tenant),
        ttl_days=req.ttl_days,
        scope=req.scope,
        include_hosts=req.include_hosts,
    )
    await audit_async(
        tenant,
        {
            "event": "api_key_created",
            "key_tenant": req.tenant,
            "tier": req.tier,
            "scope": req.scope,
            "ttl_days": req.ttl_days,
            "include_hosts": req.include_hosts,
        },
    )
    status = api_keys.status(req.tenant) or {}
    return {
        "created_by": tenant["tenant_id"],
        "tenant": req.tenant,
        "tier": req.tier,
        "scope": req.scope,
        "include_hosts": status.get("include_hosts"),
        "api_key": raw_key,
        "expires_at": status.get("expires_at"),
        "warning": "Store this key securely — it is shown only once.",
    }


@router.get("/users")
async def list_users(tenant: Tenant = Depends(require_tenant_admin)) -> dict[str, Any]:
    """Members of the caller's tenant (secrets are never returned)."""
    return {
        "tenant": tenant["tenant_id"],
        "users": api_keys.list_users(tenant["tenant_id"]),
    }


@router.post("/users")
async def create_user(
    req: UserCreateRequest,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a member with a role and a one-time API key."""
    target = req.tenant or tenant["tenant_id"]
    if target != tenant["tenant_id"] and not (tenant.get("global_admin") or tenant.get("admin")):
        await deny_async(tenant, "user_create", "Cannot create users for another tenant")
    try:
        user_id, raw_key = await api_keys.register_user_async(
            target, req.display_name, req.role, ttl_days=req.ttl_days
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    await audit_async(
        tenant,
        {
            "event": "user_created",
            "user_id": user_id,
            "target_tenant": target,
            "display_name": req.display_name,
            "role": req.role,
        },
    )
    return {
        "user_id": user_id,
        "tenant": target,
        "display_name": req.display_name,
        "role": req.role,
        "api_key": raw_key,
        "warning": "Store this key securely — it is shown only once.",
    }


@router.post("/users/{user_id}/revoke")
async def revoke_user(
    user_id: str,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Revoke a member's key; the legacy tenant key is unaffected."""
    if not await api_keys.revoke_user_async(tenant["tenant_id"], user_id):
        raise HTTPException(status_code=404, detail="Unknown active user")
    await audit_async(tenant, {"event": "user_revoked", "user_id": user_id})
    return {"revoked_user": user_id, "revoked_by": tenant["tenant_id"]}


@router.post("/keys/rotate/{tenant_id}")
async def rotate_api_key(
    tenant_id: str,
    ttl_days: int | None = Query(default=None, ge=1, le=3650),
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Rotate a key; preserve its current absolute expiry unless a TTL is supplied."""
    if not owns(tenant, tenant_id):
        await deny_async(tenant, "key_rotate", "Cannot rotate another tenant's API key")
    raw_key = await api_keys.rotate_async(tenant_id, ttl_days=ttl_days)
    if raw_key is None:
        raise HTTPException(status_code=404, detail="No active, unexpired key found for this tenant")
    await audit_async(
        tenant,
        {"event": "api_key_rotated", "key_tenant": tenant_id, "ttl_days": ttl_days},
    )
    status = api_keys.status(tenant_id) or {}
    return {
        "rotated_tenant": tenant_id,
        "rotated_by": tenant["tenant_id"],
        "scope": status.get("scope"),
        "api_key": raw_key,
        "expires_at": status.get("expires_at"),
        "warning": "Store this key securely — it is shown only once. The previous key is no longer valid.",
    }


@router.get("/keys/status")
async def key_status(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """The caller's own key state: never the secret itself."""
    status = api_keys.status(tenant["tenant_id"])
    if status is None:
        raise HTTPException(status_code=404, detail="No key found for this tenant")
    return status


@router.post("/keys/revoke/{tenant_id}")
async def revoke_api_key(
    tenant_id: str,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    if not owns(tenant, tenant_id):
        await deny_async(tenant, "key_revoke", "Cannot revoke another tenant's API key")
    if not await api_keys.revoke_async(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant key not found")
    await audit_async(tenant, {"event": "api_key_revoked", "key_tenant": tenant_id})
    return {"revoked_tenant": tenant_id, "revoked_by": tenant["tenant_id"]}


@router.get("/keys/projects")
async def list_project_keys_endpoint(
    tenant: Tenant = Depends(require_tenant_admin),
) -> dict[str, Any]:
    """List all project-scoped keys for the tenant."""
    if not tenant.get("admin"):
        keys = await list_project_keys(tenant["tenant_id"])
    else:
        keys = await list_project_keys(tenant["tenant_id"])

    return {
        "tenant": tenant["tenant_id"],
        "keys": [
            {
                "project_id": k.project_id,
                "scope_type": k.scope_type,
                "scope": k.scope,
                "tier": k.tier,
                "active": k.active,
                "allowed_projects": k.allowed_projects,
                "resource_filters": k.resource_filters,
                "created_at": k.created_at,
                "expires_at": k.expires_at,
                "last_used": k.last_used,
                "rotated_at": k.rotated_at,
            }
            for k in keys
        ],
    }


@router.get("/keys/projects/{project_id}")
async def get_project_key_endpoint(
    project_id: str,
    tenant: Tenant = Depends(require_tenant_admin),
) -> dict[str, Any]:
    """Get a specific project-scoped key."""
    key = await get_project_key(tenant["tenant_id"], project_id)
    if not key:
        raise HTTPException(status_code=404, detail="Project key not found")
    return {
        "tenant_id": key.tenant_id,
        "project_id": key.project_id,
        "scope_type": key.scope_type,
        "scope": key.scope,
        "tier": key.tier,
        "admin": key.admin,
        "active": key.active,
        "allowed_projects": key.allowed_projects,
        "resource_filters": key.resource_filters,
        "include_hosts": key.include_hosts,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
        "last_used": key.last_used,
        "rotated_at": key.rotated_at,
        "ai_enabled": key.ai_enabled,
    }


@router.post("/keys/projects")
async def create_project_key_endpoint(
    req: APIKeyCreateRequest,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new project-scoped API key."""
    if not owns(tenant, req.tenant):
        await deny_async(tenant, "key_create", "Cannot manage API keys for another tenant")
    if req.tier not in TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}")
    if not tenant.get("admin") and tier_rank(req.tier) > tier_rank(tenant["tier"]):
        await deny_async(tenant, "key_create", "Cannot mint a key above your own tier")

    raw_key, key_record = await create_project_key(
        tenant_id=req.tenant,
        tier=req.tier,
        admin=api_keys.is_admin(req.tenant),
        ttl_days=req.ttl_days,
        scope=req.scope,
        scope_type=req.scope_type,
        project_id=req.project_id,
        allowed_projects=req.allowed_projects,
        resource_filters=req.resource_filters,
        include_hosts=req.include_hosts,
    )
    await audit_async(
        tenant,
        {
            "event": "project_key_created",
            "key_tenant": req.tenant,
            "project_id": req.project_id,
            "scope_type": req.scope_type,
            "tier": req.tier,
            "scope": req.scope,
            "ttl_days": req.ttl_days,
            "allowed_projects": req.allowed_projects,
            "resource_filters": req.resource_filters,
            "include_hosts": req.include_hosts,
        },
    )
    return {
        "created_by": tenant["tenant_id"],
        "tenant": req.tenant,
        "project_id": req.project_id,
        "scope_type": req.scope_type,
        "tier": req.tier,
        "scope": req.scope,
        "allowed_projects": req.allowed_projects,
        "resource_filters": req.resource_filters,
        "include_hosts": key_record.include_hosts,
        "api_key": raw_key,
        "expires_at": key_record.expires_at,
        "warning": "Store this key securely — it is shown only once.",
    }


@router.post("/keys/projects/{project_id}/rotate")
async def rotate_project_key_endpoint(
    project_id: str,
    ttl_days: int | None = Query(default=None, ge=1, le=3650),
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Rotate a project-scoped key."""
    if not owns(tenant, tenant["tenant_id"]):
        await deny_async(tenant, "key_rotate", "Cannot rotate another tenant's API key")
    result = await rotate_project_key(tenant["tenant_id"], project_id=project_id, ttl_days=ttl_days)
    if result is None:
        raise HTTPException(status_code=404, detail="No active, unexpired project key found")
    raw_key, key_record = result
    await audit_async(
        tenant,
        {
            "event": "project_key_rotated",
            "key_tenant": tenant["tenant_id"],
            "project_id": project_id,
            "ttl_days": ttl_days,
        },
    )
    return {
        "rotated_tenant": tenant["tenant_id"],
        "project_id": project_id,
        "rotated_by": tenant["tenant_id"],
        "scope": key_record.scope,
        "scope_type": key_record.scope_type,
        "api_key": raw_key,
        "expires_at": key_record.expires_at,
        "warning": "Store this key securely — it is shown only once. The previous key is no longer valid.",
    }


@router.post("/keys/projects/{project_id}/revoke")
async def revoke_project_key_endpoint(
    project_id: str,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Revoke a project-scoped API key."""
    if not owns(tenant, tenant["tenant_id"]):
        await deny_async(tenant, "key_revoke", "Cannot revoke another tenant's API key")
    success = await deactivate_project_key(tenant["tenant_id"], project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project key not found or already inactive")
    await audit_async(
        tenant,
        {
            "event": "project_key_revoked",
            "key_tenant": tenant["tenant_id"],
            "project_id": project_id,
        },
    )
    return {
        "revoked_tenant": tenant["tenant_id"],
        "project_id": project_id,
        "revoked_by": tenant["tenant_id"],
    }
