"""API-key management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from strix.api.deps import Tenant, audit_async, deny_async, owns, require_auth
from strix.api.schemas import APIKeyCreateRequest
from strix.api.security import TIER_ORDER, api_keys, tier_rank

router = APIRouter(prefix="/api")


@router.get("/tenants")
async def list_tenants(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Tenants holding a key — only the caller's own unless administrator."""
    visible = {
        record["tenant_id"]: {
            "tier": record["tier"],
            "active": record["active"],
            "admin": record["admin"],
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
    req: APIKeyCreateRequest, tenant: Tenant = Depends(require_auth)
) -> dict[str, Any]:
    if not owns(tenant, req.tenant):
        await deny_async(
            tenant, "key_create", "Cannot manage API keys for another tenant"
        )
    if req.tier not in TIER_ORDER:
        raise HTTPException(
            status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}"
        )
    if not tenant.get("admin") and tier_rank(req.tier) > tier_rank(tenant["tier"]):
        await deny_async(tenant, "key_create", "Cannot mint a key above your own tier")

    raw_key = await api_keys.register_async(
        req.tenant, req.tier, admin=api_keys.is_admin(req.tenant), ttl_days=req.ttl_days
    )
    await audit_async(
        tenant,
        {
            "event": "api_key_created",
            "key_tenant": req.tenant,
            "tier": req.tier,
            "ttl_days": req.ttl_days,
        },
    )
    status = api_keys.status(req.tenant) or {}
    return {
        "created_by": tenant["tenant_id"],
        "tenant": req.tenant,
        "tier": req.tier,
        "api_key": raw_key,
        "expires_at": status.get("expires_at"),
        "warning": "Store this key securely — it is shown only once.",
    }


@router.post("/keys/rotate/{tenant_id}")
async def rotate_api_key(
    tenant_id: str,
    ttl_days: int | None = Query(default=None, ge=1, le=3650),
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Rotate a key; preserve its current absolute expiry unless a TTL is supplied."""
    if not owns(tenant, tenant_id):
        await deny_async(tenant, "key_rotate", "Cannot rotate another tenant's API key")
    raw_key = await api_keys.rotate_async(tenant_id, ttl_days=ttl_days)
    if raw_key is None:
        raise HTTPException(
            status_code=404, detail="No active, unexpired key found for this tenant"
        )
    await audit_async(
        tenant,
        {"event": "api_key_rotated", "key_tenant": tenant_id, "ttl_days": ttl_days},
    )
    status = api_keys.status(tenant_id) or {}
    return {
        "rotated_tenant": tenant_id,
        "rotated_by": tenant["tenant_id"],
        "api_key": raw_key,
        "expires_at": status.get("expires_at"),
        "warning": "Store this key securely — it is shown only once. "
        "The previous key is no longer valid.",
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
    tenant_id: str, tenant: Tenant = Depends(require_auth)
) -> dict[str, Any]:
    if not owns(tenant, tenant_id):
        await deny_async(tenant, "key_revoke", "Cannot revoke another tenant's API key")
    if not await api_keys.revoke_async(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant key not found")
    await audit_async(tenant, {"event": "api_key_revoked", "key_tenant": tenant_id})
    return {"revoked_tenant": tenant_id, "revoked_by": tenant["tenant_id"]}
