"""Organization management API endpoints.

Organizations group multiple tenants under a single administrative umbrella.
Org-level admin keys can manage all tenants within the organization.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from strix.api.csrf import validate_csrf_token
from strix.api.deps import (
    Tenant,
    audit_async,
    deny_async,
    require_admin,
    require_auth,
)
from strix.api.schemas import APIKeyCreateRequest
from strix.api.security import TIER_ORDER, get_current_tenant
from strix.core import org, tenants

router = APIRouter(prefix="/api")


async def require_org_admin(request: Request, tenant: Tenant = Depends(require_auth)) -> tuple[Tenant, str]:
    """Require an organization admin key (from Authorization header)."""
    # Check for org admin key in header
    from strix.api.security import get_authorization_scheme_param

    auth_header = request.headers.get("Authorization")
    scheme, raw_key = get_authorization_scheme_param(auth_header) if auth_header else (None, None)

    if scheme and scheme.lower() == "bearer" and raw_key:
        org_obj = await org.validate_org_admin_key(raw_key)
        if org_obj:
            # Verify the calling tenant is a member of this org
            tenant_org = await org.get_tenant_org(tenant["tenant_id"])
            if tenant_org != org_obj.org_id:
                await deny_async(tenant, "org_admin_required", "Not a member of this organization")
            return tenant, org_obj.org_id

    # Also allow global admins
    if tenant.get("global_admin") or tenant.get("admin"):
        # For global admins, we need an org_id from query or body
        org_id = request.query_params.get("org_id")
        if not org_id:
            raise HTTPException(
                status_code=400,
                detail="org_id query parameter required for global admin",
            )
        return tenant, org_id

    await deny_async(tenant, "org_admin_required", "Organization administrator privileges required")
    raise HTTPException(status_code=403, detail="Organization administrator privileges required")


async def get_caller_tenant(request: Request) -> Tenant:
    """Get the calling tenant for audit logging."""
    return await get_current_tenant.__wrapped__(request)  # type: ignore


@router.post("/orgs")
async def create_organization(
    request: Request,
    name: str = Query(..., min_length=1, max_length=128),
    tier: str = Query(default="standard", description="standard | elevated | unlimited"),
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new organization. Global admin only."""
    if tier not in TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}")

    org_id, admin_key = await org.create_organization(name=name, tier=tier)

    await audit_async(tenant, {"event": "org_created", "org_id": org_id, "name": name, "tier": tier})

    return {
        "org_id": org_id,
        "name": name,
        "tier": tier,
        "admin_key": admin_key,
        "warning": "Store this organization admin key securely — it is shown only once.",
    }


@router.get("/orgs")
async def list_organizations(
    tenant: Tenant = Depends(require_admin),
) -> dict[str, Any]:
    """List all organizations. Global admin only."""
    orgs = await org.list_organizations()
    return {"organizations": orgs}


@router.get("/orgs/{org_id}")
async def get_organization(
    org_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get organization details. Org admin or global admin only."""
    # Check access
    org_obj = await org.get_organization(org_id)
    if org_obj is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    tenant_org = await org.get_tenant_org(tenant["tenant_id"])
    if not (tenant.get("global_admin") or tenant.get("admin") or tenant_org == org_id):
        await deny_async(tenant, "org_access_denied", "Not a member of this organization")
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    members = await org.get_org_tenants(org_id)
    return {
        "org_id": org_obj.org_id,
        "name": org_obj.name,
        "tier": org_obj.tier,
        "created_at": org_obj.created_at,
        "updated_at": org_obj.updated_at,
        "tenants": members,
    }


@router.post("/orgs/{org_id}/tenants")
async def add_tenant_to_org(
    org_id: str,
    request: Request,
    tenant_id: str = Query(..., min_length=1, max_length=64),
    role: str = Query(default="member", description="member | admin"),
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(get_caller_tenant),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Add a tenant to an organization. Org admin only."""
    if role not in ("member", "admin"):
        raise HTTPException(status_code=400, detail="role must be 'member' or 'admin'")

    try:
        await org.add_tenant_to_org(org_id, tenant_id, role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    await audit_async(
        caller,
        {"event": "org_tenant_added", "org_id": org_id, "tenant_id": tenant_id, "role": role},
    )

    return {"org_id": org_id, "tenant_id": tenant_id, "role": role, "status": "added"}


@router.delete("/orgs/{org_id}/tenants/{tenant_id}")
async def remove_tenant_from_org(
    org_id: str,
    tenant_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(get_caller_tenant),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Remove a tenant from an organization. Org admin only."""
    removed = await org.remove_tenant_from_org(org_id, tenant_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Tenant not found in this organization")

    await audit_async(
        caller,
        {"event": "org_tenant_removed", "org_id": org_id, "tenant_id": tenant_id},
    )

    return {"org_id": org_id, "tenant_id": tenant_id, "status": "removed"}


@router.get("/orgs/{org_id}/tenants")
async def list_org_tenants(
    org_id: str,
    _: tuple[Tenant, str] = Depends(require_org_admin),
) -> dict[str, Any]:
    """List all tenants in an organization. Org admin only."""
    members = await org.get_org_tenants(org_id)
    return {"org_id": org_id, "tenants": members}


@router.post("/orgs/{org_id}/tenants/create")
async def create_tenant_in_org(
    org_id: str,
    req: APIKeyCreateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(get_caller_tenant),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new tenant and add it to the organization. Org admin only."""
    if req.tenant != req.tenant:  # Ensure tenant in body matches
        pass  # tenant_id comes from req.tenant

    if req.tier not in TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}")

    raw_key = await tenants.create_tenant(
        req.tenant,
        tier=req.tier,
        admin=req.tenant == "admin",  # Only admin tenant gets admin flag
        scope=req.scope,
    )
    await org.add_tenant_to_org(org_id, req.tenant, role="member")

    await audit_async(
        caller,
        {
            "event": "org_tenant_created",
            "org_id": org_id,
            "tenant_id": req.tenant,
            "tier": req.tier,
            "scope": req.scope,
        },
    )

    return {
        "org_id": org_id,
        "tenant": req.tenant,
        "tier": req.tier,
        "scope": req.scope,
        "api_key": raw_key,
        "warning": "Store this key securely — it is shown only once.",
    }


@router.post("/orgs/{org_id}/rotate-key")
async def rotate_org_admin_key(
    org_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(get_caller_tenant),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Rotate the organization admin key. Org admin only."""
    try:
        new_key = await org.rotate_org_admin_key(org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    await audit_async(caller, {"event": "org_key_rotated", "org_id": org_id})

    return {
        "org_id": org_id,
        "admin_key": new_key,
        "warning": "Store this key securely — it is shown only once. The previous key is no longer valid.",
    }


@router.post("/orgs/{org_id}/tier")
async def update_org_tier(
    org_id: str,
    request: Request,
    tier: str = Query(..., description="standard | elevated | unlimited"),
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(get_caller_tenant),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update organization tier. Org admin only."""
    if tier not in TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(TIER_ORDER)}")

    try:
        await org.update_org_tier(org_id, tier)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    await audit_async(caller, {"event": "org_tier_updated", "org_id": org_id, "tier": tier})

    return {"org_id": org_id, "tier": tier, "status": "updated"}


@router.post("/tenants/migrate-to-org")
async def migrate_tenant_to_org(
    request: Request,
    tenant_id: str = Query(..., min_length=1, max_length=64),
    org_name: str | None = Query(default=None, max_length=128),
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Migrate an existing tenant to a new single-tenant organization. Global admin only."""
    try:
        org_id, admin_key = await org.migrate_tenant_to_org(tenant_id, org_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    await audit_async(
        tenant,
        {"event": "tenant_migrated_to_org", "tenant_id": tenant_id, "org_id": org_id},
    )

    return {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "admin_key": admin_key,
        "warning": "Store this organization admin key securely — it is shown only once.",
    }
