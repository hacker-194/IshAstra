"""Tenant-scoped asset inventory derived from jobs and findings."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, audit_async, require_auth
from strix.api.schemas import AssetUpdate
from strix.core import store

router = APIRouter(prefix="/api")


@router.get("/assets")
async def list_assets(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Assets seen in this tenant's assessments, newest activity first."""
    tenant_id = tenant["tenant_id"]
    items = await store.list_assets(tenant=tenant_id, limit=page_size, offset=(page - 1) * page_size)
    total = await store.count_assets(tenant=tenant_id)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": page * page_size < total,
    }


@router.get("/assets/{asset_key}")
async def get_asset(asset_key: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """One asset and its findings across this tenant's jobs."""
    asset = await store.get_asset(tenant=tenant["tenant_id"], key=asset_key)
    if asset is None:
        raise HTTPException(status_code=404, detail="Unknown asset")
    return asset


@router.patch("/assets/{asset_key}")
async def update_asset(
    asset_key: str,
    req: AssetUpdate,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Set owner/criticality; identity and last-seen remain derived from scans."""
    updated = await store.update_asset_metadata(
        tenant=tenant["tenant_id"],
        key=asset_key,
        owner=req.owner,
        criticality=req.criticality,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown asset")
    await audit_async(
        tenant,
        {
            "event": "asset_metadata_updated",
            "asset_key": asset_key,
            "fields": req.model_dump(exclude_none=True),
        },
    )
    return updated
