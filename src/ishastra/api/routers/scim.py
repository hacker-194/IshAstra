"""SCIM 2.0 API Router for Ishastra.

Provides SCIM 2.0 endpoints for user and group provisioning.
Compatible with Okta, Entra ID, Keycloak, Auth0 SCIM clients.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ishastra.api.deps import audit_async
from ishastra.api.schemas import SCIMTokenCreateRequest, SCIMTokenResponse
from ishastra.core.scim import (
    SCIMGroup,
    SCIMListResponse,
    SCIMResourceTypesResponse,
    SCIMSchemasResponse,
    SCIMServiceProviderConfig,
    SCIMUser,
    get_resource_types,
    get_schemas,
    get_service_provider_config,
    init_scim_tables,
    scim_store,
    scim_token_manager,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/scim/v2", tags=["scim"])


async def require_scim_auth(request: Request) -> dict[str, Any]:
    """Validate SCIM bearer token and return token info."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected: Bearer <scim-token>",
            headers={"WWW-Authenticate": 'Bearer realm="scim"'},
        )

    token = auth_header[7:]
    token_info = await scim_token_manager.validate_token(token)

    if not token_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SCIM token",
            headers={"WWW-Authenticate": 'Bearer realm="scim", error="invalid_token"'},
        )

    return token_info


@router.on_event("startup")
async def startup_scim() -> None:
    """Initialize SCIM database tables."""
    await init_scim_tables()
    log.info("SCIM tables initialized")


@router.get("/ServiceProviderConfig", response_model=SCIMServiceProviderConfig)
async def service_provider_config() -> SCIMServiceProviderConfig:
    """Get SCIM Service Provider Configuration (RFC 7644 Section 4)."""
    return get_service_provider_config()


@router.get("/ResourceTypes", response_model=SCIMResourceTypesResponse)
async def resource_types() -> SCIMResourceTypesResponse:
    """Get SCIM Resource Types (RFC 7644 Section 4)."""
    return get_resource_types()


@router.get("/Schemas", response_model=SCIMSchemasResponse)
async def schemas() -> SCIMSchemasResponse:
    """Get SCIM Schemas (RFC 7644 Section 4)."""
    return get_schemas()


@router.post("/Users", response_model=SCIMUser, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    user: SCIMUser,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMUser:
    """Create a new user (RFC 7644 Section 3.3)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    try:
        created_user = await scim_store.create_user(user, tenant_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_user_created", "user_id": created_user.id, "userName": created_user.userName},
    )

    request.state.scim_location = f"/scim/v2/Users/{created_user.id}"

    return created_user


@router.get("/Users", response_model=SCIMListResponse)
async def list_users(
    request: Request,
    startIndex: int = Query(1, ge=1, alias="startIndex"),
    count: int = Query(100, ge=1, le=1000),
    filter: str | None = Query(None),
    token_info: dict = Depends(require_scim_auth),
) -> SCIMListResponse:
    """List users with pagination and filtering (RFC 7644 Section 3.4.2)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    return await scim_store.list_users(
        tenant_id=tenant_id,
        scim_token=scim_token,
        start_index=startIndex,
        count=count,
        filter_expr=filter,
    )


@router.get("/Users/{user_id}", response_model=SCIMUser)
async def get_user(
    user_id: str,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMUser:
    """Get a single user by ID (RFC 7644 Section 3.4.1)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    user = await scim_store.get_user(user_id, tenant_id, scim_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    return user


@router.put("/Users/{user_id}", response_model=SCIMUser)
async def update_user(
    user_id: str,
    user: SCIMUser,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMUser:
    """Update a user (full replace) (RFC 7644 Section 3.5.1)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    if user.id and user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID in body does not match URL",
        )

    user.id = user_id

    try:
        updated_user = await scim_store.update_user(user_id, user, tenant_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_user_updated", "user_id": user_id},
    )

    return updated_user


@router.patch("/Users/{user_id}", response_model=SCIMUser)
async def patch_user(
    user_id: str,
    request: Request,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMUser:
    """Partially update a user (RFC 7644 Section 3.5.2)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    body = await request.json()

    if not isinstance(body, dict) or "schemas" not in body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid PATCH request: missing schemas",
        )

    if "Operations" not in body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid PATCH request: missing Operations",
        )

    operations = body["Operations"]
    if not isinstance(operations, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operations must be an array",
        )

    valid_ops = {"add", "remove", "replace"}
    for op in operations:
        if not isinstance(op, dict) or "op" not in op:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Each operation must have an 'op' field",
            )
        if op["op"] not in valid_ops:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid operation: {op['op']}. Must be one of: add, remove, replace",
            )

    try:
        updated_user = await scim_store.patch_user(user_id, operations, tenant_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_user_patched", "user_id": user_id, "operations": operations},
    )

    return updated_user


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    token_info: dict = Depends(require_scim_auth),
) -> None:
    """Delete a user (RFC 7644 Section 3.6)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    deleted = await scim_store.delete_user(user_id, tenant_id, scim_token)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_user_deleted", "user_id": user_id},
    )


@router.post("/Groups", response_model=SCIMGroup, status_code=status.HTTP_201_CREATED)
async def create_group(
    request: Request,
    group: SCIMGroup,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMGroup:
    """Create a new group (RFC 7644 Section 3.3)."""
    tenant_id = token_info["tenant_id"]
    org_id = token_info.get("org_id")
    scim_token = token_info["token_hash"]

    try:
        created_group = await scim_store.create_group(group, tenant_id, org_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {
            "event": "scim_group_created",
            "group_id": created_group.id,
            "displayName": created_group.displayName,
        },
    )

    return created_group


@router.get("/Groups", response_model=SCIMListResponse)
async def list_groups(
    request: Request,
    startIndex: int = Query(1, ge=1, alias="startIndex"),
    count: int = Query(100, ge=1, le=1000),
    filter: str | None = Query(None),
    token_info: dict = Depends(require_scim_auth),
) -> SCIMListResponse:
    """List groups with pagination and filtering (RFC 7644 Section 3.4.2)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    return await scim_store.list_groups(
        tenant_id=tenant_id,
        scim_token=scim_token,
        start_index=startIndex,
        count=count,
        filter_expr=filter,
    )


@router.get("/Groups/{group_id}", response_model=SCIMGroup)
async def get_group(
    group_id: str,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMGroup:
    """Get a single group by ID (RFC 7644 Section 3.4.1)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    group = await scim_store.get_group(group_id, tenant_id, scim_token)
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group {group_id} not found",
        )

    return group


@router.put("/Groups/{group_id}", response_model=SCIMGroup)
async def update_group(
    group_id: str,
    group: SCIMGroup,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMGroup:
    """Update a group (full replace) (RFC 7644 Section 3.5.1)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    if group.id and group.id != group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Group ID in body does not match URL",
        )

    group.id = group_id

    try:
        updated_group = await scim_store.update_group(group_id, group, tenant_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_group_updated", "group_id": group_id},
    )

    return updated_group


@router.patch("/Groups/{group_id}", response_model=SCIMGroup)
async def patch_group(
    group_id: str,
    request: Request,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMGroup:
    """Partially update a group (RFC 7644 Section 3.5.2)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    body = await request.json()

    if not isinstance(body, dict) or "schemas" not in body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid PATCH request: missing schemas",
        )

    if "Operations" not in body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid PATCH request: missing Operations",
        )

    operations = body["Operations"]
    if not isinstance(operations, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operations must be an array",
        )

    valid_ops = {"add", "remove", "replace"}
    for op in operations:
        if not isinstance(op, dict) or "op" not in op:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Each operation must have an 'op' field",
            )
        if op["op"] not in valid_ops:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid operation: {op['op']}. Must be one of: add, remove, replace",
            )

    try:
        updated_group = await scim_store.patch_group(group_id, operations, tenant_id, scim_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_group_patched", "group_id": group_id, "operations": operations},
    )

    return updated_group


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    token_info: dict = Depends(require_scim_auth),
) -> None:
    """Delete a group (RFC 7644 Section 3.6)."""
    tenant_id = token_info["tenant_id"]
    scim_token = token_info["token_hash"]

    deleted = await scim_store.delete_group(group_id, tenant_id, scim_token)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group {group_id} not found",
        )

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": scim_token},
        {"event": "scim_group_deleted", "group_id": group_id},
    )


@router.post("/Tokens", response_model=SCIMTokenResponse)
async def create_scim_token(
    request: Request,
    req: SCIMTokenCreateRequest,
    token_info: dict = Depends(require_scim_auth),
) -> SCIMTokenResponse:
    """Create a new SCIM bearer token. Requires admin privileges."""

    tenant_id = token_info["tenant_id"]
    org_id = token_info.get("org_id")

    raw_token, token_hash = await scim_token_manager.create_token(
        tenant_id=tenant_id,
        name=req.name,
        org_id=org_id,
        ttl_days=req.ttl_days,
    )

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": token_info["token_hash"]},
        {"event": "scim_token_created", "token_name": req.name, "token_hash": token_hash[:16]},
    )

    return SCIMTokenResponse(
        token=raw_token,
        token_hash=token_hash,
        name=req.name,
        tenant_id=tenant_id,
        org_id=org_id,
        active=True,
        created_at=time.time(),
        expires_at=time.time() + req.ttl_days * 86400 if req.ttl_days else None,
    )


@router.get("/Tokens", response_model=list[SCIMTokenResponse])
async def list_scim_tokens(
    token_info: dict = Depends(require_scim_auth),
) -> list[SCIMTokenResponse]:
    """List all SCIM tokens for the tenant."""
    tenant_id = token_info["tenant_id"]
    tokens = await scim_token_manager.list_tokens(tenant_id)

    return [
        SCIMTokenResponse(
            token="",
            token_hash=t["token_hash"],
            name=t["name"],
            tenant_id=t["tenant_id"],
            org_id=t.get("org_id"),
            active=bool(t["active"]),
            created_at=t["created_at"],
            expires_at=t.get("expires_at"),
        )
        for t in tokens
    ]


@router.delete("/Tokens/{token_hash}")
async def revoke_scim_token(
    token_hash: str,
    token_info: dict = Depends(require_scim_auth),
) -> dict[str, str]:
    """Revoke a SCIM token."""
    tenant_id = token_info["tenant_id"]

    revoked = await scim_token_manager.revoke_token(token_hash)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found or already revoked",
        )

    await audit_async(
        {"tenant_id": tenant_id, "scim_token": token_info["token_hash"]},
        {"event": "scim_token_revoked", "token_hash": token_hash[:16]},
    )

    return {"status": "revoked"}
