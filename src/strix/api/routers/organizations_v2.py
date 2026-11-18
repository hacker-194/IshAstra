"""Organization management API endpoints (User-based Organizations v2).

This module provides the new organization hierarchy with:
- Organizations (top-level containers with settings)
- Teams (within organizations)
- Memberships (users linked to orgs/teams with roles)

Role hierarchy (highest to lowest):
- org_admin: full org access, can manage teams and members
- team_lead: can manage team members and team resources
- org_member: basic org access, can view org resources
- team_member: can access team resources
- viewer: read-only access to assigned resources
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, audit_async, deny_async, require_auth
from strix.api.schemas import (
    MembershipCreateRequest,
    MembershipResponse,
    MembershipUpdateRequest,
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
    Page,
    TeamCreateRequest,
    TeamResponse,
    TeamUpdateRequest,
)
from strix.core.organizations import (
    ORG_TIER_ORDER,
    VALID_ROLES,
    VALID_STATUSES,
    add_member,
    can_manage_role,
    create_org,
    create_team,
    delete_membership,
    delete_org,
    delete_team,
    get_membership,
    get_org,
    get_org_by_slug,
    get_org_memberships,
    get_team,
    get_team_by_slug,
    get_user_memberships,
    get_user_org_role,
    get_user_team_role,
    list_teams,
    remove_member,
    update_member_role,
    update_member_status,
    update_org,
    update_team,
    user_has_org_access,
)

router = APIRouter(prefix="/api/v2/orgs", tags=["organizations"])


async def require_org_access(
    request: Request,
    org_id: str,
    min_role: str = "viewer",
    tenant: Tenant = Depends(require_auth),
) -> tuple[Tenant, str]:
    """Require user has at least min_role in the organization."""
    # Check user's org role
    user_id = tenant["tenant_id"]  # Using tenant_id as user identifier
    has_access = await user_has_org_access(user_id, org_id, min_role)
    if not has_access:
        # Check if global admin
        if tenant.get("global_admin") or tenant.get("admin"):
            return tenant, org_id
        await deny_async(tenant, "org_access_denied", f"Requires {min_role} role in organization")
        raise HTTPException(status_code=403, detail=f"Requires {min_role} role in organization")
    return tenant, org_id


async def require_org_admin(
    request: Request,
    org_id: str,
    tenant: Tenant = Depends(require_auth),
) -> tuple[Tenant, str]:
    """Require org_admin role in the organization."""
    return await require_org_access(request, org_id, "org_admin", tenant)


def _org_to_response(org) -> dict[str, Any]:
    """Convert Organization to response dict with settings helpers."""
    d = org.to_dict()
    # Add convenience fields for common settings
    settings = org.settings or {}
    d["billing_email"] = settings.get("billing_email")
    d["support_email"] = settings.get("support_email")
    d["custom_domain"] = settings.get("custom_domain")
    d["sso_config"] = settings.get("sso_config", {})
    return d


def _team_to_response(team) -> dict[str, Any]:
    """Convert Team to response dict."""
    return team.to_dict()


def _membership_to_response(m) -> dict[str, Any]:
    """Convert Membership to response dict."""
    return m.to_dict()


# ---------------------------------------------------------------------------
# Organization CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=OrganizationResponse)
async def create_organization_v2(
    req: OrganizationCreateRequest,
    request: Request,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new organization. The creator becomes org_admin."""
    if req.tier not in ORG_TIER_ORDER:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {list(ORG_TIER_ORDER)}")

    org = await create_org(
        name=req.name,
        slug=req.slug,
        tier=req.tier,
        settings=req.settings or {},
    )

    # Add creator as org_admin
    user_id = tenant["tenant_id"]
    await add_member(org_id=org.org_id, user_id=user_id, role="org_admin")

    await audit_async(
        tenant,
        {"event": "org_created", "org_id": org.org_id, "name": req.name, "tier": req.tier},
    )

    return _org_to_response(org)


@router.get("", response_model=Page[OrganizationResponse])
async def list_organizations_v2(
    tenant: Tenant = Depends(require_auth),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List organizations the user is a member of."""
    user_id = tenant["tenant_id"]
    memberships = await get_user_memberships(user_id)
    org_ids = list({m.org_id for m in memberships if m.status == "active"})

    all_orgs = []
    for org_id in org_ids:
        org = await get_org(org_id)
        if org:
            all_orgs.append(_org_to_response(org))

    # Apply pagination
    total = len(all_orgs)
    paginated = all_orgs[offset : offset + limit]

    return {
        "items": paginated,
        "total": total,
        "page": offset // limit + 1,
        "page_size": limit,
        "has_next": offset + limit < total,
    }


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization_v2(
    org_id: str,
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """Get organization details. Requires org membership (viewer+)."""
    org = await get_org(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _org_to_response(org)


@router.get("/by-slug/{slug}", response_model=OrganizationResponse)
async def get_organization_by_slug_v2(
    slug: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get organization by slug. Requires org membership (viewer+)."""
    org = await get_org_by_slug(slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check access
    user_id = tenant["tenant_id"]
    has_access = await user_has_org_access(user_id, org.org_id, "viewer")
    if not has_access and not (tenant.get("global_admin") or tenant.get("admin")):
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    return _org_to_response(org)


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization_v2(
    org_id: str,
    req: OrganizationUpdateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update organization. Requires org_admin."""
    # Merge settings if provided
    settings = req.settings
    if settings is not None:
        # Get current org to merge settings
        current = await get_org(org_id)
        if current:
            merged = {**current.settings, **settings}
            settings = merged

    updated = await update_org(
        org_id,
        name=req.name,
        slug=req.slug,
        tier=req.tier,
        settings=settings,
    )

    if updated is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    await audit_async(
        caller,
        {"event": "org_updated", "org_id": org_id, "changes": req.model_dump(exclude_unset=True)},
    )

    return _org_to_response(updated)


@router.delete("/{org_id}")
async def delete_organization_v2(
    org_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete organization (cascades to teams and memberships). Requires org_admin."""
    deleted = await delete_org(org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Organization not found")

    await audit_async(caller, {"event": "org_deleted", "org_id": org_id})

    return {"org_id": org_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# Team CRUD
# ---------------------------------------------------------------------------


@router.post("/{org_id}/teams", response_model=TeamResponse)
async def create_team_v2(
    org_id: str,
    req: TeamCreateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new team within an organization. Requires org_admin."""
    team = await create_team(
        org_id=org_id,
        name=req.name,
        slug=req.slug,
        role_mappings=req.role_mappings or {},
    )

    await audit_async(
        caller,
        {"event": "team_created", "org_id": org_id, "team_id": team.team_id, "name": req.name},
    )

    return _team_to_response(team)


@router.get("/{org_id}/teams", response_model=Page[TeamResponse])
async def list_teams_v2(
    org_id: str,
    tenant: Tenant = Depends(require_auth),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """List teams in an organization. Requires org membership (viewer+)."""
    teams = await list_teams(org_id, limit=limit, offset=offset)
    return {
        "items": [_team_to_response(t) for t in teams],
        "total": len(teams),  # Note: not total count, just current page
        "page": offset // limit + 1,
        "page_size": limit,
        "has_next": len(teams) == limit,
    }


@router.get("/{org_id}/teams/{team_id}", response_model=TeamResponse)
async def get_team_v2(
    org_id: str,
    team_id: str,
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """Get team details. Requires org membership (viewer+)."""
    team = await get_team(team_id)
    if team is None or team.org_id != org_id:
        raise HTTPException(status_code=404, detail="Team not found")
    return _team_to_response(team)


@router.get("/{org_id}/teams/by-slug/{slug}", response_model=TeamResponse)
async def get_team_by_slug_v2(
    org_id: str,
    slug: str,
    tenant: Tenant = Depends(require_auth),
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """Get team by slug. Requires org membership (viewer+)."""
    team = await get_team_by_slug(org_id, slug)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    return _team_to_response(team)


@router.patch("/{org_id}/teams/{team_id}", response_model=TeamResponse)
async def update_team_v2(
    org_id: str,
    team_id: str,
    req: TeamUpdateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update a team. Requires org_admin."""
    updated = await update_team(
        team_id,
        name=req.name,
        slug=req.slug,
        role_mappings=req.role_mappings,
    )

    if updated is None:
        raise HTTPException(status_code=404, detail="Team not found")

    await audit_async(
        caller,
        {
            "event": "team_updated",
            "org_id": org_id,
            "team_id": team_id,
            "changes": req.model_dump(exclude_unset=True),
        },
    )

    return _team_to_response(updated)


@router.delete("/{org_id}/teams/{team_id}")
async def delete_team_v2(
    org_id: str,
    team_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete a team (cascades to memberships). Requires org_admin."""
    team = await get_team(team_id)
    if team is None or team.org_id != org_id:
        raise HTTPException(status_code=404, detail="Team not found")

    deleted = await delete_team(team_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Team not found")

    await audit_async(caller, {"event": "team_deleted", "org_id": org_id, "team_id": team_id})

    return {"team_id": team_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# Membership CRUD
# ---------------------------------------------------------------------------


@router.post("/{org_id}/members", response_model=MembershipResponse)
async def add_member_v2(
    org_id: str,
    req: MembershipCreateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Add a member to an organization (and optionally a team). Requires org_admin."""
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(VALID_ROLES)}")
    if req.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of: {sorted(VALID_STATUSES)}"
        )

    membership = await add_member(
        org_id=org_id,
        user_id=req.user_id,
        role=req.role,
        team_id=req.team_id,
        status=req.status,
    )

    await audit_async(
        caller,
        {
            "event": "member_added",
            "org_id": org_id,
            "user_id": req.user_id,
            "role": req.role,
            "team_id": req.team_id,
            "status": req.status,
        },
    )

    return _membership_to_response(membership)


@router.get("/{org_id}/members", response_model=Page[MembershipResponse])
async def list_members_v2(
    org_id: str,
    tenant: Tenant = Depends(require_auth),
    team_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """List members in an organization (optionally filtered by team). Requires org membership (viewer+)."""
    memberships = await get_org_memberships(org_id, team_id=team_id)
    # Apply pagination manually
    total = len(memberships)
    paginated = memberships[offset : offset + limit]

    return {
        "items": [_membership_to_response(m) for m in paginated],
        "total": total,
        "page": offset // limit + 1,
        "page_size": limit,
        "has_next": offset + limit < total,
    }


@router.get("/{org_id}/members/{membership_id}", response_model=MembershipResponse)
async def get_member_v2(
    org_id: str,
    membership_id: str,
    _: tuple[Tenant, str] = Depends(require_org_access),
) -> dict[str, Any]:
    """Get member details. Requires org membership (viewer+)."""
    membership = await get_membership(membership_id)
    if membership is None or membership.org_id != org_id:
        raise HTTPException(status_code=404, detail="Membership not found")
    return _membership_to_response(membership)


@router.patch("/{org_id}/members/{membership_id}", response_model=MembershipResponse)
async def update_member_v2(
    org_id: str,
    membership_id: str,
    req: MembershipUpdateRequest,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update a member's role or status. Requires org_admin."""
    membership = await get_membership(membership_id)
    if membership is None or membership.org_id != org_id:
        raise HTTPException(status_code=404, detail="Membership not found")

    # Validate actor can manage target role
    actor_role = await get_user_org_role(caller["tenant_id"], org_id)
    if actor_role is None:
        raise HTTPException(status_code=403, detail="Actor not a member of this organization")

    if req.role is not None:
        if req.role not in VALID_ROLES:
            raise HTTPException(
                status_code=400, detail=f"Invalid role. Must be one of: {sorted(VALID_ROLES)}"
            )
        if not can_manage_role(actor_role, req.role):
            raise HTTPException(status_code=403, detail=f"Role {actor_role} cannot assign role {req.role}")
        updated = await update_member_role(membership_id, role=req.role, actor_role=actor_role)
        if updated is None:
            raise HTTPException(status_code=404, detail="Membership not found")
        membership = updated

    if req.status is not None:
        if req.status not in VALID_STATUSES:
            raise HTTPException(
                status_code=400, detail=f"Invalid status. Must be one of: {sorted(VALID_STATUSES)}"
            )
        updated = await update_member_status(membership_id, status=req.status)
        if updated is None:
            raise HTTPException(status_code=404, detail="Membership not found")
        membership = updated

    await audit_async(
        caller,
        {
            "event": "member_updated",
            "org_id": org_id,
            "membership_id": membership_id,
            "changes": req.model_dump(exclude_unset=True),
        },
    )

    return _membership_to_response(membership)


@router.post("/{org_id}/members/{membership_id}/remove")
async def remove_member_v2(
    org_id: str,
    membership_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Remove a member (soft delete - sets status to 'removed'). Requires org_admin."""
    membership = await get_membership(membership_id)
    if membership is None or membership.org_id != org_id:
        raise HTTPException(status_code=404, detail="Membership not found")

    removed = await remove_member(membership_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Membership not found")

    await audit_async(caller, {"event": "member_removed", "org_id": org_id, "membership_id": membership_id})

    return {"membership_id": membership_id, "status": "removed"}


@router.delete("/{org_id}/members/{membership_id}")
async def delete_membership_v2(
    org_id: str,
    membership_id: str,
    request: Request,
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Permanently delete a membership record. Requires org_admin."""
    membership = await get_membership(membership_id)
    if membership is None or membership.org_id != org_id:
        raise HTTPException(status_code=404, detail="Membership not found")

    deleted = await delete_membership(membership_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Membership not found")

    await audit_async(caller, {"event": "member_deleted", "org_id": org_id, "membership_id": membership_id})

    return {"membership_id": membership_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# User's memberships and roles
# ---------------------------------------------------------------------------


@router.get("/my/memberships")
async def get_my_memberships(
    tenant: Tenant = Depends(require_auth),
    org_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Get current user's memberships across all orgs, or filtered by org."""
    user_id = tenant["tenant_id"]
    memberships = await get_user_memberships(user_id, org_id)
    return {"memberships": [_membership_to_response(m) for m in memberships]}


@router.get("/my/orgs/{org_id}/role")
async def get_my_org_role(
    org_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get current user's highest role in an organization."""
    user_id = tenant["tenant_id"]
    role = await get_user_org_role(user_id, org_id)
    return {"org_id": org_id, "role": role}


@router.get("/my/teams/{team_id}/role")
async def get_my_team_role(
    team_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get current user's role in a specific team."""
    user_id = tenant["tenant_id"]
    role = await get_user_team_role(user_id, team_id)
    return {"team_id": team_id, "role": role}


# ---------------------------------------------------------------------------
# Invitation endpoint (placeholder for email-based invites)
# ---------------------------------------------------------------------------


@router.post("/{org_id}/invite")
async def invite_member(
    org_id: str,
    request: Request,
    email: str = Query(..., description="Email to invite"),
    role: str = Query(default="org_member", description="Role for the invited user"),
    team_id: str | None = Query(default=None, description="Optional team to add to"),
    _: tuple[Tenant, str] = Depends(require_org_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Invite a user to the organization by email.

    This creates a pending membership. The user must accept the invitation
    (implementation depends on auth system).
    """
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(VALID_ROLES)}")

    # No message is sent and no acceptance token exists, so returning a pending
    # membership would report success for an invitation nobody can accept.
    # Fail explicitly until the email/acceptance flow exists.
    raise HTTPException(
        status_code=501,
        detail=(
            "Email invitations are not implemented: no message is sent and no "
            "acceptance token exists. Add the member directly with "
            "POST /api/v2/orgs/{org_id}/members."
        ),
    )
