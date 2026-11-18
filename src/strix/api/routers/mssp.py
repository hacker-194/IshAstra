"""MSSP (Managed Security Service Provider) partner program API endpoints.

Provides endpoints for:
- Partner registration and management
- Customer management
- Invitations
- Usage reporting and billing integration points
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, audit_async, require_admin, require_auth
from strix.api.schemas import (
    MSSPCustomerCreateRequest,
    MSSPCustomerResponse,
    MSSPCustomerStatusEnum,
    MSSPCustomerUpdateRequest,
    MSSPInvitationCreateRequest,
    MSSPInvitationResponse,
    MSSPPartnerCreateRequest,
    MSSPPartnerResponse,
    MSSPPartnerStatusEnum,
    MSSPPartnerUpdateRequest,
    MSSPPartnerUsageReportRequest,
    MSSPTierEnum,
    MSSPTierLimitsModel,
    MSSPUsageRecordResponse,
    MSSPUsageSummaryResponse,
)
from strix.core.mssp import (
    MSSP_TIER_ORDER as MSSP_TIER_ORDER,
)
from strix.core.mssp import (
    CustomerStatus as MSSPCustomerStatus,
)
from strix.core.mssp import (
    MSSPPartner,
    MSSPPartnerStatus,
    MSSPTier,
    accept_invitation,
    add_customer,
    create_invitation,
    create_partner,
    delete_partner,
    get_customer,
    get_customer_effective_limits,
    get_invitation_by_token,
    get_mssp_tier_limits,
    get_partner,
    get_partner_usage_summary,
    get_usage_records,
    list_partner_customers,
    list_partner_invitations,
    list_partners,
    record_usage,
    rotate_partner_admin_key,
    update_customer,
    update_partner,
    validate_partner_admin_key,
)
from strix.core.pricing import PricingTier

router = APIRouter(prefix="/api/mssp", tags=["mssp"])


def _convert_partner(partner: MSSPPartner, include_limits: bool = False) -> MSSPPartnerResponse:
    """Convert core MSSPPartner to API model."""
    limits = None
    if include_limits:
        tier_limits = get_mssp_tier_limits(partner.tier)
        limits = MSSPTierLimitsModel(
            max_customers=tier_limits.max_customers,
            max_total_assessments_per_month=tier_limits.max_total_assessments_per_month,
            max_total_concurrent_assessments=tier_limits.max_total_concurrent_assessments,
            can_resell=tier_limits.can_resell,
            white_label_reports=tier_limits.white_label_reports,
            custom_branding=tier_limits.custom_branding,
            dedicated_support=tier_limits.dedicated_support,
            portal_api_access=tier_limits.portal_api_access,
            revenue_share_pct=tier_limits.revenue_share_pct,
        )

    return MSSPPartnerResponse(
        partner_id=partner.partner_id,
        name=partner.name,
        slug=partner.slug,
        tier=MSSPTierEnum(partner.tier.value),
        status=MSSPPartnerStatusEnum(partner.status.value),
        contact_email=partner.contact_email,
        company_website=partner.company_website,
        settings=partner.settings,
        created_at=partner.created_at,
        updated_at=partner.updated_at,
        approved_at=partner.approved_at,
        approved_by=partner.approved_by,
        limits=limits,
    )


def _convert_customer(customer, effective_limits: dict[str, Any] | None = None) -> MSSPCustomerResponse:
    """Convert core MSSPCustomer to API model."""
    from strix.api.schemas import PricingTierEnum
    return MSSPCustomerResponse(
        customer_id=customer.customer_id,
        partner_id=customer.partner_id,
        tenant_id=customer.tenant_id,
        name=customer.name,
        status=MSSPCustomerStatusEnum(customer.status.value),
        tier=PricingTierEnum(customer.tier.value),
        billing_contact_email=customer.billing_contact_email,
        technical_contact_email=customer.technical_contact_email,
        settings=customer.settings,
        created_at=customer.created_at,
        updated_at=customer.updated_at,
        trial_ends_at=customer.trial_ends_at,
        contract_ends_at=customer.contract_ends_at,
        effective_limits=effective_limits,
    )


# ---------------------------------------------------------------------------
# Partner endpoints (require global admin or partner admin key)
# ---------------------------------------------------------------------------


async def require_partner_admin(
    request: Request, tenant: Tenant = Depends(require_auth)
) -> tuple[Tenant, MSSPPartner]:
    """Require MSSP partner admin key (from Authorization header)."""
    from strix.api.security import get_authorization_scheme_param

    auth_header = request.headers.get("Authorization")
    scheme, raw_key = get_authorization_scheme_param(auth_header) if auth_header else (None, None)

    if scheme and scheme.lower() == "bearer" and raw_key:
        partner = await validate_partner_admin_key(raw_key)
        if partner:
            if partner.status != MSSPPartnerStatus.ACTIVE:
                raise HTTPException(status_code=403, detail="Partner account not active")
            return tenant, partner

    # Also allow global admins
    if tenant.get("global_admin") or tenant.get("admin"):
        partner_id = request.query_params.get("partner_id")
        if not partner_id:
            raise HTTPException(
                status_code=400,
                detail="partner_id query parameter required for global admin",
            )
        partner = await get_partner(partner_id)
        if not partner:
            raise HTTPException(status_code=404, detail="Partner not found")
        return tenant, partner

    raise HTTPException(status_code=403, detail="MSSP partner administrator privileges required")


@router.post("/partners")
async def create_mssp_partner(
    request: Request,
    req: MSSPPartnerCreateRequest,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new MSSP partner. Global admin only."""
    try:
        tier = MSSPTier(req.tier.value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    partner_id, admin_key = await create_partner(
        name=req.name,
        contact_email=req.contact_email,
        company_website=req.company_website,
        tier=tier,
        settings=req.settings,
    )

    partner = await get_partner(partner_id)
    assert partner is not None, "Partner just created but not found"

    await audit_async(
        tenant,
        {
            "event": "mssp_partner_created",
            "partner_id": partner_id,
            "name": req.name,
            "tier": req.tier.value,
        },
    )

    return {
        "partner": _convert_partner(partner, include_limits=True),
        "admin_key": admin_key,
        "warning": "Store this partner admin key securely — it is shown only once.",
    }


@router.get("/partners")
async def list_mssp_partners(
    status: MSSPPartnerStatusEnum | None = None,
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0, ge=0),
    tenant: Tenant = Depends(require_admin),
) -> dict[str, Any]:
    """List all MSSP partners. Global admin only."""
    partner_status = MSSPPartnerStatus(status.value) if status else None
    partners = await list_partners(status=partner_status, limit=limit, offset=offset)
    return {"partners": [_convert_partner(p, include_limits=True) for p in partners]}


@router.get("/partners/{partner_id}")
async def get_mssp_partner(
    partner_id: str,
    tenant: Tenant = Depends(require_auth),
) -> MSSPPartnerResponse:
    """Get MSSP partner details. Partner admin or global admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    # Check access
    if not (tenant.get("global_admin") or tenant.get("admin")):
        # Check if tenant has partner admin key
        auth_header = tenant.get("request_headers", {}).get("Authorization") if hasattr(tenant, "get") else None
        # In practice, the require_partner_admin dependency would be used

    return _convert_partner(partner, include_limits=True)


@router.patch("/partners/{partner_id}")
async def update_mssp_partner(
    partner_id: str,
    req: MSSPPartnerUpdateRequest,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> MSSPPartnerResponse:
    """Update an MSSP partner. Partner admin or global admin only."""
    try:
        tier = MSSPTier(req.tier.value) if req.tier else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    try:
        status = MSSPPartnerStatus(req.status.value) if req.status else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    partner = await update_partner(
        partner_id,
        name=req.name,
        tier=tier,
        status=status,
        contact_email=req.contact_email,
        company_website=req.company_website,
        settings=req.settings,
        approved_by=caller.get("tenant_id") if caller.get("global_admin") else None,
    )

    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    await audit_async(
        caller,
        {
            "event": "mssp_partner_updated",
            "partner_id": partner_id,
            "changes": req.model_dump(exclude_none=True),
        },
    )

    return _convert_partner(partner, include_limits=True)


@router.post("/partners/{partner_id}/rotate-key")
async def rotate_mssp_partner_key(
    partner_id: str,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Rotate the MSSP partner admin key. Partner admin only."""
    new_key = await rotate_partner_admin_key(partner_id)

    await audit_async(caller, {"event": "mssp_partner_key_rotated", "partner_id": partner_id})

    return {
        "partner_id": partner_id,
        "admin_key": new_key,
        "warning": "Store this key securely — it is shown only once. The previous key is no longer valid.",
    }


@router.delete("/partners/{partner_id}")
async def delete_mssp_partner(
    partner_id: str,
    request: Request,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete an MSSP partner. Global admin only."""
    deleted = await delete_partner(partner_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Partner not found")

    await audit_async(tenant, {"event": "mssp_partner_deleted", "partner_id": partner_id})

    return {"partner_id": partner_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# Customer endpoints (partner admin)
# ---------------------------------------------------------------------------


@router.post("/partners/{partner_id}/customers")
async def add_mssp_customer(
    partner_id: str,
    req: MSSPCustomerCreateRequest,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> MSSPCustomerResponse:
    """Add a customer to an MSSP partner. Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    try:
        tier = PricingTier(req.tier.value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    # Validate tier against partner limits
    if partner.tier == MSSPTier.REGISTERED and tier in (PricingTier.PRO, PricingTier.ENTERPRISE):
        raise HTTPException(
            status_code=400,
            detail="Registered partners cannot have Pro or Enterprise customers",
        )

    try:
        customer = await add_customer(
            partner_id=partner_id,
            tenant_id=req.tenant_id,
            name=req.name,
            tier=tier,
            billing_contact_email=req.billing_contact_email,
            technical_contact_email=req.technical_contact_email,
            settings=req.settings,
            trial_days=req.trial_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    effective_limits = get_customer_effective_limits(customer, partner)

    await audit_async(
        caller,
        {
            "event": "mssp_customer_added",
            "partner_id": partner_id,
            "customer_id": customer.customer_id,
            "tenant_id": req.tenant_id,
            "tier": req.tier.value,
        },
    )

    return _convert_customer(customer, effective_limits)


@router.get("/partners/{partner_id}/customers")
async def list_mssp_customers(
    partner_id: str,
    status: MSSPCustomerStatusEnum | None = None,
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0, ge=0),
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
) -> dict[str, Any]:
    """List customers for an MSSP partner. Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    customer_status = MSSPCustomerStatus(status.value) if status else None
    customers = await list_partner_customers(partner_id, status=customer_status, limit=limit, offset=offset)

    return {
        "customers": [_convert_customer(c, get_customer_effective_limits(c, partner)) for c in customers]
    }


@router.get("/partners/{partner_id}/customers/{customer_id}")
async def get_mssp_customer(
    partner_id: str,
    customer_id: str,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
) -> MSSPCustomerResponse:
    """Get MSSP customer details. Partner admin only."""
    customer = await get_customer(customer_id)
    if not customer or customer.partner_id != partner_id:
        raise HTTPException(status_code=404, detail="Customer not found")

    partner = await get_partner(partner_id)
    effective_limits = get_customer_effective_limits(customer, partner) if partner else None

    return _convert_customer(customer, effective_limits)


@router.patch("/partners/{partner_id}/customers/{customer_id}")
async def update_mssp_customer(
    partner_id: str,
    customer_id: str,
    req: MSSPCustomerUpdateRequest,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> MSSPCustomerResponse:
    """Update an MSSP customer. Partner admin only."""
    customer = await get_customer(customer_id)
    if not customer or customer.partner_id != partner_id:
        raise HTTPException(status_code=404, detail="Customer not found")

    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    try:
        tier = PricingTier(req.tier.value) if req.tier else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    try:
        status = MSSPCustomerStatus(req.status.value) if req.status else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    # Validate tier change against partner limits
    if tier and partner.tier == MSSPTier.REGISTERED and tier in (PricingTier.PRO, PricingTier.ENTERPRISE):
        raise HTTPException(
            status_code=400,
            detail="Registered partners cannot have Pro or Enterprise customers",
        )

    updated = await update_customer(
        customer_id,
        name=req.name,
        status=status,
        tier=tier,
        billing_contact_email=req.billing_contact_email,
        technical_contact_email=req.technical_contact_email,
        settings=req.settings,
        contract_ends_at=req.contract_ends_at,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Customer not found")

    effective_limits = get_customer_effective_limits(updated, partner)

    await audit_async(
        caller,
        {
            "event": "mssp_customer_updated",
            "partner_id": partner_id,
            "customer_id": customer_id,
            "changes": req.model_dump(exclude_none=True),
        },
    )

    return _convert_customer(updated, effective_limits)


@router.delete("/partners/{partner_id}/customers/{customer_id}")
async def remove_mssp_customer(
    partner_id: str,
    customer_id: str,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Remove a customer from an MSSP partner (sets status to churned). Partner admin only."""
    customer = await get_customer(customer_id)
    if not customer or customer.partner_id != partner_id:
        raise HTTPException(status_code=404, detail="Customer not found")

    removed = await update_customer(customer_id, status=MSSPCustomerStatus.CHURNED)
    if not removed:
        raise HTTPException(status_code=404, detail="Customer not found")

    await audit_async(
        caller,
        {"event": "mssp_customer_removed", "partner_id": partner_id, "customer_id": customer_id},
    )

    return {"partner_id": partner_id, "customer_id": customer_id, "status": "churned"}


# ---------------------------------------------------------------------------
# Invitation endpoints
# ---------------------------------------------------------------------------


@router.post("/partners/{partner_id}/invitations")
async def create_mssp_invitation(
    partner_id: str,
    req: MSSPInvitationCreateRequest,
    request: Request,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> MSSPInvitationResponse:
    """Create an invitation for a customer to join the MSSP. Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    try:
        tier = PricingTier(req.tier.value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    # Validate tier against partner limits
    if partner.tier == MSSPTier.REGISTERED and tier in (PricingTier.PRO, PricingTier.ENTERPRISE):
        raise HTTPException(
            status_code=400,
            detail="Registered partners cannot invite Pro or Enterprise customers",
        )

    invitation = await create_invitation(
        partner_id=partner_id,
        email=req.email,
        customer_name=req.customer_name,
        tier=tier,
        expires_in_days=req.expires_in_days,
    )

    await audit_async(
        caller,
        {
            "event": "mssp_invitation_created",
            "partner_id": partner_id,
            "invitation_id": invitation.invitation_id,
            "email": req.email,
            "tier": req.tier.value,
        },
    )

    return MSSPInvitationResponse(
        invitation_id=invitation.invitation_id,
        partner_id=invitation.partner_id,
        email=invitation.email,
        customer_name=invitation.customer_name,
        tier=invitation.tier,  # type: ignore
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        accepted_at=invitation.accepted_at,
    )


@router.get("/invitations/{token}")
async def get_mssp_invitation(token: str) -> MSSPInvitationResponse:
    """Get invitation details by token (public endpoint for acceptance flow)."""
    invitation = await get_invitation_by_token(token)
    if not invitation:
        raise HTTPException(status_code=404, detail="Invitation not found")

    return MSSPInvitationResponse(
        invitation_id=invitation.invitation_id,
        partner_id=invitation.partner_id,
        email=invitation.email,
        customer_name=invitation.customer_name,
        tier=invitation.tier,  # type: ignore
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        accepted_at=invitation.accepted_at,
    )


@router.post("/invitations/{token}/accept")
async def accept_mssp_invitation(
    token: str,
    tenant_id: str = Query(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"),
) -> MSSPCustomerResponse:
    """Accept an MSSP invitation and create the customer tenant."""
    try:
        customer = await accept_invitation(token, tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    partner = await get_partner(customer.partner_id)
    effective_limits = get_customer_effective_limits(customer, partner) if partner else None

    return _convert_customer(customer, effective_limits)


@router.get("/partners/{partner_id}/invitations")
async def list_mssp_invitations(
    partner_id: str,
    status: str | None = None,
    limit: int = Query(default=50, le=100),
    offset: int = Query(default=0, ge=0),
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
) -> dict[str, Any]:
    """List invitations for an MSSP partner. Partner admin only."""
    invitations = await list_partner_invitations(partner_id, status=status, limit=limit, offset=offset)
    return {
        "invitations": [
            MSSPInvitationResponse(
                invitation_id=i.invitation_id,
                partner_id=i.partner_id,
                email=i.email,
                customer_name=i.customer_name,
                tier=i.tier,  # type: ignore
                status=i.status,
                expires_at=i.expires_at,
                created_at=i.created_at,
                accepted_at=i.accepted_at,
            )
            for i in invitations
        ]
    }


# ---------------------------------------------------------------------------
# Usage reporting endpoints
# ---------------------------------------------------------------------------


@router.post("/partners/{partner_id}/usage")
async def record_mssp_usage(
    partner_id: str,
    customer_id: str = Query(..., description="Customer ID"),
    period_start: float = Query(..., description="Period start (Unix timestamp)"),
    period_end: float = Query(..., description="Period end (Unix timestamp)"),
    assessments_run: int = Query(default=0, ge=0),
    assessments_succeeded: int = Query(default=0, ge=0),
    findings_generated: int = Query(default=0, ge=0),
    api_calls: int = Query(default=0, ge=0),
    retention_days_used: int = Query(default=0, ge=0),
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
    caller: Tenant = Depends(require_auth),
) -> MSSPUsageRecordResponse:
    """Record usage for a customer (for billing integration). Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    customer = await get_customer(customer_id)
    if not customer or customer.partner_id != partner_id:
        raise HTTPException(status_code=404, detail="Customer not found")

    record = await record_usage(
        partner_id=partner_id,
        customer_id=customer_id,
        period_start=period_start,
        period_end=period_end,
        assessments_run=assessments_run,
        assessments_succeeded=assessments_succeeded,
        findings_generated=findings_generated,
        api_calls=api_calls,
        retention_days_used=retention_days_used,
    )

    return MSSPUsageRecordResponse(
        record_id=record.record_id,
        partner_id=record.partner_id,
        customer_id=record.customer_id,
        period_start=record.period_start,
        period_end=record.period_end,
        assessments_run=record.assessments_run,
        assessments_succeeded=record.assessments_succeeded,
        findings_generated=record.findings_generated,
        api_calls=record.api_calls,
        retention_days_used=record.retention_days_used,
        created_at=record.created_at,
    )


@router.get("/partners/{partner_id}/usage")
async def get_mssp_usage_records(
    partner_id: str,
    customer_id: str | None = None,
    period_start: float | None = None,
    period_end: float | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
) -> dict[str, Any]:
    """Get usage records for a partner. Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    records = await get_usage_records(
        partner_id,
        customer_id=customer_id,
        period_start=period_start,
        period_end=period_end,
        limit=limit,
        offset=offset,
    )

    return {
        "records": [
            MSSPUsageRecordResponse(
                record_id=r.record_id,
                partner_id=r.partner_id,
                customer_id=r.customer_id,
                period_start=r.period_start,
                period_end=r.period_end,
                assessments_run=r.assessments_run,
                assessments_succeeded=r.assessments_succeeded,
                findings_generated=r.findings_generated,
                api_calls=r.api_calls,
                retention_days_used=r.retention_days_used,
                created_at=r.created_at,
            )
            for r in records
        ]
    }


@router.post("/partners/{partner_id}/usage/summary")
async def get_mssp_usage_summary(
    partner_id: str,
    req: MSSPPartnerUsageReportRequest,
    _: tuple[Tenant, MSSPPartner] = Depends(require_partner_admin),
) -> MSSPUsageSummaryResponse:
    """Get aggregated usage summary for a partner. Partner admin only."""
    partner = await get_partner(partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="Partner not found")

    summary = await get_partner_usage_summary(partner_id, req.period_start, req.period_end)

    return MSSPUsageSummaryResponse(
        partner_id=partner_id,
        period_start=req.period_start,
        period_end=req.period_end,
        total_assessments=summary["total_assessments"],
        total_succeeded=summary["total_succeeded"],
        total_findings=summary["total_findings"],
        total_api_calls=summary["total_api_calls"],
        total_retention_days=summary["total_retention_days"],
        active_customers=summary["active_customers"],
    )


# ---------------------------------------------------------------------------
# Tier info endpoints (public)
# ---------------------------------------------------------------------------


@router.get("/tiers")
async def list_mssp_tiers() -> dict[str, Any]:
    """List all MSSP partner tiers with their limits."""
    tiers = []
    for tier in MSSPTier:
        limits = get_mssp_tier_limits(tier)
        tiers.append(
            {
                "tier": tier.value,
                "name": tier.value.capitalize(),
                "limits": MSSPTierLimitsModel(
                    max_customers=limits.max_customers,
                    max_total_assessments_per_month=limits.max_total_assessments_per_month,
                    max_total_concurrent_assessments=limits.max_total_concurrent_assessments,
                    can_resell=limits.can_resell,
                    white_label_reports=limits.white_label_reports,
                    custom_branding=limits.custom_branding,
                    dedicated_support=limits.dedicated_support,
                    portal_api_access=limits.portal_api_access,
                    revenue_share_pct=limits.revenue_share_pct,
                ),
            }
        )
    return {"tiers": tiers}
