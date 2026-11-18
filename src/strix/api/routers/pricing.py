"""Pricing tier API endpoints.

Provides endpoints for:
- Listing available pricing tiers
- Getting current tier info and limits
- Upgrading/downgrading tiers
- Usage reporting
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, audit_async, require_admin, require_auth
from strix.api.schemas import (
    FeatureFlagsModel,
    PricingTierEnum,
    TierInfoModel,
    TierLimitsModel,
    TierUpgradeRequest,
    TierUpgradeResponse,
    UsageReportModel,
)
from strix.core import store
from strix.core.pricing import (
    FeatureFlags,
    PricingTier,
    get_tier_info,
    get_tier_limits,
    is_downgrade,
    is_upgrade,
    list_all_tiers,
)

router = APIRouter(prefix="/api", tags=["pricing"])


def _convert_tier_limits(limits) -> TierLimitsModel:
    """Convert core TierLimits to API model."""
    return TierLimitsModel(
        assessments_per_month=limits.assessments_per_month,
        max_concurrent_assessments=limits.max_concurrent_assessments,
        max_users=limits.max_users,
        retention_days=limits.retention_days,
        api_rate_limit_rpm=limits.api_rate_limit_rpm,
        max_projects=limits.max_projects,
        max_webhooks=limits.max_webhooks,
        max_schedules=limits.max_schedules,
        max_finding_records=limits.max_finding_records,
    )


def _convert_feature_flags(features: FeatureFlags) -> FeatureFlagsModel:
    """Convert core FeatureFlags to API model."""
    return FeatureFlagsModel(
        web_assessment=features.web_assessment,
        api_assessment=features.api_assessment,
        network_assessment=features.network_assessment,
        agent_assessment=features.agent_assessment,
        full_web_profile=features.full_web_profile,
        full_api_profile=features.full_api_profile,
        oidc_sso=features.oidc_sso,
        saml_sso=features.saml_sso,
        scim_provisioning=features.scim_provisioning,
        multi_tenant=features.multi_tenant,
        org_hierarchy=features.org_hierarchy,
        teams_rbac=features.teams_rbac,
        custom_roles=features.custom_roles,
        sarif_export=features.sarif_export,
        html_report=features.html_report,
        pdf_report=features.pdf_report,
        custom_reports=features.custom_reports,
        compliance_reports=features.compliance_reports,
        webhook_delivery=features.webhook_delivery,
        github_integration=features.github_integration,
        gitlab_integration=features.gitlab_integration,
        jira_integration=features.jira_integration,
        slack_integration=features.slack_integration,
        finding_deduplication=features.finding_deduplication,
        finding_trends=features.finding_trends,
        verified_resolution=features.verified_resolution,
        risk_acceptance_workflow=features.risk_acceptance_workflow,
        asset_inventory=features.asset_inventory,
        custom_policies=features.custom_policies,
        api_key_scoping=features.api_key_scoping,
        mssp_partner_portal=features.mssp_partner_portal,
        multi_customer_management=features.multi_customer_management,
        white_label_reports=features.white_label_reports,
        dedicated_support=features.dedicated_support,
    )


def _convert_tier_info(info) -> TierInfoModel:
    """Convert core TierInfo to API model."""
    return TierInfoModel(
        tier=PricingTierEnum(info.tier.value),
        name=info.name,
        description=info.description,
        limits=_convert_tier_limits(info.limits),
        features=_convert_feature_flags(info.features),
        monthly_price_usd=info.monthly_price_usd,
        annual_price_usd=info.annual_price_usd,
    )


@router.get("/pricing/tiers")
async def list_tiers() -> dict[str, Any]:
    """List all available pricing tiers with their limits and features."""
    tiers = [_convert_tier_info(t) for t in list_all_tiers()]
    return {"tiers": tiers}


@router.get("/pricing/tiers/{tier}")
async def get_tier(tier: PricingTierEnum) -> TierInfoModel:
    """Get detailed information for a specific pricing tier."""
    try:
        pricing_tier = PricingTier(tier.value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"Tier '{tier}' not found") from exc

    info = get_tier_info(pricing_tier)
    return _convert_tier_info(info)


@router.get("/pricing/current")
async def get_current_tier(
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get current tenant's tier information and limits."""
    tenant_tier = tenant.get("tier", "free")
    try:
        pricing_tier = PricingTier(tenant_tier)
    except ValueError:
        pricing_tier = PricingTier.FREE

    info = get_tier_info(pricing_tier)

    return {
        "tier": _convert_tier_info(info),
        "current_usage": await _get_current_usage(tenant["tenant_id"]),
    }


@router.get("/pricing/usage")
async def get_usage_report(
    tenant: Tenant = Depends(require_auth),
) -> UsageReportModel:
    """Get current usage report for the authenticated tenant."""
    tenant_id = tenant["tenant_id"]
    tenant_tier = tenant.get("tier", "free")

    try:
        pricing_tier = PricingTier(tenant_tier)
    except ValueError:
        pricing_tier = PricingTier.FREE

    limits = get_tier_limits(pricing_tier)
    usage = await _get_current_usage(tenant_id)

    # Calculate overages
    overages = {}
    if limits.assessments_per_month > 0 and usage["assessments_used"] >= limits.assessments_per_month:
        overages["assessments"] = usage["assessments_used"] - limits.assessments_per_month
    if limits.max_concurrent_assessments > 0 and usage["concurrent_assessments"] >= limits.max_concurrent_assessments:
        overages["concurrent"] = usage["concurrent_assessments"] - limits.max_concurrent_assessments
    if limits.max_users > 0 and usage["users_count"] >= limits.max_users:
        overages["users"] = usage["users_count"] - limits.max_users
    if limits.api_rate_limit_rpm > 0 and usage["api_calls_used"] >= limits.api_rate_limit_rpm:
        overages["api_calls"] = usage["api_calls_used"] - limits.api_rate_limit_rpm

    return UsageReportModel(
        tenant_id=tenant_id,
        current_tier=PricingTierEnum(pricing_tier.value),
        period_start=usage["period_start"],
        period_end=usage["period_end"],
        assessments_used=usage["assessments_used"],
        assessments_limit=limits.assessments_per_month,
        concurrent_assessments=usage["concurrent_assessments"],
        concurrent_limit=limits.max_concurrent_assessments,
        users_count=usage["users_count"],
        users_limit=limits.max_users,
        api_calls_used=usage["api_calls_used"],
        api_calls_limit=limits.api_rate_limit_rpm,
        findings_count=usage["findings_count"],
        findings_limit=limits.max_finding_records,
        retention_days_used=usage["retention_days_used"],
        retention_days_limit=limits.retention_days,
        projects_count=usage["projects_count"],
        projects_limit=limits.max_projects,
        webhooks_count=usage["webhooks_count"],
        webhooks_limit=limits.max_webhooks,
        schedules_count=usage["schedules_count"],
        schedules_limit=limits.max_schedules,
        overages=overages,
    )


@router.post("/pricing/upgrade")
async def upgrade_tier(
    request: Request,
    req: TierUpgradeRequest,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> TierUpgradeResponse:
    """Upgrade or downgrade the tenant's pricing tier.

    Requires admin privileges. In a production system, this would integrate
    with a billing provider (Stripe, etc.). For now, it updates the tier
    in the database immediately.
    """
    tenant_id = tenant["tenant_id"]
    current_tier_str = tenant.get("tier", "free")

    try:
        current_tier = PricingTier(current_tier_str)
    except ValueError:
        current_tier = PricingTier.FREE

    try:
        new_tier = PricingTier(req.tier.value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    if current_tier == new_tier:
        raise HTTPException(status_code=400, detail="Already on this tier")

    # Check if upgrade or downgrade
    upgrade = is_upgrade(current_tier, new_tier)
    downgrade = is_downgrade(current_tier, new_tier)

    # For downgrades, check if current usage exceeds new limits
    if downgrade:
        limits = get_tier_limits(new_tier)
        usage = await _get_current_usage(tenant_id)

        violations = []
        if limits.assessments_per_month > 0 and usage["assessments_used"] > limits.assessments_per_month:
            violations.append(f"Assessments used ({usage['assessments_used']}) exceeds limit ({limits.assessments_per_month})")
        if limits.max_users > 0 and usage["users_count"] > limits.max_users:
            violations.append(f"Users ({usage['users_count']}) exceeds limit ({limits.max_users})")
        if limits.max_projects > 0 and usage["projects_count"] > limits.max_projects:
            violations.append(f"Projects ({usage['projects_count']}) exceeds limit ({limits.max_projects})")

        if violations:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot downgrade: current usage exceeds {new_tier.value} limits: {'; '.join(violations)}",
            )

    # Update tenant tier in database
    db = await store.get_database()
    now = time.time()
    async with db.transaction() as conn:
        await store._execute(
            conn,
            "UPDATE api_keys SET tier = ?, updated_at = ? WHERE tenant_id = ?",
            new_tier.value,
            now,
            tenant_id,
        )

    # Determine effective date
    if downgrade:
        # Downgrades take effect at next billing cycle
        effective_date = now + 30 * 86400  # 30 days
        prorated = False
    else:
        # Upgrades take effect immediately
        effective_date = now
        prorated = True

    await audit_async(
        tenant,
        {
            "event": "tier_changed",
            "tenant_id": tenant_id,
            "from_tier": current_tier.value,
            "to_tier": new_tier.value,
            "billing_cycle": req.billing_cycle,
            "upgrade": upgrade,
        },
    )

    return TierUpgradeResponse(
        previous_tier=PricingTierEnum(current_tier.value),
        new_tier=PricingTierEnum(new_tier.value),
        effective_date=effective_date,
        billing_cycle=req.billing_cycle,
        prorated=prorated,
    )


@router.get("/pricing/features/{feature}")
async def check_feature_access(
    feature: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Check if current tenant has access to a specific feature."""
    tenant_tier = tenant.get("tier", "free")
    try:
        pricing_tier = PricingTier(tenant_tier)
    except ValueError:
        pricing_tier = PricingTier.FREE

    from strix.core.pricing import FEATURE_DESCRIPTIONS, can_access_feature

    has_access = can_access_feature(pricing_tier, feature)
    description = FEATURE_DESCRIPTIONS.get(feature, "Unknown feature")

    return {
        "feature": feature,
        "description": description,
        "has_access": has_access,
        "current_tier": pricing_tier.value,
    }


async def _get_current_usage(tenant_id: str) -> dict[str, Any]:
    """Get current usage statistics for a tenant."""
    db = await store.get_database()
    now = time.time()
    period_start = now - 30 * 86400  # Last 30 days
    period_end = now

    async with db.transaction() as conn:
        # Assessments this period
        assessments_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM jobs WHERE tenant = ? AND created_at >= ? AND created_at <= ?",
            tenant_id,
            period_start,
            period_end,
        )
        assessments_used = assessments_row["cnt"] if assessments_row else 0

        # Concurrent running assessments
        concurrent_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM jobs WHERE tenant = ? AND state IN ('running', 'queued')",
            tenant_id,
        )
        concurrent_assessments = concurrent_row["cnt"] if concurrent_row else 0

        # Users (tenant_users table)
        users_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM tenant_users WHERE tenant_id = ? AND active = 1",
            tenant_id,
        )
        users_count = users_row["cnt"] if users_row else 1  # At least the admin

        # API calls (from audit log or rate limiter - simplified)
        # For now, estimate from jobs * average calls per job
        api_calls_used = assessments_used * 50  # Rough estimate

        # Findings count
        findings_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM findings WHERE tenant = ?",
            tenant_id,
        )
        findings_count = findings_row["cnt"] if findings_row else 0

        # Retention days used (approximate from oldest finding)
        retention_row = await store._fetchone(
            conn,
            "SELECT MIN(created_at) as oldest FROM jobs WHERE tenant = ?",
            tenant_id,
        )
        retention_days_used = 0
        if retention_row and retention_row["oldest"]:
            retention_days_used = int((now - retention_row["oldest"]) / 86400)

        # Projects
        projects_row = await store._fetchone(
            conn,
            "SELECT COUNT(DISTINCT project) as cnt FROM jobs WHERE tenant = ?",
            tenant_id,
        )
        projects_count = projects_row["cnt"] if projects_row else 1

        # Webhooks
        webhooks_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM webhook_sinks",
        )
        webhooks_count = webhooks_row["cnt"] if webhooks_row else 0

        # Schedules
        schedules_row = await store._fetchone(
            conn,
            "SELECT COUNT(*) as cnt FROM assessment_schedules WHERE target IN (SELECT target FROM jobs WHERE tenant = ?)",
            tenant_id,
        )
        schedules_count = schedules_row["cnt"] if schedules_row else 0

    return {
        "period_start": period_start,
        "period_end": period_end,
        "assessments_used": assessments_used,
        "concurrent_assessments": concurrent_assessments,
        "users_count": users_count,
        "api_calls_used": api_calls_used,
        "findings_count": findings_count,
        "retention_days_used": retention_days_used,
        "projects_count": projects_count,
        "webhooks_count": webhooks_count,
        "schedules_count": schedules_count,
    }
