"""Pricing tier models and feature flags for future premium launch.

This module provides the data models and business logic for Strix pricing tiers.
All features remain MIT-licensed and open-source. No payment processing — just
the data models and API structure for future premium features.

Tiers:
- FREE: Community/individual use, limited assessments
- STARTER: Small teams, basic features
- PRO: Growing teams, advanced features
- ENTERPRISE: Large organizations, full features + MSSP support
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PricingTier(str, Enum):
    """Available pricing tiers."""

    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# Tier order for comparison (higher = more features)
TIER_ORDER = {
    PricingTier.FREE: 0,
    PricingTier.STARTER: 1,
    PricingTier.PRO: 2,
    PricingTier.ENTERPRISE: 3,
}


@dataclass(frozen=True)
class TierLimits:
    """Resource limits for a pricing tier."""

    # Assessments per month (0 = unlimited)
    assessments_per_month: int

    # Maximum concurrent assessments
    max_concurrent_assessments: int

    # Maximum users in the organization/tenant
    max_users: int

    # Data retention in days (0 = unlimited)
    retention_days: int

    # API rate limit (requests per minute)
    api_rate_limit_rpm: int

    # Maximum projects
    max_projects: int

    # Maximum webhook sinks
    max_webhooks: int

    # Maximum scheduled assessments
    max_schedules: int

    # Maximum finding records retained
    max_finding_records: int


# Default limits per tier
TIER_LIMITS: dict[PricingTier, TierLimits] = {
    PricingTier.FREE: TierLimits(
        assessments_per_month=10,
        max_concurrent_assessments=1,
        max_users=1,
        retention_days=30,
        api_rate_limit_rpm=30,
        max_projects=1,
        max_webhooks=2,
        max_schedules=2,
        max_finding_records=1000,
    ),
    PricingTier.STARTER: TierLimits(
        assessments_per_month=100,
        max_concurrent_assessments=2,
        max_users=5,
        retention_days=90,
        api_rate_limit_rpm=100,
        max_projects=5,
        max_webhooks=10,
        max_schedules=10,
        max_finding_records=10000,
    ),
    PricingTier.PRO: TierLimits(
        assessments_per_month=1000,
        max_concurrent_assessments=5,
        max_users=25,
        retention_days=365,
        api_rate_limit_rpm=500,
        max_projects=25,
        max_webhooks=50,
        max_schedules=50,
        max_finding_records=100000,
    ),
    PricingTier.ENTERPRISE: TierLimits(
        assessments_per_month=0,  # unlimited
        max_concurrent_assessments=20,
        max_users=0,  # unlimited
        retention_days=0,  # unlimited
        api_rate_limit_rpm=2000,
        max_projects=0,  # unlimited
        max_webhooks=0,  # unlimited
        max_schedules=0,  # unlimited
        max_finding_records=0,  # unlimited
    ),
}


@dataclass(frozen=True)
class FeatureFlags:
    """Feature flags per tier."""

    # Assessment features
    web_assessment: bool = True
    api_assessment: bool = True
    network_assessment: bool = True
    agent_assessment: bool = False
    full_web_profile: bool = False  # web-full with Nikto, sqlmap
    full_api_profile: bool = False  # api-full with Nikto, sqlmap

    # Authentication & SSO
    oidc_sso: bool = False
    saml_sso: bool = False
    scim_provisioning: bool = False

    # Organization features
    multi_tenant: bool = False
    org_hierarchy: bool = False
    teams_rbac: bool = False
    custom_roles: bool = False

    # Reporting & export
    sarif_export: bool = True
    html_report: bool = True
    pdf_report: bool = False
    custom_reports: bool = False
    compliance_reports: bool = False  # NRB/NTA/NCSP

    # Integrations
    webhook_delivery: bool = True
    github_integration: bool = False
    gitlab_integration: bool = False
    jira_integration: bool = False
    slack_integration: bool = False

    # Advanced features
    finding_deduplication: bool = True
    finding_trends: bool = False
    verified_resolution: bool = False
    risk_acceptance_workflow: bool = False
    asset_inventory: bool = True
    custom_policies: bool = False
    api_key_scoping: bool = False  # project-scoped, read-only keys

    # MSSP features
    mssp_partner_portal: bool = False
    multi_customer_management: bool = False
    white_label_reports: bool = False
    dedicated_support: bool = False


# Feature flags per tier
TIER_FEATURES: dict[PricingTier, FeatureFlags] = {
    PricingTier.FREE: FeatureFlags(
        web_assessment=True,
        api_assessment=True,
        network_assessment=True,
        agent_assessment=False,
        full_web_profile=False,
        full_api_profile=False,
        oidc_sso=False,
        saml_sso=False,
        scim_provisioning=False,
        multi_tenant=False,
        org_hierarchy=False,
        teams_rbac=False,
        custom_roles=False,
        sarif_export=True,
        html_report=True,
        pdf_report=False,
        custom_reports=False,
        compliance_reports=False,
        webhook_delivery=True,
        github_integration=False,
        gitlab_integration=False,
        jira_integration=False,
        slack_integration=False,
        finding_deduplication=True,
        finding_trends=False,
        verified_resolution=False,
        risk_acceptance_workflow=False,
        asset_inventory=True,
        custom_policies=False,
        api_key_scoping=False,
        mssp_partner_portal=False,
        multi_customer_management=False,
        white_label_reports=False,
        dedicated_support=False,
    ),
    PricingTier.STARTER: FeatureFlags(
        web_assessment=True,
        api_assessment=True,
        network_assessment=True,
        agent_assessment=True,
        full_web_profile=True,
        full_api_profile=True,
        oidc_sso=True,
        saml_sso=False,
        scim_provisioning=False,
        multi_tenant=True,
        org_hierarchy=True,
        teams_rbac=True,
        custom_roles=False,
        sarif_export=True,
        html_report=True,
        pdf_report=True,
        custom_reports=False,
        compliance_reports=False,
        webhook_delivery=True,
        github_integration=True,
        gitlab_integration=True,
        jira_integration=False,
        slack_integration=True,
        finding_deduplication=True,
        finding_trends=True,
        verified_resolution=True,
        risk_acceptance_workflow=True,
        asset_inventory=True,
        custom_policies=True,
        api_key_scoping=True,
        mssp_partner_portal=False,
        multi_customer_management=False,
        white_label_reports=False,
        dedicated_support=False,
    ),
    PricingTier.PRO: FeatureFlags(
        web_assessment=True,
        api_assessment=True,
        network_assessment=True,
        agent_assessment=True,
        full_web_profile=True,
        full_api_profile=True,
        oidc_sso=True,
        saml_sso=True,
        scim_provisioning=True,
        multi_tenant=True,
        org_hierarchy=True,
        teams_rbac=True,
        custom_roles=True,
        sarif_export=True,
        html_report=True,
        pdf_report=True,
        custom_reports=True,
        compliance_reports=True,
        webhook_delivery=True,
        github_integration=True,
        gitlab_integration=True,
        jira_integration=True,
        slack_integration=True,
        finding_deduplication=True,
        finding_trends=True,
        verified_resolution=True,
        risk_acceptance_workflow=True,
        asset_inventory=True,
        custom_policies=True,
        api_key_scoping=True,
        mssp_partner_portal=False,
        multi_customer_management=False,
        white_label_reports=False,
        dedicated_support=True,
    ),
    PricingTier.ENTERPRISE: FeatureFlags(
        web_assessment=True,
        api_assessment=True,
        network_assessment=True,
        agent_assessment=True,
        full_web_profile=True,
        full_api_profile=True,
        oidc_sso=True,
        saml_sso=True,
        scim_provisioning=True,
        multi_tenant=True,
        org_hierarchy=True,
        teams_rbac=True,
        custom_roles=True,
        sarif_export=True,
        html_report=True,
        pdf_report=True,
        custom_reports=True,
        compliance_reports=True,
        webhook_delivery=True,
        github_integration=True,
        gitlab_integration=True,
        jira_integration=True,
        slack_integration=True,
        finding_deduplication=True,
        finding_trends=True,
        verified_resolution=True,
        risk_acceptance_workflow=True,
        asset_inventory=True,
        custom_policies=True,
        api_key_scoping=True,
        mssp_partner_portal=True,
        multi_customer_management=True,
        white_label_reports=True,
        dedicated_support=True,
    ),
}


@dataclass(frozen=True)
class TierInfo:
    """Complete tier information for API responses."""

    tier: PricingTier
    name: str
    description: str
    limits: TierLimits
    features: FeatureFlags
    monthly_price_usd: float  # 0 for free tier
    annual_price_usd: float  # 0 for free tier


# Human-readable tier information
TIER_INFO: dict[PricingTier, TierInfo] = {
    PricingTier.FREE: TierInfo(
        tier=PricingTier.FREE,
        name="Free",
        description="Community tier for individuals and open-source projects",
        limits=TIER_LIMITS[PricingTier.FREE],
        features=TIER_FEATURES[PricingTier.FREE],
        monthly_price_usd=0,
        annual_price_usd=0,
    ),
    PricingTier.STARTER: TierInfo(
        tier=PricingTier.STARTER,
        name="Starter",
        description="For small teams starting their security program",
        limits=TIER_LIMITS[PricingTier.STARTER],
        features=TIER_FEATURES[PricingTier.STARTER],
        monthly_price_usd=49,
        annual_price_usd=490,
    ),
    PricingTier.PRO: TierInfo(
        tier=PricingTier.PRO,
        name="Pro",
        description="For growing teams with advanced security needs",
        limits=TIER_LIMITS[PricingTier.PRO],
        features=TIER_FEATURES[PricingTier.PRO],
        monthly_price_usd=199,
        annual_price_usd=1990,
    ),
    PricingTier.ENTERPRISE: TierInfo(
        tier=PricingTier.ENTERPRISE,
        name="Enterprise",
        description="For large organizations and MSSP partners",
        limits=TIER_LIMITS[PricingTier.ENTERPRISE],
        features=TIER_FEATURES[PricingTier.ENTERPRISE],
        monthly_price_usd=999,
        annual_price_usd=9990,
    ),
}


def get_tier_limits(tier: PricingTier | str) -> TierLimits:
    """Get limits for a tier."""
    if isinstance(tier, str):
        try:
            tier = PricingTier(tier)
        except ValueError:
            tier = PricingTier.FREE
    return TIER_LIMITS.get(tier, TIER_LIMITS[PricingTier.FREE])


def get_tier_features(tier: PricingTier | str) -> FeatureFlags:
    """Get feature flags for a tier."""
    if isinstance(tier, str):
        try:
            tier = PricingTier(tier)
        except ValueError:
            tier = PricingTier.FREE
    return TIER_FEATURES.get(tier, TIER_FEATURES[PricingTier.FREE])


def get_tier_info(tier: PricingTier | str) -> TierInfo:
    """Get complete tier information."""
    if isinstance(tier, str):
        try:
            tier = PricingTier(tier)
        except ValueError:
            tier = PricingTier.FREE
    return TIER_INFO.get(tier, TIER_INFO[PricingTier.FREE])


def list_all_tiers() -> list[TierInfo]:
    """List all tiers in order."""
    return [TIER_INFO[t] for t in PricingTier]


def can_access_feature(tier: PricingTier | str, feature: str) -> bool:
    """Check if a tier has access to a feature."""
    features = get_tier_features(tier)
    return getattr(features, feature, False)


def check_limit(tier: PricingTier | str, limit_name: str, current_value: int) -> bool:
    """Check if current value is within tier limit. Returns True if allowed."""
    limits = get_tier_limits(tier)
    limit_value = getattr(limits, limit_name, 0)
    if limit_value == 0:  # unlimited
        return True
    return current_value < limit_value


def compare_tiers(tier_a: PricingTier | str, tier_b: PricingTier | str) -> int:
    """Compare two tiers. Returns -1 if a < b, 0 if equal, 1 if a > b."""
    if isinstance(tier_a, str):
        try:
            tier_a = PricingTier(tier_a)
        except ValueError:
            tier_a = PricingTier.FREE
    if isinstance(tier_b, str):
        try:
            tier_b = PricingTier(tier_b)
        except ValueError:
            tier_b = PricingTier.FREE
    order_a = TIER_ORDER.get(tier_a, 0)
    order_b = TIER_ORDER.get(tier_b, 0)
    if order_a < order_b:
        return -1
    if order_a > order_b:
        return 1
    return 0


def is_upgrade(from_tier: PricingTier | str, to_tier: PricingTier | str) -> bool:
    """Check if moving from from_tier to to_tier is an upgrade."""
    # compare_tiers returns -1 if from < to (meaning upgrade), 1 if from > to (downgrade)
    return compare_tiers(from_tier, to_tier) < 0


def is_downgrade(from_tier: PricingTier | str, to_tier: PricingTier | str) -> bool:
    """Check if moving from from_tier to to_tier is a downgrade."""
    return compare_tiers(from_tier, to_tier) > 0


# Feature flag descriptions for API/docs
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "web_assessment": "Web application vulnerability assessment",
    "api_assessment": "API security assessment",
    "network_assessment": "Network infrastructure assessment",
    "agent_assessment": "Agent-based autonomous assessment",
    "full_web_profile": "Full web profile (Nikto, sqlmap, Nuclei)",
    "full_api_profile": "Full API profile (Nikto, sqlmap, Nuclei)",
    "oidc_sso": "OpenID Connect single sign-on",
    "saml_sso": "SAML 2.0 single sign-on",
    "scim_provisioning": "SCIM 2.0 user/group provisioning",
    "multi_tenant": "Multi-tenant organization support",
    "org_hierarchy": "Organization hierarchy (orgs, teams, memberships)",
    "teams_rbac": "Team-based role-based access control",
    "custom_roles": "Custom role definitions",
    "sarif_export": "SARIF export for findings",
    "html_report": "HTML assessment reports",
    "pdf_report": "PDF assessment reports",
    "custom_reports": "Custom report templates",
    "compliance_reports": "Compliance reports (NRB, NTA, NCSP)",
    "webhook_delivery": "Webhook event delivery",
    "github_integration": "GitHub Actions / Code Scanning integration",
    "gitlab_integration": "GitLab CI/CD integration",
    "jira_integration": "Jira issue tracking integration",
    "slack_integration": "Slack notifications",
    "finding_deduplication": "Cross-job finding deduplication",
    "finding_trends": "Finding trend analysis (day/week/month)",
    "verified_resolution": "Verified resolution with coverage evidence",
    "risk_acceptance_workflow": "Risk acceptance/exception workflow",
    "asset_inventory": "Derived asset inventory",
    "custom_policies": "Custom engagement policies",
    "api_key_scoping": "Project-scoped and read-only API keys",
    "mssp_partner_portal": "MSSP partner portal access",
    "multi_customer_management": "Multi-customer management",
    "white_label_reports": "White-label report branding",
    "dedicated_support": "Dedicated support channel",
}
