"""Pricing models for IshAstra - completely free and open source.

All features are available without restrictions. No payment processing,
no tier gating, no usage limits. Apache-2.0 licensed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PricingTier(str, Enum):
    """Available pricing tier - only FREE exists."""

    FREE = "free"


@dataclass(frozen=True)
class TierLimits:
    """Resource limits - all unlimited for FREE tier."""

    assessments_per_month: int = 0
    max_concurrent_assessments: int = 0
    max_users: int = 0
    retention_days: int = 0
    api_rate_limit_rpm: int = 0
    max_projects: int = 0
    max_webhooks: int = 0
    max_schedules: int = 0
    max_finding_records: int = 0


@dataclass(frozen=True)
class FeatureFlags:
    """Feature flags - all enabled for FREE tier."""

    web_assessment: bool = True
    api_assessment: bool = True
    network_assessment: bool = True
    agent_assessment: bool = True
    full_web_profile: bool = True
    full_api_profile: bool = True

    oidc_sso: bool = True
    saml_sso: bool = True
    scim_provisioning: bool = True

    multi_tenant: bool = True
    org_hierarchy: bool = True
    teams_rbac: bool = True
    custom_roles: bool = True

    sarif_export: bool = True
    html_report: bool = True
    pdf_report: bool = True
    custom_reports: bool = True
    compliance_reports: bool = True

    webhook_delivery: bool = True
    github_integration: bool = True
    gitlab_integration: bool = True
    jira_integration: bool = True
    slack_integration: bool = True

    finding_deduplication: bool = True
    finding_trends: bool = True
    verified_resolution: bool = True
    risk_acceptance_workflow: bool = True
    asset_inventory: bool = True
    custom_policies: bool = True
    api_key_scoping: bool = True

    mssp_partner_portal: bool = True
    multi_customer_management: bool = True
    white_label_reports: bool = True
    dedicated_support: bool = False


TIER_LIMITS = {PricingTier.FREE: TierLimits()}
TIER_FEATURES = {PricingTier.FREE: FeatureFlags()}


@dataclass(frozen=True)
class TierInfo:
    """Complete tier information for API responses."""

    tier: PricingTier
    name: str
    description: str
    limits: TierLimits
    features: FeatureFlags
    monthly_price_usd: float
    annual_price_usd: float


TIER_INFO = {
    PricingTier.FREE: TierInfo(
        tier=PricingTier.FREE,
        name="Free",
        description="All features free and unlimited - open source",
        limits=TIER_LIMITS[PricingTier.FREE],
        features=TIER_FEATURES[PricingTier.FREE],
        monthly_price_usd=0,
        annual_price_usd=0,
    ),
}


def get_tier_limits(tier: PricingTier | str) -> TierLimits:
    """Get limits for a tier - always returns unlimited."""
    return TIER_LIMITS[PricingTier.FREE]


def get_tier_features(tier: PricingTier | str) -> FeatureFlags:
    """Get feature flags for a tier - always returns all enabled."""
    return TIER_FEATURES[PricingTier.FREE]


def get_tier_info(tier: PricingTier | str) -> TierInfo:
    """Get complete tier information."""
    return TIER_INFO[PricingTier.FREE]


def list_all_tiers() -> list[TierInfo]:
    """List all tiers - only FREE."""
    return [TIER_INFO[PricingTier.FREE]]


def can_access_feature(tier: PricingTier | str, feature: str) -> bool:
    """Check if a tier has access to a feature - always True."""
    return True


def check_limit(tier: PricingTier | str, limit_name: str, current_value: int) -> bool:
    """Check if current value is within tier limit - always True (unlimited)."""
    return True


def compare_tiers(tier_a: PricingTier | str, tier_b: PricingTier | str) -> int:
    """Compare two tiers - always equal."""
    return 0


def is_upgrade(from_tier: PricingTier | str, to_tier: PricingTier | str) -> bool:
    """Check if moving from from_tier to to_tier is an upgrade - always False."""
    return False


def is_downgrade(from_tier: PricingTier | str, to_tier: PricingTier | str) -> bool:
    """Check if moving from from_tier to to_tier is a downgrade - always False."""
    return False


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
