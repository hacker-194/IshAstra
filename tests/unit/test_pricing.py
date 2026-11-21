"""Unit tests for Ishastra Pricing Tiers.

Tests cover:
- Tier limits and feature flags
- Tier comparison (upgrade/downgrade)
- Feature access checks
- Limit validation
"""

from __future__ import annotations

from ishastra.core.pricing import (
    FEATURE_DESCRIPTIONS,
    TIER_FEATURES,
    TIER_INFO,
    TIER_LIMITS,
    FeatureFlags,
    PricingTier,
    TierInfo,
    TierLimits,
    can_access_feature,
    check_limit,
    compare_tiers,
    get_tier_features,
    get_tier_info,
    get_tier_limits,
    is_downgrade,
    is_upgrade,
    list_all_tiers,
)


class TestTierOrdering:
    """Tests for tier ordering and comparison."""

    def test_tier_order_values(self):
        """Test tier order values are correct."""
        from ishastra.core.pricing import TIER_ORDER

        assert TIER_ORDER[PricingTier.FREE] == 0
        assert TIER_ORDER[PricingTier.STARTER] == 1
        assert TIER_ORDER[PricingTier.PRO] == 2
        assert TIER_ORDER[PricingTier.ENTERPRISE] == 3

    def test_compare_tiers(self):
        """Test tier comparison."""
        assert compare_tiers(PricingTier.FREE, PricingTier.STARTER) == -1
        assert compare_tiers(PricingTier.PRO, PricingTier.STARTER) == 1
        assert compare_tiers(PricingTier.ENTERPRISE, PricingTier.ENTERPRISE) == 0
        assert compare_tiers("free", "pro") == -1

    def test_is_upgrade(self):
        """Test upgrade detection."""
        assert is_upgrade(PricingTier.FREE, PricingTier.STARTER) is True
        assert is_upgrade(PricingTier.STARTER, PricingTier.PRO) is True
        assert is_upgrade(PricingTier.PRO, PricingTier.ENTERPRISE) is True
        assert is_upgrade(PricingTier.ENTERPRISE, PricingTier.FREE) is False
        assert is_upgrade(PricingTier.STARTER, PricingTier.STARTER) is False

    def test_is_downgrade(self):
        """Test downgrade detection."""
        assert is_downgrade(PricingTier.ENTERPRISE, PricingTier.PRO) is True
        assert is_downgrade(PricingTier.PRO, PricingTier.STARTER) is True
        assert is_downgrade(PricingTier.STARTER, PricingTier.FREE) is True
        assert is_downgrade(PricingTier.FREE, PricingTier.ENTERPRISE) is False
        assert is_downgrade(PricingTier.STARTER, PricingTier.STARTER) is False


class TestTierLimits:
    """Tests for tier limits."""

    def test_free_tier_limits(self):
        """Test FREE tier limits."""
        limits = TIER_LIMITS[PricingTier.FREE]
        assert limits.assessments_per_month == 10
        assert limits.max_concurrent_assessments == 1
        assert limits.max_users == 1
        assert limits.retention_days == 30
        assert limits.api_rate_limit_rpm == 30
        assert limits.max_projects == 1
        assert limits.max_webhooks == 2
        assert limits.max_schedules == 2
        assert limits.max_finding_records == 1000

    def test_starter_tier_limits(self):
        """Test STARTER tier limits."""
        limits = TIER_LIMITS[PricingTier.STARTER]
        assert limits.assessments_per_month == 100
        assert limits.max_concurrent_assessments == 2
        assert limits.max_users == 5
        assert limits.retention_days == 90
        assert limits.api_rate_limit_rpm == 100
        assert limits.max_projects == 5
        assert limits.max_webhooks == 10
        assert limits.max_schedules == 10
        assert limits.max_finding_records == 10000

    def test_pro_tier_limits(self):
        """Test PRO tier limits."""
        limits = TIER_LIMITS[PricingTier.PRO]
        assert limits.assessments_per_month == 1000
        assert limits.max_concurrent_assessments == 5
        assert limits.max_users == 25
        assert limits.retention_days == 365
        assert limits.api_rate_limit_rpm == 500
        assert limits.max_projects == 25
        assert limits.max_webhooks == 50
        assert limits.max_schedules == 50
        assert limits.max_finding_records == 100000

    def test_enterprise_tier_limits(self):
        """Test ENTERPRISE tier limits (unlimited = 0)."""
        limits = TIER_LIMITS[PricingTier.ENTERPRISE]
        assert limits.assessments_per_month == 0
        assert limits.max_concurrent_assessments == 20
        assert limits.max_users == 0
        assert limits.retention_days == 0
        assert limits.api_rate_limit_rpm == 2000
        assert limits.max_projects == 0
        assert limits.max_webhooks == 0
        assert limits.max_schedules == 0
        assert limits.max_finding_records == 0

    def test_get_tier_limits(self):
        """Test get_tier_limits function."""
        limits = get_tier_limits(PricingTier.FREE)
        assert limits.assessments_per_month == 10
        limits = get_tier_limits("starter")
        assert limits.assessments_per_month == 100

        limits = get_tier_limits("unknown")
        assert limits.assessments_per_month == 10


class TestFeatureFlags:
    """Tests for feature flags per tier."""

    def test_free_tier_features(self):
        """Test FREE tier features."""
        features = TIER_FEATURES[PricingTier.FREE]
        assert features.web_assessment is True
        assert features.api_assessment is True
        assert features.network_assessment is True
        assert features.agent_assessment is False
        assert features.full_web_profile is False
        assert features.oidc_sso is False
        assert features.saml_sso is False
        assert features.scim_provisioning is False
        assert features.multi_tenant is False
        assert features.org_hierarchy is False
        assert features.pdf_report is False
        assert features.compliance_reports is False
        assert features.github_integration is False
        assert features.finding_trends is False
        assert features.verified_resolution is False
        assert features.risk_acceptance_workflow is False
        assert features.custom_policies is False
        assert features.api_key_scoping is False
        assert features.mssp_partner_portal is False
        assert features.white_label_reports is False
        assert features.dedicated_support is False

    def test_starter_tier_features(self):
        """Test STARTER tier features."""
        features = TIER_FEATURES[PricingTier.STARTER]
        assert features.web_assessment is True
        assert features.agent_assessment is True
        assert features.full_web_profile is True
        assert features.full_api_profile is True
        assert features.oidc_sso is True
        assert features.saml_sso is False
        assert features.scim_provisioning is False
        assert features.multi_tenant is True
        assert features.org_hierarchy is True
        assert features.teams_rbac is True
        assert features.pdf_report is True
        assert features.github_integration is True
        assert features.gitlab_integration is True
        assert features.slack_integration is True
        assert features.finding_trends is True
        assert features.verified_resolution is True
        assert features.risk_acceptance_workflow is True
        assert features.custom_policies is True
        assert features.api_key_scoping is True
        assert features.mssp_partner_portal is False
        assert features.dedicated_support is False

    def test_pro_tier_features(self):
        """Test PRO tier features."""
        features = TIER_FEATURES[PricingTier.PRO]
        assert features.saml_sso is True
        assert features.scim_provisioning is True
        assert features.custom_roles is True
        assert features.custom_reports is True
        assert features.compliance_reports is True
        assert features.jira_integration is True
        assert features.dedicated_support is True
        assert features.mssp_partner_portal is False

    def test_enterprise_tier_features(self):
        """Test ENTERPRISE tier features."""
        features = TIER_FEATURES[PricingTier.ENTERPRISE]
        assert features.mssp_partner_portal is True
        assert features.multi_customer_management is True
        assert features.white_label_reports is True
        assert features.dedicated_support is True

    def test_get_tier_features(self):
        """Test get_tier_features function."""
        features = get_tier_features(PricingTier.FREE)
        assert features.web_assessment is True
        features = get_tier_features("pro")
        assert features.saml_sso is True

        features = get_tier_features("unknown")
        assert features.web_assessment is True


class TestFeatureAccess:
    """Tests for feature access checks."""

    def test_can_access_feature(self):
        """Test can_access_feature function."""
        assert can_access_feature(PricingTier.FREE, "web_assessment") is True
        assert can_access_feature(PricingTier.FREE, "agent_assessment") is False
        assert can_access_feature(PricingTier.STARTER, "agent_assessment") is True
        assert can_access_feature(PricingTier.FREE, "saml_sso") is False
        assert can_access_feature(PricingTier.PRO, "saml_sso") is True
        assert can_access_feature(PricingTier.FREE, "mssp_partner_portal") is False
        assert can_access_feature(PricingTier.ENTERPRISE, "mssp_partner_portal") is True

        assert can_access_feature(PricingTier.ENTERPRISE, "unknown_feature") is False

    def test_feature_descriptions(self):
        """Test feature descriptions exist for all features."""
        features = TIER_FEATURES[PricingTier.ENTERPRISE]
        for feature_name in features.__dict__:
            assert feature_name in FEATURE_DESCRIPTIONS
            assert len(FEATURE_DESCRIPTIONS[feature_name]) > 0


class TestLimitChecks:
    """Tests for limit validation."""

    def test_check_limit_free(self):
        """Test limit checks for FREE tier."""

        assert check_limit(PricingTier.FREE, "assessments_per_month", 5) is True
        assert check_limit(PricingTier.FREE, "max_users", 0) is True

        assert check_limit(PricingTier.FREE, "assessments_per_month", 10) is False

        assert check_limit(PricingTier.FREE, "max_users", 1) is False
        assert check_limit(PricingTier.FREE, "max_users", 0) is True

    def test_check_limit_unlimited(self):
        """Test limit checks for ENTERPRISE tier (unlimited = 0)."""

        assert check_limit(PricingTier.ENTERPRISE, "assessments_per_month", 10000) is True
        assert check_limit(PricingTier.ENTERPRISE, "max_users", 1000) is True
        assert check_limit(PricingTier.ENTERPRISE, "retention_days", 3650) is True


class TestTierInfo:
    """Tests for complete tier information."""

    def test_list_all_tiers(self):
        """Test listing all tiers in order."""
        tiers = list_all_tiers()
        assert len(tiers) == 4
        assert tiers[0].tier == PricingTier.FREE
        assert tiers[1].tier == PricingTier.STARTER
        assert tiers[2].tier == PricingTier.PRO
        assert tiers[3].tier == PricingTier.ENTERPRISE

    def test_tier_info_free(self):
        """Test FREE tier info."""
        info = TIER_INFO[PricingTier.FREE]
        assert info.tier == PricingTier.FREE
        assert info.name == "Free"
        assert info.monthly_price_usd == 0
        assert info.annual_price_usd == 0

    def test_tier_info_starter(self):
        """Test STARTER tier info."""
        info = TIER_INFO[PricingTier.STARTER]
        assert info.tier == PricingTier.STARTER
        assert info.name == "Starter"
        assert info.monthly_price_usd == 49
        assert info.annual_price_usd == 490

    def test_tier_info_pro(self):
        """Test PRO tier info."""
        info = TIER_INFO[PricingTier.PRO]
        assert info.tier == PricingTier.PRO
        assert info.name == "Pro"
        assert info.monthly_price_usd == 199
        assert info.annual_price_usd == 1990

    def test_tier_info_enterprise(self):
        """Test ENTERPRISE tier info."""
        info = TIER_INFO[PricingTier.ENTERPRISE]
        assert info.tier == PricingTier.ENTERPRISE
        assert info.name == "Enterprise"
        assert info.monthly_price_usd == 999
        assert info.annual_price_usd == 9990

    def test_get_tier_info(self):
        """Test get_tier_info function."""
        info = get_tier_info(PricingTier.FREE)
        assert info.tier == PricingTier.FREE
        info = get_tier_info("pro")
        assert info.tier == PricingTier.PRO

        info = get_tier_info("unknown")
        assert info.tier == PricingTier.FREE


class TestTierModels:
    """Tests for dataclass models."""

    def test_tier_limits_dataclass(self):
        """Test TierLimits dataclass."""
        limits = TierLimits(
            assessments_per_month=100,
            max_concurrent_assessments=2,
            max_users=5,
            retention_days=90,
            api_rate_limit_rpm=100,
            max_projects=5,
            max_webhooks=10,
            max_schedules=10,
            max_finding_records=10000,
        )
        assert limits.assessments_per_month == 100
        assert limits.max_users == 5

    def test_feature_flags_dataclass(self):
        """Test FeatureFlags dataclass."""
        features = FeatureFlags(web_assessment=True, agent_assessment=False)
        assert features.web_assessment is True
        assert features.agent_assessment is False

        assert features.api_assessment is True
        assert features.sarif_export is True

    def test_tier_info_dataclass(self):
        """Test TierInfo dataclass."""
        info = TierInfo(
            tier=PricingTier.FREE,
            name="Free",
            description="Test",
            limits=TIER_LIMITS[PricingTier.FREE],
            features=TIER_FEATURES[PricingTier.FREE],
            monthly_price_usd=0,
            annual_price_usd=0,
        )
        assert info.tier == PricingTier.FREE
        assert info.name == "Free"
