"""Unit tests for Ishastra Pricing - Free/Open Source Model.

Tests cover:
- Single FREE tier with unlimited limits
- All features enabled for FREE tier
- No tier comparison/upgrade/downgrade needed
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
    get_tier_features,
    get_tier_info,
    get_tier_limits,
    list_all_tiers,
)


class TestTierSingleFree:
    """Tests for single FREE tier model."""

    def test_only_free_tier_exists(self):
        """Test only FREE tier exists."""
        assert list(PricingTier) == [PricingTier.FREE]

    def test_tier_order_only_free(self):
        """Test tier order only has FREE."""
        from ishastra.core.pricing import PricingTier

        # TIER_ORDER no longer exists - only FREE tier
        assert list(PricingTier) == [PricingTier.FREE]

    def test_list_all_tiers(self):
        """Test listing all tiers returns only FREE."""
        tiers = list_all_tiers()
        assert len(tiers) == 1
        assert tiers[0].tier == PricingTier.FREE

    def test_compare_tiers_same(self):
        """Test comparing FREE to FREE returns 0."""
        from ishastra.core.pricing import compare_tiers

        assert compare_tiers(PricingTier.FREE, PricingTier.FREE) == 0
        assert compare_tiers("free", "free") == 0

    def test_is_upgrade_always_false(self):
        """Test is_upgrade always returns False (no upgrades)."""
        from ishastra.core.pricing import is_upgrade

        assert is_upgrade(PricingTier.FREE, PricingTier.FREE) is False

    def test_is_downgrade_always_false(self):
        """Test is_downgrade always returns False (no downgrades)."""
        from ishastra.core.pricing import is_downgrade

        assert is_downgrade(PricingTier.FREE, PricingTier.FREE) is False


class TestFreeTierLimits:
    """Tests for FREE tier limits (all unlimited = 0)."""

    def test_free_tier_limits_all_unlimited(self):
        """Test FREE tier has all limits set to 0 (unlimited)."""
        limits = TIER_LIMITS[PricingTier.FREE]
        assert limits.assessments_per_month == 0
        assert limits.max_concurrent_assessments == 0
        assert limits.max_users == 0
        assert limits.retention_days == 0
        assert limits.api_rate_limit_rpm == 0
        assert limits.max_projects == 0
        assert limits.max_webhooks == 0
        assert limits.max_schedules == 0
        assert limits.max_finding_records == 0

    def test_get_tier_limits(self):
        """Test get_tier_limits function."""
        limits = get_tier_limits(PricingTier.FREE)
        assert limits.assessments_per_month == 0
        limits = get_tier_limits("free")
        assert limits.assessments_per_month == 0

        # Unknown tier falls back to FREE
        limits = get_tier_limits("unknown")
        assert limits.assessments_per_month == 0


class TestFreeTierFeatures:
    """Tests for FREE tier features (all enabled)."""

    def test_free_tier_all_features_enabled(self):
        """Test FREE tier has all features enabled (except dedicated_support)."""
        features = TIER_FEATURES[PricingTier.FREE]
        # All features should be True except dedicated_support
        for attr_name, value in features.__dict__.items():
            if attr_name == "dedicated_support":
                assert value is False, f"Feature {attr_name} should be False"
            else:
                assert value is True, f"Feature {attr_name} should be enabled"

    def test_get_tier_features(self):
        """Test get_tier_features function."""
        features = get_tier_features(PricingTier.FREE)
        assert features.web_assessment is True
        features = get_tier_features("free")
        assert features.saml_sso is True

        # Unknown tier falls back to FREE
        features = get_tier_features("unknown")
        assert features.web_assessment is True


class TestFeatureAccess:
    """Tests for feature access checks."""

    def test_can_access_feature_always_true(self):
        """Test all features accessible on FREE tier."""
        assert can_access_feature(PricingTier.FREE, "web_assessment") is True
        assert can_access_feature(PricingTier.FREE, "agent_assessment") is True
        assert can_access_feature(PricingTier.FREE, "saml_sso") is True
        assert can_access_feature(PricingTier.FREE, "mssp_partner_portal") is True
        assert can_access_feature(PricingTier.FREE, "dedicated_support") is True
        assert can_access_feature(PricingTier.FREE, "any_feature") is True

    def test_feature_descriptions_exist(self):
        """Test feature descriptions exist for all features."""
        features = TIER_FEATURES[PricingTier.FREE]
        for feature_name in features.__dict__:
            assert feature_name in FEATURE_DESCRIPTIONS
            assert len(FEATURE_DESCRIPTIONS[feature_name]) > 0


class TestLimitChecks:
    """Tests for limit validation with unlimited limits."""

    def test_check_limit_always_true(self):
        """Test limit checks always pass with unlimited (0) limits."""
        # 0 means unlimited, so any value should pass
        assert check_limit(PricingTier.FREE, "assessments_per_month", 10000) is True
        assert check_limit(PricingTier.FREE, "max_users", 1000) is True
        assert check_limit(PricingTier.FREE, "retention_days", 3650) is True
        assert check_limit(PricingTier.FREE, "max_projects", 500) is True
        assert check_limit(PricingTier.FREE, "max_finding_records", 999999) is True


class TestTierInfo:
    """Tests for tier information."""

    def test_tier_info_free(self):
        """Test FREE tier info."""
        info = TIER_INFO[PricingTier.FREE]
        assert info.tier == PricingTier.FREE
        assert info.name == "Free"
        assert info.monthly_price_usd == 0
        assert info.annual_price_usd == 0
        assert info.description == "All features free and unlimited - open source"

    def test_get_tier_info(self):
        """Test get_tier_info function."""
        info = get_tier_info(PricingTier.FREE)
        assert info.tier == PricingTier.FREE
        info = get_tier_info("free")
        assert info.tier == PricingTier.FREE

        # Unknown tier falls back to FREE
        info = get_tier_info("unknown")
        assert info.tier == PricingTier.FREE


class TestTierModels:
    """Tests for dataclass models."""

    def test_tier_limits_dataclass(self):
        """Test TierLimits dataclass."""
        limits = TierLimits(
            assessments_per_month=0,
            max_concurrent_assessments=0,
            max_users=0,
            retention_days=0,
            api_rate_limit_rpm=0,
            max_projects=0,
            max_webhooks=0,
            max_schedules=0,
            max_finding_records=0,
        )
        assert limits.assessments_per_month == 0
        assert limits.max_users == 0

    def test_feature_flags_dataclass(self):
        """Test FeatureFlags dataclass with all True."""
        features = FeatureFlags(web_assessment=True, agent_assessment=True)
        assert features.web_assessment is True
        assert features.agent_assessment is True
        # Defaults should be True
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
