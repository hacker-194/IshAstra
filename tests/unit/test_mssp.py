"""Unit tests for Ishastra MSSP Partner Program - Free/Open Source Model.

Tests cover:
- Partner tier limits (MSSP partner tiers still exist for management)
- Partner/customer/invitation models
- Customer effective limits - all free/unlimited
"""

from __future__ import annotations

from ishastra.core.mssp import (
    MSSP_TIER_LIMITS,
    MSSP_TIER_ORDER,
    CustomerStatus,
    MSSPCustomer,
    MSSPPartner,
    MSSPPartnerInvitation,
    MSSPPartnerStatus,
    MSSPTier,
    MSSPTierLimits,
    MSSPUsageRecord,
    get_customer_effective_limits,
    get_mssp_tier_limits,
)
from ishastra.core.pricing import PricingTier


class TestMSSPTierOrdering:
    """Tests for MSSP tier ordering."""

    def test_tier_order_values(self):
        """Test MSSP tier order values."""
        assert MSSP_TIER_ORDER[MSSPTier.REGISTERED] == 0
        assert MSSP_TIER_ORDER[MSSPTier.AUTHORIZED] == 1
        assert MSSP_TIER_ORDER[MSSPTier.PREMIER] == 2


class TestMSSPTierLimits:
    """Tests for MSSP tier limits (partner management tiers)."""

    def test_registered_tier_limits(self):
        """Test REGISTERED tier limits."""
        limits = MSSP_TIER_LIMITS[MSSPTier.REGISTERED]
        assert limits.max_customers == 5
        assert limits.max_total_assessments_per_month == 500
        assert limits.max_total_concurrent_assessments == 5
        assert limits.can_resell is False
        assert limits.white_label_reports is False
        assert limits.custom_branding is False
        assert limits.dedicated_support is False
        assert limits.portal_api_access is True
        assert limits.revenue_share_pct == 0.0

    def test_authorized_tier_limits(self):
        """Test AUTHORIZED tier limits."""
        limits = MSSP_TIER_LIMITS[MSSPTier.AUTHORIZED]
        assert limits.max_customers == 50
        assert limits.max_total_assessments_per_month == 5000
        assert limits.max_total_concurrent_assessments == 20
        assert limits.can_resell is True
        assert limits.white_label_reports is True
        assert limits.custom_branding is True
        assert limits.dedicated_support is False
        assert limits.portal_api_access is True
        assert limits.revenue_share_pct == 10.0

    def test_premier_tier_limits(self):
        """Test PREMIER tier limits (unlimited = 0)."""
        limits = MSSP_TIER_LIMITS[MSSPTier.PREMIER]
        assert limits.max_customers == 0
        assert limits.max_total_assessments_per_month == 0
        assert limits.max_total_concurrent_assessments == 0
        assert limits.can_resell is True
        assert limits.white_label_reports is True
        assert limits.custom_branding is True
        assert limits.dedicated_support is True
        assert limits.portal_api_access is True
        assert limits.revenue_share_pct == 20.0

    def test_get_mssp_tier_limits(self):
        """Test get_mssp_tier_limits function."""
        limits = get_mssp_tier_limits(MSSPTier.REGISTERED)
        assert limits.max_customers == 5

        limits = get_mssp_tier_limits("unknown")
        assert limits.max_customers == 5


class TestMSSPModels:
    """Tests for MSSP dataclass models."""

    def test_mssp_tier_limits_dataclass(self):
        """Test MSSPTierLimits dataclass."""
        limits = MSSPTierLimits(
            max_customers=10,
            max_total_assessments_per_month=1000,
            max_total_concurrent_assessments=10,
            can_resell=True,
            white_label_reports=True,
            custom_branding=False,
            dedicated_support=False,
            portal_api_access=True,
            revenue_share_pct=15.0,
        )
        assert limits.max_customers == 10
        assert limits.revenue_share_pct == 15.0

    def test_mssp_partner_model(self):
        """Test MSSPPartner model creation."""
        partner = MSSPPartner(
            partner_id="mssp_abc123",
            name="Test Partner",
            slug="test-partner",
            tier=MSSPTier.REGISTERED,
            status=MSSPPartnerStatus.PENDING,
            admin_key_hash="hash123",
            contact_email="partner@test.com",
            company_website="https://test.com",
            settings={},
            created_at=1000.0,
            updated_at=1000.0,
        )
        assert partner.partner_id == "mssp_abc123"
        assert partner.tier == MSSPTier.REGISTERED
        assert partner.status == MSSPPartnerStatus.PENDING

    def test_mssp_customer_model(self):
        """Test MSSPCustomer model creation - all customers are FREE tier."""
        customer = MSSPCustomer(
            customer_id="cust_abc123",
            partner_id="mssp_abc123",
            tenant_id="tenant_123",
            name="Test Customer",
            status=CustomerStatus.ACTIVE,
            tier=PricingTier.FREE,  # All customers are FREE
            billing_contact_email="billing@customer.com",
            technical_contact_email="tech@customer.com",
            settings={},
            created_at=1000.0,
            updated_at=1000.0,
        )
        assert customer.customer_id == "cust_abc123"
        assert customer.tier == PricingTier.FREE
        assert customer.status == CustomerStatus.ACTIVE

    def test_mssp_usage_record_model(self):
        """Test MSSPUsageRecord model creation."""
        record = MSSPUsageRecord(
            record_id="usage_abc123",
            partner_id="mssp_abc123",
            customer_id="cust_abc123",
            period_start=1000.0,
            period_end=2000.0,
            assessments_run=100,
            assessments_succeeded=95,
            findings_generated=50,
            api_calls=5000,
            retention_days_used=300,
            created_at=1500.0,
        )
        assert record.record_id == "usage_abc123"
        assert record.assessments_run == 100

    def test_mssp_invitation_model(self):
        """Test MSSPPartnerInvitation model creation - all free tier."""
        invitation = MSSPPartnerInvitation(
            invitation_id="inv_abc123",
            partner_id="mssp_abc123",
            email="customer@test.com",
            customer_name="New Customer",
            tier=PricingTier.FREE,  # All invitations are FREE tier
            status="pending",
            token="token123",
            expires_at=2000.0,
            created_at=1000.0,
        )
        assert invitation.invitation_id == "inv_abc123"
        assert invitation.status == "pending"
        assert invitation.tier == PricingTier.FREE


class TestCustomerEffectiveLimits:
    """Tests for customer effective limits calculation - all free/unlimited."""

    def test_registered_partner_free_customer(self):
        """Test effective limits for FREE customer under REGISTERED partner - all unlimited."""

        class MockPartner:
            tier = MSSPTier.REGISTERED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "free"
        assert limits["partner_tier"] == "registered"
        # All limits are 0 (unlimited) for FREE tier
        assert limits["assessments_per_month"] == 0
        assert limits["max_users"] == 0
        assert limits["max_concurrent_assessments"] == 0
        assert limits["retention_days"] == 0
        assert limits["api_rate_limit_rpm"] == 0
        assert limits["max_projects"] == 0
        assert limits["max_webhooks"] == 0
        assert limits["max_schedules"] == 0
        assert limits["max_finding_records"] == 0

    def test_authorized_partner_free_customer(self):
        """Test effective limits for FREE customer under AUTHORIZED partner - all unlimited."""

        class MockPartner:
            tier = MSSPTier.AUTHORIZED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "free"
        assert limits["partner_tier"] == "authorized"
        # All limits are 0 (unlimited)
        assert limits["assessments_per_month"] == 0
        assert limits["max_users"] == 0

    def test_premier_partner_free_customer(self):
        """Test effective limits for FREE customer under PREMIER partner - all unlimited."""

        class MockPartner:
            tier = MSSPTier.PREMIER

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "free"
        assert limits["partner_tier"] == "premier"
        assert limits["assessments_per_month"] == 0
        assert limits["max_users"] == 0

    def test_features_included(self):
        """Test that features are included in effective limits - all enabled."""

        class MockPartner:
            tier = MSSPTier.AUTHORIZED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert "features" in limits
        features = limits["features"]
        # All features should be True (except dedicated_support)
        for feature_name, value in features.items():
            if feature_name == "dedicated_support":
                assert value is False
            else:
                assert value is True, f"Feature {feature_name} should be enabled"


class TestMSSPStatusEnums:
    """Tests for MSSP status enums."""

    def test_partner_status_values(self):
        """Test partner status enum values."""
        assert MSSPPartnerStatus.PENDING.value == "pending"
        assert MSSPPartnerStatus.ACTIVE.value == "active"
        assert MSSPPartnerStatus.SUSPENDED.value == "suspended"
        assert MSSPPartnerStatus.TERMINATED.value == "terminated"

    def test_customer_status_values(self):
        """Test customer status enum values."""
        assert CustomerStatus.ACTIVE.value == "active"
        assert CustomerStatus.TRIAL.value == "trial"
        assert CustomerStatus.SUSPENDED.value == "suspended"
        assert CustomerStatus.CHURNED.value == "churned"

    def test_mssp_tier_values(self):
        """Test MSSP tier enum values."""
        assert MSSPTier.REGISTERED.value == "registered"
        assert MSSPTier.AUTHORIZED.value == "authorized"
        assert MSSPTier.PREMIER.value == "premier"


class TestMSSPTierLimitConstraints:
    """Tests for MSSP tier limit constraint validation logic."""

    def test_premier_partner_unlimited(self):
        """Test that PREMIER partners have unlimited customers."""
        limits = MSSP_TIER_LIMITS[MSSPTier.PREMIER]
        assert limits.max_customers == 0
        assert limits.max_total_assessments_per_month == 0
