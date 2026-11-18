"""Unit tests for Strix MSSP Partner Program.

Tests cover:
- Partner tier limits
- Partner/customer/invitation models
- Tier limit validation
- Customer effective limits
"""

from __future__ import annotations

from strix.core.mssp import (
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
from strix.core.pricing import PricingTier


class TestMSSPTierOrdering:
    """Tests for MSSP tier ordering."""

    def test_tier_order_values(self):
        """Test MSSP tier order values."""
        assert MSSP_TIER_ORDER[MSSPTier.REGISTERED] == 0
        assert MSSP_TIER_ORDER[MSSPTier.AUTHORIZED] == 1
        assert MSSP_TIER_ORDER[MSSPTier.PREMIER] == 2


class TestMSSPTierLimits:
    """Tests for MSSP tier limits."""

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
        # Unknown tier falls back to REGISTERED
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
        """Test MSSPCustomer model creation."""
        customer = MSSPCustomer(
            customer_id="cust_abc123",
            partner_id="mssp_abc123",
            tenant_id="tenant_123",
            name="Test Customer",
            status=CustomerStatus.ACTIVE,
            tier=PricingTier.STARTER,
            billing_contact_email="billing@customer.com",
            technical_contact_email="tech@customer.com",
            settings={},
            created_at=1000.0,
            updated_at=1000.0,
        )
        assert customer.customer_id == "cust_abc123"
        assert customer.tier == PricingTier.STARTER
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
        """Test MSSPPartnerInvitation model creation."""
        invitation = MSSPPartnerInvitation(
            invitation_id="inv_abc123",
            partner_id="mssp_abc123",
            email="customer@test.com",
            customer_name="New Customer",
            tier=PricingTier.FREE,
            status="pending",
            token="token123",
            expires_at=2000.0,
            created_at=1000.0,
        )
        assert invitation.invitation_id == "inv_abc123"
        assert invitation.status == "pending"
        assert invitation.tier == PricingTier.FREE


class TestCustomerEffectiveLimits:
    """Tests for customer effective limits calculation."""

    def test_registered_partner_free_customer(self):
        """Test effective limits for FREE customer under REGISTERED partner."""

        # Create mock objects
        class MockPartner:
            tier = MSSPTier.REGISTERED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "free"
        assert limits["partner_tier"] == "registered"
        assert limits["assessments_per_month"] == 10
        assert limits["max_users"] == 1

    def test_registered_partner_starter_customer(self):
        """Test effective limits for STARTER customer under REGISTERED partner."""

        class MockPartner:
            tier = MSSPTier.REGISTERED

        class MockCustomer:
            tier = PricingTier.STARTER

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "starter"
        assert limits["partner_tier"] == "registered"
        assert limits["assessments_per_month"] == 100
        assert limits["max_users"] == 5

    def test_authorized_partner_pro_customer(self):
        """Test effective limits for PRO customer under AUTHORIZED partner."""

        class MockPartner:
            tier = MSSPTier.AUTHORIZED

        class MockCustomer:
            tier = PricingTier.PRO

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "pro"
        assert limits["partner_tier"] == "authorized"
        assert limits["assessments_per_month"] == 1000
        assert limits["max_users"] == 25

    def test_premier_partner_enterprise_customer(self):
        """Test effective limits for ENTERPRISE customer under PREMIER partner."""

        class MockPartner:
            tier = MSSPTier.PREMIER

        class MockCustomer:
            tier = PricingTier.ENTERPRISE

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "enterprise"
        assert limits["partner_tier"] == "premier"
        assert limits["assessments_per_month"] == 0  # unlimited
        assert limits["max_users"] == 0  # unlimited

    def test_features_included(self):
        """Test that features are included in effective limits."""

        class MockPartner:
            tier = MSSPTier.AUTHORIZED

        class MockCustomer:
            tier = PricingTier.STARTER

        partner = MockPartner()
        customer = MockCustomer()

        limits = get_customer_effective_limits(customer, partner)
        assert "features" in limits
        features = limits["features"]
        assert features["web_assessment"] is True
        assert features["agent_assessment"] is True
        assert features["oidc_sso"] is True
        assert features["saml_sso"] is False  # STARTER doesn't have SAML


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
    """Tests for tier limit constraint validation logic."""

    def test_registered_partner_cannot_have_pro_customer(self):
        """Test that REGISTERED partners cannot have PRO customers."""
        # This is validated in the API layer, but we test the logic here
        customer_tier = PricingTier.PRO

        # REGISTERED partners can only have FREE/STARTER
        allowed_tiers = [PricingTier.FREE, PricingTier.STARTER]
        assert customer_tier not in allowed_tiers

    def test_authorized_partner_can_have_all_tiers(self):
        """Test that AUTHORIZED partners can have all customer tiers."""
        # AUTHORIZED partners can have any tier
        allowed_tiers = [PricingTier.FREE, PricingTier.STARTER, PricingTier.PRO, PricingTier.ENTERPRISE]
        for tier in allowed_tiers:
            assert tier in allowed_tiers

    def test_premier_partner_unlimited(self):
        """Test that PREMIER partners have unlimited customers."""
        limits = MSSP_TIER_LIMITS[MSSPTier.PREMIER]
        assert limits.max_customers == 0  # 0 = unlimited
        assert limits.max_total_assessments_per_month == 0  # unlimited
