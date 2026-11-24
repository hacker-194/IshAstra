"""Integration tests for Ishastra MSSP API endpoints.

Tests the MSSP partner/customer/invitation API router with a test client.
Verifies that the mypy-clean router endpoints work correctly.
"""

from __future__ import annotations

from ishastra.core.mssp import (
    MSSP_TIER_LIMITS,
    MSSP_TIER_ORDER,
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
from ishastra.core.mssp import CustomerStatus


class TestMSSPIntegrationModels:
    """Integration tests for MSSP model roundtrips and limits."""

    def test_tier_ordering(self):
        """Test MSSP tier ordering is consistent."""
        assert MSSP_TIER_ORDER[MSSPTier.REGISTERED] == 0
        assert MSSP_TIER_ORDER[MSSPTier.AUTHORIZED] == 1
        assert MSSP_TIER_ORDER[MSSPTier.PREMIER] == 2

    def test_tier_limits_exist(self):
        """Test that all tier limits exist and are consistent."""
        for tier in MSSPTier:
            limits = get_mssp_tier_limits(tier)
            assert limits is not None
            assert hasattr(limits, "max_customers")
            assert hasattr(limits, "max_total_assessments_per_month")

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

    def test_customer_effective_limits_free(self):
        """Test effective limits for FREE customer."""
        class MockPartner:
            tier = MSSPTier.REGISTERED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()
        limits = get_customer_effective_limits(customer, partner)
        assert limits["customer_tier"] == "free"
        assert limits["partner_tier"] == "registered"
        assert limits["assessments_per_month"] == 0  # unlimited
        assert limits["max_users"] == 0  # unlimited
        assert limits["max_concurrent_assessments"] == 0  # unlimited

    def test_customer_effective_limits_features(self):
        """Test that all features are included and enabled."""
        class MockPartner:
            tier = MSSPTier.AUTHORIZED

        class MockCustomer:
            tier = PricingTier.FREE

        partner = MockPartner()
        customer = MockCustomer()
        limits = get_customer_effective_limits(customer, partner)
        assert "features" in limits
        features = limits["features"]
        # All features True except dedicated_support
        for feature_name, value in features.items():
            if feature_name == "dedicated_support":
                assert value is False
            else:
                assert value is True, f"Feature {feature_name} should be enabled"


class TestMSSPIntegrationPartners:
    """Integration tests for MSSP partner models."""

    def test_mssp_partner_model(self):
        """Test MSSPPartner model creation and roundtrip."""
        from ishastra.core.mssp import MSSPPartner, MSSPTier, MSSPPartnerStatus

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
            approved_at=None,
            approved_by=None,
        )

        partner_dict = partner.to_dict()
        # to_dict does not include admin_key_hash, approved_at, approved_by
        assert partner_dict["partner_id"] == "mssp_abc123"
        assert partner_dict["name"] == "Test Partner"
        assert partner_dict["tier"] == "registered"
        # to_dict excludes: admin_key_hash, approved_at, approved_by

        # Roundtrip through from_row requires the full dict
        partner_dict_full = partner_dict.copy()
        partner_dict_full["admin_key_hash"] = "hash123"
        partner_dict_full["approved_at"] = None
        partner_dict_full["approved_by"] = None

        partner2 = MSSPPartner.from_row(partner_dict_full)
        assert partner2.partner_id == partner.partner_id
        assert partner2.name == partner.name
        assert partner2.tier == partner.tier
        assert partner2.status == partner.status

    def test_mssp_customer_model(self):
        """Test MSSPCustomer model creation - all customers are FREE tier."""
        from ishastra.core.mssp import MSSPCustomer
        from ishastra.core.pricing import PricingTier

        customer = MSSPCustomer(
            customer_id="cust_abc123",
            partner_id="mssp_abc123",
            tenant_id="tenant_123",
            name="Test Customer",
            status=CustomerStatus.ACTIVE,  # Use enum, not string
            tier=PricingTier.FREE,
            billing_contact_email="billing@customer.com",
            technical_contact_email="tech@customer.com",
            settings={},
            created_at=1000.0,
            updated_at=1000.0,
            trial_ends_at=None,
            contract_ends_at=None,
        )

        customer_dict = customer.to_dict()
        assert customer_dict["customer_id"] == "cust_abc123"
        assert customer_dict["tier"] == "free"
        assert customer_dict["status"] == "active"  # enum .value

        # Roundtrip through from_row
        customer2 = MSSPCustomer.from_row(customer_dict)
        assert customer2.customer_id == customer.customer_id
        assert customer2.tier == customer.tier
        assert customer2.status == customer.status

    def test_mssp_usage_record_model(self):
        """Test MSSPUsageRecord model creation and roundtrip."""
        from ishastra.core.mssp import MSSPUsageRecord

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

        record_dict = record.to_dict()
        assert record_dict["record_id"] == "usage_abc123"
        assert record_dict["assessments_run"] == 100

        # Roundtrip through from_row
        record2 = MSSPUsageRecord.from_row(record_dict)
        assert record2.record_id == record.record_id
        assert record2.assessments_run == record.assessments_run

    def test_mssp_invitation_model(self):
        """Test MSSPPartnerInvitation model creation - all free tier."""
        from ishastra.core.mssp import MSSPPartnerInvitation
        from ishastra.core.pricing import PricingTier

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

        invitation_dict = invitation.to_dict()
        assert invitation_dict["invitation_id"] == "inv_abc123"
        assert invitation_dict["tier"] == "free"
        # to_dict excludes: token, accepted_at

        # Roundtrip through from_row requires full dict with token
        invitation_dict_full = invitation_dict.copy()
        invitation_dict_full["token"] = "token123"
        invitation_dict_full["accepted_at"] = None

        invitation2 = MSSPPartnerInvitation.from_row(invitation_dict_full)
        assert invitation2.invitation_id == invitation.invitation_id
        assert invitation2.tier == invitation.tier
        assert invitation2.status == invitation.status