"""Tests for capability token module.

Tests: CapabilityToken creation, signing, verification, expiration, serialization.
Module: ishastra.security.capabilities.token
Existing tests: None (new v4.0 module)
User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from __future__ import annotations

import time

import pytest

from ishastra.security.capabilities.token import (
    MAX_TTL_SECONDS,
    CapabilityToken,
    create_capability_token,
    fingerprint,
    new_keypair,
    public_key,
    sign,
    verify_signature,
)


class TestCapabilityToken:
    """Test capability token creation, signing, and verification."""

    def test_new_keypair(self):
        """Test keypair generation."""
        private, public = new_keypair()
        assert private
        assert public
        assert private != public

    def test_public_key_derivation(self):
        """Test deriving public key from private."""
        private, public = new_keypair()
        derived = public_key(private)
        assert derived == public

    def test_fingerprint(self):
        """Test key fingerprint."""
        _, public = new_keypair()
        fp = fingerprint(public)
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_sign_verify(self):
        """Test signing and verification."""
        private, public = new_keypair()
        payload = {"test": "data", "number": 42}
        signature = sign(payload, private)
        assert verify_signature(payload, signature, public)
        assert not verify_signature(payload, signature, "wrong" + public[5:])

    def test_create_capability_token(self):
        """Test creating a capability token."""
        private, _ = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com", "*.example.com"],
            pinned_ips=["1.2.3.4", "5.6.7.8"],
            allowed_ports=[80, 443],
            allowed_protocols=["tcp", "http", "https"],
            allowed_tools=["nmap", "nuclei"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=300,
        )

        assert token.tenant_id == "tenant-1"
        assert token.engagement_id == "eng-1"
        assert token.job_id == "job-1"
        assert token.targets == ("example.com", "*.example.com")
        assert token.pinned_ips == ("1.2.3.4", "5.6.7.8")
        assert token.allowed_ports == (80, 443)
        assert token.allowed_protocols == ("tcp", "http", "https")
        assert token.allowed_tools == ("nmap", "nuclei")
        assert token.policy_hash == "abc123"
        assert token.rules_of_engagement_hash == "def456"
        assert token.request_budget == 1000
        assert token.bandwidth_limit_mb == 100
        assert token.signature
        assert token.issuer == fingerprint(public_key(private))

    def test_token_verification(self):
        """Test token verification."""
        private, public = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=[],
            allowed_ports=[80, 443],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=300,
        )

        valid, reason = token.verify(public)
        assert valid
        assert reason == ""

    def test_token_expiration(self):
        """Test token expiration check."""
        private, public = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=[],
            allowed_ports=[80],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=1,  # 1 second TTL
        )

        valid, _ = token.verify(public, now=time.time())
        assert valid

        valid, reason = token.verify(public, now=time.time() + 2)
        assert not valid
        assert "expired" in reason.lower()

    def test_token_not_yet_valid(self):
        """Test token not yet valid (future iat)."""
        private, public = new_keypair()
        future = time.time() + 100
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=[],
            allowed_ports=[80],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=300,
        )
        body = token.body()
        body["iat"] = future
        token = CapabilityToken(**body).sign(private)

        valid, reason = token.verify(public, now=time.time())
        assert not valid
        assert "not yet valid" in reason.lower()

    def test_token_wrong_issuer(self):
        """Test token with wrong issuer key."""
        private1, public1 = new_keypair()
        private2, public2 = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=[],
            allowed_ports=[80],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private1,
            ttl_seconds=300,
        )

        valid, reason = token.verify(public2)
        assert not valid
        assert "signature" in reason.lower() or "issuer" in reason.lower()

    def test_token_ttl_limit(self):
        """Test TTL cannot exceed maximum."""
        private, _ = new_keypair()
        with pytest.raises(ValueError, match="exceeds maximum"):
            create_capability_token(
                tenant_id="tenant-1",
                engagement_id="eng-1",
                job_id="job-1",
                targets=["example.com"],
                pinned_ips=[],
                allowed_ports=[80],
                allowed_protocols=["tcp"],
                allowed_tools=["nmap"],
                policy_hash="abc123",
                rules_of_engagement_hash="def456",
                request_budget=1000,
                bandwidth_limit_mb=100,
                issuer_private_key=private,
                ttl_seconds=MAX_TTL_SECONDS + 1,
            )

    def test_token_serialization(self):
        """Test token to/from dict."""
        private, public = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=["1.2.3.4"],
            allowed_ports=[80, 443],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=300,
        )

        token_dict = token.to_dict()
        restored = CapabilityToken.from_dict(token_dict)

        assert restored.jti == token.jti
        assert restored.tenant_id == token.tenant_id
        assert restored.targets == token.targets
        assert restored.signature == token.signature

        valid, _ = restored.verify(public)
        assert valid

    def test_remaining_ttl(self):
        """Test remaining TTL calculation."""
        private, _ = new_keypair()
        token = create_capability_token(
            tenant_id="tenant-1",
            engagement_id="eng-1",
            job_id="job-1",
            targets=["example.com"],
            pinned_ips=[],
            allowed_ports=[80],
            allowed_protocols=["tcp"],
            allowed_tools=["nmap"],
            policy_hash="abc123",
            rules_of_engagement_hash="def456",
            request_budget=1000,
            bandwidth_limit_mb=100,
            issuer_private_key=private,
            ttl_seconds=300,
        )

        ttl = token.remaining_ttl(now=token.iat)
        assert 299 <= ttl <= 300

        ttl = token.remaining_ttl(now=token.exp + 1)
        assert ttl < 0


class TestCapabilityTokenEdgeCases:
    """Test edge cases and validation."""

    def test_empty_targets_rejected(self):
        """Empty targets should be rejected."""
        private, _ = new_keypair()
        with pytest.raises(ValueError, match="targets cannot be empty"):
            create_capability_token(
                tenant_id="tenant-1",
                engagement_id="eng-1",
                job_id="job-1",
                targets=[],
                pinned_ips=[],
                allowed_ports=[80],
                allowed_protocols=["tcp"],
                allowed_tools=["nmap"],
                policy_hash="abc123",
                rules_of_engagement_hash="def456",
                request_budget=1000,
                bandwidth_limit_mb=100,
                issuer_private_key=private,
                ttl_seconds=300,
            )

    def test_zero_request_budget_rejected(self):
        """Zero request budget should be rejected."""
        private, _ = new_keypair()
        with pytest.raises(ValueError, match="request_budget must be positive"):
            create_capability_token(
                tenant_id="tenant-1",
                engagement_id="eng-1",
                job_id="job-1",
                targets=["example.com"],
                pinned_ips=[],
                allowed_ports=[80],
                allowed_protocols=["tcp"],
                allowed_tools=["nmap"],
                policy_hash="abc123",
                rules_of_engagement_hash="def456",
                request_budget=0,
                bandwidth_limit_mb=100,
                issuer_private_key=private,
                ttl_seconds=300,
            )

    def test_missing_required_fields(self):
        """Missing required fields should be rejected."""
        private, _ = new_keypair()
        with pytest.raises(ValueError):
            create_capability_token(
                tenant_id="",  # Empty
                engagement_id="eng-1",
                job_id="job-1",
                targets=["example.com"],
                pinned_ips=[],
                allowed_ports=[80],
                allowed_protocols=["tcp"],
                allowed_tools=["nmap"],
                policy_hash="abc123",
                rules_of_engagement_hash="def456",
                request_budget=1000,
                bandwidth_limit_mb=100,
                issuer_private_key=private,
                ttl_seconds=300,
            )
