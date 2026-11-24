"""Issuer and revocation tests: key rotation, issuance, bulk revocation."""

from __future__ import annotations

import pytest

from ishastra.core import store
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import (
    MAX_TTL_SECONDS,
    fingerprint,
    new_keypair,
    public_key,
)
from ishastra.security.capabilities.verifier import CapabilityVerifier

POLICY = "a" * 64
ROE = "b" * 64


@pytest.fixture
async def db():
    return await store.get_database()


@pytest.fixture
async def issuer(db):
    private_key, _ = new_keypair()
    config = CapabilityIssuer.create_config(signing_key_private=private_key, database=db)
    instance = CapabilityIssuer(config)
    await instance.initialize()
    return instance


def _scope():
    return configure(
        program="Lifecycle Test",
        authorized_by="Test",
        authorization_ref="LC-001",
        include=["example.com"],
        allowed_ports=[443],
    )


async def _issue(issuer, *, tenant="tenant-lc", engagement="eng-lc", job="job-lc", pinned=None):
    return await issuer.issue_and_register_token(
        tenant_id=tenant,
        engagement_id=engagement,
        job_id=job,
        scope=_scope(),
        policy_hash=POLICY,
        rules_of_engagement_hash=ROE,
        allowed_tools=["nuclei"],
        request_budget=5,
        bandwidth_limit_mb=1,
        pinned_ips=pinned,
    )


async def test_key_id_matches_the_signing_key(issuer) -> None:
    expected = fingerprint(public_key(issuer.config.signing_key_private))
    assert issuer.config.key_id == expected


async def test_pinned_ips_are_bound_into_the_token(issuer) -> None:
    token = await _issue(issuer, pinned=["93.184.216.34"])
    assert token.pinned_ips == ("93.184.216.34",)
    assert token.policy_hash == POLICY
    assert token.audience == "ishastra-egress-gateway"


async def test_ttl_above_fifteen_minutes_is_rejected(issuer) -> None:
    with pytest.raises(ValueError, match="maximum"):
        issuer.issue_token(
            tenant_id="t",
            engagement_id="e",
            job_id="j",
            scope=_scope(),
            policy_hash=POLICY,
            rules_of_engagement_hash=ROE,
            allowed_tools=["nuclei"],
            request_budget=1,
            bandwidth_limit_mb=1,
            ttl_seconds=MAX_TTL_SECONDS + 1,
        )


async def test_revoke_by_job(issuer) -> None:
    token = await _issue(issuer, tenant="t-job", job="job-revoke")
    assert await issuer.is_revoked(token.jti) is False
    assert await issuer.revoke_all_for_job("job-revoke", "cancelled") == 1
    assert await issuer.is_revoked(token.jti) is True
    assert await issuer.revoke_all_for_job("job-revoke", "cancelled") == 0


async def test_revoke_by_tenant(issuer) -> None:
    first = await _issue(issuer, tenant="t-tenant", engagement="e1", job="job-a")
    second = await _issue(issuer, tenant="t-tenant", engagement="e1", job="job-b")
    assert await issuer.revoke_all_for_tenant("t-tenant", "offboarded") == 2
    assert await issuer.is_revoked(first.jti) is True
    assert await issuer.is_revoked(second.jti) is True


async def test_revoke_by_engagement(issuer) -> None:
    token = await _issue(issuer, tenant="t-eng", engagement="eng-close", job="job-c")
    assert await issuer.revoke_all_for_engagement("eng-close", "closed") == 1
    assert await issuer.is_revoked(token.jti) is True


async def test_rotated_key_still_verifies_existing_tokens(issuer, db) -> None:
    token = await _issue(issuer, tenant="t-rotate", job="job-rotate")
    rotated_config = issuer.rotate_key()
    verifier = CapabilityVerifier.from_issuer_config(rotated_config, database=db, require_job_running=False)

    result = await verifier.verify_async(token.to_dict())
    assert result.valid, result.reason
    assert rotated_config.key_id != issuer.config.key_id


async def test_unknown_key_cannot_verify(issuer) -> None:
    token = await _issue(issuer, tenant="t-other", job="job-other")
    other_private, _ = new_keypair()
    other_config = CapabilityIssuer.create_config(signing_key_private=other_private)
    verifier = CapabilityVerifier.from_issuer_config(other_config, require_job_running=False)
    result = await verifier.verify_async(token.to_dict())
    assert result.valid is False
    assert "unknown issuer" in result.reason
