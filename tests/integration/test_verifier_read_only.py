"""The verifier reads capability state in a read-only PostgreSQL transaction.

Requires ``ISHASTRA_TEST_PG_DSN``; skipped otherwise.
"""

from __future__ import annotations

import os

import pytest

from ishastra.core import store
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import new_keypair
from ishastra.security.capabilities.verifier import CapabilityVerifier

DSN = os.environ.get("ISHASTRA_TEST_PG_DSN")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="ISHASTRA_TEST_PG_DSN not set"),
]


@pytest.fixture
async def db():
    previous = store.current_path()
    store.configure(DSN)
    database = await store.get_database()
    try:
        yield database
    finally:
        await store.close_database()
        store.configure(previous)


async def test_read_only_transaction_rejects_writes(db) -> None:
    assert db.is_postgresql()
    async with db.read_transaction() as conn:
        assert await conn.fetchval("SELECT 1") == 1
        with pytest.raises(Exception) as excinfo:
            await conn.execute(
                "INSERT INTO jobs (id, tenant, target, profile, actor, policy, "
                "state, verdict, coverage, created_at) "
                "VALUES ('job-ro-probe', 'tenant-ro', 'example.com', 'web', 'tester', "
                "'{}', 'queued', 'clean', '{}', 1.0) ON CONFLICT DO NOTHING"
            )
        assert "read-only" in str(excinfo.value).lower()


async def test_verifier_checks_job_state_under_read_only(db) -> None:
    private_key, _ = new_keypair()
    config = CapabilityIssuer.create_config(
        signing_key_private=private_key, database=db
    )
    issuer = CapabilityIssuer(config)
    await issuer.initialize()

    job_id = "job-readonly-transaction"
    token = await issuer.issue_and_register_token(
        tenant_id="tenant-ro",
        engagement_id="eng-ro",
        job_id=job_id,
        scope=configure(
            program="Read-only test",
            authorized_by="Test",
            authorization_ref="RO-1",
            include=["example.com"],
            allowed_ports=[443],
        ),
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        allowed_tools=["nuclei"],
        request_budget=1,
        bandwidth_limit_mb=1,
    )

    async with db.transaction() as conn:
        await conn.execute(
            "INSERT INTO jobs (id, tenant, target, profile, actor, policy, "
            "state, verdict, coverage, created_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "
            "ON CONFLICT (id) DO UPDATE SET state = 'running'",
            job_id,
            "tenant-ro",
            "example.com",
            "web",
            "tester",
            "{}",
            "running",
            "clean",
            "{}",
            1.0,
        )

    verifier = CapabilityVerifier.from_issuer_config(
        config, database=db, require_job_running=True
    )
    result = await verifier.verify_async(token.to_dict())
    assert result.valid, result.reason

    async with db.transaction() as conn:
        await conn.execute("UPDATE jobs SET state = 'queued' WHERE id = $1", job_id)

    result = await verifier.verify_async(token.to_dict())
    assert not result.valid
    assert "not running" in result.reason
