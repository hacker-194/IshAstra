"""API key registry: a replica sees keys created or revoked elsewhere.

The registry is loaded from the database once at startup and validated from
memory. Without the bounded refresh, a key created on another replica returns
403 here, and — worse — a revoked key keeps working. These fail if the refresh
stops running or stops picking up revocations.
"""

from __future__ import annotations

import pytest

from ishastra.api.security import APIKeyStore

pytestmark = pytest.mark.asyncio


async def test_refresh_sees_a_key_created_by_another_replica(store_with_scope):
    here = APIKeyStore(persistent=True)
    there = APIKeyStore(persistent=True)
    await here.load_async()
    await there.load_async()

    raw = await there.register_async(tenant_id="tenant-created-elsewhere", tier="pro")
    assert await here.validate_async(raw) is None, "unexpectedly visible before a refresh"

    here._loaded_at = 0.0
    tenant = await here.validate_async(raw)
    assert tenant is not None
    assert tenant["tenant_id"] == "tenant-created-elsewhere"


async def test_refresh_sees_a_revocation_from_another_replica(store_with_scope):
    here = APIKeyStore(persistent=True)
    there = APIKeyStore(persistent=True)
    raw = await there.register_async(tenant_id="tenant-revoked-elsewhere", tier="pro")
    await here.load_async()
    assert await here.validate_async(raw) is not None

    assert await there.revoke_async("tenant-revoked-elsewhere") is True
    here._loaded_at = 0.0

    assert await here.validate_async(raw) is None, "a revoked key was still accepted"
