"""Audit chain: concurrent appends get distinct, gap-free sequences.

The tip was read in one transaction and the insert written in another, so two
processes could both claim the same sequence and one entry would be lost to the
primary key. These are the checks that fail if that regression returns.
"""

from __future__ import annotations

import asyncio

import pytest

from ishastra.audit import AuditChain
from ishastra.core import store


@pytest.mark.asyncio
async def test_concurrent_appends_do_not_collide(store_with_scope):
    chain = AuditChain(persistent=True, hmac_key="k" * 32)

    digests = await asyncio.gather(
        *(chain.append_async({"event": f"concurrent-{index}"}) for index in range(12))
    )

    assert len(set(digests)) == 12, "two appends produced the same digest"
    assert await chain.len_async() == 12, "an entry was lost to a sequence conflict"
    ok, reason = await chain.verify_async()
    assert ok, reason


def test_race_detection_covers_both_engines():
    assert store._is_chain_race(RuntimeError("UNIQUE constraint failed: audit_chain.sequence"))
    assert store._is_chain_race(
        RuntimeError('duplicate key value violates unique constraint "audit_chain_pkey"')
    )
    assert store._is_chain_race(RuntimeError("database is locked"))
    assert store._is_chain_race(RuntimeError("could not serialize access due to concurrent update"))
    assert not store._is_chain_race(RuntimeError("no such table: audit_chain"))
