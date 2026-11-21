"""Closing the async chain iterator from another task must not raise.

``verify_async`` returns early when a chain fails to verify, which closes
``_iter_entries_async``. If that generator holds the lock across a ``yield``,
the lock is released by whichever task finalizes the generator and
``_ReentrantAsyncLock`` raises ``Lock released by non-owner`` — masking the real
verification result and, during startup, aborting the application with a
secondary ``database is locked`` error.
"""

from __future__ import annotations

import asyncio

import pytest

from ishastra.audit import AuditChain


@pytest.mark.asyncio
async def test_iterator_can_be_closed_from_another_task(store_with_scope):
    chain = AuditChain(persistent=True, hmac_key="k" * 32)
    await chain.append_async({"event": "one"})
    await chain.append_async({"event": "two"})

    iterator = chain._iter_entries_async()
    sequence, _previous, _digest, body = await iterator.__anext__()
    assert sequence == 1
    assert body["event"] == "one"

    # Before the fix this raised RuntimeError("Lock released by non-owner"),
    # because the generator frame owned the lock while suspended at the yield.
    await asyncio.create_task(iterator.aclose())


@pytest.mark.asyncio
async def test_failed_verification_returns_instead_of_raising(store_with_scope):
    chain = AuditChain(persistent=True, hmac_key="k" * 32)
    await chain.append_async({"event": "one"})
    await chain.append_async({"event": "two"})

    # A different key cannot reproduce the MACs, so verification stops at the
    # first entry and returns instead of raising.
    reader = AuditChain(persistent=True, hmac_key="x" * 32)
    ok, reason = await reader.verify_async()
    assert ok is False
    assert reason
