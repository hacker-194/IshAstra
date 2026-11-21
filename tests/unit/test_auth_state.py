"""Auth flow state: single use, expiring, and shared across processes.

The old dicts were per process, so a login that started on one API replica
failed on another. These checks fail if the store stops being single-use (a
replayable state/PKCE value is a login-CSRF) or stops expiring.
"""

from __future__ import annotations

import time

import pytest

from ishastra.api import session_state

pytestmark = pytest.mark.asyncio


async def test_value_is_readable_without_consuming_it():
    await session_state.put("oidc_session", "sid-1", {"state": "abc"}, ttl=60)
    assert await session_state.get("oidc_session", "sid-1") == {"state": "abc"}
    assert await session_state.get("oidc_session", "sid-1") == {"state": "abc"}


async def test_take_returns_a_value_exactly_once():
    await session_state.put("oidc_state", "state-1", "verifier", ttl=60)
    assert await session_state.take("oidc_state", "state-1") == "verifier"
    assert await session_state.take("oidc_state", "state-1") is None


async def test_discard_removes_the_value():
    await session_state.put("oidc_nonce", "nonce-1", 123.0, ttl=60)
    await session_state.discard("oidc_nonce", "nonce-1")
    assert await session_state.get("oidc_nonce", "nonce-1") is None


async def test_expired_value_is_not_returned(monkeypatch):
    await session_state.put("saml", "req-expired", {"created_at": time.time()}, ttl=0.01)
    time.sleep(0.05)
    assert await session_state.take("saml", "req-expired") is None


async def test_namespaces_do_not_collide():
    await session_state.put("oidc_state", "same-key", "state-value", ttl=60)
    await session_state.put("saml", "same-key", "saml-value", ttl=60)
    assert await session_state.take("oidc_state", "same-key") == "state-value"
    assert await session_state.take("saml", "same-key") == "saml-value"
