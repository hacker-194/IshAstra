"""API key lifecycle: expiry, lazy deactivation, rotation, status visibility.

Keys are hashes at rest and raw values are shown exactly once. Expiry is
enforced at validation time (a 401 indistinguishable from revocation), and
rotation kills the previous key on the spot.
"""
from __future__ import annotations

import time

import pytest

from strix.api import security
from strix.api.security import APIKeyStore


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A persistent APIKeyStore over a per-test database."""
    from strix.core import store
    store.configure(tmp_path / "strix.db")
    return APIKeyStore(persistent=True)


def test_register_without_ttl_never_expires(store):
    raw = store.register("acme", "pro")
    record = store.validate(raw)
    assert record is not None
    assert record["record"]["expires_at"] is None
    status = store.status("acme")
    assert status["days_remaining"] is None and status["expires_at"] is None


def test_register_with_ttl_sets_expiry_and_validates(store):
    raw = store.register("acme", "pro", ttl_days=30)
    record = store.validate(raw)
    assert record is not None
    expires_at = record["record"]["expires_at"]
    assert expires_at is not None and expires_at > time.time()
    status = store.status("acme")
    assert 29 <= (status["days_remaining"] or 0) <= 30


def test_expired_key_is_rejected_and_lazily_deactivated(store, monkeypatch):
    raw = store.register("acme", "pro", ttl_days=1)
    assert store.validate(raw) is not None
    # move the clock past expiry
    real_time = time.time
    monkeypatch.setattr(security.time, "time",
                        lambda: real_time() + 2 * 86400)
    assert store.validate(raw) is None          # 401 for the caller
    monkeypatch.setattr(security.time, "time", real_time)
    # the deactivation is durable: a fresh store instance refuses too
    reloaded = APIKeyStore(persistent=True)
    reloaded.load()
    assert reloaded.validate(raw) is None
    status = reloaded.status("acme")
    assert status["active"] is False


def test_rotation_kills_the_old_key_immediately(store):
    old_key = store.register("acme", "pro", ttl_days=10)
    new_key = store.rotate("acme", ttl_days=30)
    assert new_key and new_key != old_key
    assert store.validate(old_key) is None      # instant death
    assert store.validate(new_key) is not None
    status = store.status("acme")
    assert status["rotated_at"] is not None
    assert 29 <= (status["days_remaining"] or 0) <= 30


def test_rotation_preserves_tier_and_admin(store):
    store.register("root", "enterprise", admin=True)
    new_key = store.rotate("root", ttl_days=90)
    record = store.validate(new_key)
    assert record is not None
    assert record["tier"] == "enterprise" and record["admin"] is True


def test_rotate_unknown_tenant_returns_none(store):
    assert store.rotate("ghost") is None


def test_keys_survive_restart_with_expiry_state(store):
    raw = store.register("acme", "pro", ttl_days=5)
    reloaded = APIKeyStore(persistent=True)
    reloaded.load()
    record = reloaded.validate(raw)
    assert record is not None
    assert record["record"]["expires_at"] is not None
    status = reloaded.status("acme")
    assert status is not None and status["expires_at"] is not None


def test_expiry_and_rotation_survive_restart(store):
    old_key = store.register("acme", "pro")
    new_key = store.rotate("acme", ttl_days=5)
    reloaded = APIKeyStore(persistent=True)
    reloaded.load()
    assert reloaded.validate(old_key) is None
    assert reloaded.validate(new_key) is not None
    assert reloaded.status("acme")["rotated_at"] is not None


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
def _client(monkeypatch):
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from strix.api import deps
    from strix.api.app import create_app
    from strix.core import store

    # The app lifespan adopts the environment's STRIX_DB; point it at this
    # test's temporary database so a test run never drops a strix.db into the
    # repository root.
    monkeypatch.setattr(deps, "settings",
                        replace(deps.settings, db_path=store.current_path()))
    return TestClient(create_app())


@pytest.fixture
def api(store, monkeypatch):
    from strix.api.security import api_keys as global_keys
    client = _client(monkeypatch)
    with client:
        # bootstrap an admin key through the same adoption path production uses
        admin_key = "strix-admin-test-key-0001"
        global_keys.adopt("admin", "enterprise", admin_key)
        client.headers.update({"Authorization": f"Bearer {admin_key}"})
        yield client


def test_create_with_ttl_reports_expiry(api):
    response = api.post("/api/keys/create", json={"tenant": "acme", "tier": "pro",
                                                  "ttl_days": 7})
    assert response.status_code == 200
    body = response.json()
    assert body["expires_at"] is not None
    # the raw key is shown once; status never contains it
    status = api.get("/api/keys/status").json()
    assert "api_key" not in status


def test_rotate_endpoint_invalidates_previous_key(api):
    from strix.api.security import api_keys as global_keys
    first = api.post("/api/keys/create", json={"tenant": "acme", "tier": "pro"}).json()
    rotated = api.post("/api/keys/rotate/acme").json()
    assert rotated["api_key"] != first["api_key"]
    # the previous key is dead immediately (global registry, no second client needed)
    assert global_keys.validate(first["api_key"]) is None
    assert global_keys.validate(rotated["api_key"]) is not None


def test_ttl_bounds_enforced(api):
    response = api.post("/api/keys/create", json={"tenant": "acme", "tier": "pro",
                                                  "ttl_days": 0})
    assert response.status_code == 422
    response = api.post("/api/keys/create", json={"tenant": "acme", "tier": "pro",
                                                  "ttl_days": 99999})
    assert response.status_code == 422


def test_status_is_per_tenant(api):
    api.post("/api/keys/create", json={"tenant": "acme", "tier": "pro"})
    # admin sees their own status here; acme's status needs acme's key
    mine = api.get("/api/keys/status").json()
    assert mine["tenant_id"] == "admin"


def test_rotation_without_ttl_preserves_existing_expiry(store):
    old_key = store.register("expiring", "pro", ttl_days=10)
    old_expiry = store.status("expiring")["expires_at"]
    new_key = store.rotate("expiring")
    assert new_key and store.validate(old_key) is None
    assert store.validate(new_key) is not None
    assert store.status("expiring")["expires_at"] == old_expiry


def test_revoked_key_cannot_be_revived_by_rotation(store):
    store.register("revoked", "pro")
    assert store.revoke("revoked") is True
    assert store.rotate("revoked") is None


def test_concurrent_rotations_leave_exactly_one_current_key(store):
    from concurrent.futures import ThreadPoolExecutor

    original = store.register("racing", "pro")
    with ThreadPoolExecutor(max_workers=8) as pool:
        minted = list(pool.map(lambda _index: store.rotate("racing"), range(8)))
    keys = [key for key in minted if key]
    assert store.validate(original) is None
    valid = [key for key in keys if store.validate(key) is not None]
    assert len(valid) == 1


def test_rotate_endpoint_preserves_ttl_when_not_overridden(api):
    first = api.post("/api/keys/create", json={"tenant": "expiring-api", "tier": "pro",
                                               "ttl_days": 5})
    assert first.status_code == 200
    initial_expiry = first.json()["expires_at"]
    rotated = api.post("/api/keys/rotate/expiring-api")
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["expires_at"] == initial_expiry


def test_rotate_endpoint_can_explicitly_reset_ttl(api):
    first = api.post("/api/keys/create", json={"tenant": "reset-ttl-api", "tier": "pro",
                                               "ttl_days": 5})
    rotated = api.post("/api/keys/rotate/reset-ttl-api?ttl_days=30")
    assert first.status_code == rotated.status_code == 200
    assert rotated.json()["expires_at"] > first.json()["expires_at"]
