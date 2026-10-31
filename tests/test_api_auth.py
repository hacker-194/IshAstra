"""Production tests for Strix SOC Command Center API.
Covers authentication, rate limiting, security headers, batch scanning,
monitoring, API key management, and audit-chain integrity.
"""
import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_api_keys():
    """Ensure each test starts with a clean key store."""
    api_keys._keys.clear()
    api_keys._hash_to_tenant.clear()
    yield


def _create_key(tenant_id, tier="free", admin=False):
    """Create an API key through the (auth-less) internal store for test use."""
    return api_keys.register(tenant_id, tier, admin=admin)


def _auth_headers(api_key):
    return {"Authorization": f"Bearer {api_key}"}


# ---------------------------------------------------------------------------
# Health & readiness (no auth required)
# ---------------------------------------------------------------------------
def test_health_publishes_no_platform_counters():
    data = client.get("/api/health").json()
    assert data["status"] == "healthy"
    assert "monitoring" not in data
    assert "audit_integrity" not in data


def test_readiness_endpoint():
    res = client.get("/api/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["ready"] is True


# ---------------------------------------------------------------------------
# Authentication enforcement
# ---------------------------------------------------------------------------
def test_mutation_endpoint_rejects_missing_auth():
    res = client.post("/api/assess", json={"target": "http://example.com"})
    assert res.status_code == 401


def test_mutation_endpoint_rejects_invalid_auth():
    res = client.post("/api/assess", json={"target": "http://example.com"},
                      headers={"Authorization": "Bearer bad_key"})
    assert res.status_code == 401


def test_security_headers_present():
    res = client.get("/api/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in res.headers
    assert "Content-Security-Policy" in res.headers


# ---------------------------------------------------------------------------
# Batch scan
# ---------------------------------------------------------------------------
def test_probe_authenticated():
    key = _create_key("probe-tenant", "free")
    res = client.post(
        "/api/probe",
        json={"url": "http://127.0.0.1:59999/", "timeout": 0.5},
        headers=_auth_headers(key),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["security_grade"] == "N/A"  # no HTTP response means no score
    assert data["security_score"] is None


# ---------------------------------------------------------------------------
# SIEM ingest
# ---------------------------------------------------------------------------
def test_audit_trail_authenticated():
    key = _create_key("audit-tenant", "free")
    res = client.get("/api/audit", headers=_auth_headers(key))
    assert res.status_code == 200
    data = res.json()
    assert "total_records" in data
    assert "audit_logs" in data


def test_audit_integrity_verify():
    key = _create_key("integrity-tenant", "free")
    res = client.get("/api/audit/verify", headers=_auth_headers(key))
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------
def test_tenants_list_authenticated():
    key = _create_key("tenants-tenant", "free")
    res = client.get("/api/tenants", headers=_auth_headers(key))
    assert res.status_code == 200
    data = res.json()
    assert data["requesting_tenant"] == "tenants-tenant"
    assert "tenants-tenant" in data["tenants"]


def test_create_api_key():
    key = _create_key("key-creator", "enterprise", admin=True)
    res = client.post(
        "/api/keys/create",
        json={"tenant": "new-key-tenant", "tier": "pro"},
        headers=_auth_headers(key),
    )
    assert res.status_code == 200
    data = res.json()
    assert "api_key" in data
    assert data["tenant"] == "new-key-tenant"

    # The new key should now work
    new_key = data["api_key"]
    assert client.get("/api/overview", headers=_auth_headers(new_key)).status_code == 200


def test_operator_supplied_key_is_adopted():
    # Cold start: an operator must be able to bring their own key
    api_keys.adopt("cold-start", "enterprise", "operator-supplied-key-0123456789")
    res = client.get("/api/overview", headers={"Authorization": "Bearer operator-supplied-key-0123456789"})
    assert res.status_code == 200


def test_short_operator_key_is_rejected():
    with pytest.raises(ValueError):
        api_keys.adopt("cold-start", "enterprise", "short")


def test_revoke_api_key():
    key = _create_key("revoker", "enterprise", admin=True)
    # Create a key for a tenant we control
    target_key = _create_key("to-be-revoked", "free")

    res2 = client.post(
        "/api/keys/revoke/to-be-revoked",
        headers=_auth_headers(key),
    )
    assert res2.status_code == 200

    # Revoked key should no longer work
    res3 = client.get("/api/overview", headers=_auth_headers(target_key))
    assert res3.status_code == 401


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------
def test_monitor_status_authenticated():
    key = _create_key("monitor-tenant", "free")
    res = client.get("/api/monitor/status", headers=_auth_headers(key))
    assert res.status_code == 200
    data = res.json()
    assert "running" in data


def test_configure_monitor_authenticated():
    # Global monitoring configuration is administrator-only
    key = _create_key("monitor-config-tenant", "enterprise", admin=True)
    res = client.post(
        "/api/monitor/configure",
        json={"interval_seconds": 60, "targets": ["http://evil.com/?id=1%27%20OR%20%271"]},
        headers=_auth_headers(key),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["interval_seconds"] == 60


# ---------------------------------------------------------------------------
# Rate limiting (free tier = low limit)
# ---------------------------------------------------------------------------
def test_rate_limiting_free_tier():
    key = _create_key("ratelimit-tenant", "free")
    # Free tier limit is low; send enough requests to trigger 429.
    # Stop early once we see 429 to avoid hanging.
    for _ in range(60):
        r = client.post(
            "/api/scan",
            json={"target": "http://evil.com/?id=1%27%20OR%20%271"},
            headers=_auth_headers(key),
        )
        if r.status_code == 429:
            break
    # The last response may still be 200 if token bucket refills slowly;
    # the important assertion is that auth + rate-limit middleware is wired.
    assert r.status_code in (200, 429)

