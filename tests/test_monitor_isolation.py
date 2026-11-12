"""Monitoring and statistics must not leak across tenants (Phase 2).

Ordinary tenants see only their own, database-scoped counts. Platform-wide
counters require an administrator. Public liveness endpoints publish no
platform counters at all.
"""
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import jobs, store

client = TestClient(app)

GLOBAL_COUNTERS = {"targets_monitored", "audit_entries", "active_alerts"}


def _auth(name: str, *, admin: bool = False):
    key = api_keys.register(name, "enterprise", admin=admin)
    return {"Authorization": f"Bearer {key}"}


def _save_job(tenant: str, target: str) -> None:
    job = jobs.Job(target=target, profile="web", actor=tenant, policy={})
    job.state = jobs.JobState.COMPLETED
    job.started_at, job.finished_at = 100.0, 101.0
    store._run_async(store.save_job(job, tenant=tenant))


def test_monitor_status_is_scoped_to_the_callers_tenant():
    alpha = _auth("mon-alpha")
    beta = _auth("mon-beta")
    _save_job("mon-alpha", "http://example.com/?q=mon-alpha-only")

    data = client.get("/api/monitor/status", headers=alpha).json()
    assert data["running"] in (True, False)          # liveness is fine
    assert not GLOBAL_COUNTERS & set(data), "global counters leaked to a tenant"
    assert data["jobs"] == 1
    assert data["tenant_id"] == "mon-alpha"

    other = client.get("/api/monitor/status", headers=beta).json()
    assert other["jobs"] == 0                        # nothing of alpha's is visible
    assert "mon-alpha-only" not in str(other)


def test_platform_monitoring_counters_require_an_administrator():
    admin = _auth("mon-platform-admin", admin=True)
    data = client.get("/api/monitor/status", headers=admin).json()
    assert data["scope"] == "platform"
    assert set(data) >= GLOBAL_COUNTERS


def test_overview_does_not_publish_platform_monitoring():
    data = client.get("/api/overview", headers=_auth("ov-mon")).json()
    assert "monitoring" not in data, "overview exposed platform-wide monitor state"


def test_health_check_publishes_no_platform_counters():
    data = client.get("/api/health").json()
    assert "monitoring" not in data
    assert "audit_integrity" not in data
    assert "audit_entries" not in str(data)


def test_audit_integrity_detail_is_not_global_for_tenants():
    tenant = _auth("av-tenant")
    data = client.get("/api/audit/verify", headers=tenant).json()
    assert "valid" in data
    # A chain-wide entry count (or its break position) reveals other tenants'
    # activity volume, so it is administrator-only.
    assert "entries" not in data

    admin = _auth("av-admin", admin=True)
    admin_data = client.get("/api/audit/verify", headers=admin).json()
    assert "entries" in admin_data
