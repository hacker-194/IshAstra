"""Authorization boundary: keys, tiers, tenants, jobs, reports, audit.

These tests encode the defects reported against the platform. An authenticated
tenant must not be able to mint keys for anyone else, escalate its own tier,
read another tenant's jobs/findings/audit, or pick its identity from the request
body.
"""
import json

import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import scope, store
from strix.core.adapters import Adapter, AdapterResult

client = TestClient(app)


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def key_for(tenant, tier="pro", *, admin=False):
    return api_keys.register(tenant, tier, admin=admin)


class Noop(Adapter):
    """Adapter that never touches the network, so job tests stay hermetic."""

    id = "noop"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(findings=[], notes=["noop"])


def assess(key, target):
    """Run one inline assessment as ``key`` and return the response."""
    return client.post("/api/assess",
                       json={"target": target, "profile": "web", "wait": True},
                       headers=auth(key))


@pytest.fixture
def noop_adapters(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])


# ---------------------------------------------------------------------------
# API key minting and revocation
# ---------------------------------------------------------------------------
def test_tenant_cannot_mint_a_key_for_another_tenant():
    victim = key_for("victim-co", "pro")
    attacker = key_for("attacker-co", "free")
    res = client.post("/api/keys/create",
                      json={"tenant": "victim-co", "tier": "enterprise"},
                      headers=auth(attacker))
    assert res.status_code == 403
    # the victim's own key must still work afterwards
    assert client.get("/api/overview", headers=auth(victim)).status_code == 200


def test_tenant_cannot_escalate_its_own_tier():
    free_key = key_for("free-co", "free")
    res = client.post("/api/keys/create",
                      json={"tenant": "free-co", "tier": "enterprise"},
                      headers=auth(free_key))
    assert res.status_code == 403


def test_tenant_may_rotate_its_own_key_at_its_own_tier():
    own = key_for("rotator-co", "pro")
    res = client.post("/api/keys/create",
                      json={"tenant": "rotator-co", "tier": "pro"},
                      headers=auth(own))
    assert res.status_code == 200
    assert res.json()["tier"] == "pro"


def test_administrator_may_mint_for_another_tenant():
    admin = key_for("soc-admin", "enterprise", admin=True)
    res = client.post("/api/keys/create",
                      json={"tenant": "onboarded-co", "tier": "pro"},
                      headers=auth(admin))
    assert res.status_code == 200
    new_key = res.json()["api_key"]
    assert client.get("/api/overview", headers=auth(new_key)).status_code == 200


def test_tenant_cannot_revoke_another_tenants_key():
    key_for("revoke-victim", "pro")
    attacker = key_for("revoke-attacker", "pro")
    assert client.post("/api/keys/revoke/revoke-victim",
                       headers=auth(attacker)).status_code == 403
    assert client.post("/api/keys/revoke/revoke-attacker",
                       headers=auth(attacker)).status_code == 200


def test_revoked_key_is_rejected_everywhere():
    key = key_for("revoked-co", "pro")
    assert client.post("/api/keys/revoke/revoked-co", headers=auth(key)).status_code == 200
    assert client.get("/api/overview", headers=auth(key)).status_code == 401
    assert assess(key, "http://example.com/").status_code == 401


def test_denied_key_request_does_not_echo_secrets():
    attacker = key_for("echo-attacker", "free")
    res = client.post("/api/keys/create",
                      json={"tenant": "victim-co", "tier": "enterprise"},
                      headers=auth(attacker))
    assert attacker not in res.text
    assert "strix_" not in res.text


# ---------------------------------------------------------------------------
# Tenant administration
# ---------------------------------------------------------------------------
def test_tenant_list_is_scoped_to_the_caller():
    alpha = key_for("alpha-co", "pro")
    key_for("beta-co", "pro")
    data = client.get("/api/tenants", headers=auth(alpha)).json()
    assert "alpha-co" in data["tenants"]
    assert "beta-co" not in data["tenants"]


def test_admin_sees_all_tenants():
    admin = key_for("list-admin", "enterprise", admin=True)
    key_for("gamma-co", "pro")
    data = client.get("/api/tenants", headers=auth(admin)).json()
    assert {"gamma-co", "list-admin"} <= set(data["tenants"])


def test_non_admin_cannot_reconfigure_global_monitoring():
    tenant = key_for("monitor-attacker", "pro")
    res = client.post("/api/monitor/configure",
                      json={"interval_seconds": 60, "targets": ["http://example.com/"]},
                      headers=auth(tenant))
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# Cross-tenant job, report and audit access
# ---------------------------------------------------------------------------
def test_job_reads_are_scoped_to_the_owner(noop_adapters):
    owner = key_for("job-owner", "pro")
    other = key_for("job-other", "pro")
    job = client.post("/api/assess",
                      json={"target": "http://example.com/", "profile": "web",
                            "wait": True},
                      headers=auth(owner)).json()

    assert client.get(f"/api/assess/{job['id']}", headers=auth(owner)).status_code == 200
    assert client.get(f"/api/assess/{job['id']}", headers=auth(other)).status_code == 404
    assert client.get(job["sarif_url"], headers=auth(other)).status_code == 404


def test_jobs_are_listed_and_survive_a_restart(noop_adapters):
    owner = key_for("persist-owner", "pro")
    job = client.post("/api/assess",
                      json={"target": "http://example.com/", "profile": "web",
                            "wait": True},
                      headers=auth(owner)).json()

    listed = client.get("/api/assess", headers=auth(owner)).json()
    assert job["id"] in [item["id"] for item in listed["items"]]

    # Simulate a process restart: same file, freshly configured store.
    store.configure(store.current_path())
    reloaded = client.get(f"/api/assess/{job['id']}", headers=auth(owner))
    assert reloaded.status_code == 200
    assert reloaded.json()["state"] == job["state"]


def test_report_requires_ownership_of_the_assessment(noop_adapters):
    owner = key_for("report-owner", "pro")
    other = key_for("report-other", "pro")
    target = "http://example.com/?q=report-owner"
    assert assess(owner, target).status_code == 200

    assert client.post("/api/report", json={"target": target},
                       headers=auth(owner)).status_code == 200
    assert client.post("/api/report", json={"target": target},
                       headers=auth(other)).status_code == 404


def test_audit_trail_never_shows_another_tenants_activity(noop_adapters):
    alpha = key_for("audit-alpha", "pro")
    beta = key_for("audit-beta", "pro")
    assert assess(alpha, "http://example.com/?q=alpha-only").status_code == 200

    beta_logs = client.get("/api/audit", headers=auth(beta)).json()["audit_logs"]
    assert all("alpha-only" not in json.dumps(entry) for entry in beta_logs)

    alpha_logs = client.get("/api/audit", headers=auth(alpha)).json()["audit_logs"]
    assert any("alpha-only" in json.dumps(entry) for entry in alpha_logs)


def test_overview_counts_only_the_callers_activity(noop_adapters):
    worker = key_for("overview-worker", "pro")
    bystander = key_for("overview-bystander", "pro")
    for i in range(2):
        assess(worker, f"http://example.com/?q=ov-{i}")

    assert client.get("/api/overview", headers=auth(worker)).json()["total_jobs"] == 2
    assert client.get("/api/overview", headers=auth(bystander)).json()["total_jobs"] == 0


# ---------------------------------------------------------------------------
# Scope cannot be expanded by request content
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://victim.example.net/",
])
def test_no_principal_can_scan_outside_the_authorized_scope(target):
    # A scope that authorizes neither loopback nor metadata space (the fixture
    # scope allows loopback for hermetic tests); no key, admin or not, may
    # widen it.
    scope.configure(program="engagement under test", authorized_by="pytest",
                    authorization_ref="cross-scope-test",
                    include=["example.com", "evil.com"])
    admin = key_for("scope-admin", "enterprise", admin=True)
    assert client.post("/api/assess", json={"target": target, "profile": "web"},
                       headers=auth(admin)).status_code == 403


def test_denied_authorization_is_audited():
    admin = key_for("audit-admin", "enterprise", admin=True)
    attacker = key_for("audited-attacker", "free")
    client.post("/api/keys/create",
                json={"tenant": "audit-admin", "tier": "enterprise"},
                headers=auth(attacker))

    events = client.get("/api/audit", headers=auth(admin)).json()["audit_logs"]
    assert any(event.get("event") == "security_denied" for event in events)
