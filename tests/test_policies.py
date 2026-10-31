"""Engagement authorization policies: isolation, lifecycle, CIDR guard, API.

These tests encode the Priority One rules: every assessment binds to a specific
versioned authorization policy; customers cannot authorize themselves; a
revoked or expired policy stops assessments that are already queued; and a
configured network range cannot silently cover half the internet.
"""
import json
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import policies as policies_module
from strix.core import scope, store
from strix.core.adapters import Adapter, AdapterCancelled, AdapterResult
from strix.core.policies import EngagementPolicy, PolicyError, registry
from strix.core.worker import assessment_worker

client = TestClient(app)


def auth(key):
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture(autouse=True)
def clean_policies():
    """Each test starts with an empty policy registry backed by its own DB."""
    registry._policies.clear()
    registry._loaded = True
    yield
    registry._policies.clear()
    registry._loaded = False


def make_policy(tenant="acme-co", *, include=("example.com",), **overrides):
    fields = dict(
        tenant_id=tenant, program="Acme engagement", authorized_by="Jane Counsel",
        authorization_ref="eng-2026-001", include=include,
    )
    fields.update(overrides)
    return registry.create(**fields)


def stored_policy(tenant="acme-co", *, include=("example.com",), **overrides):
    """Insert a policy directly (bypassing create-time window validation)."""
    now = time.time()
    fields = dict(
        policy_id="pol_deadbeefcafe", tenant_id=tenant, program="Acme engagement",
        authorized_by="Jane Counsel", authorization_ref="eng-2026-001",
        include=include, status="active", version=1,
        created_at=now, updated_at=now,
    )
    fields.update(overrides)
    policy = EngagementPolicy(**fields)
    store.save_policy(policy.to_row())
    registry.load()
    return policy


class Noop(Adapter):
    id = "noop"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(findings=[], notes=["noop"])


@pytest.fixture
def noop_adapters(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])


# ---------------------------------------------------------------------------
# Who may authorize: only platform administrators, never the customer
# ---------------------------------------------------------------------------
def test_customer_cannot_create_its_own_policy():
    key = api_keys.register("self-auth", "enterprise")   # a normal tenant
    res = client.post("/api/policies", headers=auth(key), json={
        "tenant": "self-auth", "program": "self-authorized", "authorized_by": "me",
        "authorization_ref": "self", "include": ["example.com"]})
    assert res.status_code == 403, "a customer must not self-authorize"
    assert registry.list() == []


def test_only_platform_administrators_see_the_policy_list():
    admin = api_keys.register("pol-admin", "enterprise", admin=True)
    tenant = api_keys.register("pol-tenant", "pro")
    make_policy(tenant="pol-tenant")
    assert client.get("/api/policies", headers=auth(admin)).status_code == 200
    assert client.get("/api/policies", headers=auth(tenant)).status_code == 403


def test_policy_creation_is_sealed_in_the_audit_chain():
    admin = api_keys.register("seal-admin", "enterprise", admin=True)
    client.post("/api/policies", headers=auth(admin), json={
        "tenant": "sealed-co", "program": "Sealed", "authorized_by": "Counsel",
        "authorization_ref": "eng-77", "include": ["example.com"]})
    data = client.get("/api/audit/verify", headers=auth(admin)).json()
    assert data["valid"] is True
    events = client.get("/api/audit", headers=auth(admin)).json()["audit_logs"]
    assert any(e.get("event") == "policy_created" for e in events)


# ---------------------------------------------------------------------------
# Managed mode: per-tenant boundaries
# ---------------------------------------------------------------------------
def test_assessment_runs_under_the_tenants_own_policy(noop_adapters):
    make_policy(tenant="engaged-co", include=["example.com", "*.example.com"])
    key = api_keys.register("engaged-co", "pro")
    other = api_keys.register("bystander-co", "pro")

    ok = client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                     headers=auth(key))
    assert ok.status_code == 200
    assert ok.json()["policy"]["policy_id"].startswith("pol_")
    assert ok.json()["policy"]["policy_version"] == 1

    # A tenant without a policy has no authorization at all — even for a host
    # the neighboring engagement is allowed to scan.
    assert client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                       headers=auth(other)).status_code == 403


def test_out_of_policy_target_is_refused_for_that_tenant(noop_adapters):
    make_policy(tenant="narrow-co", include=["example.com"])
    key = api_keys.register("narrow-co", "pro")
    assert client.post("/api/assess", json={"target": "http://evil.com/", "wait": True},
                       headers=auth(key)).status_code == 403


def test_policy_id_must_belong_to_the_caller(noop_adapters):
    victim = make_policy(tenant="victim-co", include=["example.com"])
    stranger = api_keys.register("stranger-co", "pro")
    res = client.post("/api/assess", json={"target": "http://example.com/",
                                           "policy_id": victim.policy_id, "wait": True},
                      headers=auth(stranger))
    assert res.status_code == 403


def test_scope_view_shows_only_the_callers_policy():
    make_policy(tenant="visible-co", include=["example.com"])
    make_policy(tenant="hidden-co", include=["secret.example.net"])
    own = client.get("/api/scope", headers=auth(api_keys.register("visible-co", "pro"))).json()
    assert own["configured"] is True and own["mode"] == "managed"
    assert own["policy"]["include"] == ["example.com"]
    dumped = json.dumps(own)
    assert "secret.example.net" not in dumped, "another engagement's hosts leaked"

    none = client.get("/api/scope",
                      headers=auth(api_keys.register("policyless", "pro"))).json()
    assert none["configured"] is False


# ---------------------------------------------------------------------------
# Lifecycle: expiry, revocation, version binding
# ---------------------------------------------------------------------------
def test_expired_policy_refuses_assessment(noop_adapters):
    stored_policy(tenant="expired-co", expires_at=time.time() - 1)
    key = api_keys.register("expired-co", "pro")
    res = client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                      headers=auth(key))
    assert res.status_code == 403
    assert "expired" in res.json()["detail"]


def test_not_yet_effective_policy_refuses_assessment(noop_adapters):
    stored_policy(tenant="future-co", effective_at=time.time() + 3600)
    key = api_keys.register("future-co", "pro")
    res = client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                      headers=auth(key))
    assert res.status_code == 403 and "effective" in res.json()["detail"]


def test_revocation_takes_effect_immediately(noop_adapters):
    policy = make_policy(tenant="revoked-co")
    key = api_keys.register("revoked-co", "pro")
    assert client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                       headers=auth(key)).status_code == 200

    admin = api_keys.register("revoke-admin", "enterprise", admin=True)
    res = client.post(f"/api/policies/{policy.policy_id}/revoke", headers=auth(admin))
    assert res.status_code == 200

    assert client.post("/api/assess", json={"target": "http://example.com/", "wait": True},
                       headers=auth(key)).status_code == 403


def test_worker_refuses_a_job_whose_policy_was_revoked_after_submission():
    policy = make_policy(tenant="late-co", include=["example.com"])
    job = jobs_prepare("http://example.com/", tenant="late-co")
    assert job.policy["policy_id"] == policy.policy_id
    assert job.policy["policy_version"] == policy.version

    registry.revoke(policy.policy_id)     # withdrawn after submission
    finished = jobs_execute(job)
    assert finished.state.value == "failed"
    assert "revoked" in finished.error


def jobs_prepare(target, tenant, profile="web"):
    snapshot, reason = policies_module.tenant_scope_snapshot(tenant)
    assert snapshot is not None, reason
    from strix.core import jobs
    return jobs.prepare(target, profile=profile, actor=tenant, scope_snapshot=snapshot)


def jobs_execute(job):
    from strix.core import jobs
    jobs.execute(job)
    return job


def test_worker_refuses_a_job_bound_to_a_foreign_tenant():
    make_policy(tenant="owner-co", include=["example.com"])
    job = jobs_prepare("http://example.com/", tenant="owner-co")
    job.actor = "impersonator-co"       # the binding check must catch this
    finished = jobs_execute(job)
    assert finished.state.value == "failed"
    assert "does not belong" in finished.error


@pytest.mark.asyncio
async def test_queued_job_bound_to_a_revoked_policy_is_cancelled(monkeypatch):
    """A blocked adapter keeps a job running; revoking its policy cancels it."""
    policy = await registry.create_async(
        tenant_id="inflight-co", program="P", authorized_by="A",
        authorization_ref="R", include=["example.com"]
    )

    class Blocking(Adapter):
        id = "blocking"
        asset_types = ("web",)
        started = threading.Event()
        release = threading.Event()

        def assess(self, target, *, timeout, cancel, context=None):
            type(self).started.set()
            # Wait on release event, but check cancel event periodically
            while not type(self).release.wait(timeout=0.1):
                if cancel.is_set():
                    raise AdapterCancelled("policy revoked")
            # Check cancel after release in case it was set during wait
            if cancel.is_set():
                raise AdapterCancelled("policy revoked")
            return AdapterResult()

    monkeypatch.setattr(adapter_module, "select", lambda profile: [Blocking()])

    from strix.core import jobs
    snapshot, _ = policies_module.tenant_scope_snapshot("inflight-co")
    job = jobs.prepare("http://example.com/", actor="inflight-co",
                       scope_snapshot=snapshot, timeout=30)
    await assessment_worker.start()
    try:
        await assessment_worker.submit(job, on_finish=lambda finished: None)
        assert Blocking.started.wait(timeout=5)
        # Revocation goes through the API: withdrawal must also stop in-flight work.
        admin = api_keys.register("cancel-admin", "enterprise", admin=True)
        res = client.post(f"/api/policies/{policy.policy_id}/revoke", headers=auth(admin))
        assert res.status_code == 200
        assert res.json()["cancelled_jobs"] == 1
        assert job.cancelled is True
        Blocking.release.set()
        for _ in range(100):
            if job.state.value == "cancelled":
                break
            time.sleep(0.05)
        assert job.state.value == "cancelled"
    finally:
        await assessment_worker.shutdown()


# ---------------------------------------------------------------------------
# CIDR authorization guard
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("network", ["0.0.0.0/0", "128.0.0.0/1", "255.0.0.0/5",
                                     "::/0", "8000::/1", "::ffff:0:0/96"])
def test_dangerously_broad_networks_are_refused(network):
    with pytest.raises(ValueError):
        registry.create(tenant_id="broad-co", program="P", authorized_by="A",
                        authorization_ref="R", include=["example.com"],
                        authorized_networks=[network])


def test_broad_network_requires_a_deliberate_override():
    policy = registry.create(tenant_id="wild-co", program="P", authorized_by="A",
                             authorization_ref="R", include=["example.com"],
                             authorized_networks=["0.0.0.0/0"],
                             allow_broad_networks=True)
    assert policy.allow_broad_networks is True
    # The override is visible in the audit trail (sealed by the API) and in
    # the policy record itself, never silently granted.
    assert policy.to_scope().allow_broad_networks is True


def test_conventional_internal_networks_remain_allowed():
    for network in ("10.0.0.0/8", "192.168.1.0/24", "127.0.0.0/8", "fd00::/8",
                    "::1/128"):
        registry.create(tenant_id="net-co", program="P", authorized_by="A",
                        authorization_ref="R", include=["example.com"],
                        authorized_networks=[network])


def test_invalid_network_and_host_and_port_definitions_are_refused():
    for kwargs in (
        {"authorized_networks": ["10.0.0.0/999"]},
        {"authorized_networks": ["not-a-network"]},
        {"include": ["-iL.example.com"]},
        {"include": ["bad host.com"]},
        {"include": [""]},
        {"allowed_ports": [0]},
        {"allowed_ports": [70000]},
        {"allowed_ports": ["80"]},
        {"tenant_id": "bad tenant!"},
        {"authorization_ref": ""},
    ):
        fields = dict(tenant_id="reject-co", program="P", authorized_by="A",
                      authorization_ref="R", include=["example.com"])
        fields.update(kwargs)
        with pytest.raises((PolicyError, ValueError)):
            registry.create(**fields)


def test_mixed_public_and_unauthorized_internal_dns_is_refused_under_policy(monkeypatch):
    make_policy(tenant="dns-co", include=["dual.example.com"])
    monkeypatch.setattr(scope, "resolve_sync",
                        lambda host, port=None: ["93.184.216.34", "10.0.0.5"])
    snapshot, _ = policies_module.tenant_scope_snapshot("dns-co")
    denial, reason, dest = snapshot.destination("http://dual.example.com/")
    assert denial == "out_of_scope" and dest is None and "non-public" in reason


def test_policy_snapshot_pins_destination_and_authorizes_internal_network(monkeypatch):
    make_policy(tenant="int-co", include=["int.example.com"],
                authorized_networks=["10.0.0.0/8"])
    monkeypatch.setattr(scope, "resolve_sync", lambda host, port=None: ["10.0.0.5"])
    snapshot, _ = policies_module.tenant_scope_snapshot("int-co")
    denial, reason, dest = snapshot.destination("http://int.example.com/")
    assert (denial, reason) == ("", "")
    assert dest is not None and dest.ip == "10.0.0.5"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def test_policies_survive_a_restart():
    make_policy(tenant="durable-co", include=["example.com", "extra.example.net"],
                allowed_ports=[80, 443], authorized_networks=["10.0.0.0/8"])
    registry._loaded = False
    registry._policies.clear()
    registry.load()
    restored = registry.resolve("durable-co")[0]
    assert restored is not None
    assert restored.include == ("example.com", "extra.example.net")
    assert restored.allowed_ports == (80, 443)
    assert restored.authorized_networks == ("10.0.0.0/8",)
    assert restored.to_scope().check("http://example.com/") == ("", "")


def test_policy_rows_live_in_the_database():
    make_policy(tenant="db-co")
    connection = sqlite3.connect(store.current_path())
    rows = connection.execute("SELECT tenant_id, status FROM engagement_policies").fetchall()
    connection.close()
    assert ("db-co", "active") in rows


# ---------------------------------------------------------------------------
# Managed mode reaches every outbound path, not just assessments
# ---------------------------------------------------------------------------
def test_probe_is_refused_without_a_policy_in_managed_mode(monkeypatch, local_target):
    # One policy anywhere switches the deployment into managed (auto) mode.
    make_policy(tenant="probed-co", include=["127.0.0.1"],
                authorized_networks=["127.0.0.0/8"])

    outside = api_keys.register("policyless-probe", "pro")
    res = client.post("/api/probe", json={"url": "http://example.com/"},
                      headers=auth(outside))
    assert res.status_code == 403

    # With the tenant's own policy, the probe runs — through the real gate,
    # against a loopback target the policy explicitly authorizes.
    inside = api_keys.register("probed-co", "pro")
    res = client.post("/api/probe", json={"url": f"{local_target.url}/?q=hello"},
                      headers=auth(inside))
    assert res.status_code == 200 and res.json()["status_code"] == 200
    assert res.json()["body_snippet"] == "hello"


def test_administrator_cannot_probe_without_a_policy_of_their_own(monkeypatch):
    """Admin role grants policy administration, never authorization itself."""
    make_policy(tenant="somebody-else", include=["example.com"])
    admin = api_keys.register("admin-no-policy", "enterprise", admin=True)
    res = client.post("/api/probe", json={"url": "http://example.com/"},
                      headers=auth(admin))
    assert res.status_code == 403


def test_worker_refuses_job_after_active_policy_version_changes():
    policy = make_policy(tenant="versioned-co", include=["example.com"])
    job = jobs_prepare("http://example.com/", tenant="versioned-co")
    registry.update(policy.policy_id, program="Updated engagement")
    finished = jobs_execute(job)
    assert finished.state.value == "failed"
    assert "changed after this job was queued" in finished.error


def test_assessment_uses_the_exact_selected_policy(noop_adapters):
    selected = make_policy(tenant="selected-policy-co", include=["example.com"])
    # The newer default policy deliberately excludes the target. Explicitly
    # pinning the older valid policy must check and bind that same snapshot.
    make_policy(tenant="selected-policy-co", include=["other.example.net"])
    key = api_keys.register("selected-policy-co", "pro")
    response = client.post(
        "/api/assess",
        json={"target": "http://example.com/", "policy_id": selected.policy_id, "wait": True},
        headers=auth(key),
    )
    assert response.status_code == 200, response.text
    assert response.json()["policy"]["policy_id"] == selected.policy_id


def test_policy_update_endpoint_versions_cancels_and_audits():
    policy = make_policy(tenant="policy-update-co", include=["example.com"])
    admin = api_keys.register("policy-update-admin", "enterprise", admin=True)
    response = client.patch(
        f"/api/policies/{policy.policy_id}", headers=auth(admin),
        json={"include": ["example.com", "api.example.com"], "program": "Revised engagement"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["version"] == policy.version + 1
    assert body["program"] == "Revised engagement"
    assert body["include"] == ["example.com", "api.example.com"]
    audit = client.get("/api/audit", headers=auth(admin)).text
    assert "policy_updated" in audit


def test_historical_reports_keep_the_policy_bound_at_scan_time(noop_adapters):
    policy = make_policy(tenant="report-policy-co", include=["example.com"],
                         program="Original engagement", authorization_ref="original-ref")
    key = api_keys.register("report-policy-co", "pro")
    target = "http://example.com/historical-report"
    assessed = client.post("/api/assess", json={"target": target, "wait": True},
                           headers=auth(key))
    assert assessed.status_code == 200, assessed.text
    # Change both the descriptive record and scope so the old target is no
    # longer in the current policy. Historical evidence must still cite v1.
    registry.update(policy.policy_id, program="Replacement engagement",
                    authorization_ref="replacement-ref", include=["other.example.net"])

    report = client.post("/api/report", json={"target": target}, headers=auth(key))
    assert report.status_code == 200, report.text
    payload = report.json()
    assert payload["program"] == "Original engagement"
    assert payload["authorization_ref"] == "original-ref"
    assert payload["scope_include"] == ["example.com"]
    assert payload["policy_id"] == policy.policy_id
    assert payload["policy_version"] == 1
    assert payload["authorization_metadata_available"] is True

    html = client.get(f"/api/assess/{assessed.json()['id']}/report.html", headers=auth(key))
    assert html.status_code == 200
    assert "Original engagement" in html.text
    assert "Replacement engagement" not in html.text


def test_registry_refuses_policy_with_expiry_already_in_the_past():
    with pytest.raises(PolicyError, match="expires_at must be in the future"):
        registry.create(tenant_id="expired-co", program="P", authorized_by="A",
                        authorization_ref="R", include=["example.com"],
                        expires_at=time.time() - 10)


def test_registry_translates_invalid_scope_into_policy_error():
    with pytest.raises(PolicyError, match="not a valid DNS name"):
        registry.create(tenant_id="invalid-host-co", program="P", authorized_by="A",
                        authorization_ref="R", include=["bad host.com"])
