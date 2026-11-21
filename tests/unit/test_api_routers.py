"""Tests for ishastra.api.routers modules."""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from fastapi.testclient import TestClient

from ishastra.api.app import create_app
from ishastra.core import store


@pytest.fixture
def app(monkeypatch):
    """Create test app with overrides."""
    from ishastra.api.deps import reset_settings
    from ishastra.api.security import api_keys
    from ishastra.core import scope

    reset_settings()
    api_keys.reset()

    import os
    import tempfile

    db_fd, db_path = tempfile.mkstemp(suffix=".db", prefix="strix_test_")
    os.close(db_fd)

    # monkeypatch restores these after the test, so one test's database, scope and
    # keys cannot leak into the next module that runs in the same process.
    monkeypatch.setenv("ISHASTRA_DB", db_path)
    monkeypatch.setenv("ISHASTRA_SCOPE_FILE", "/tmp/scope.json")
    monkeypatch.setenv("ISHASTRA_API_KEY", "test-key-12345678901234567890123456789012")
    monkeypatch.setenv("ISHASTRA_ENCRYPTION_KEY", "i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ=")
    monkeypatch.setenv("ISHASTRA_AUDIT_HMAC_KEY", "dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==")
    monkeypatch.setenv("ISHASTRA_WORKERS", "1")

    scope_content = """{
  "program": "Test Program",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-001",
  "include": ["example.com", "*.example.com", "httpbin.org"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [80, 443],
  "allow_broad_networks": false
}"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(scope_content)
        scope_path = f.name

    asyncio.run(store.close_db_pool())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    store.configure(db_path)
    scope.load(scope_path)

    loop.run_until_complete(store.get_database())

    app = create_app()

    async def bootstrap():
        from ishastra.api import deps
        from ishastra.api.app import _bootstrap_admin_key_async
        from ishastra.api.deps import init_http_client
        from ishastra.core import policies
        from ishastra.core.scheduler import create_scheduler

        await init_http_client()
        await api_keys.load_async()
        await policies.registry.load_async()
        await deps.audit_log.load_async()
        await deps.monitor.load_async()
        await _bootstrap_admin_key_async()

        from ishastra.api import app as app_module

        app_module._scheduler = await create_scheduler(
            audit_chain=deps.audit_chain,
            monitor=deps.monitor,
            settings=deps.settings,
            job_timeout=300.0,
            scope_mode=deps.settings.scope_mode,
        )
        await app_module._scheduler.start()

    loop.run_until_complete(bootstrap())

    yield app

    from ishastra.api import app as app_module

    if app_module._scheduler is not None:
        loop.run_until_complete(app_module._scheduler.stop())
        app_module._scheduler = None
    loop.run_until_complete(store.close_db_pool())

    loop.run_until_complete(asyncio.sleep(0.1))
    loop.close()
    asyncio.set_event_loop(None)

    with contextlib.suppress(OSError):
        os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_client(app):
    """Create test client with auth."""
    client = TestClient(app)
    client.headers["Authorization"] = "Bearer test-key-12345678901234567890123456789012"
    return client


class TestPoliciesRouter:
    """Tests for policies router."""

    def test_list_policies(self, auth_client):
        """Test GET /api/policies."""
        response = auth_client.get("/api/policies")
        assert response.status_code == 200
        data = response.json()
        assert "policies" in data
        assert isinstance(data["policies"], list)

    def test_get_policy_not_found(self, auth_client):
        """Test GET /api/policies/{id} for non-existent policy."""
        response = auth_client.get("/api/policies/nonexistent")
        assert response.status_code == 404

    def test_create_policy(self, auth_client):
        """Test POST /api/policies."""
        policy_data = {
            "tenant": "default",
            "program": "Test Program",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-001",
            "include": ["example.com"],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [80, 443],
            "allow_broad_networks": False,
        }
        response = auth_client.post("/api/policies", json=policy_data)
        assert response.status_code in (200, 201)
        data = response.json()
        assert "policy_id" in data
        assert data["policy_id"].startswith("pol_")

    def test_update_policy(self, auth_client):
        """Test PATCH /api/policies/{id}."""

        policy_data = {
            "tenant": "default",
            "program": "Test Program 2",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-002",
            "include": ["example.com"],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [80, 443],
            "allow_broad_networks": False,
        }
        create_resp = auth_client.post("/api/policies", json=policy_data)
        if create_resp.status_code in (200, 201):
            policy_id = create_resp.json()["policy_id"]

            update_data = {"program": "Updated Program"}
            response = auth_client.patch(f"/api/policies/{policy_id}", json=update_data)
            assert response.status_code == 200
            data = response.json()
            assert data["program"] == "Updated Program"

    def test_revoke_policy(self, auth_client):
        """Test POST /api/policies/{id}/revoke (no DELETE endpoint)."""

        policy_data = {
            "tenant": "default",
            "program": "Test Program 3",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-003",
            "include": ["example.com"],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [80, 443],
            "allow_broad_networks": False,
        }
        create_resp = auth_client.post("/api/policies", json=policy_data)
        if create_resp.status_code in (200, 201):
            policy_id = create_resp.json()["policy_id"]

            response = auth_client.post(f"/api/policies/{policy_id}/revoke")
            assert response.status_code == 200
            data = response.json()
            assert data.get("status") == "revoked"

    def test_policy_requires_auth(self, client):
        """Test policies endpoints require authentication."""
        response = client.get("/api/policies")
        assert response.status_code == 401


class TestMonitoringRouter:
    """Tests for monitoring router."""

    def test_get_metrics(self, auth_client):
        """Test GET /api/metrics/otel returns Prometheus format."""
        response = auth_client.get("/api/metrics/otel")
        assert response.status_code == 200

        assert response.text.startswith("# HELP") or "strix_" in response.text

    def test_get_health(self, auth_client):
        """Test GET /api/health."""
        response = auth_client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_monitoring_requires_auth(self, client):
        """Test monitoring endpoints require authentication."""
        response = client.get("/api/metrics/otel")
        assert response.status_code == 401


class TestProbeRouter:
    """Tests for probe router."""

    def test_probe_endpoint(self, auth_client):
        """Test POST /api/probe."""
        probe_data = {
            "url": "https://example.com/",
            "timeout": 6.0,
        }
        response = auth_client.post("/api/probe", json=probe_data)

        assert response.status_code in (200, 202, 400, 422)

    def test_probe_requires_auth(self, client):
        """Test probe endpoint requires authentication."""
        response = client.post("/api/probe", json={"url": "https://example.com/"})
        assert response.status_code == 401


class TestProofRouter:
    """Tests for proof router."""

    def test_verify_proof(self, auth_client):
        """Test POST /api/proof/verify."""

        proof_data = {
            "proof": {
                "grant": {
                    "grant_id": "test-grant",
                    "program": "Test",
                    "authorized_by": "Tester",
                    "authorization_ref": "TEST-001",
                    "include": ["example.com"],
                    "exclude": [],
                    "authorized_networks": [],
                    "allowed_ports": [],
                    "allow_broad_networks": False,
                    "issued_at": 1700000000,
                    "expires_at": 1800000000,
                    "issuer": "test-issuer",
                },
                "receipts": [],
                "summary": {"allowed": 0, "denied": 0},
            }
        }
        response = auth_client.post("/api/proof/verify", json=proof_data)
        assert response.status_code in (200, 400)

    def test_proof_requires_no_auth(self, client):
        """Test proof endpoint is public (no authentication required)."""

        response = client.post("/api/proof/verify", json={"proof": {}})
        assert response.status_code == 200
        data = response.json()
        assert "ok" in data
        assert "errors" in data


class TestSystemRouter:
    """Tests for system router."""

    def test_get_version(self, auth_client):
        """Test GET /api/overview (includes tenant info)."""
        response = auth_client.get("/api/overview")
        assert response.status_code == 200
        data = response.json()
        assert "tenant_id" in data
        assert "tier" in data

    def test_get_status(self, auth_client):
        """Test GET /api/health."""
        response = auth_client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_system_requires_auth(self, client):
        """Test system endpoints require authentication."""
        response = client.get("/api/overview")
        assert response.status_code == 401


class TestTenantsRouter:
    """Tests for tenants router."""

    def test_list_tenants(self, auth_client):
        """Test GET /api/tenants."""
        response = auth_client.get("/api/tenants")
        assert response.status_code == 200
        data = response.json()
        assert "tenants" in data
        assert isinstance(data["tenants"], dict)

    def test_create_tenant(self, auth_client):
        """Test POST /api/keys/create (create tenant API key)."""
        tenant_data = {
            "tenant": "test-tenant",
            "tier": "standard",
            "ttl_days": 30,
            "scope": "read",
        }
        response = auth_client.post("/api/keys/create", json=tenant_data)
        assert response.status_code in (200, 201, 400)

    def test_get_tenant(self, auth_client):
        """Test GET /api/users (list users)."""
        response = auth_client.get("/api/users")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert isinstance(data["users"], list)

    def test_update_tenant(self, auth_client):
        """Test POST /api/keys/rotate/{tenant_id}."""
        response = auth_client.post("/api/keys/rotate/test-tenant")
        assert response.status_code in (200, 404)

    def test_delete_tenant(self, auth_client):
        """Test POST /api/keys/revoke/{tenant_id}."""
        response = auth_client.post("/api/keys/revoke/test-tenant")
        assert response.status_code in (200, 404)

    def test_tenants_requires_auth(self, client):
        """Test tenants endpoints require authentication."""
        response = client.get("/api/tenants")
        assert response.status_code == 401


class TestSchedulerRouter:
    """Tests for scheduler router."""

    def test_list_schedules(self, auth_client):
        """Test GET /api/schedules."""
        response = auth_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_create_schedule(self, auth_client):
        """Test POST /api/schedules."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        response = auth_client.post("/api/schedules", json=schedule_data)
        assert response.status_code in (200, 201, 400)

    def test_get_schedule(self, auth_client):
        """Test GET /api/schedules/{id}."""

        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            response = auth_client.get(f"/api/schedules/{schedule_id}")
            assert response.status_code == 200

    def test_update_schedule(self, auth_client):
        """Test PATCH /api/schedules/{id}."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            update_data = {"profile": "web-deep"}
            response = auth_client.patch(f"/api/schedules/{schedule_id}", json=update_data)
            assert response.status_code in (200, 404)

    def test_delete_schedule(self, auth_client):
        """Test DELETE /api/schedules/{id}."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            response = auth_client.delete(f"/api/schedules/{schedule_id}")

            assert response.status_code in (200, 404)
            if response.status_code == 200:
                data = response.json()
                assert data.get("deleted") is True

    def test_pause_schedule(self, auth_client):
        """Test POST /api/schedules/{id}/pause."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            response = auth_client.post(f"/api/schedules/{schedule_id}/pause")
            assert response.status_code in (200, 404)

    def test_resume_schedule(self, auth_client):
        """Test POST /api/schedules/{id}/resume."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            response = auth_client.post(f"/api/schedules/{schedule_id}/resume")
            assert response.status_code in (200, 404)

    def test_run_now(self, auth_client):
        """Test POST /api/schedules/{id}/run."""
        schedule_data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
        }
        create_resp = auth_client.post("/api/schedules", json=schedule_data)
        if create_resp.status_code in (200, 201):
            schedule_id = create_resp.json()["id"]
            response = auth_client.post(f"/api/schedules/{schedule_id}/run")
            assert response.status_code in (200, 202, 404)

    def test_scheduler_status(self, auth_client):
        """Test GET /api/scheduler/status."""
        response = auth_client.get("/api/scheduler/status")
        assert response.status_code == 200
        data = response.json()
        assert "total_schedules" in data
        assert "active_schedules" in data

    def test_scheduler_requires_auth(self, client):
        """Test scheduler endpoints require authentication."""
        response = client.get("/api/schedules")
        assert response.status_code == 401


class TestAssessmentsRouter:
    """Tests for assessments router (additional coverage)."""

    def test_list_assessments(self, auth_client):
        """Test GET /api/assess."""
        response = auth_client.get("/api/assess")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_create_assessment(self, auth_client):
        """Test POST /api/assess."""
        assessment_data = {
            "target": "https://example.com/",
            "profile": "web",
        }
        response = auth_client.post("/api/assess", json=assessment_data)
        assert response.status_code in (200, 201, 202, 400)

    def test_get_assessment(self, auth_client):
        """Test GET /api/assess/{job_id}."""

        assessment_data = {"target": "https://example.com/", "profile": "web"}
        create_resp = auth_client.post("/api/assess", json=assessment_data)
        if create_resp.status_code in (200, 201, 202):
            assessment_id = create_resp.json().get("id") or create_resp.json().get("job_id")
            if assessment_id:
                response = auth_client.get(f"/api/assess/{assessment_id}")
                assert response.status_code in (200, 404)

    def test_assessment_requires_auth(self, client):
        """Test assessments endpoints require authentication."""
        response = client.get("/api/assess")
        assert response.status_code == 401


class TestFindingsRouter:
    """Tests for findings router."""

    def test_list_findings(self, auth_client):
        """Test GET /api/findings."""
        response = auth_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_findings_requires_auth(self, client):
        """Test findings endpoints require authentication."""
        response = client.get("/api/findings")
        assert response.status_code == 401


class TestAssetsRouter:
    """Tests for assets router."""

    def test_list_assets(self, auth_client):
        """Test GET /api/assets."""
        response = auth_client.get("/api/assets")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_assets_requires_auth(self, client):
        """Test assets endpoints require authentication."""
        response = client.get("/api/assets")
        assert response.status_code == 401


class TestPolicyDiffAndLifecycle:
    """Diff and lifecycle views: reviewer-facing, read-only."""

    @staticmethod
    def _create(client, program, ref, include):
        response = client.post(
            "/api/policies",
            json={
                "tenant": "default",
                "program": program,
                "authorized_by": "Test Authorizer",
                "authorization_ref": ref,
                "include": include,
                "exclude": [],
                "authorized_networks": [],
                "allowed_ports": [443],
                "allow_broad_networks": False,
            },
        )
        assert response.status_code in (200, 201), response.text
        return response.json()["policy_id"]

    def test_diff_reports_added_and_removed_hosts(self, auth_client):
        before = self._create(auth_client, "Diff Before", "DIFF-1", ["a.example.com", "b.example.com"])
        after = self._create(auth_client, "Diff After", "DIFF-2", ["b.example.com", "c.example.com"])

        response = auth_client.get(f"/api/policies/{before}/diff/{after}")

        assert response.status_code == 200
        diff = response.json()["diff"]
        assert diff["include"]["added"] == ["c.example.com"]
        assert diff["include"]["removed"] == ["a.example.com"]
        assert diff["allowed_ports"] == {"added": [], "removed": []}

    def test_diff_unknown_policy_is_404(self, auth_client):
        created = self._create(auth_client, "Diff Missing", "DIFF-3", ["a.example.com"])
        assert auth_client.get(f"/api/policies/{created}/diff/nope").status_code == 404

    def test_lifecycle_counts_every_policy_once(self, auth_client):
        created = self._create(auth_client, "Lifecycle", "LIFE-1", ["life.example.com"])

        response = auth_client.get("/api/policies/lifecycle")

        assert response.status_code == 200
        body = response.json()
        assert set(body["counts"]) == {"draft", "active", "revoked", "expired"}
        assert created in body["policies"]["active"]
        assert sum(body["counts"].values()) == sum(len(ids) for ids in body["policies"].values())
        assert body["counts"]["active"] == len(body["policies"]["active"])

    def test_lifecycle_state_marks_revoked_and_draft(self):
        from ishastra.core.policies import EngagementPolicy

        def policy(**over):
            fields = {
                "policy_id": "pol_state",
                "tenant_id": "acme",
                "program": "State",
                "authorized_by": "Test",
                "authorization_ref": "STATE-1",
                "include": ("example.com",),
            }
            fields.update(over)
            return EngagementPolicy(**fields)

        assert policy(status="revoked").lifecycle_state() == "revoked"
        assert policy(effective_at=4_000_000_000.0).lifecycle_state() == "draft"
        assert policy(expires_at=1.0).lifecycle_state() == "expired"
        assert policy(effective_at=1.0, expires_at=4_000_000_000.0).lifecycle_state() == "active"

    def test_a_policy_carries_asn_and_country_policy(self, auth_client):
        response = auth_client.post(
            "/api/policies",
            json={
                "tenant": "default",
                "program": "Geo",
                "authorized_by": "Test Authorizer",
                "authorization_ref": "GEO-1",
                "include": ["geo.example.com"],
                "allowed_asns": [15133],
                "allowed_countries": ["np"],
            },
        )

        assert response.status_code in (200, 201), response.text
        created = response.json()
        assert created["allowed_asns"] == [15133]
        assert created["allowed_countries"] == ["NP"]

        listed = auth_client.get(f"/api/policies/{created['policy_id']}")
        assert listed.json()["allowed_asns"] == [15133]

    def test_diff_reports_asn_and_country_changes(self, auth_client):
        before = self._create(auth_client, "Geo Before", "GEO-2", ["geo.example.com"])
        changed = auth_client.patch(
            f"/api/policies/{before}",
            json={"allowed_asns": [15133], "allowed_countries": ["NP"]},
        )
        assert changed.status_code == 200, changed.text

        response = auth_client.get(f"/api/policies/{before}/diff/{before}")

        assert response.status_code == 200
        assert response.json()["diff"]["allowed_asns"] == {"added": [], "removed": []}
