"""Tests for strix.api.routers.system module."""

from __future__ import annotations

import os
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from strix.api.app import create_app
from strix.api.dependencies import reset_settings
from strix.api.security import api_keys
from strix.core import scope, store
from strix.core.scheduler import create_scheduler


@pytest_asyncio.fixture
async def app_with_db(temp_db, scope_file):
    """Create test app with configured database and scope."""
    # Reset module-level singletons for test isolation
    reset_settings()
    api_keys.reset()
    # Override STRIX_DB so lifespan uses the test database
    os.environ["STRIX_DB"] = temp_db
    store.configure(temp_db)
    scope.load(scope_file)
    app = create_app()

    # Manually run bootstrap (lifespan doesn't run until first request,
    # but auth needs keys loaded beforehand)
    from strix.api import app as app_module
    from strix.api import dependencies as deps
    from strix.api.app import _bootstrap_admin_key_async
    from strix.api.dependencies import init_http_client
    from strix.core import policies

    async def bootstrap():
        await init_http_client()
        await api_keys.load_async()
        await policies.registry.load_async()
        await deps.audit_log.load_async()
        await deps.monitor.load_async()
        await _bootstrap_admin_key_async()

        # Initialize scheduler (same as app.py lifespan)
        app_module._scheduler = await create_scheduler(
            audit_chain=deps.audit_chain,
            monitor=deps.monitor,
            settings=deps.settings,
            job_timeout=300.0,
            scope_mode=deps.settings.scope_mode,
        )
        await app_module._scheduler.start()

    await bootstrap()
    yield app

    # Cleanup scheduler - run in the same event loop
    if app_module._scheduler is not None:
        await app_module._scheduler.stop()
        app_module._scheduler = None


@pytest_asyncio.fixture
async def client(app_with_db):
    """Create test client."""
    transport = ASGITransport(app=app_with_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def auth_client(app_with_db):
    """Create test client with auth."""
    transport = ASGITransport(app=app_with_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.headers["Authorization"] = "Bearer test-key-12345678901234567890123456789012"
        yield client


class TestSystemRoutes:
    """Test system API routes."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self, client):
        """Test /api/health endpoint."""
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    @pytest.mark.asyncio
    async def test_ready_endpoint(self, client):
        """Test /api/ready endpoint."""
        response = await client.get("/api/ready")
        # Ready might be false if no scope loaded, but endpoint should work
        assert response.status_code in (200, 503)
        data = response.json()
        assert "ready" in data
        assert "scope_configured" in data

    @pytest.mark.asyncio
    async def test_metrics_endpoint_requires_auth(self, client):
        """Test /api/metrics requires admin auth."""
        response = await client.get("/api/metrics")
        # Should require authentication
        assert response.status_code == 401


class TestAssessmentRoutes:
    """Test assessment API routes."""

    @pytest.mark.asyncio
    async def test_create_assessment(self, auth_client):
        """Test POST /api/assess creates assessment."""
        response = await auth_client.post(
            "/api/assess",
            json={"target": "https://example.com/", "profile": "web"},
        )
        assert response.status_code == 202
        data = response.json()
        assert "id" in data
        assert data["state"] == "queued"

    @pytest.mark.asyncio
    async def test_create_assessment_with_auth(self, auth_client):
        """Test POST /api/assess with auth config."""
        response = await auth_client.post(
            "/api/assess",
            json={
                "target": "https://example.com/",
                "profile": "web",
                "auth": {
                    "type": "token",
                    "bearer": "test-token",
                    "principal_id": "test-principal",
                },
            },
        )
        assert response.status_code == 202
        data = response.json()
        assert "id" in data

    @pytest.mark.asyncio
    async def test_list_assessments(self, auth_client):
        """Test GET /api/assess lists assessments."""
        response = await auth_client.get("/api/assess")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    @pytest.mark.asyncio
    async def test_get_assessment(self, auth_client):
        """Test GET /api/assess/{job_id}."""
        # First create an assessment
        create_resp = await auth_client.post(
            "/api/assess",
            json={"target": "https://example.com/", "profile": "web"},
        )
        job_id = create_resp.json()["id"]

        # Get the assessment
        response = await auth_client.get(f"/api/assess/{job_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == job_id
        assert data["target"] == "https://example.com/"

    @pytest.mark.asyncio
    async def test_get_nonexistent_assessment(self, auth_client):
        """Test GET /api/assess/{job_id} for nonexistent job."""
        response = await auth_client.get("/api/assess/nonexistent-job-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_assessment(self, auth_client):
        """Test POST /api/assess/{job_id}/cancel."""
        create_resp = await auth_client.post(
            "/api/assess",
            json={"target": "https://example.com/", "profile": "web"},
        )
        job_id = create_resp.json()["id"]

        response = await auth_client.post(f"/api/assess/{job_id}/cancel")
        assert response.status_code == 200
        data = response.json()
        assert data["state"] == "cancelling"

    @pytest.mark.asyncio
    async def test_retry_assessment(self, auth_client):
        """Test POST /api/assess/{job_id}/retry."""
        create_resp = await auth_client.post(
            "/api/assess",
            json={"target": "https://example.com/", "profile": "web"},
        )
        job_id = create_resp.json()["id"]

        # Manually set job state to "failed" so it can be retried
        # (retry only works on failed, partial, or cancelled jobs)
        from strix.core import store

        db = await store.get_database()
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE jobs SET state = 'failed', verdict = 'failed', finished_at = ? WHERE id = ?",
                (time.time(), job_id),
            )

        response = await auth_client.post(f"/api/assess/{job_id}/retry")
        assert response.status_code == 202
        data = response.json()
        assert "id" in data


class TestSchedulerRoutes:
    """Test scheduler API routes."""

    @pytest.mark.asyncio
    async def test_list_schedules(self, auth_client):
        """Test GET /api/schedules."""
        response = await auth_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_create_schedule(self, auth_client):
        """Test POST /api/schedules."""
        response = await auth_client.post(
            "/api/schedules",
            json={
                "target": "https://example.com/",
                "cron_expression": "0 2 * * *",
                "timezone": "UTC",
                "profile": "web",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["target"] == "https://example.com/"

    @pytest.mark.asyncio
    async def test_get_scheduler_status(self, auth_client):
        """Test GET /api/scheduler/status."""
        response = await auth_client.get("/api/scheduler/status")
        assert response.status_code == 200
        data = response.json()
        assert "total_schedules" in data
        assert "active_schedules" in data
        assert "running" in data
        assert "paused_schedules" in data

    @pytest.mark.asyncio
    async def test_get_frequencies(self, auth_client):
        """Test GET /api/schedules/frequencies."""
        response = await auth_client.get("/api/schedules/frequencies")
        assert response.status_code == 200
        data = response.json()
        assert "frequencies" in data
        assert isinstance(data["frequencies"], list)
        assert len(data["frequencies"]) > 0
        # Check structure
        for freq in data["frequencies"]:
            assert "name" in freq
            assert "example_cron" in freq
            assert "description" in freq
        # Check timezone_examples
        assert "timezone_examples" in data
        assert isinstance(data["timezone_examples"], list)


class TestAssetRoutes:
    """Asset inventory, remediation metadata and finding history."""

    @pytest.mark.asyncio
    async def test_asset_workflow(self, auth_client):
        from strix.core.findings import Finding
        from strix.core.jobs import Job, JobState

        job = Job(
            id="asset-api-job",
            target="https://example.com/",
            profile="web",
            actor="admin",
            policy={},
            state=JobState.COMPLETED,
        )
        job.findings = [
            Finding(
                asset="https://example.com/",
                category="missing_csp",
                title="Missing CSP",
                severity="low",
                confidence="high",
                detector="test",
                detector_version="1",
                evidence="no header",
                location="/",
            )
        ]
        await store.save_job(job, tenant="admin")
        fingerprint = job.findings[0].fingerprint

        listed = await auth_client.get("/api/assets")
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        key = listed.json()["items"][0]["asset_key"]

        detail = await auth_client.get(f"/api/assets/{key}")
        assert detail.status_code == 200
        assert detail.json()["findings"][0]["fingerprint"] == fingerprint

        patched_asset = await auth_client.patch(
            f"/api/assets/{key}", json={"owner": "alice", "criticality": "high"}
        )
        assert patched_asset.status_code == 200
        assert patched_asset.json()["owner"] == "alice"

        remediation = await auth_client.patch(
            f"/api/assess/{job.id}/findings/{fingerprint}/remediation",
            json={"owner": "alice", "due_at": 1234567890.0},
        )
        assert remediation.status_code == 200
        assert remediation.json()["owner"] == "alice"

        history = await auth_client.get(f"/api/assess/{job.id}/findings/{fingerprint}/history")
        assert history.status_code == 200
        assert [event["event"] for event in history.json()["events"]] == ["created"]

        changed = await auth_client.patch(
            f"/api/assess/{job.id}/findings/{fingerprint}", json={"status": "triaged"}
        )
        assert changed.status_code == 200
        history = await auth_client.get(f"/api/assess/{job.id}/findings/{fingerprint}/history")
        assert [event["event"] for event in history.json()["events"]] == [
            "created",
            "status_changed",
        ]


class TestCrossJobFindingRoutes:
    """Cross-job finding records expose first/last seen and occurrence history."""

    @pytest.mark.asyncio
    async def test_list_and_detail(self, auth_client):
        from strix.core.findings import Finding
        from strix.core.jobs import Job, JobState

        for job_id, finished_at in (
            ("cross-api-job-1", 1234567890.0),
            ("cross-api-job-2", 1234567920.0),
        ):
            job = Job(
                id=job_id,
                target="https://cross-job.example/",
                profile="web",
                actor="admin",
                policy={},
                state=JobState.COMPLETED,
            )
            job.finished_at = finished_at
            job.findings = [
                Finding(
                    asset="https://cross-job.example/",
                    category="missing_csp",
                    title="Missing CSP",
                    severity="low",
                    confidence="high",
                    detector="test",
                    detector_version="1",
                    evidence="no header",
                    location="/",
                )
            ]
            await store.save_job(job, tenant="admin")
        fingerprint = job.findings[0].fingerprint

        listed = await auth_client.get("/api/findings?page_size=200")
        assert listed.status_code == 200
        assert listed.json()["total"] >= 1
        item = next(entry for entry in listed.json()["items"] if entry["fingerprint"] == fingerprint)
        assert item["occurrence_count"] == 2
        assert item["first_seen"] == 1234567890.0
        assert item["last_seen"] == 1234567920.0

        detail = await auth_client.get(f"/api/findings/{fingerprint}")
        assert detail.status_code == 200
        assert [entry["job_id"] for entry in detail.json()["history"]] == [
            "cross-api-job-1",
            "cross-api-job-2",
        ]

        unknown = await auth_client.get(f"/api/findings/{'0' * 32}")
        assert unknown.status_code == 404
        malformed = await auth_client.get("/api/findings/not-a-fingerprint")
        assert malformed.status_code == 422

        remediation = await auth_client.patch(
            f"/api/findings/{fingerprint}/remediation",
            json={"owner": "alice", "due_at": 1234569000.0},
        )
        assert remediation.status_code == 200
        assert remediation.json()["owner"] == "alice"

        exception = await auth_client.post(
            f"/api/findings/{fingerprint}/exception",
            json={"until": time.time() + 86400, "reason": "accepted for 30 days"},
        )
        assert exception.status_code == 201
        assert exception.json()["exception_state"] == "pending"
        approved = await auth_client.post(
            f"/api/findings/{fingerprint}/exception/decision",
            json={"approve": True, "note": "accepted"},
        )
        assert approved.status_code == 200
        assert approved.json()["exception_state"] == "approved"
        repeated = await auth_client.post(
            f"/api/findings/{fingerprint}/exception/decision", json={"approve": False}
        )
        assert repeated.status_code == 404

        from strix.core.jobs import AdapterRun, RunState

        for job_id, runs in (
            ("cross-api-verify-partial", []),
            ("cross-api-verify", [AdapterRun(adapter="test", state=RunState.OK)]),
        ):
            verify = Job(
                id=job_id,
                target="https://cross-job.example/",
                profile="web",
                actor="admin",
                policy={},
                state=JobState.COMPLETED,
            )
            verify.finished_at = 1234568000.0
            verify.runs = runs
            await store.save_job(verify, tenant="admin")

        refused = await auth_client.post(
            f"/api/findings/{fingerprint}/resolve", json={"job_id": "cross-api-verify-partial"}
        )
        assert refused.status_code == 409
        resolved = await auth_client.post(
            f"/api/findings/{fingerprint}/resolve", json={"job_id": "cross-api-verify"}
        )
        assert resolved.status_code == 200
        assert resolved.json()["resolution"]["state"] == "resolved"
        assert resolved.json()["resolution"]["job_id"] == "cross-api-verify"

        trends = await auth_client.get("/api/findings/trends?start=1234567800&end=1234568100&bucket=day")
        assert trends.status_code == 200
        assert sum(item["observations"] for item in trends.json()["buckets"]) == 2
        bad_range = await auth_client.get("/api/findings/trends?start=10&end=5")
        assert bad_range.status_code == 400


class TestTenantUsers:
    """Multiple users per tenant with admin/analyst/viewer roles."""

    @pytest.mark.asyncio
    async def test_user_roles_and_revocation(self, auth_client, app_with_db):
        analyst = await auth_client.post("/api/users", json={"display_name": "Analyst", "role": "analyst"})
        assert analyst.status_code == 200
        assert analyst.json()["role"] == "analyst"
        viewer = await auth_client.post("/api/users", json={"display_name": "Viewer", "role": "viewer"})
        assert viewer.status_code == 200
        assert viewer.json()["role"] == "viewer"

        # Reload from storage to prove user keys are durable.
        await api_keys.load_async()

        transport = ASGITransport(app=app_with_db)
        async with AsyncClient(transport=transport, base_url="http://test") as analyst_client:
            analyst_client.headers["Authorization"] = f"Bearer {analyst.json()['api_key']}"
            assert (await analyst_client.get("/api/findings")).status_code == 200
            denied = await analyst_client.post(
                "/api/keys/create", json={"tenant": "admin", "tier": "standard"}
            )
            assert denied.status_code == 403
            assert (await analyst_client.post("/api/users", json={"display_name": "x"})).status_code == 403

        async with AsyncClient(transport=transport, base_url="http://test") as viewer_client:
            viewer_client.headers["Authorization"] = f"Bearer {viewer.json()['api_key']}"
            assert (await viewer_client.get("/api/findings")).status_code == 200
            blocked = await viewer_client.post(
                "/api/assess", json={"target": "https://example.com/", "profile": "web"}
            )
            assert blocked.status_code == 403
            assert "read-only" in blocked.json()["detail"]
            assert (await viewer_client.get("/api/users")).status_code == 403

        listed = await auth_client.get("/api/users")
        assert listed.status_code == 200
        assert len(listed.json()["users"]) == 2

        revoked = await auth_client.post(f"/api/users/{viewer.json()['user_id']}/revoke")
        assert revoked.status_code == 200
        async with AsyncClient(transport=transport, base_url="http://test") as viewer_client:
            viewer_client.headers["Authorization"] = f"Bearer {viewer.json()['api_key']}"
            assert (await viewer_client.get("/api/findings")).status_code == 401


class TestAPIKeyScopes:
    """Read-scoped keys can read but cannot mutate."""

    @pytest.mark.asyncio
    async def test_read_scope_allows_reads_and_refuses_writes(self, auth_client, app_with_db):
        created = await auth_client.post(
            "/api/keys/create",
            json={"tenant": "reader", "tier": "free", "scope": "read"},
        )
        assert created.status_code == 200
        assert created.json()["scope"] == "read"

        # Reload from storage so the scope is proven durable, not memory-only.
        await api_keys.load_async()

        transport = ASGITransport(app=app_with_db)
        async with AsyncClient(transport=transport, base_url="http://test") as reader:
            reader.headers["Authorization"] = f"Bearer {created.json()['api_key']}"

            status = await reader.get("/api/keys/status")
            assert status.status_code == 200
            assert status.json()["scope"] == "read"

            listed = await reader.get("/api/assess")
            assert listed.status_code == 200

            blocked = await reader.post(
                "/api/assess", json={"target": "https://example.com/", "profile": "web"}
            )
            assert blocked.status_code == 403
            assert "read-only" in blocked.json()["detail"]

            key_create = await reader.post("/api/keys/create", json={"tenant": "reader", "tier": "standard"})
            assert key_create.status_code == 403
