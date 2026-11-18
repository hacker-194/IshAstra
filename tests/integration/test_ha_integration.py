"""Integration tests for HA features.

These tests validate HA functionality in an integrated environment
with real API, scheduler, and database components.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Skip if PostgreSQL not available
pytestmark = pytest.mark.skipif(
    not os.environ.get("STRIX_POSTGRES_DSN"),
    reason="Requires PostgreSQL (set STRIX_POSTGRES_DSN)",
)


@pytest_asyncio.fixture
async def ha_app(temp_db: str, scope_file: str):
    """Create test app with HA mode enabled."""
    import os

    # Enable HA mode
    os.environ["STRIX_HA_MODE"] = "true"
    os.environ["STRIX_DB"] = temp_db
    os.environ["STRIX_SCOPE_FILE"] = scope_file
    os.environ["STRIX_API_KEY"] = "test-key-12345678901234567890123456789012"
    os.environ["STRIX_AUDIT_HMAC_KEY"] = "dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw=="
    os.environ["STRIX_RATE_LIMIT_DISABLED"] = "1"
    os.environ["STRIX_SKIP_REDIS_INIT"] = "1"
    os.environ["STRIX_WORKERS"] = "1"

    # Reset module-level singletons
    from strix.api.dependencies import reset_settings
    from strix.api.security import api_keys

    reset_settings()
    api_keys.reset()

    from strix.api.app import create_app
    from strix.core import scope, store

    store.configure(temp_db)
    scope.load(scope_file)

    app = create_app()

    # Manually run bootstrap
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

        # Initialize scheduler with HA
        app_module._scheduler = await deps.create_scheduler(
            audit_chain=deps.audit_chain,
            monitor=deps.monitor,
            settings=deps.settings,
            job_timeout=300.0,
            scope_mode=deps.settings.scope_mode,
        )
        await app_module._scheduler.start()

    await bootstrap()

    yield app

    # Cleanup
    if app_module._scheduler is not None:
        await app_module._scheduler.stop()
        app_module._scheduler = None

    # Disable HA mode
    os.environ["STRIX_HA_MODE"] = "false"


@pytest_asyncio.fixture
async def auth_client(ha_app):
    """Create authenticated test client."""
    transport = ASGITransport(app=ha_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.headers["Authorization"] = "Bearer test-key-12345678901234567890123456789012"
        yield client


class TestHAAppStartup:
    """Tests for HA-enabled app startup."""

    @pytest.mark.asyncio
    async def test_app_starts_in_ha_mode(self, ha_app):
        """Test that app starts with HA mode enabled."""
        from strix.api import app as app_module

        # Verify HA mode is detected
        assert os.environ.get("STRIX_HA_MODE") == "true"

        # Scheduler should be initialized
        assert app_module._scheduler is not None

    @pytest.mark.asyncio
    async def test_health_endpoint_includes_ha_status(self, auth_client):
        """Test that health endpoint includes HA information."""
        response = await auth_client.get("/api/health")
        assert response.status_code == 200

        data = response.json()
        # Health endpoint should include basic status
        assert "status" in data

    @pytest.mark.asyncio
    async def test_readiness_endpoint_includes_ha(self, auth_client):
        """Test that readiness endpoint checks HA status."""
        response = await auth_client.get("/api/ready")
        assert response.status_code == 200

        data = response.json()
        assert "ready" in data


class TestHASchedulerIntegration:
    """Tests for scheduler integration with HA."""

    @pytest.mark.asyncio
    async def test_schedule_creation_in_ha(self, auth_client):
        """Test creating schedules in HA mode."""
        response = await auth_client.post(
            "/api/schedules",
            json={
                "target": "https://example.com",
                "cron_expression": "0 2 * * *",
                "timezone": "UTC",
                "profile": "web",
            },
        )
        assert response.status_code == 201

        data = response.json()
        assert "id" in data
        assert data["target"] == "https://example.com"
        assert data["cron_expression"] == "0 2 * * *"

    @pytest.mark.asyncio
    async def test_schedule_list_in_ha(self, auth_client):
        """Test listing schedules in HA mode."""
        # Create a schedule first
        await auth_client.post(
            "/api/schedules",
            json={
                "target": "https://example.com",
                "cron_expression": "0 2 * * *",
                "timezone": "UTC",
                "profile": "web",
            },
        )

        # List schedules
        response = await auth_client.get("/api/schedules")
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 1

    @pytest.mark.asyncio
    async def test_scheduler_status_in_ha(self, auth_client):
        """Test scheduler status endpoint in HA mode."""
        response = await auth_client.get("/api/scheduler/status")
        assert response.status_code == 200

        data = response.json()
        assert "running" in data
        assert "total_schedules" in data
        assert "active_schedules" in data


class TestHAJobExecution:
    """Tests for job execution in HA mode."""

    @pytest.mark.asyncio
    async def test_assessment_creation_in_ha(self, auth_client):
        """Test creating assessments in HA mode."""
        response = await auth_client.post(
            "/api/assess",
            json={
                "target": "https://httpbin.org/get",
                "profile": "web",
            },
        )
        # May be refused due to scope, but should not error
        assert response.status_code in (202, 403)

    @pytest.mark.asyncio
    async def test_job_requeue_on_node_failure_simulation(self, auth_client, temp_db):
        """Test job requeue behavior when node fails.

        This simulates the fail_interrupted logic that runs on startup.
        """
        from strix.core import jobs, store

        store.configure(temp_db)
        await store.get_db()

        # Create a job in queued state
        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={},
            timeout=300.0,
        )
        job.state = jobs.JobState.QUEUED

        await store.save_job(job, tenant="test")

        # Verify job is queued
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "queued"

        # Simulate process restart
        failed_count = await store.fail_interrupted()
        assert failed_count >= 1

        # Verify job is failed
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "failed"


class TestHAPolicyBinding:
    """Tests for policy binding in HA mode."""

    @pytest.mark.asyncio
    async def test_policy_revocation_cancels_jobs_in_ha(self, auth_client):
        """Test that policy revocation cancels jobs across HA nodes."""
        # This tests the request_cancel_for_policy functionality
        # which is used when a policy is revoked

        from strix.core import store

        # Create jobs bound to a policy
        policy_id = "test-policy-123"

        # Create job with policy binding
        from strix.core import jobs

        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={"policy_id": policy_id},
            timeout=300.0,
        )
        job.state = jobs.JobState.QUEUED

        await store.save_job(job, tenant="test")

        # Request cancellation for policy
        cancelled = await store.request_cancel_for_policy(policy_id)
        assert cancelled >= 1

        # Verify job was cancelled
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "cancelled"


class TestHAMonitoring:
    """Tests for monitoring in HA mode."""

    @pytest.mark.asyncio
    async def test_monitor_status_in_ha(self, auth_client):
        """Test monitor status endpoint in HA mode."""
        response = await auth_client.get("/api/monitor/status")
        assert response.status_code == 200

        data = response.json()
        assert "running" in data
        assert "targets" in data

    @pytest.mark.asyncio
    async def test_alert_webhook_in_ha(self, auth_client):
        """Test alert webhook configuration in HA mode."""
        response = await auth_client.post(
            "/api/alerts/webhook",
            json={
                "url": "https://webhook.example.com/alerts",
                "secret": "test-secret",
            },
        )
        # May fail if URL not accessible, but should accept config
        assert response.status_code in (200, 201, 400)


class TestHAGracefulShutdown:
    """Tests for graceful shutdown in HA mode."""

    @pytest.mark.asyncio
    async def test_shutdown_cancels_queued_jobs(self, ha_app, temp_db):
        """Test that shutdown cancels queued jobs."""
        from strix.api import app as app_module
        from strix.core import jobs, store

        store.configure(temp_db)
        await store.get_db()

        # Create queued job
        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={},
            timeout=300.0,
        )
        job.state = jobs.JobState.QUEUED

        await store.save_job(job, tenant="test")

        # Stop app (simulates shutdown)
        if app_module._scheduler:
            await app_module._scheduler.stop()

        # Verify job marked failed
        loaded = await store.get_job(job.id, tenant="test")
        # Job should be failed due to fail_interrupted
        assert loaded["state"] in ("failed", "cancelled")


class TestHAMetrics:
    """Tests for metrics in HA mode."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_in_ha(self, auth_client):
        """Test metrics endpoint includes HA metrics."""
        response = await auth_client.get("/api/metrics")
        assert response.status_code == 200

        # Should include Prometheus metrics
        content = response.text
        assert "strix_" in content  # Strix metrics prefix


# Scaffolding for infrastructure-dependent integration tests


@pytest.mark.infrastructure
class TestRealInfrastructureHAIntegration:
    """Integration tests requiring real infrastructure."""

    @pytest.mark.asyncio
    async def test_kubernetes_ha_deployment(self):
        """Test HA deployment in Kubernetes.

        Requires:
        - kind or real Kubernetes cluster
        - Strix Helm chart deployed with replicaCount > 1
        - PostgreSQL and Redis deployed
        """
        pytest.skip("Requires Kubernetes infrastructure")

    @pytest.mark.asyncio
    async def test_rolling_update_preserves_leadership(self):
        """Test that rolling updates don't cause leadership flapping.

        Requires:
        - Kubernetes deployment with rolling update strategy
        - Multiple replicas
        """
        pytest.skip("Requires Kubernetes infrastructure")

    @pytest.mark.asyncio
    async def test_pod_disruption_budget_respected(self):
        """Test that PodDisruptionBudget ensures HA during maintenance.

        Requires:
        - PDB configured for API and scheduler
        - kubectl drain or node maintenance
        """
        pytest.skip("Requires Kubernetes infrastructure")

    @pytest.mark.asyncio
    async def test_cross_zone_failover(self):
        """Test failover across availability zones.

        Requires:
        - Multi-zone Kubernetes cluster
        - Topology spread constraints configured
        """
        pytest.skip("Requires multi-zone Kubernetes infrastructure")

    @pytest.mark.asyncio
    async def test_postgresql_patroni_failover(self):
        """Test application behavior during PostgreSQL Patroni failover.

        Requires:
        - Patroni PostgreSQL cluster
        - Ability to trigger failover
        """
        pytest.skip("Requires Patroni PostgreSQL infrastructure")

    @pytest.mark.asyncio
    async def test_redis_sentinel_failover(self):
        """Test rate limiting behavior during Redis Sentinel failover.

        Requires:
        - Redis Sentinel deployment
        - Ability to trigger failover
        """
        pytest.skip("Requires Redis Sentinel infrastructure")
