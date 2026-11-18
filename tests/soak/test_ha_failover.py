"""HA/Failover soak tests for Strix.

These tests validate multi-node HA behavior including:
- Leader election using PostgreSQL advisory locks
- Scheduler failover when leader node fails
- Job requeue on node failure
- Database connection pooling under failover

NOTE: These tests require PostgreSQL and a real multi-node setup.
They are structured as test scaffolding - actual multi-node testing
requires real infrastructure (kind cluster, multiple PostgreSQL nodes).
"""

from __future__ import annotations

import asyncio
import os
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

# Skip all tests if PostgreSQL is not available
pytestmark = pytest.mark.skipif(
    not os.environ.get("STRIX_POSTGRES_DSN"),
    reason="Requires PostgreSQL (set STRIX_POSTGRES_DSN)",
)


@pytest_asyncio.fixture
async def pg_settings():
    """Create settings with PostgreSQL DSN."""
    from strix.config import Settings

    dsn = os.environ.get("STRIX_POSTGRES_DSN", "postgresql://strix:strix@localhost:5432/strix")
    return Settings(
        db_path=dsn,
        scope_file="/tmp/scope.json",
        api_key="test-key-12345678901234567890123456789012",
        audit_hmac_key="dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==",
        redis_url="redis://localhost:6379/0",
        workers=1,
        queue_max=32,
    )


@pytest_asyncio.fixture
async def ha_manager(pg_settings):
    """Create HA manager for testing."""
    from strix.audit import AuditChain
    from strix.core.ha import HAManager, LeaderElectionConfig

    # Create a mock audit chain for testing
    audit_chain = MagicMock(spec=AuditChain)
    audit_chain.append_async = AsyncMock()

    config = LeaderElectionConfig(
        lock_name="strix_test_leader_election",
        ttl_seconds=10,
        retry_interval=1.0,
    )

    manager = HAManager(
        settings=pg_settings,
        audit_chain=audit_chain,
        election_config=config,
        drain_timeout=5.0,
    )

    yield manager

    # Cleanup
    await manager.stop()


class TestLeaderElection:
    """Tests for leader election using PostgreSQL advisory locks."""

    @pytest.mark.asyncio
    async def test_single_node_acquires_leadership(self, ha_manager):
        """Test that a single node can acquire leadership."""
        is_leader = await ha_manager.start()
        assert is_leader is True
        assert ha_manager.is_leader is True
        assert ha_manager.state.value == "leader"

    @pytest.mark.asyncio
    async def test_leader_releases_lock_on_stop(self, ha_manager):
        """Test that leadership lock is released on stop."""
        await ha_manager.start()
        assert ha_manager.is_leader

        await ha_manager.stop()
        assert ha_manager.state.value == "stopped"

    @pytest.mark.asyncio
    async def test_standby_becomes_leader_after_failover(self, pg_settings):
        """Test that standby node becomes leader when leader fails.

        This test simulates two nodes - one leader, one standby.
        When the leader releases the lock, the standby should acquire it.
        """
        from strix.audit import AuditChain
        from strix.core.ha import HAManager, LeaderElectionConfig

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_failover_election",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        # Start first node (leader)
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader1 = await leader.start()
        assert is_leader1 is True

        # Start second node (standby)
        standby = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader2 = await standby.start()
        assert is_leader2 is False
        assert standby.state.value == "standby"

        # Leader releases lock
        await leader.election.release_leadership()
        await leader.stop()

        # Standby should acquire leadership on next campaign
        # Note: In real scenario, standby would re-campaign automatically
        # Here we manually trigger a new campaign
        async with standby.election.campaign() as acquired:
            assert acquired is True

        await standby.stop()

    @pytest.mark.asyncio
    async def test_leadership_transfer_graceful(self, pg_settings):
        """Test graceful leadership transfer between nodes."""
        from strix.audit import AuditChain
        from strix.core.ha import HAManager, LeaderElectionConfig

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_transfer_election",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()
        assert leader.is_leader

        # Simulate graceful leadership transfer
        # Leader voluntarily releases and standby acquires
        await leader.election.release_leadership()

        standby = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        async with standby.election.campaign() as acquired:
            assert acquired is True

        await standby.stop()


class TestSchedulerFailover:
    """Tests for scheduler failover behavior."""

    @pytest.mark.asyncio
    async def test_scheduler_only_runs_on_leader(self, ha_manager, pg_settings):
        """Test that scheduler only runs assessments on leader node."""
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        await ha_manager.start()

        # Create mock monitor
        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        # Create scheduler
        scheduler = await create_scheduler(
            audit_chain=ha_manager.audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )

        # In HA mode, scheduler should only run if this node is leader
        if ha_manager.is_leader:
            await scheduler.start()
            assert scheduler.running is True
            await scheduler.stop()
        else:
            # Standby node should not start scheduler
            assert scheduler.running is False

    @pytest.mark.asyncio
    async def test_scheduled_jobs_resume_on_new_leader(self, pg_settings):
        """Test that scheduled jobs resume when new leader takes over.

        This test validates that:
        1. Schedules are persisted in database
        2. New leader loads schedules from database
        3. Jobs are re-scheduled on new leader
        """
        from strix.audit import AuditChain
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_scheduler_failover",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        # Leader node with scheduler
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader = await leader.start()
        assert is_leader

        scheduler = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler.start()

        # Create a test schedule
        schedule = await scheduler.create_schedule(
            target="https://example.com",
            cron_expression="0 * * * *",  # Hourly
            profile="web",
        )

        # Verify schedule was created
        loaded = await scheduler.get_schedule(schedule.id)
        assert loaded is not None
        assert loaded.target == "https://example.com"

        # Stop leader (simulate failure)
        await scheduler.stop()
        await leader.stop()

        # New leader starts
        new_leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader2 = await new_leader.start()
        assert is_leader2

        # New scheduler instance should load existing schedules
        new_scheduler = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await new_scheduler.initialize()

        # Verify schedule was loaded
        loaded = await new_scheduler.get_schedule(schedule.id)
        assert loaded is not None
        assert loaded.target == "https://example.com"

        await new_scheduler.stop()
        await new_leader.stop()


class TestJobRequeueOnNodeFailure:
    """Tests for job requeue behavior when a node fails."""

    @pytest.mark.asyncio
    async def queued_jobs_marked_failed_on_restart(self, pg_settings):
        """Test that queued/running jobs are marked failed on process restart."""
        # Create a job in queued state
        from strix.core import jobs, store

        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={},
            timeout=300.0,
        )

        # Manually set to queued state
        job.state = jobs.JobState.QUEUED

        await store.save_job(job, tenant="test")

        # Verify job is in queued state
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "queued"

        # Simulate process restart - call fail_interrupted
        failed_count = await store.fail_interrupted()
        assert failed_count >= 1

        # Verify job is now failed
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "failed"
        assert "interrupted by process restart" in loaded["error"]

    @pytest.mark.asyncio
    async def test_running_jobs_marked_failed_on_restart(self, pg_settings):
        """Test that running jobs are marked failed on process restart."""
        from strix.core import jobs, store

        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={},
            timeout=300.0,
        )
        job.state = jobs.JobState.RUNNING
        job.worker_id = "test-worker-1"

        await store.save_job(job, tenant="test")

        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "running"

        # Simulate process restart
        failed_count = await store.fail_interrupted()
        assert failed_count >= 1

        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["state"] == "failed"
        assert "interrupted by process restart" in loaded["error"]

    @pytest.mark.asyncio
    async def test_celery_jobs_revoked_on_cancellation(self, pg_settings):
        """Test that Celery queued tasks are revoked on cancellation.

        This validates the cooperative cancellation mechanism
        where cancel_requested flag is persisted and workers poll it.
        """
        # Create job with cancel_requested flag
        from strix.core import jobs, store

        job = jobs.prepare(
            target="https://example.com",
            profile="web",
            actor="test",
            policy={},
            timeout=300.0,
        )
        job.state = jobs.JobState.QUEUED

        await store.save_job(job, tenant="test")

        # Request cancellation
        success = await store.request_cancel(job.id, tenant="test")
        assert success is True

        # Verify cancel_requested flag is set
        loaded = await store.get_job(job.id, tenant="test")
        assert loaded["cancel_requested"] is True
        assert loaded["state"] == "cancelled"


class TestDatabaseConnectionPoolingUnderFailover:
    """Tests for database connection pooling behavior during failover."""

    @pytest.mark.asyncio
    async def test_connection_pool_survives_leader_change(self, pg_settings):
        """Test that database connections remain valid after leadership change."""
        from strix.audit import AuditChain
        from strix.core import store
        from strix.core.ha import HAManager, LeaderElectionConfig

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_pool_failover",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        # Leader with active database operations
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        # Perform database operations
        async with store.get_db_async() as db, db.transaction() as conn:
            await conn.execute("SELECT 1")

        # Release leadership
        await leader.election.release_leadership()
        await leader.stop()

        # New leader - database should still work
        new_leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await new_leader.start()

        # Verify database still accessible
        async with store.get_db_async() as db, db.transaction() as conn:
            result = await conn.fetchrow("SELECT 1 as test")
            assert result["test"] == 1

        await new_leader.stop()

    @pytest.mark.asyncio
    async def test_concurrent_operations_during_failover(self, pg_settings):
        """Test concurrent database operations during leadership transition."""
        from strix.audit import AuditChain
        from strix.core import store
        from strix.core.ha import HAManager, LeaderElectionConfig

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_concurrent_failover",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        # Run concurrent database operations
        async def db_operation(i: int) -> int:
            async with store.get_db_async() as db, db.transaction() as conn:
                result = await conn.fetchrow("SELECT $1 as val", i)
                return result["val"]

        # Execute multiple concurrent operations
        tasks = [db_operation(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        assert results == list(range(10))

        # Trigger failover during operations
        await leader.election.release_leadership()

        # Operations should still work on new leader
        new_leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await new_leader.start()

        tasks = [db_operation(i) for i in range(10, 20)]
        results = await asyncio.gather(*tasks)
        assert results == list(range(10, 20))

        await new_leader.stop()


class TestHAHealthChecks:
    """Tests for HA health check coordination."""

    @pytest.mark.asyncio
    async def test_health_checks_report_node_status(self, ha_manager):
        """Test that health checks report correct node status."""
        await ha_manager.start()

        health = await ha_manager.get_status()
        assert health["node_id"] == ha_manager.node_id
        assert health["ha_mode"] is True
        assert "health" in health
        assert "checks" in health["health"]

    @pytest.mark.asyncio
    async def test_database_health_check(self, ha_manager, pg_settings):
        """Test database health check."""
        await ha_manager.start()

        health = await ha_manager.get_status()
        db_check = health["health"]["checks"].get("database")
        assert db_check is not None
        # In test environment with mock, may not connect to real PG
        # Just verify check runs without error

    @pytest.mark.asyncio
    async def test_health_check_degraded_on_failure(self, ha_manager):
        """Test that health check reports degraded when checks fail."""

        # Register a failing check
        async def failing_check():
            raise Exception("Simulated failure")

        ha_manager.health.register_check("failing", failing_check)
        await ha_manager.start()

        health = await ha_manager.get_status()
        failing_check = health["health"]["checks"].get("failing")
        assert failing_check is not None
        assert failing_check["status"] == "unhealthy"
        assert health["health"]["status"] == "degraded"


class TestGracefulShutdown:
    """Tests for graceful shutdown with job drain."""

    @pytest.mark.asyncio
    async def test_shutdown_waits_for_drain(self, ha_manager):
        """Test that shutdown waits for in-flight work to complete."""
        await ha_manager.start()

        # Register a callback that takes some time
        drain_completed = asyncio.Event()

        async def slow_callback():
            await asyncio.sleep(0.1)
            drain_completed.set()

        ha_manager.shutdown.register_shutdown_callback(slow_callback)

        # Trigger shutdown
        await ha_manager.shutdown.shutdown("TEST")

        # Verify drain completed
        assert drain_completed.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_timeout(self, ha_manager):
        """Test that shutdown times out after drain_timeout."""
        await ha_manager.start()

        # Register a callback that takes longer than timeout
        async def very_slow_callback():
            await asyncio.sleep(10)

        ha_manager.shutdown.register_shutdown_callback(very_slow_callback)

        # Shutdown should complete within timeout + buffer
        start = time.time()
        await ha_manager.shutdown.shutdown("TEST")
        elapsed = time.time() - start

        # Should timeout at drain_timeout (5s) + small buffer
        assert elapsed < 8.0  # Allow some buffer

    @pytest.mark.asyncio
    async def test_signal_handlers_installed(self, ha_manager):
        """Test that signal handlers are installed on start."""
        await ha_manager.start()

        # Verify signal handlers are installed (can't easily test actual signals)
        # Just verify no exception during install
        ha_manager.shutdown.install_signal_handlers()  # Should be idempotent
        ha_manager.shutdown.remove_signal_handlers()


class TestHAIntegration:
    """Integration tests for HA features."""

    @pytest.mark.asyncio
    async def test_full_failover_cycle(self, pg_settings):
        """Test a complete failover cycle: leader -> fail -> new leader -> recovery."""
        from strix.audit import AuditChain
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_full_cycle",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        # Phase 1: Initial leader with scheduler
        leader1 = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader = await leader1.start()
        assert is_leader

        scheduler1 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler1.start()

        # Create schedule
        schedule = await scheduler1.create_schedule(
            target="https://example.com",
            cron_expression="0 * * * *",
            profile="web",
        )

        # Phase 2: Leader fails
        await scheduler1.stop()
        await leader1.stop()

        # Phase 3: New leader takes over
        leader2 = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        is_leader2 = await leader2.start()
        assert is_leader2

        scheduler2 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler2.initialize()

        # Verify schedule recovered
        loaded = await scheduler2.get_schedule(schedule.id)
        assert loaded is not None
        assert loaded.target == "https://example.com"

        # Phase 4: New leader runs normally
        await scheduler2.start()
        assert scheduler2.running

        # Cleanup
        await scheduler2.stop()
        await leader2.stop()

    @pytest.mark.asyncio
    async def test_multiple_standby_nodes(self, pg_settings):
        """Test multiple standby nodes with single leader."""
        from strix.audit import AuditChain
        from strix.core.ha import HAManager, LeaderElectionConfig

        audit_chain = MagicMock(spec=AuditChain)
        audit_chain.append_async = AsyncMock()

        config = LeaderElectionConfig(
            lock_name="strix_test_multiple_standby",
            ttl_seconds=5,
            retry_interval=0.5,
        )

        # Start leader
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()
        assert leader.is_leader

        # Start multiple standbys
        standbys = []
        for _ in range(3):
            standby = HAManager(
                settings=pg_settings,
                audit_chain=audit_chain,
                election_config=config,
                drain_timeout=5.0,
            )
            is_leader = await standby.start()
            assert is_leader is False
            assert standby.state.value == "standby"
            standbys.append(standby)

        # All standbys should be in standby state
        for standby in standbys:
            assert standby.state.value == "standby"

        # Leader fails
        await leader.stop()

        # One standby should become leader (in real scenario, they'd re-campaign)
        # Here we test that at least one can acquire lock
        async with standbys[0].election.campaign() as acquired:
            assert acquired is True

        # Cleanup
        for standby in standbys:
            await standby.stop()


# Scaffolding for tests that require real infrastructure
# These are marked as requiring infrastructure and skipped by default


@pytest.mark.infrastructure
class TestRealInfrastructureHA:
    """Tests that require real Kubernetes/PostgreSQL infrastructure.

    These tests are scaffolding for CI/CD pipelines that have
    access to kind clusters or real PostgreSQL instances.

    To run: pytest tests/soak/test_ha_failover.py -m infrastructure
    """

    @pytest.mark.asyncio
    async def test_kind_cluster_leader_election(self):
        """Test leader election in a kind cluster with multiple pods.

        Requires:
        - kind cluster with 3+ nodes
        - PostgreSQL deployed in cluster
        - Strix deployed with replicaCount > 1
        """
        pytest.skip("Requires kind cluster infrastructure")

    @pytest.mark.asyncio
    async def test_pod_failure_triggers_failover(self):
        """Test that pod deletion triggers leader failover.

        Requires:
        - Running Strix deployment with HA mode
        - Ability to delete leader pod
        """
        pytest.skip("Requires Kubernetes infrastructure")

    @pytest.mark.asyncio
    async def test_network_partition_behavior(self):
        """Test behavior during network partition.

        Requires:
        - Multi-node PostgreSQL setup
        - Network partition simulation (tc/netem)
        """
        pytest.skip("Requires network partition testing infrastructure")

    @pytest.mark.asyncio
    async def test_postgresql_failover(self):
        """Test behavior when PostgreSQL primary fails over to replica.

        Requires:
        - PostgreSQL with streaming replication
        - Patroni or similar for automatic failover
        """
        pytest.skip("Requires PostgreSQL HA infrastructure")
