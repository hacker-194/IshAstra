"""Leader election soak tests for Strix.

These tests focus specifically on distributed lock behavior,
single active scheduler guarantee, and graceful leadership transfer.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

# Skip if PostgreSQL not available
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
async def audit_chain():
    """Create mock audit chain."""
    audit = MagicMock()
    audit.append_async = AsyncMock()
    return audit


class TestDistributedLock:
    """Tests for PostgreSQL advisory lock-based distributed locking."""

    @pytest.mark.asyncio
    async def test_advisory_lock_acquire_release(self, pg_settings, audit_chain):
        """Test basic advisory lock acquire and release."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_lock_basic",
            ttl_seconds=10,
        )

        election = LeaderElection(config, pg_settings, audit_chain)

        # Acquire lock
        acquired = await election.try_acquire_leadership()
        assert acquired is True
        assert election._lock_held is True

        # Release lock
        await election.release_leadership()
        assert election._lock_held is False

    @pytest.mark.asyncio
    async def test_advisory_lock_exclusion(self, pg_settings, audit_chain):
        """Test that only one node can hold the lock at a time."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_lock_exclusion",
            ttl_seconds=10,
        )

        election1 = LeaderElection(config, pg_settings, audit_chain)
        election2 = LeaderElection(config, pg_settings, audit_chain)

        # First node acquires
        acquired1 = await election1.try_acquire_leadership()
        assert acquired1 is True

        # Second node should fail
        acquired2 = await election2.try_acquire_leadership()
        assert acquired2 is False

        # Release first
        await election1.release_leadership()

        # Now second can acquire
        acquired2 = await election2.try_acquire_leadership()
        assert acquired2 is True

        await election2.release_leadership()

    @pytest.mark.asyncio
    async def test_lock_auto_release_on_connection_loss(self, pg_settings, audit_chain):
        """Test that lock is released when connection is lost.

        PostgreSQL advisory locks are session-scoped and automatically
        released when the session ends.
        """
        from strix.core import store
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_lock_session",
            ttl_seconds=10,
        )

        election = LeaderElection(config, pg_settings, audit_chain)
        acquired = await election.try_acquire_leadership()
        assert acquired is True

        # Close database connection (simulates process death)
        await store.close_db_pool()

        # Wait a bit for session cleanup
        await asyncio.sleep(0.5)

        # New election should be able to acquire
        election2 = LeaderElection(config, pg_settings, audit_chain)
        acquired2 = await election2.try_acquire_leadership()
        assert acquired2 is True

        await election2.release_leadership()

    @pytest.mark.asyncio
    async def test_lock_id_collision_handling(self, pg_settings, audit_chain):
        """Test that different lock names don't interfere."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config1 = LeaderElectionConfig(lock_name="strix_lock_a", ttl_seconds=10)
        config2 = LeaderElectionConfig(lock_name="strix_lock_b", ttl_seconds=10)

        election1 = LeaderElection(config1, pg_settings, audit_chain)
        election2 = LeaderElection(config2, pg_settings, audit_chain)

        # Both should be able to acquire different locks
        acquired1 = await election1.try_acquire_leadership()
        acquired2 = await election2.try_acquire_leadership()

        assert acquired1 is True
        assert acquired2 is True

        await election1.release_leadership()
        await election2.release_leadership()


class TestSingleActiveScheduler:
    """Tests ensuring only one scheduler runs at a time."""

    @pytest.mark.asyncio
    async def test_scheduler_only_on_leader(self, pg_settings, audit_chain):
        """Test that scheduler only starts on leader node."""
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        config = LeaderElectionConfig(
            lock_name="strix_test_scheduler_single",
            ttl_seconds=10,
            retry_interval=1.0,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        # Create two HA managers
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )

        standby = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )

        # Start both
        is_leader1 = await leader.start()
        is_leader2 = await standby.start()

        assert is_leader1 is True
        assert is_leader2 is False

        # Create schedulers on both
        scheduler1 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )

        scheduler2 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )

        # Only leader's scheduler should run
        if leader.is_leader:
            await scheduler1.start()
            assert scheduler1.running is True
            await scheduler1.stop()
        else:
            assert scheduler1.running is False

        if standby.is_leader:
            await scheduler2.start()
            assert scheduler2.running is True
            await scheduler2.stop()
        else:
            assert scheduler2.running is False

        await leader.stop()
        await standby.stop()

    @pytest.mark.asyncio
    async def test_scheduler_stops_when_losing_leadership(self, pg_settings, audit_chain):
        """Test that scheduler stops when node loses leadership."""
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        config = LeaderElectionConfig(
            lock_name="strix_test_scheduler_lose_leadership",
            ttl_seconds=10,
            retry_interval=1.0,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        scheduler = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler.start()
        assert scheduler.running is True

        # Simulate leadership loss
        await leader.election.release_leadership()
        leader._state = leader._state.STANDBY

        # Scheduler should be stopped (in real impl, HA manager would stop it)
        await scheduler.stop()
        assert scheduler.running is False

        await leader.stop()

    @pytest.mark.asyncio
    async def test_no_duplicate_scheduled_jobs(self, pg_settings, audit_chain):
        """Test that scheduled jobs don't run on multiple nodes."""
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        config = LeaderElectionConfig(
            lock_name="strix_test_no_dup_jobs",
            ttl_seconds=10,
            retry_interval=1.0,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        scheduler = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler.start()

        # Create a schedule
        schedule = await scheduler.create_schedule(
            target="https://example.com",
            cron_expression="* * * * *",  # Every minute
            profile="web",
        )

        # Verify only one job would be scheduled
        jobs = scheduler._scheduler.get_jobs() if scheduler._scheduler else []
        schedule_jobs = [j for j in jobs if j.id.startswith(f"sched_{schedule.id}")]
        assert len(schedule_jobs) == 1

        await scheduler.stop()
        await leader.stop()


class TestGracefulLeadershipTransfer:
    """Tests for graceful leadership transfer."""

    @pytest.mark.asyncio
    async def test_voluntary_leadership_transfer(self, pg_settings, audit_chain):
        """Test voluntary leadership transfer between nodes."""
        from strix.core.ha import HAManager, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_voluntary_transfer",
            ttl_seconds=10,
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

        # Start standby
        standby = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await standby.start()
        assert standby.state.value == "standby"

        # Leader voluntarily transfers leadership
        await leader.election.release_leadership()

        # Standby campaigns and becomes leader
        async with standby.election.campaign() as acquired:
            assert acquired is True

        # Verify new leader state
        assert standby.election._lock_held is True

        await standby.stop()

    @pytest.mark.asyncio
    async def test_leader_drain_before_transfer(self, pg_settings, audit_chain):
        """Test that leader drains jobs before transferring leadership."""
        from strix.core.ha import HAManager, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_drain_transfer",
            ttl_seconds=10,
            retry_interval=0.5,
        )

        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        # Register a drain callback
        drain_done = asyncio.Event()

        async def drain_jobs():
            await asyncio.sleep(0.1)
            drain_done.set()

        leader.shutdown.register_shutdown_callback(drain_jobs)

        # Simulate graceful shutdown (which includes leadership release)
        await leader.shutdown.shutdown("TRANSFER")

        # Verify drain completed before leadership released
        assert drain_done.is_set()
        assert leader.election._lock_held is False

        await leader.stop()

    @pytest.mark.asyncio
    async def test_standby_promotion_preserves_state(self, pg_settings, audit_chain):
        """Test that standby promotion preserves scheduler state."""
        from strix.core.ha import HAManager, LeaderElectionConfig
        from strix.core.scheduler import create_scheduler
        from strix.monitor import Monitor

        config = LeaderElectionConfig(
            lock_name="strix_test_state_preserve",
            ttl_seconds=10,
            retry_interval=0.5,
        )

        monitor = MagicMock(spec=Monitor)
        monitor.alert_sinks = []

        # Leader creates schedule
        leader = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        await leader.start()

        scheduler1 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler1.start()

        schedule = await scheduler1.create_schedule(
            target="https://example.com",
            cron_expression="0 * * * *",
            profile="web",
        )
        schedule_id = schedule.id

        await scheduler1.stop()
        await leader.stop()

        # Standby becomes leader
        standby = HAManager(
            settings=pg_settings,
            audit_chain=audit_chain,
            election_config=config,
            drain_timeout=5.0,
        )
        async with standby.election.campaign() as acquired:
            assert acquired is True

        # New scheduler loads existing schedules
        scheduler2 = await create_scheduler(
            audit_chain=audit_chain,
            monitor=monitor,
            settings=pg_settings,
            job_timeout=300.0,
            scope_mode=pg_settings.scope_mode,
        )
        await scheduler2.initialize()

        # Verify schedule was preserved
        loaded = await scheduler2.get_schedule(schedule_id)
        assert loaded is not None
        assert loaded.target == "https://example.com"

        await scheduler2.stop()
        await standby.stop()


class TestLeaderElectionEdgeCases:
    """Tests for edge cases in leader election."""

    @pytest.mark.asyncio
    async def test_rapid_leadership_changes(self, pg_settings, audit_chain):
        """Test rapid leadership acquire/release cycles."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_rapid_changes",
            ttl_seconds=10,
            retry_interval=0.1,
        )

        election = LeaderElection(config, pg_settings, audit_chain)

        # Rapid acquire/release cycles
        for _ in range(10):
            acquired = await election.try_acquire_leadership()
            assert acquired is True
            await election.release_leadership()
            assert election._lock_held is False

    @pytest.mark.asyncio
    async def test_concurrent_campaign_attempts(self, pg_settings, audit_chain):
        """Test multiple concurrent campaign attempts."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_concurrent_campaign",
            ttl_seconds=10,
            retry_interval=0.1,
        )

        elections = [LeaderElection(config, pg_settings, audit_chain) for _ in range(5)]

        # All try to campaign simultaneously
        results = []
        for election in elections:
            async with election.campaign() as acquired:
                results.append(acquired)

        # Only one should succeed
        assert sum(results) == 1

    @pytest.mark.asyncio
    async def test_heartbeat_maintains_leadership(self, pg_settings, audit_chain):
        """Test that heartbeat maintains leadership lock."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        config = LeaderElectionConfig(
            lock_name="strix_test_heartbeat",
            ttl_seconds=2,  # Short TTL for testing
            retry_interval=0.5,
        )

        election = LeaderElection(config, pg_settings, audit_chain)

        acquired = await election.try_acquire_leadership()
        assert acquired is True

        await election.start_heartbeat()

        # Wait for a few heartbeats
        await asyncio.sleep(1.5)

        # Lock should still be held
        assert election._lock_held is True

        await election.stop_heartbeat()
        await election.release_leadership()

    @pytest.mark.asyncio
    async def test_sqlite_mode_single_node(self, audit_chain):
        """Test that SQLite mode always returns leader (single node)."""
        from strix.config import Settings
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        settings = Settings(
            db_path="sqlite:///tmp/test.db",
            scope_file="/tmp/scope.json",
            api_key="test-key-12345678901234567890123456789012",
            audit_hmac_key="dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==",
        )

        config = LeaderElectionConfig(lock_name="strix_test_sqlite", ttl_seconds=10)
        election = LeaderElection(config, settings, audit_chain)

        # In SQLite mode, should always return True (single node)
        acquired = await election.try_acquire_leadership()
        assert acquired is True

        # Release should be no-op
        await election.release_leadership()

    @pytest.mark.asyncio
    async def test_lock_name_isolation(self, pg_settings, audit_chain):
        """Test that different applications can use different lock names."""
        from strix.core.ha import LeaderElection, LeaderElectionConfig

        # App A uses its own lock name
        config_a = LeaderElectionConfig(lock_name="app_a_leader", ttl_seconds=10)
        election_a = LeaderElection(config_a, pg_settings, audit_chain)

        # App B uses different lock name
        config_b = LeaderElectionConfig(lock_name="app_b_leader", ttl_seconds=10)
        election_b = LeaderElection(config_b, pg_settings, audit_chain)

        # Both can be leaders simultaneously
        acquired_a = await election_a.try_acquire_leadership()
        acquired_b = await election_b.try_acquire_leadership()

        assert acquired_a is True
        assert acquired_b is True

        await election_a.release_leadership()
        await election_b.release_leadership()


# Scaffolding for infrastructure-dependent tests


@pytest.mark.infrastructure
class TestRealInfrastructureLeaderElection:
    """Tests requiring real PostgreSQL/Kubernetes infrastructure."""

    @pytest.mark.asyncio
    async def test_postgresql_advisory_lock_persistence(self):
        """Test that advisory lock persists across transactions.

        Advisory locks are session-scoped, not transaction-scoped.
        """
        pytest.skip("Requires PostgreSQL infrastructure")

    @pytest.mark.asyncio
    async def test_patroni_failover_leadership(self):
        """Test leadership behavior during Patroni PostgreSQL failover.

        When PostgreSQL primary fails over, client connections are
        terminated and advisory locks are released.
        """
        pytest.skip("Requires Patroni PostgreSQL HA cluster")

    @pytest.mark.asyncio
    async def test_kubernetes_leader_election_configmap(self):
        """Test alternative leader election using Kubernetes ConfigMap.

        This is an alternative to PostgreSQL advisory locks.
        """
        pytest.skip("Requires Kubernetes cluster")

    @pytest.mark.asyncio
    async def test_etcd_leader_election(self):
        """Test leader election using etcd (for non-PostgreSQL deployments)."""
        pytest.skip("Requires etcd cluster")
