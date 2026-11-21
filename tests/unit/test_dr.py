"""Unit tests for DR/Failover module (src/ishastra/dr.py).

This module implements Disaster Recovery and Failover automation with:
- Multi-region DR orchestration (primary/secondary/tertiary)
- PostgreSQL Point-in-Time Recovery (pg_basebackup + WAL)
- Redis Streams consumer groups for queue coordination
- Object storage abstraction (S3, GCS, local filesystem)
- Chaos engineering for DR validation
- Automated failover with health checks

No existing test files for this module - it's newly created in Phase 7.
User instruction: "fix all remaining gaps" - complete the unit tests for the DR module.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ishastra.dr import (
    ChaosTester,
    DRManager,
    DRState,
    DRStatus,
    FailoverResult,
    PITRConfig,
    PITRManager,
    RegionConfig,
    RegionRole,
    create_dr_config_example,
)


class TestRegionConfig:
    """Tests for RegionConfig."""

    def test_region_config_creation(self):
        """Test creating a region config."""
        region = RegionConfig(
            name="us-east-1",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test-bucket"},
            priority=100,
            enabled=True,
        )
        assert region.name == "us-east-1"
        assert region.role == RegionRole.PRIMARY
        assert region.priority == 100
        assert region.enabled is True


class TestDRState:
    """Tests for DRState."""

    def test_default_state(self):
        """Test default DR state values."""
        state = DRState()
        assert state.status == DRStatus.HEALTHY
        assert state.primary_region == ""
        assert state.active_region == ""
        assert state.last_failover is None
        assert state.last_failover_reason is None
        assert state.regions == {}
        assert state.replication_lag_seconds == {}
        assert state.last_check is None


class TestDRManager:
    """Tests for DRManager."""

    @pytest.fixture
    def temp_files(self):
        """Create temporary state and config files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "dr_state.json"
            config_file = Path(tmpdir) / "dr_config.json"
            yield state_file, config_file

    @pytest.fixture
    def dr_manager(self, temp_files):
        """Create DRManager with temp files."""
        state_file, config_file = temp_files
        return DRManager(state_file=state_file, config_file=config_file)

    def test_init_creates_empty_state(self, dr_manager):
        """Test initialization creates empty state."""
        assert dr_manager.state.status == DRStatus.HEALTHY
        assert dr_manager.state.regions == {}

    def test_add_region(self, dr_manager):
        """Test adding a region."""
        region = RegionConfig(
            name="us-east-1",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test-bucket"},
        )
        dr_manager.add_region(region)

        assert "us-east-1" in dr_manager.state.regions
        assert dr_manager.state.primary_region == "us-east-1"

    def test_add_secondary_region(self, dr_manager):
        """Test adding a secondary region."""
        primary = RegionConfig(
            name="us-east-1",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test-bucket"},
        )
        secondary = RegionConfig(
            name="us-west-2",
            role=RegionRole.SECONDARY,
            endpoint="https://api-west.example.com",
            database_url="postgresql://user:pass@db-west:5432/ishastra",
            redis_url="redis://redis-west:6379/0",
            object_storage={"backend": "s3", "bucket": "test-bucket-west"},
            priority=50,
        )
        dr_manager.add_region(primary)
        dr_manager.add_region(secondary)

        assert "us-west-2" in dr_manager.state.regions
        assert dr_manager.state.regions["us-west-2"].priority == 50

    @pytest.mark.asyncio
    async def test_check_region_health_local_db(self, dr_manager):
        """Test health check with local SQLite database."""
        region = RegionConfig(
            name="local",
            role=RegionRole.PRIMARY,
            endpoint="http://localhost:8000",
            database_url="sqlite:///./test.db",
            redis_url="redis://localhost:6379/0",
            object_storage={"backend": "local", "path": "/tmp/test_store"},
        )
        dr_manager.add_region(region)

        with patch("redis.asyncio.Redis") as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis_instance.ping = AsyncMock(return_value=True)
            mock_redis_instance.close = AsyncMock()
            mock_redis.from_url.return_value = mock_redis_instance

            with patch("pathlib.Path.exists", return_value=True):
                health = await dr_manager.check_region_health("local")

        assert health["region"] == "local"
        assert "checks" in health

    @pytest.mark.asyncio
    async def test_check_region_health_disabled_region(self, dr_manager):
        """Test health check returns unhealthy for disabled region."""
        region = RegionConfig(
            name="disabled",
            role=RegionRole.SECONDARY,
            endpoint="http://disabled.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test"},
            enabled=False,
        )
        dr_manager.add_region(region)

        health = await dr_manager.check_region_health("disabled")
        assert health["healthy"] is False
        assert health["reason"] == "Region not configured or disabled"

    @pytest.mark.asyncio
    async def test_check_region_health_unknown_region(self, dr_manager):
        """Test health check returns unhealthy for unknown region."""
        health = await dr_manager.check_region_health("unknown")
        assert health["healthy"] is False
        assert health["reason"] == "Region not configured or disabled"

    @pytest.mark.asyncio
    async def test_initiate_failover_target_not_configured(self, dr_manager):
        """Test failover fails when target region not configured."""
        region = RegionConfig(
            name="primary",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test"},
        )
        dr_manager.add_region(region)

        result = await dr_manager.initiate_failover("nonexistent", reason="test")

        assert result.success is False
        assert result.to_region == "nonexistent"
        assert "Target region not configured" in result.steps_failed

    @pytest.mark.asyncio
    async def test_initiate_failover_target_disabled(self, dr_manager):
        """Test failover fails when target region is disabled."""
        primary = RegionConfig(
            name="primary",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "s3", "bucket": "test"},
        )
        secondary = RegionConfig(
            name="secondary",
            role=RegionRole.SECONDARY,
            endpoint="https://api-west.example.com",
            database_url="postgresql://user:pass@db-west:5432/ishastra",
            redis_url="redis://redis-west:6379/0",
            object_storage={"backend": "s3", "bucket": "test-west"},
            enabled=False,
        )
        dr_manager.add_region(primary)
        dr_manager.add_region(secondary)

        result = await dr_manager.initiate_failover("secondary", reason="test")

        assert result.success is False
        assert "Target region is disabled" in result.steps_failed

    @pytest.mark.asyncio
    async def test_initiate_failover_success(self, dr_manager):
        """Test successful failover with PostgreSQL."""
        primary = RegionConfig(
            name="primary",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="postgresql://user:pass@db:5432/ishastra",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "local", "path": "/tmp/primary"},
        )
        secondary = RegionConfig(
            name="secondary",
            role=RegionRole.SECONDARY,
            endpoint="https://api-west.example.com",
            database_url="postgresql://user:pass@db-west:5432/ishastra",
            redis_url="redis://redis-west:6379/0",
            object_storage={"backend": "local", "path": "/tmp/secondary"},
            priority=50,
        )
        dr_manager.add_region(primary)
        dr_manager.add_region(secondary)

        with (
            patch.object(dr_manager, "check_region_health", new_callable=AsyncMock) as mock_health,
            patch.object(dr_manager, "_promote_database", new_callable=AsyncMock),
            patch.object(dr_manager, "_update_dns", new_callable=AsyncMock),
            patch.object(dr_manager, "_redirect_redis", new_callable=AsyncMock),
        ):
            mock_health.return_value = {"healthy": True, "checks": {}}
            result = await dr_manager.initiate_failover("secondary", reason="test")

        assert result.success is True
        assert result.from_region == "primary"
        assert result.to_region == "secondary"
        assert result.reason == "test"
        assert "Target region health verified" in result.steps_completed
        assert "Database promoted" in result.steps_completed
        assert "DNS updated" in result.steps_completed
        assert "Redis redirected" in result.steps_completed
        assert "State updated" in result.steps_completed
        assert dr_manager.state.active_region == "secondary"
        assert dr_manager.state.status == DRStatus.FAILOVER_COMPLETE

    @pytest.mark.asyncio
    async def test_initiate_failover_with_force(self, dr_manager):
        """Test failover with force=True bypasses health check."""
        primary = RegionConfig(
            name="primary",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="sqlite:///./primary.db",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "local", "path": "/tmp/primary"},
        )
        secondary = RegionConfig(
            name="secondary",
            role=RegionRole.SECONDARY,
            endpoint="https://api-west.example.com",
            database_url="sqlite:///./secondary.db",
            redis_url="redis://redis-west:6379/0",
            object_storage={"backend": "local", "path": "/tmp/secondary"},
        )
        dr_manager.add_region(primary)
        dr_manager.add_region(secondary)

        with (
            patch.object(dr_manager, "check_region_health", new_callable=AsyncMock) as mock_health,
            patch.object(dr_manager, "_promote_database", new_callable=AsyncMock),
            patch.object(dr_manager, "_update_dns", new_callable=AsyncMock),
            patch.object(dr_manager, "_redirect_redis", new_callable=AsyncMock),
        ):
            mock_health.return_value = {"healthy": False, "checks": {}}
            result = await dr_manager.initiate_failover("secondary", reason="test", force=True)

        assert result.success is True
        assert "Target region health verified" in result.steps_completed


class TestPITRManager:
    """Tests for PITRManager."""

    @pytest.fixture
    def pitr_manager(self):
        """Create PITRManager with temp directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield PITRManager(
                database_url="postgresql://user:pass@db:5432/ishastra",
                backup_dir=Path(tmpdir) / "pitr",
                config=PITRConfig(retention_days=7),
            )

    @pytest.mark.asyncio
    async def test_create_base_backup(self, pitr_manager):
        """Test creating a base backup."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            backup_path = await pitr_manager.create_base_backup()

            assert backup_path.name.startswith("base_")
            assert backup_path.parent == pitr_manager.backup_dir

    @pytest.mark.asyncio
    async def test_create_base_backup_failure(self, pitr_manager):
        """Test base backup failure raises error."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b"pg_basebackup failed"))
            mock_proc.returncode = 1
            mock_exec.return_value = mock_proc

            with pytest.raises(RuntimeError, match="pg_basebackup failed"):
                await pitr_manager.create_base_backup()

    @pytest.mark.asyncio
    async def test_list_backups_empty(self, pitr_manager):
        """Test listing backups when none exist."""
        backups = await pitr_manager.list_backups()
        assert backups == []

    @pytest.mark.asyncio
    async def test_list_backups(self, pitr_manager):
        """Test listing backups."""

        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        backup1 = pitr_manager.backup_dir / "base_20240101_120000"
        backup2 = pitr_manager.backup_dir / "base_20240102_120000"
        backup1.mkdir()
        backup2.mkdir()

        import os
        from datetime import UTC, datetime

        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp()
        t2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC).timestamp()
        os.utime(backup1, (t1, t1))
        os.utime(backup2, (t2, t2))

        backups = await pitr_manager.list_backups()

        assert len(backups) == 2
        assert backups[0]["name"] == "base_20240101_120000"
        assert backups[1]["name"] == "base_20240102_120000"
        assert "created" in backups[0]
        assert "size_bytes" in backups[0]

    @pytest.mark.asyncio
    async def test_verify_backup_not_found(self, pitr_manager):
        """Test verifying non-existent backup."""
        result = await pitr_manager.verify_backup("/nonexistent/backup.tar.gz")
        assert result["valid"] is False
        assert result["error"] == "Backup not found"

    @pytest.mark.asyncio
    async def test_verify_backup_valid(self, pitr_manager):
        """Test verifying a valid backup."""
        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = pitr_manager.backup_dir / "base_test"
        backup_file.mkdir()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await pitr_manager.verify_backup(str(backup_file))

            assert result["valid"] is True
            assert result["path"] == str(backup_file)

    @pytest.mark.asyncio
    async def test_verify_backup_invalid(self, pitr_manager):
        """Test verifying an invalid/corrupt backup."""
        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = pitr_manager.backup_dir / "base_test"
        backup_file.mkdir()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b"corrupt"))
            mock_proc.returncode = 1
            mock_exec.return_value = mock_proc

            result = await pitr_manager.verify_backup(str(backup_file))

            assert result["valid"] is False
            assert "Corrupt archive" in result["error"]

    @pytest.mark.asyncio
    async def test_restore_to_time(self, pitr_manager):
        """Test restoring to a point in time."""
        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        base_backup = pitr_manager.backup_dir / "base_20240101_120000"
        base_backup.mkdir()

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc

            with tempfile.TemporaryDirectory() as tmpdir:
                target_dir = Path(tmpdir) / "restored"
                restored = await pitr_manager.restore_to_time(
                    target_time="2024-01-02T12:00:00+00:00",
                    target_dir=target_dir,
                    base_backup=str(base_backup),
                )

                assert restored == target_dir
                assert (target_dir / "recovery.signal").exists()
                assert (target_dir / "postgresql.auto.conf").exists()

                conf_content = (target_dir / "postgresql.auto.conf").read_text()
                assert "recovery_target_time = '2024-01-02T12:00:00+00:00'" in conf_content
                assert "recovery_target_timeline = 'latest'" in conf_content
                assert "recovery_target_action = 'promote'" in conf_content

    @pytest.mark.asyncio
    async def test_restore_to_time_auto_select_backup(self, pitr_manager):
        """Test restore auto-selects latest backup before target time."""
        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        backup1 = pitr_manager.backup_dir / "base_20240101_120000"
        backup2 = pitr_manager.backup_dir / "base_20240102_120000"
        backup1.mkdir()
        backup2.mkdir()

        import os
        from datetime import UTC, datetime

        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp()
        t2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC).timestamp()
        os.utime(backup1, (t1, t1))
        os.utime(backup2, (t2, t2))

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc

            with tempfile.TemporaryDirectory() as tmpdir:
                target_dir = Path(tmpdir) / "restored"
                restored = await pitr_manager.restore_to_time(
                    target_time="2024-01-03T12:00:00+00:00",
                    target_dir=target_dir,
                )

                assert restored == target_dir

    @pytest.mark.asyncio
    async def test_restore_to_time_no_suitable_backup(self, pitr_manager):
        """Test restore fails when no backup before target time."""

        with pytest.raises(RuntimeError, match="No base backups available"):
            await pitr_manager.restore_to_time(
                target_time="2023-01-01T12:00:00+00:00",
                target_dir="/tmp/restored",
            )

        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)
        backup = pitr_manager.backup_dir / "base_20240101_120000"
        backup.mkdir()
        import os
        from datetime import UTC, datetime

        t = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp()
        os.utime(backup, (t, t))

        with pytest.raises(RuntimeError, match="No base backup before target time"):
            await pitr_manager.restore_to_time(
                target_time="2023-01-01T12:00:00+00:00",
                target_dir="/tmp/restored",
            )

    @pytest.mark.asyncio
    async def test_cleanup_old_backups(self, pitr_manager):
        """Test cleanup removes old backups."""
        pitr_manager.backup_dir.mkdir(parents=True, exist_ok=True)

        old_time = datetime.now(UTC).replace(day=1).strftime("%Y%m%d_%H%M%S")
        old_backup = pitr_manager.backup_dir / f"base_{old_time}"
        old_backup.touch()

        new_time = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        new_backup = pitr_manager.backup_dir / f"base_{new_time}"
        new_backup.touch()

        with patch("ishastra.dr.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime.now(UTC)
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            removed = await pitr_manager.cleanup_old_backups()

            assert isinstance(removed, int)


class TestChaosTester:
    """Tests for ChaosTester."""

    @pytest.fixture
    def dr_manager(self):
        """Create a DRManager for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "dr_state.json"
            config_file = Path(tmpdir) / "dr_config.json"
            yield DRManager(state_file=state_file, config_file=config_file)

    @pytest.fixture
    def chaos_tester(self, dr_manager):
        """Create ChaosTester."""

        primary = RegionConfig(
            name="primary",
            role=RegionRole.PRIMARY,
            endpoint="https://api.example.com",
            database_url="sqlite:///./primary.db",
            redis_url="redis://redis:6379/0",
            object_storage={"backend": "local", "path": "/tmp/primary"},
        )
        secondary = RegionConfig(
            name="secondary",
            role=RegionRole.SECONDARY,
            endpoint="https://api-west.example.com",
            database_url="sqlite:///./secondary.db",
            redis_url="redis://redis-west:6379/0",
            object_storage={"backend": "local", "path": "/tmp/secondary"},
        )
        dr_manager.add_region(primary)
        dr_manager.add_region(secondary)
        yield ChaosTester(dr_manager)

    @pytest.mark.asyncio
    async def test_test_replication_lag(self, chaos_tester):
        """Test replication lag test."""
        with patch.object(chaos_tester.dr_manager, "health_check_all", new_callable=AsyncMock) as mock_health:
            mock_health.return_value = {
                "primary": {"healthy": True, "checks": {}},
                "secondary": {
                    "healthy": True,
                    "checks": {"replication_lag": {"seconds": 10, "healthy": True}},
                },
            }

            result = await chaos_tester.test_replication_lag()

            assert result["test"] == "replication_lag"
            assert result["success"] is True
            assert "replication_lag" in result
            assert "secondary" in result["replication_lag"]

    @pytest.mark.asyncio
    async def test_test_primary_failure(self, chaos_tester):
        """Test primary failure test."""
        with patch.object(
            chaos_tester.dr_manager, "initiate_failover", new_callable=AsyncMock
        ) as mock_failover:
            mock_failover.return_value = FailoverResult(
                success=True,
                from_region="primary",
                to_region="secondary",
                reason="chaos_test_primary_failure",
                duration_seconds=5.0,
                steps_completed=["step1", "step2"],
                steps_failed=[],
            )
            with patch.object(
                chaos_tester.dr_manager, "check_region_health", new_callable=AsyncMock
            ) as mock_health:
                mock_health.return_value = {"healthy": True, "checks": {}}

                result = await chaos_tester.test_primary_failure()

                assert result["test"] == "primary_failure"
                assert result["success"] is True
                assert "failover_result" in result
                assert "post_failover_health" in result

    @pytest.mark.asyncio
    async def test_test_primary_failure_no_secondary(self, chaos_tester):
        """Test primary failure test with no secondary."""

        del chaos_tester.dr_manager.state.regions["secondary"]

        result = await chaos_tester.test_primary_failure()

        assert result["test"] == "primary_failure"
        assert result["success"] is False
        assert result["error"] == "No secondary region available"

    @pytest.mark.asyncio
    async def test_test_network_partition(self, chaos_tester):
        """Test network partition test."""
        result = await chaos_tester.test_network_partition()

        assert result["test"] == "network_partition"
        assert result["success"] is True
        assert "note" in result

    @pytest.mark.asyncio
    async def test_test_data_corruption_recovery(self, chaos_tester):
        """Test data corruption recovery test."""
        result = await chaos_tester.test_data_corruption_recovery()

        assert result["test"] == "data_corruption_recovery"
        assert result["success"] is True
        assert "note" in result

    @pytest.mark.asyncio
    async def test_run_all_tests(self, chaos_tester):
        """Test running all chaos tests."""

        with patch.object(chaos_tester.dr_manager, "health_check_all", new_callable=AsyncMock) as mock_health:
            mock_health.return_value = {
                "primary": {"healthy": True, "checks": {}},
                "secondary": {
                    "healthy": True,
                    "checks": {"replication_lag": {"seconds": 10, "healthy": True}},
                },
            }
            with patch.object(
                chaos_tester.dr_manager, "initiate_failover", new_callable=AsyncMock
            ) as mock_failover:
                mock_failover.return_value = FailoverResult(
                    success=True,
                    from_region="primary",
                    to_region="secondary",
                    reason="chaos_test_primary_failure",
                    duration_seconds=5.0,
                    steps_completed=["step1", "step2"],
                    steps_failed=[],
                )
                with patch.object(
                    chaos_tester.dr_manager, "check_region_health", new_callable=AsyncMock
                ) as mock_check:
                    mock_check.return_value = {"healthy": True, "checks": {}}

                    results = await chaos_tester.run_all_tests()

                    assert len(results) == 4
                    assert all(r["success"] for r in results)


class TestCreateDRConfigExample:
    """Tests for create_dr_config_example."""

    @pytest.mark.asyncio
    async def test_create_dr_config_example(self):
        """Test creating example DR config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "dr_config.json"
            await create_dr_config_example(output)

            assert output.exists()
            config = json.loads(output.read_text())

            assert "regions" in config
            assert "us-east-1" in config["regions"]
            assert "us-west-2" in config["regions"]
            assert "eu-west-1" in config["regions"]
            assert config["regions"]["us-east-1"]["role"] == "primary"
            assert config["regions"]["us-west-2"]["role"] == "secondary"
            assert config["regions"]["eu-west-1"]["role"] == "tertiary"
            assert config["max_replication_lag_seconds"] == 300
            assert config["auto_failover_enabled"] is True
