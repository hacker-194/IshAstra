"""Tests for ishastra.core.scheduler module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ishastra.core.scheduler import (
    DEFAULT_TIMEZONE,
    AssessmentSchedule,
    ScheduleFrequency,
    Scheduler,
    ScheduleRunResult,
    ScheduleState,
)


class TestScheduleState:
    """Tests for ScheduleState enum."""

    def test_schedule_state_values(self):
        """Test ScheduleState enum values."""
        assert ScheduleState.ACTIVE.value == "active"
        assert ScheduleState.PAUSED.value == "paused"
        assert ScheduleState.DISABLED.value == "disabled"


class TestScheduleFrequency:
    """Tests for ScheduleFrequency enum."""

    def test_schedule_frequency_values(self):
        """Test ScheduleFrequency enum values."""
        assert ScheduleFrequency.DAILY.value == "daily"
        assert ScheduleFrequency.WEEKLY.value == "weekly"
        assert ScheduleFrequency.MONTHLY.value == "monthly"
        assert ScheduleFrequency.CUSTOM.value == "custom"


class TestAssessmentSchedule:
    """Tests for AssessmentSchedule dataclass."""

    def test_default_creation(self):
        """Test default AssessmentSchedule creation."""
        schedule = AssessmentSchedule()
        assert schedule.id.startswith("sched_")
        assert schedule.target == ""
        assert schedule.cron_expression == ""
        assert schedule.timezone == DEFAULT_TIMEZONE
        assert schedule.profile == "web"
        assert schedule.state == ScheduleState.ACTIVE
        assert schedule.created_at > 0
        assert schedule.updated_at > 0
        assert schedule.last_run is None
        assert schedule.next_run is None
        assert schedule.run_count == 0
        assert schedule.max_concurrent == 1
        assert schedule.catch_up is True
        assert schedule.enabled is True

    def test_custom_creation(self):
        """Test custom AssessmentSchedule creation."""
        schedule = AssessmentSchedule(
            id="test-sched-1",
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="America/New_York",
            profile="web-deep",
            state=ScheduleState.PAUSED,
            policy_id="pol_test",
            max_concurrent=2,
            catch_up=False,
        )
        assert schedule.id == "test-sched-1"
        assert schedule.target == "https://example.com/"
        assert schedule.cron_expression == "0 2 * * *"
        assert schedule.timezone == "America/New_York"
        assert schedule.profile == "web-deep"
        assert schedule.state == ScheduleState.PAUSED
        assert schedule.policy_id == "pol_test"
        assert schedule.max_concurrent == 2
        assert schedule.catch_up is False

    def test_to_dict(self):
        """Test AssessmentSchedule.to_dict()."""
        schedule = AssessmentSchedule(
            id="test-sched-1",
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="UTC",
            profile="web",
            state=ScheduleState.ACTIVE,
            policy_id="pol_test",
            created_at=1700000000.0,
            updated_at=1700000000.0,
            last_run=1699999999.0,
            next_run=1700000000.0,
            run_count=5,
            max_concurrent=1,
            catch_up=True,
            enabled=True,
        )
        data = schedule.to_dict()
        assert data["id"] == "test-sched-1"
        assert data["target"] == "https://example.com/"
        assert data["cron_expression"] == "0 2 * * *"
        assert data["timezone"] == "UTC"
        assert data["profile"] == "web"
        assert data["state"] == "active"
        assert data["policy_id"] == "pol_test"
        assert data["created_at"] == 1700000000.0
        assert data["updated_at"] == 1700000000.0
        assert data["last_run"] == 1699999999.0
        assert data["next_run"] == 1700000000.0
        assert data["run_count"] == 5
        assert data["max_concurrent"] == 1
        assert data["catch_up"] is True
        assert data["enabled"] is True

    def test_from_dict(self):
        """Test AssessmentSchedule.from_dict()."""
        data = {
            "id": "test-sched-1",
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
            "state": "active",
            "policy_id": "pol_test",
            "created_at": 1700000000.0,
            "updated_at": 1700000000.0,
            "last_run": 1699999999.0,
            "next_run": 1700000000.0,
            "run_count": 5,
            "max_concurrent": 1,
            "catch_up": True,
            "enabled": True,
        }
        schedule = AssessmentSchedule.from_dict(data)
        assert schedule.id == "test-sched-1"
        assert schedule.target == "https://example.com/"
        assert schedule.cron_expression == "0 2 * * *"
        assert schedule.timezone == "UTC"
        assert schedule.profile == "web"
        assert schedule.state == ScheduleState.ACTIVE
        assert schedule.policy_id == "pol_test"
        assert schedule.created_at == 1700000000.0
        assert schedule.updated_at == 1700000000.0
        assert schedule.last_run == 1699999999.0
        assert schedule.next_run == 1700000000.0
        assert schedule.run_count == 5
        assert schedule.max_concurrent == 1
        assert schedule.catch_up is True
        assert schedule.enabled is True

    def test_from_dict_defaults(self):
        """Test from_dict with minimal data uses defaults."""
        data = {
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
        }
        schedule = AssessmentSchedule.from_dict(data)
        assert schedule.id.startswith("sched_")
        assert schedule.timezone == DEFAULT_TIMEZONE
        assert schedule.profile == "web"
        assert schedule.state == ScheduleState.ACTIVE
        assert schedule.max_concurrent == 1
        assert schedule.catch_up is True
        assert schedule.enabled is True

    def test_compute_next_run(self):
        """Test compute_next_run calculates correct next run time."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="UTC",
        )
        from_time = 1704067200.0
        next_run = schedule.compute_next_run(from_time)

        assert next_run == 1704074400.0

    def test_compute_next_run_different_timezone(self):
        """Test compute_next_run with different timezone."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 9 * * *",
            timezone="America/New_York",
        )
        from_time = 1704067200.0
        next_run = schedule.compute_next_run(from_time)

        assert next_run > from_time

        assert 1704090000 < next_run < 1704200000

    def test_validate_valid(self):
        """Test validate with valid schedule."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="UTC",
            max_concurrent=1,
        )
        assert schedule.validate() is None

    def test_validate_missing_target(self):
        """Test validate with missing target."""
        schedule = AssessmentSchedule(
            target="",
            cron_expression="0 2 * * *",
        )
        assert schedule.validate() == "target is required"

    def test_validate_missing_cron(self):
        """Test validate with missing cron expression."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="",
        )
        assert schedule.validate() == "cron_expression is required"

    def test_validate_invalid_cron(self):
        """Test validate with invalid cron expression."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="invalid cron",
        )
        assert schedule.validate() is not None
        assert "invalid cron expression" in schedule.validate()

    def test_validate_unknown_timezone(self):
        """Test validate with unknown timezone."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="Invalid/Timezone",
        )
        assert schedule.validate() is not None
        assert "unknown timezone" in schedule.validate()

    def test_validate_invalid_max_concurrent(self):
        """Test validate with invalid max_concurrent."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 2 * * *",
            max_concurrent=0,
        )
        assert schedule.validate() == "max_concurrent must be >= 1"


class TestScheduleRunResult:
    """Tests for ScheduleRunResult dataclass."""

    def test_creation(self):
        """Test ScheduleRunResult creation."""
        result = ScheduleRunResult(
            schedule_id="sched_1",
            job_id="job_1",
            target="https://example.com/",
            started_at=1700000000.0,
            finished_at=1700000100.0,
            state="completed",
            findings_count=5,
            new_high_severity=2,
            error="",
            alert_emitted=True,
        )
        assert result.schedule_id == "sched_1"
        assert result.job_id == "job_1"
        assert result.target == "https://example.com/"
        assert result.started_at == 1700000000.0
        assert result.finished_at == 1700000100.0
        assert result.state == "completed"
        assert result.findings_count == 5
        assert result.new_high_severity == 2
        assert result.error == ""
        assert result.alert_emitted is True


class TestScheduler:
    """Tests for Scheduler class."""

    @pytest.fixture
    def mock_audit_chain(self):
        """Create mock audit chain."""
        return MagicMock()

    @pytest.fixture
    def mock_monitor(self):
        """Create mock monitor."""
        return MagicMock()

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.db_path = ":memory:"
        return settings

    @pytest.fixture
    def scheduler(self, mock_audit_chain, mock_monitor, mock_settings):
        """Create Scheduler instance."""
        return Scheduler(
            audit_chain=mock_audit_chain,
            monitor=mock_monitor,
            settings=mock_settings,
            job_timeout=300.0,
            scope_mode="auto",
        )

    def test_scheduler_creation(self, scheduler):
        """Test Scheduler creation."""
        assert scheduler.audit_chain is not None
        assert scheduler.monitor is not None
        assert scheduler.settings is not None
        assert scheduler.job_timeout == 300.0
        assert scheduler.scope_mode == "auto"
        assert scheduler._schedules == {}
        assert scheduler._scheduler is None
        assert scheduler._running is False

    def test_getstate_excludes_lock(self, scheduler):
        """Test __getstate__ excludes lock."""
        state = scheduler.__getstate__()
        assert "_lock" in state
        assert state["_lock"] is None

    def test_setstate_restores_lock(self, scheduler):
        """Test __setstate__ restores lock."""
        state = scheduler.__getstate__()
        state["_lock"] = None
        scheduler.__setstate__(state)
        assert scheduler._lock is not None

    @pytest.mark.asyncio
    async def test_initialize(self, scheduler):
        """Test initialize method."""
        with (
            patch.object(scheduler, "_load_schedules", new_callable=AsyncMock) as mock_load,
            patch.object(scheduler, "_setup_scheduler", new_callable=AsyncMock) as mock_setup,
            patch.object(scheduler, "_schedule_all", new_callable=AsyncMock) as mock_schedule,
        ):
            await scheduler.initialize()
            mock_load.assert_called_once()
            mock_setup.assert_called_once()
            mock_schedule.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_schedules(self, scheduler):
        """Test _load_schedules method."""
        mock_db = AsyncMock()
        mock_row = {
            "id": "sched_1",
            "target": "https://example.com/",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
            "profile": "web",
            "state": "active",
            "policy_id": None,
            "created_at": 1700000000.0,
            "updated_at": 1700000000.0,
            "last_run": None,
            "next_run": None,
            "run_count": 0,
            "max_concurrent": 1,
            "catch_up": True,
            "enabled": True,
        }
        mock_db.fetchall.return_value = [mock_row]

        with patch("ishastra.core.store.get_db_async") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_db
            await scheduler._load_schedules()

        assert "sched_1" in scheduler._schedules
        assert scheduler._schedules["sched_1"].target == "https://example.com/"

    @pytest.mark.asyncio
    async def test_load_schedules_handles_error(self, scheduler):
        """Test _load_schedules handles errors gracefully."""
        mock_db = AsyncMock()
        mock_row = {"id": "bad_sched", "target": "https://example.com/"}
        mock_db.fetchall.return_value = [mock_row]

        with patch("ishastra.core.store.get_db_async") as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_db
            await scheduler._load_schedules()

        assert "bad_sched" not in scheduler._schedules

    @pytest.mark.asyncio
    async def test_save_schedule(self, scheduler):
        """Test _save_schedule method."""
        schedule = AssessmentSchedule(
            id="sched_1",
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="UTC",
            profile="web",
            state=ScheduleState.ACTIVE,
        )

        mock_db = AsyncMock()
        mock_conn = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_get_db_async():
            yield mock_db

        @asynccontextmanager
        async def mock_transaction():
            yield mock_conn

        mock_db.transaction = mock_transaction

        with (
            patch("ishastra.core.store.get_db_async", mock_get_db_async),
            patch("ishastra.core.store._execute") as mock_execute,
        ):
            await scheduler._save_schedule(schedule)

            mock_execute.assert_called_once()

    def test_compute_next_run_static(self):
        """Test compute_next_run without instance."""
        schedule = AssessmentSchedule(
            target="https://example.com/",
            cron_expression="0 2 * * *",
            timezone="UTC",
        )
        from_time = 1704067200.0
        next_run = schedule.compute_next_run(from_time)
        assert next_run == 1704074400.0


class TestSchedulerConstants:
    """Tests for scheduler constants."""

    def test_alert_severities(self):
        """Test ALERT_SEVERITIES constant."""
        from ishastra.core.scheduler import ALERT_SEVERITIES

        assert "critical" in ALERT_SEVERITIES
        assert "high" in ALERT_SEVERITIES
        assert "medium" not in ALERT_SEVERITIES
        assert "low" not in ALERT_SEVERITIES

    def test_monitor_tenant(self):
        """Test MONITOR_TENANT constant."""
        from ishastra.core.scheduler import MONITOR_TENANT

        assert MONITOR_TENANT == "system"

    def test_default_timezone(self):
        """Test DEFAULT_TIMEZONE constant."""
        assert DEFAULT_TIMEZONE == "UTC"

    def test_max_missed_runs(self):
        """Test MAX_MISSED_RUNS constant."""
        from ishastra.core.scheduler import MAX_MISSED_RUNS

        assert MAX_MISSED_RUNS == 10
