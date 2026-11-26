"""Recurring assessment scheduler with change detection and alerting.

This module provides cron-like scheduling for recurring security assessments,
integrated with the existing monitor and webhook alerting infrastructure.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import croniter
import pytz
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from ishastra.audit import AuditChain
from ishastra.config import Settings
from ishastra.core import exceptions_worker, jobs, policies, scope, store
from ishastra.core.redaction import sanitize_target
from ishastra.monitor import Monitor

log = logging.getLogger(__name__)


ALERT_SEVERITIES = frozenset({"critical", "high"})
MONITOR_TENANT = "system"
DEFAULT_TIMEZONE = "UTC"
MAX_MISSED_RUNS = 10


SCHEDULER_LEASE_NAME = "scheduler"
SCHEDULER_LEASE_TTL = 30.0
SCHEDULER_LEASE_RENEWAL_INTERVAL = 10.0


_scheduler_instance: Scheduler | None = None


def _run_scheduled_assessment_job(schedule_id: str) -> None:
    """Module-level job callback for APScheduler (picklable)."""
    import asyncio

    scheduler = _scheduler_instance
    if scheduler is None:
        log.warning("Scheduled run for %s but scheduler not initialized", schedule_id)
        return

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if loop.is_running():
        loop.create_task(scheduler._run_scheduled_assessment_async(schedule_id))
    else:
        log.warning("Event loop not running for scheduled assessment %s", schedule_id)


def _run_evidence_pack_generation_job() -> None:
    """Module-level job callback for monthly evidence pack generation."""
    import asyncio

    scheduler = _scheduler_instance
    if scheduler is None:
        log.warning("Evidence pack generation run but scheduler not initialized")
        return
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if loop.is_running():
        loop.create_task(scheduler._run_evidence_pack_generation_async())
    else:
        log.warning("Event loop not running for evidence pack generation")


class ScheduleState(str, Enum):
    """State of a scheduled assessment."""

    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


class ScheduleFrequency(str, Enum):
    """Predefined frequency options."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class AssessmentSchedule:
    """Configuration for a recurring assessment."""

    id: str = field(default_factory=lambda: f"sched_{uuid.uuid4().hex[:12]}")
    target: str = ""
    cron_expression: str = ""
    timezone: str = DEFAULT_TIMEZONE
    profile: str = "web"
    state: ScheduleState = ScheduleState.ACTIVE
    policy_id: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_run: float | None = None
    next_run: float | None = None
    run_count: int = 0
    max_concurrent: int = 1
    catch_up: bool = True
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": sanitize_target(self.target),
            "cron_expression": self.cron_expression,
            "timezone": self.timezone,
            "profile": self.profile,
            "state": self.state.value,
            "policy_id": self.policy_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "run_count": self.run_count,
            "max_concurrent": self.max_concurrent,
            "catch_up": self.catch_up,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssessmentSchedule:
        return cls(
            id=data.get("id", f"sched_{uuid.uuid4().hex[:12]}"),
            target=data["target"],
            cron_expression=data["cron_expression"],
            timezone=data.get("timezone", DEFAULT_TIMEZONE),
            profile=data.get("profile", "web"),
            state=ScheduleState(data.get("state", "active")),
            policy_id=data.get("policy_id"),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            last_run=data.get("last_run"),
            next_run=data.get("next_run"),
            run_count=data.get("run_count", 0),
            max_concurrent=data.get("max_concurrent", 1),
            catch_up=data.get("catch_up", True),
            enabled=data.get("enabled", True),
        )

    def compute_next_run(self, from_time: float | None = None) -> float:
        """Calculate the next run time from the given time (or now)."""
        if from_time is None:
            from_time = time.time()
        try:
            tz = pytz.timezone(self.timezone)
        except pytz.UnknownTimeZoneError:
            log.warning("Unknown timezone %s, falling back to UTC", self.timezone)
            tz = pytz.UTC
        cron = croniter.croniter(self.cron_expression, datetime.fromtimestamp(from_time, tz))
        next_dt = cron.get_next(datetime)
        return next_dt.timestamp()

    def validate(self) -> str | None:
        """Validate the schedule configuration. Returns error message or None."""
        if not self.target:
            return "target is required"
        if not self.cron_expression:
            return "cron_expression is required"
        try:
            croniter.croniter(self.cron_expression)
        except (ValueError, KeyError) as exc:
            return f"invalid cron expression: {exc}"
        try:
            pytz.timezone(self.timezone)
        except pytz.UnknownTimeZoneError:
            return f"unknown timezone: {self.timezone}"
        if self.max_concurrent < 1:
            return "max_concurrent must be >= 1"
        return None


@dataclass
class ScheduleRunResult:
    """Result of a scheduled assessment run."""

    schedule_id: str
    job_id: str
    target: str
    started_at: float
    finished_at: float
    state: str
    findings_count: int
    new_high_severity: int
    error: str = ""
    alert_emitted: bool = False


class Scheduler:
    """Async scheduler for recurring assessments with change detection.

    In multi-process PostgreSQL deployments, leader election ensures only one
    scheduler instance runs assessments. Uses PostgreSQL advisory locks via
    distributed_leases table for coordination.
    """

    def __init__(
        self,
        *,
        audit_chain: AuditChain,
        monitor: Monitor,
        settings: Settings,
        job_timeout: float = 300.0,
        scope_mode: str = "auto",
    ) -> None:
        self.audit_chain = audit_chain
        self.monitor = monitor
        self.settings = settings
        self.job_timeout = job_timeout
        self.scope_mode = scope_mode

        self._holder_id = f"{os.getpid()}@{os.uname().nodename}"
        self._scheduler_lease: store.Lease | None = None
        self._lease_renewal_task: asyncio.Task | None = None

        self._schedules: dict[str, AssessmentSchedule] = {}
        self._scheduler: AsyncIOScheduler | None = None
        self._running = False
        self._lock = asyncio.Lock()
        self._job_callbacks: dict[str, Callable] = {}

    def __getstate__(self) -> dict[str, Any]:
        """Exclude non-picklable attributes (asyncio.Lock) from serialization."""
        state = self.__dict__.copy()
        state["_lock"] = None
        state["_lease_renewal_task"] = None
        state["_scheduler_lease"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Restore state and reinitialize the lock."""
        self.__dict__.update(state)
        self._lock = asyncio.Lock()
        self._lease_renewal_task = None
        self._scheduler_lease = None

    async def _try_become_leader(self) -> bool:
        """Attempt to acquire scheduler leader lease.

        Returns True if this instance is the leader, False otherwise.
        """
        lease = await store.try_acquire_lease(
            SCHEDULER_LEASE_NAME,
            self._holder_id,
            category="scheduler",
            ttl_seconds=SCHEDULER_LEASE_TTL,
        )
        if lease and lease.acquired:
            self._scheduler_lease = lease
            log.info("Became scheduler leader: %s (fencing_token=%d)", self._holder_id, lease.fencing_token)
            return True
        current_holder, current_token = await store.get_lease_holder(SCHEDULER_LEASE_NAME)
        log.info(
            "Scheduler leader is %s (fencing_token=%d), running as follower",
            current_holder,
            current_token,
        )
        return False

    async def _renew_lease_loop(self) -> None:
        """Background task to renew the scheduler lease periodically."""
        try:
            while self._running:
                await asyncio.sleep(SCHEDULER_LEASE_RENEWAL_INTERVAL)
                if self._scheduler_lease and self._scheduler_lease.acquired:
                    renewed, new_token = await store.renew_lease(
                        SCHEDULER_LEASE_NAME,
                        self._holder_id,
                        ttl_seconds=SCHEDULER_LEASE_TTL,
                    )
                    if not renewed:
                        log.warning("Lost scheduler leadership, stopping scheduled jobs")
                        self._scheduler_lease._acquired = False
                        await self._stop_scheduled_jobs()
                        break
                    self._scheduler_lease.fencing_token = new_token
                    log.debug("Renewed scheduler lease, fencing_token=%d", new_token)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("Lease renewal loop failed: %s", exc)

    async def _stop_scheduled_jobs(self) -> None:
        """Remove all scheduled assessment jobs (keep system jobs)."""
        if not self._scheduler:
            return
        for schedule_id in list(self._schedules.keys()):
            await self._remove_job(schedule_id)

    async def _resume_scheduled_jobs(self) -> None:
        """Re-add all active scheduled jobs."""
        if not self._scheduler:
            return
        for schedule in self._schedules.values():
            if schedule.enabled and schedule.state == ScheduleState.ACTIVE:
                await self._add_job(schedule)

    async def initialize(self) -> None:
        """Initialize the scheduler and load persisted schedules."""
        global _scheduler_instance
        _scheduler_instance = self
        await self._load_schedules()
        await self._setup_scheduler()

        is_leader = await self._try_become_leader()
        if is_leader:
            self._lease_renewal_task = asyncio.create_task(self._renew_lease_loop())
            await self._schedule_all()
        else:
            log.info("Running as scheduler follower, only system jobs will execute")

        await self.start()

    async def _setup_scheduler(self) -> None:
        """Configure APScheduler with SQLAlchemy job store."""

        db_url = self.settings.db_path
        if db_url.startswith(("postgresql://", "postgres://")) or ":memory:" in db_url:
            jobstores: dict[str, Any] = {"default": MemoryJobStore()}
        else:
            import os

            base = os.path.splitext(db_url)[0]
            jobstore_url = f"sqlite:///{base}_scheduler.db"
            jobstores = {"default": SQLAlchemyJobStore(url=jobstore_url)}
        self._scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            timezone=pytz.UTC,
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 3600,
            },
        )

    async def _load_schedules(self) -> None:
        """Load schedules from database."""
        async with store.get_db_async() as db:
            rows = await db.fetchall("SELECT * FROM assessment_schedules")
            for row in rows:
                try:
                    schedule = AssessmentSchedule.from_dict(dict(row))
                    self._schedules[schedule.id] = schedule
                except Exception as exc:
                    log.warning("Failed to load schedule %s: %s", row.get("id"), exc)

    async def _save_schedule(self, schedule: AssessmentSchedule) -> None:
        """Persist a schedule to database."""
        data = schedule.to_dict()
        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO assessment_schedules
                       (id, target, cron_expression, timezone, profile, state,
                        policy_id, created_at, updated_at, last_run, next_run,
                        run_count, max_concurrent, catch_up, enabled)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                       target = excluded.target,
                       cron_expression = excluded.cron_expression,
                       timezone = excluded.timezone,
                       profile = excluded.profile,
                       state = excluded.state,
                       policy_id = excluded.policy_id,
                       updated_at = excluded.updated_at,
                       last_run = excluded.last_run,
                       next_run = excluded.next_run,
                       run_count = excluded.run_count,
                       max_concurrent = excluded.max_concurrent,
                       catch_up = excluded.catch_up,
                       enabled = excluded.enabled""",
                data["id"],
                data["target"],
                data["cron_expression"],
                data["timezone"],
                data["profile"],
                data["state"],
                data["policy_id"],
                data["created_at"],
                data["updated_at"],
                data["last_run"],
                data["next_run"],
                data["run_count"],
                data["max_concurrent"],
                data["catch_up"],
                data["enabled"],
            )

    async def _delete_schedule(self, schedule_id: str) -> None:
        """Remove a schedule from database."""
        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(conn, "DELETE FROM assessment_schedules WHERE id = ?", schedule_id)

    async def _schedule_all(self) -> None:
        """Schedule all active schedules."""
        if not self._scheduler:
            return
        for schedule in self._schedules.values():
            if schedule.enabled and schedule.state == ScheduleState.ACTIVE:
                await self._add_job(schedule)

        self._scheduler.add_job(
            _run_evidence_pack_generation_job,
            trigger=CronTrigger(day=1, hour=3, minute=0, timezone=pytz.UTC),
            id="evidence_pack_generation",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=86400,
            coalesce=True,
        )
        log.info("Scheduled monthly evidence pack generation")

        from apscheduler.triggers.interval import IntervalTrigger

        self._scheduler.add_job(
            exceptions_worker._run_exceptions_worker_job,
            trigger=IntervalTrigger(hours=1, timezone=pytz.UTC),
            id="exceptions_worker",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=3600,
            coalesce=True,
        )
        log.info("Scheduled exceptions worker (hourly)")

    async def _add_job(self, schedule: AssessmentSchedule) -> None:
        """Add a schedule as an APScheduler job."""
        if not self._scheduler:
            return
        try:
            tz = pytz.timezone(schedule.timezone)
        except pytz.UnknownTimeZoneError:
            tz = pytz.UTC
            log.warning("Schedule %s: unknown timezone %s, using UTC", schedule.id, schedule.timezone)

        trigger = CronTrigger.from_crontab(schedule.cron_expression, timezone=tz)

        job_id = f"sched_{schedule.id}"
        self._scheduler.add_job(
            _run_scheduled_assessment_job,
            trigger=trigger,
            id=job_id,
            args=[schedule.id],
            replace_existing=True,
            max_instances=schedule.max_concurrent,
            misfire_grace_time=3600,
            coalesce=True,
        )

        schedule.next_run = schedule.compute_next_run()
        await self._save_schedule(schedule)
        log.info(
            "Scheduled assessment %s for %s (next: %s)",
            schedule.id,
            schedule.target,
            datetime.fromtimestamp(schedule.next_run, tz).isoformat() if schedule.next_run else "never",
        )

    async def _remove_job(self, schedule_id: str) -> None:
        """Remove a scheduled job."""
        if not self._scheduler:
            return
        job_id = f"sched_{schedule_id}"
        with contextlib.suppress(Exception):
            self._scheduler.remove_job(job_id)

    async def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return
        if self._scheduler:
            self._scheduler.start()
        self._running = True
        log.info("Assessment scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            return

        if self._lease_renewal_task and not self._lease_renewal_task.done():
            self._lease_renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._lease_renewal_task

        if self._scheduler_lease and self._scheduler_lease.acquired:
            await store.release_lease(
                SCHEDULER_LEASE_NAME,
                self._holder_id,
                fencing_token=self._scheduler_lease.fencing_token,
            )
            self._scheduler_lease._acquired = False
            log.info("Released scheduler lease (fencing_token=%d)", self._scheduler_lease.fencing_token)

        if self._scheduler:
            self._scheduler.shutdown(wait=True)
        self._running = False
        log.info("Assessment scheduler stopped")

    async def create_schedule(
        self,
        target: str,
        cron_expression: str,
        *,
        timezone: str = DEFAULT_TIMEZONE,
        profile: str = "web",
        policy_id: str | None = None,
        max_concurrent: int = 1,
        catch_up: bool = True,
    ) -> AssessmentSchedule:
        """Create a new recurring assessment schedule."""

        if hasattr(self.monitor, "scope_mode"):
            snapshot = None
            if await policies.registry.list_async():
                snapshot, _ = await policies.tenant_scope_snapshot_async(MONITOR_TENANT)
            from ishastra.core.redaction import has_sensitive_query_params

            if has_sensitive_query_params(target):
                raise ValueError("scheduled targets cannot contain credential-bearing query parameters")
            from ishastra.api.deps import check_target_or_raise

            check_target_or_raise(target, snapshot)

        try:
            croniter.croniter(cron_expression)
        except (ValueError, KeyError) as exc:
            raise ValueError(f"invalid cron expression: {exc}") from None

        try:
            pytz.timezone(timezone)
        except pytz.UnknownTimeZoneError:
            raise ValueError(f"unknown timezone: {timezone}") from None

        schedule = AssessmentSchedule(
            target=target,
            cron_expression=cron_expression,
            timezone=timezone,
            profile=profile,
            policy_id=policy_id,
            max_concurrent=max_concurrent,
            catch_up=catch_up,
        )

        error = schedule.validate()
        if error:
            raise ValueError(error)

        async with self._lock:
            self._schedules[schedule.id] = schedule
            await self._save_schedule(schedule)

            if (
                self._running
                and self._scheduler_lease
                and self._scheduler_lease.acquired
                and schedule.enabled
                and schedule.state == ScheduleState.ACTIVE
            ):
                await self._add_job(schedule)

        await self.audit_chain.append_async(
            {
                "type": "schedule_created",
                "schedule_id": schedule.id,
                "target": sanitize_target(target),
                "cron_expression": cron_expression,
                "timezone": timezone,
                "profile": profile,
            }
        )
        return schedule

    async def get_schedule(self, schedule_id: str) -> AssessmentSchedule | None:
        """Get a schedule by ID."""
        return self._schedules.get(schedule_id)

    async def list_schedules(self) -> list[AssessmentSchedule]:
        """List all schedules."""
        return list(self._schedules.values())

    async def update_schedule(
        self,
        schedule_id: str,
        *,
        cron_expression: str | None = None,
        timezone: str | None = None,
        profile: str | None = None,
        state: ScheduleState | None = None,
        policy_id: str | None = None,
        max_concurrent: int | None = None,
        catch_up: bool | None = None,
        enabled: bool | None = None,
    ) -> AssessmentSchedule:
        """Update an existing schedule."""
        async with self._lock:
            schedule = self._schedules.get(schedule_id)
            if not schedule:
                raise ValueError(f"schedule {schedule_id} not found")

            if cron_expression is not None:
                try:
                    croniter.croniter(cron_expression)
                except (ValueError, KeyError) as exc:
                    raise ValueError(f"invalid cron expression: {exc}") from None
                schedule.cron_expression = cron_expression

            if timezone is not None:
                try:
                    pytz.timezone(timezone)
                except pytz.UnknownTimeZoneError:
                    raise ValueError(f"unknown timezone: {timezone}") from None
                schedule.timezone = timezone

            if profile is not None:
                schedule.profile = profile

            if state is not None:
                schedule.state = state

            if policy_id is not None:
                schedule.policy_id = policy_id

            if max_concurrent is not None:
                if max_concurrent < 1:
                    raise ValueError("max_concurrent must be >= 1")
                schedule.max_concurrent = max_concurrent

            if catch_up is not None:
                schedule.catch_up = catch_up

            if enabled is not None:
                schedule.enabled = enabled

            schedule.updated_at = time.time()
            error = schedule.validate()
            if error:
                raise ValueError(error)

            await self._save_schedule(schedule)

            if self._running and self._scheduler_lease and self._scheduler_lease.acquired:
                await self._remove_job(schedule_id)
                if schedule.enabled and schedule.state == ScheduleState.ACTIVE:
                    await self._add_job(schedule)

        await self.audit_chain.append_async(
            {
                "type": "schedule_updated",
                "schedule_id": schedule_id,
                "target": sanitize_target(schedule.target),
            }
        )
        return schedule

    async def delete_schedule(self, schedule_id: str) -> None:
        """Delete a schedule."""
        async with self._lock:
            schedule = self._schedules.pop(schedule_id, None)
            if not schedule:
                raise ValueError(f"schedule {schedule_id} not found")

            if self._scheduler_lease and self._scheduler_lease.acquired:
                await self._remove_job(schedule_id)
            await self._delete_schedule(schedule_id)

        await self.audit_chain.append_async(
            {
                "type": "schedule_deleted",
                "schedule_id": schedule_id,
                "target": sanitize_target(schedule.target),
            }
        )

    async def pause_schedule(self, schedule_id: str) -> AssessmentSchedule:
        """Pause a schedule."""
        schedule = await self.update_schedule(schedule_id, state=ScheduleState.PAUSED)

        if self._scheduler_lease and self._scheduler_lease.acquired:
            await self._remove_job(schedule_id)
        return schedule

    async def resume_schedule(self, schedule_id: str) -> AssessmentSchedule:
        """Resume a paused schedule."""
        schedule = await self.update_schedule(schedule_id, state=ScheduleState.ACTIVE)

        if self._scheduler_lease and self._scheduler_lease.acquired and schedule.enabled:
            await self._add_job(schedule)
        return schedule

    async def run_now(self, schedule_id: str) -> ScheduleRunResult:
        """Manually trigger a scheduled assessment immediately."""
        schedule = self._schedules.get(schedule_id)
        if not schedule:
            raise ValueError(f"schedule {schedule_id} not found")
        return await self._execute_assessment(schedule)

    async def _run_scheduled_assessment_async(self, schedule_id: str) -> None:
        """Internal async callback for APScheduler to run an assessment.

        Only executes if this instance holds the scheduler lease (leader).
        Followers skip execution to prevent duplicate runs.
        """

        if not self._scheduler_lease or not self._scheduler_lease.acquired:
            log.debug("Skipping scheduled assessment %s: not scheduler leader", schedule_id)
            return

        schedule = self._schedules.get(schedule_id)
        if not schedule:
            log.warning("Scheduled run for unknown schedule %s", schedule_id)
            return
        if not schedule.enabled or schedule.state != ScheduleState.ACTIVE:
            log.info("Skipping disabled/paused schedule %s", schedule_id)
            return

        await self._execute_assessment(schedule)

    async def _execute_assessment(self, schedule: AssessmentSchedule) -> ScheduleRunResult:
        """Execute a single assessment run for a schedule."""
        started_at = time.time()
        schedule.last_run = started_at
        schedule.run_count += 1
        schedule.next_run = schedule.compute_next_run(started_at)
        await self._save_schedule(schedule)

        log.info("Starting scheduled assessment %s for %s", schedule.id, schedule.target)

        snapshot: scope.Scope | None = None
        mode = self.scope_mode
        managed = mode == "managed" or (mode == "auto" and bool(await policies.registry.list_async()))
        if mode not in {"auto", "global", "managed"}:
            managed = True
        if managed:
            snapshot, reason = await policies.tenant_scope_snapshot_async(MONITOR_TENANT)
            if snapshot is None:
                result = ScheduleRunResult(
                    schedule_id=schedule.id,
                    job_id="",
                    target=schedule.target,
                    started_at=started_at,
                    finished_at=time.time(),
                    state="failed",
                    findings_count=0,
                    new_high_severity=0,
                    error=f"out_of_scope: {reason}",
                )
                await self._emit_schedule_alert(schedule, result)
                return result

        job = jobs.prepare(
            schedule.target,
            profile=schedule.profile,
            actor=MONITOR_TENANT,
            policy={"policy_id": schedule.policy_id} if schedule.policy_id else None,
            timeout=self.job_timeout,
            scope_snapshot=snapshot,
        )

        try:
            jobs.execute(job)
        except Exception as exc:
            log.exception("Scheduled assessment %s crashed", schedule.id)
            finished_at = time.time()
            result = ScheduleRunResult(
                schedule_id=schedule.id,
                job_id=job.id,
                target=schedule.target,
                started_at=started_at,
                finished_at=finished_at,
                state="failed",
                findings_count=0,
                new_high_severity=0,
                error=str(exc),
            )
            await self._emit_schedule_alert(schedule, result)
            await self.audit_chain.append_async(
                {
                    "type": "schedule_run_failed",
                    "schedule_id": schedule.id,
                    "job_id": job.id,
                    "target": sanitize_target(schedule.target),
                    "error": str(exc),
                }
            )
            return result

        finished_at = time.time()

        new_high_severity = await self._compare_and_alert(schedule, job)

        result = ScheduleRunResult(
            schedule_id=schedule.id,
            job_id=job.id,
            target=schedule.target,
            started_at=started_at,
            finished_at=finished_at,
            state=job.state.value,
            findings_count=len(job.findings),
            new_high_severity=new_high_severity,
            alert_emitted=new_high_severity > 0,
        )

        await store.save_job(job, tenant=MONITOR_TENANT)

        await self.audit_chain.append_async(
            {
                "type": "schedule_run_completed",
                "schedule_id": schedule.id,
                "job_id": job.id,
                "target": sanitize_target(schedule.target),
                "state": job.state.value,
                "findings": len(job.findings),
                "new_high_severity": new_high_severity,
                "duration_ms": round((finished_at - started_at) * 1000, 1),
            }
        )

        return result

    async def _compare_and_alert(self, schedule: AssessmentSchedule, job: jobs.Job) -> int:
        """Compare findings with previous run and alert on new high-severity findings."""

        key = sanitize_target(schedule.target)
        baseline = await store.load_monitor_baseline()
        previous = baseline.get(key, set())

        current = {f.fingerprint: f for f in job.findings}

        new_high = [f for fp, f in current.items() if fp not in previous and f.severity in ALERT_SEVERITIES]

        if new_high:
            alert = {
                "rule_name": "scheduled_new_finding",
                "severity": ("critical" if any(f.severity == "critical" for f in new_high) else "high"),
                "target": schedule.target,
                "job": job.id,
                "schedule_id": schedule.id,
                "message": f"{len(new_high)} new high-severity finding(s) from scheduled assessment",
                "findings": [
                    {
                        "category": f.category,
                        "severity": f.severity,
                        "title": f.title,
                        "location": f.location,
                    }
                    for f in new_high
                ],
            }

            from ishastra.core.redaction import redact

            alert = redact(
                {
                    "target": sanitize_target(str(alert.get("target", ""))),
                    **{k: v for k, v in alert.items() if k != "target"},
                }
            )
            await self.audit_chain.append_async({"type": "alert", **alert})
            for sink in self.monitor.alert_sinks:
                with contextlib.suppress(Exception):
                    await sink.send(alert)

        await store.save_monitor_baseline(schedule.target, set(current))

        return len(new_high)

    async def _emit_schedule_alert(self, schedule: AssessmentSchedule, result: ScheduleRunResult) -> None:
        """Emit an alert for schedule execution issues."""
        alert = {
            "rule_name": "scheduled_assessment_failed",
            "severity": "high",
            "target": schedule.target,
            "schedule_id": schedule.id,
            "job_id": result.job_id,
            "message": f"Scheduled assessment failed: {result.error}",
        }
        from ishastra.core.redaction import redact

        alert = redact(
            {
                "target": sanitize_target(str(alert.get("target", ""))),
                **{k: v for k, v in alert.items() if k != "target"},
            }
        )
        await self.audit_chain.append_async({"type": "alert", **alert})
        for sink in self.monitor.alert_sinks:
            with contextlib.suppress(Exception):
                await sink.send(alert)

    async def _run_evidence_pack_generation_async(self) -> None:
        """Generate monthly evidence packs for all tenants."""
        from ishastra.core.evidence import generate_monthly_evidence_packs

        try:
            generated = await generate_monthly_evidence_packs(self.audit_chain)
            log.info("Generated %d monthly evidence packs", len(generated))
        except Exception as exc:
            log.exception("Failed to generate monthly evidence packs: %s", exc)
            await self.audit_chain.append_async(
                {
                    "type": "evidence_pack_generation_failed",
                    "error": str(exc),
                }
            )

    @property
    def running(self) -> bool:
        return self._running

    async def status(self) -> dict[str, Any]:
        """Get scheduler status."""
        return {
            "running": self._running,
            "total_schedules": len(self._schedules),
            "active_schedules": sum(
                1 for s in self._schedules.values() if s.enabled and s.state == ScheduleState.ACTIVE
            ),
            "paused_schedules": sum(1 for s in self._schedules.values() if s.state == ScheduleState.PAUSED),
        }


async def create_scheduler(
    audit_chain: AuditChain,
    monitor: Monitor,
    settings: Settings,
    job_timeout: float = 300.0,
    scope_mode: str = "auto",
) -> Scheduler:
    """Factory function to create and initialize a scheduler."""
    scheduler = Scheduler(
        audit_chain=audit_chain,
        monitor=monitor,
        settings=settings,
        job_timeout=job_timeout,
        scope_mode=scope_mode,
    )
    await scheduler.initialize()
    return scheduler
