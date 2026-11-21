"""Compliance trend reporting and scheduled evidence pack generation.

This module provides quarterly/yearly compliance trend reports with CSV export,
scheduled evidence pack generation, and trend analysis using regulatory_summary.
"""

from __future__ import annotations

import csv
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import StringIO
from typing import Any

import croniter
import pytz
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from ishastra.audit import AuditChain
from ishastra.config import Settings
from ishastra.core import store
from ishastra.core.evidence import (
    ALL_MAPPINGS,
    generate_monthly_evidence_packs,
)
from ishastra.core.findings import Finding, regulatory_summary
from ishastra.monitor import Monitor

log = logging.getLogger(__name__)


DEFAULT_TIMEZONE = "UTC"
COMPLIANCE_REPORT_RETENTION_DAYS = 2555


_compliance_scheduler_instance: ComplianceScheduler | None = None


def _run_compliance_report_job(tenant: str, schedule_id: str) -> None:
    """Module-level job callback for APScheduler (picklable)."""
    import asyncio

    scheduler = _compliance_scheduler_instance
    if scheduler is None:
        log.warning("Compliance report run for %s but scheduler not initialized", schedule_id)
        return
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if loop.is_running():
        loop.create_task(scheduler._run_compliance_report_async(tenant, schedule_id))
    else:
        log.warning("Event loop not running for compliance report %s", schedule_id)


def _run_evidence_pack_job() -> None:
    """Module-level job callback for scheduled evidence pack generation."""
    import asyncio

    scheduler = _compliance_scheduler_instance
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


class ReportFrequency(str):
    """Predefined frequency options for compliance reports."""

    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


@dataclass
class ComplianceSchedule:
    """Configuration for a recurring compliance report."""

    id: str = field(default="")
    tenant: str = ""
    cron_expression: str = ""
    timezone: str = DEFAULT_TIMEZONE
    frameworks: list[str] = field(default_factory=lambda: ["nrb", "nta", "ncsp"])
    frequency: str = ReportFrequency.QUARTERLY
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_run: float | None = None
    next_run: float | None = None
    run_count: int = 0

    def __post_init__(self):
        if not self.id:
            import uuid

            self.id = f"compliance_{uuid.uuid4().hex[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant": self.tenant,
            "cron_expression": self.cron_expression,
            "timezone": self.timezone,
            "frameworks": self.frameworks,
            "frequency": self.frequency,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "run_count": self.run_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComplianceSchedule:
        return cls(
            id=data.get("id", f"compliance_{__import__('uuid').uuid4().hex[:12]}"),
            tenant=data["tenant"],
            cron_expression=data["cron_expression"],
            timezone=data.get("timezone", DEFAULT_TIMEZONE),
            frameworks=data.get("frameworks", ["nrb", "nta", "ncsp"]),
            frequency=data.get("frequency", ReportFrequency.QUARTERLY),
            enabled=data.get("enabled", True),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            last_run=data.get("last_run"),
            next_run=data.get("next_run"),
            run_count=data.get("run_count", 0),
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
        if not self.tenant:
            return "tenant is required"
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
        if self.frequency not in (ReportFrequency.QUARTERLY, ReportFrequency.YEARLY, ReportFrequency.CUSTOM):
            return f"invalid frequency: {self.frequency}"
        for fw in self.frameworks:
            if fw.lower() not in ALL_MAPPINGS:
                return f"unknown framework: {fw}"
        return None


@dataclass
class ComplianceReportResult:
    """Result of a compliance report generation."""

    schedule_id: str
    tenant: str
    started_at: float
    finished_at: float
    state: str
    report_id: str
    total_findings: int
    frameworks_covered: list[str]
    error: str = ""


class ComplianceScheduler:
    """Async scheduler for recurring compliance reports with trend analysis."""

    def __init__(
        self,
        *,
        audit_chain: AuditChain,
        monitor: Monitor,
        settings: Settings,
    ) -> None:
        self.audit_chain = audit_chain
        self.monitor = monitor
        self.settings = settings

        self._schedules: dict[str, ComplianceSchedule] = {}
        self._scheduler: AsyncIOScheduler | None = None
        self._running = False
        self._lock = __import__("asyncio").Lock()

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["_lock"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = __import__("asyncio").Lock()

    async def initialize(self) -> None:
        """Initialize the scheduler and load persisted schedules."""
        global _compliance_scheduler_instance
        _compliance_scheduler_instance = self
        await self._load_schedules()
        await self._setup_scheduler()
        await self._schedule_all()

    async def _setup_scheduler(self) -> None:
        """Configure APScheduler with SQLAlchemy job store."""
        db_url = self.settings.db_path
        if db_url.startswith(("postgresql://", "postgres://")):
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
            rows = await db.fetchall("SELECT * FROM compliance_schedules")
            for row in rows:
                try:
                    schedule = ComplianceSchedule.from_dict(dict(row))
                    self._schedules[schedule.id] = schedule
                except Exception as exc:
                    log.warning("Failed to load compliance schedule %s: %s", row.get("id"), exc)

    async def _save_schedule(self, schedule: ComplianceSchedule) -> None:
        """Persist a schedule to database."""
        data = schedule.to_dict()
        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO compliance_schedules
                       (id, tenant, cron_expression, timezone, frameworks, frequency,
                        enabled, created_at, updated_at, last_run, next_run, run_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                       tenant = excluded.tenant,
                       cron_expression = excluded.cron_expression,
                       timezone = excluded.timezone,
                       frameworks = excluded.frameworks,
                       frequency = excluded.frequency,
                       enabled = excluded.enabled,
                       updated_at = excluded.updated_at,
                       last_run = excluded.last_run,
                       next_run = excluded.next_run,
                       run_count = excluded.run_count""",
                data["id"],
                data["tenant"],
                data["cron_expression"],
                data["timezone"],
                json.dumps(data["frameworks"]),
                data["frequency"],
                int(data["enabled"]),
                data["created_at"],
                data["updated_at"],
                data["last_run"],
                data["next_run"],
                data["run_count"],
            )

    async def _delete_schedule(self, schedule_id: str) -> None:
        """Remove a schedule from database."""
        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(conn, "DELETE FROM compliance_schedules WHERE id = ?", schedule_id)

    async def _schedule_all(self) -> None:
        """Schedule all active schedules."""
        if not self._scheduler:
            return
        for schedule in self._schedules.values():
            if schedule.enabled:
                await self._add_job(schedule)

        self._scheduler.add_job(
            _run_evidence_pack_job,
            trigger=CronTrigger(day=1, hour=3, minute=0, timezone=pytz.UTC),
            id="compliance_evidence_pack_generation",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=86400,
            coalesce=True,
        )
        log.info("Scheduled monthly evidence pack generation for compliance")

    async def _add_job(self, schedule: ComplianceSchedule) -> None:
        """Add a schedule as an APScheduler job."""
        if not self._scheduler:
            return
        try:
            tz = pytz.timezone(schedule.timezone)
        except pytz.UnknownTimeZoneError:
            tz = pytz.UTC
            log.warning("Schedule %s: unknown timezone %s, using UTC", schedule.id, schedule.timezone)

        trigger = CronTrigger.from_crontab(schedule.cron_expression, timezone=tz)

        job_id = f"compliance_{schedule.id}"
        self._scheduler.add_job(
            _run_compliance_report_job,
            trigger=trigger,
            id=job_id,
            args=[schedule.tenant, schedule.id],
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=3600,
            coalesce=True,
        )

        schedule.next_run = schedule.compute_next_run()
        await self._save_schedule(schedule)
        log.info(
            "Scheduled compliance report %s for tenant %s (next: %s)",
            schedule.id,
            schedule.tenant,
            datetime.fromtimestamp(schedule.next_run, tz).isoformat() if schedule.next_run else "never",
        )

    async def _remove_job(self, schedule_id: str) -> None:
        """Remove a scheduled job."""
        if not self._scheduler:
            return
        job_id = f"compliance_{schedule_id}"
        with __import__("contextlib").suppress(Exception):
            self._scheduler.remove_job(job_id)

    async def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return
        if self._scheduler:
            self._scheduler.start()
        self._running = True
        log.info("Compliance report scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            return
        if self._scheduler:
            self._scheduler.shutdown(wait=True)
        self._running = False
        log.info("Compliance report scheduler stopped")

    async def create_schedule(
        self,
        tenant: str,
        cron_expression: str,
        *,
        timezone: str = DEFAULT_TIMEZONE,
        frameworks: list[str] | None = None,
        frequency: str = ReportFrequency.QUARTERLY,
    ) -> ComplianceSchedule:
        """Create a new recurring compliance report schedule."""

        try:
            croniter.croniter(cron_expression)
        except (ValueError, KeyError) as exc:
            raise ValueError(f"invalid cron expression: {exc}") from None

        try:
            pytz.timezone(timezone)
        except pytz.UnknownTimeZoneError:
            raise ValueError(f"unknown timezone: {timezone}") from None

        if frameworks is None:
            frameworks = ["nrb", "nta", "ncsp"]
        for fw in frameworks:
            if fw.lower() not in ALL_MAPPINGS:
                raise ValueError(f"unknown framework: {fw}")

        schedule = ComplianceSchedule(
            tenant=tenant,
            cron_expression=cron_expression,
            timezone=timezone,
            frameworks=frameworks,
            frequency=frequency,
        )

        error = schedule.validate()
        if error:
            raise ValueError(error)

        async with self._lock:
            self._schedules[schedule.id] = schedule
            await self._save_schedule(schedule)

            if self._running and schedule.enabled:
                await self._add_job(schedule)

        await self.audit_chain.append_async(
            {
                "type": "compliance_schedule_created",
                "schedule_id": schedule.id,
                "tenant": tenant,
                "cron_expression": cron_expression,
                "timezone": timezone,
                "frameworks": frameworks,
                "frequency": frequency,
            }
        )
        return schedule

    async def get_schedule(self, schedule_id: str) -> ComplianceSchedule | None:
        """Get a schedule by ID."""
        return self._schedules.get(schedule_id)

    async def list_schedules(self, tenant: str | None = None) -> list[ComplianceSchedule]:
        """List all schedules, optionally filtered by tenant."""
        schedules = list(self._schedules.values())
        if tenant:
            schedules = [s for s in schedules if s.tenant == tenant]
        return schedules

    async def update_schedule(
        self,
        schedule_id: str,
        *,
        cron_expression: str | None = None,
        timezone: str | None = None,
        frameworks: list[str] | None = None,
        frequency: str | None = None,
        enabled: bool | None = None,
    ) -> ComplianceSchedule:
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

            if frameworks is not None:
                for fw in frameworks:
                    if fw.lower() not in ALL_MAPPINGS:
                        raise ValueError(f"unknown framework: {fw}")
                schedule.frameworks = frameworks

            if frequency is not None:
                valid_freq = (
                    ReportFrequency.QUARTERLY,
                    ReportFrequency.YEARLY,
                    ReportFrequency.CUSTOM,
                )
                if frequency not in valid_freq:
                    raise ValueError(f"invalid frequency: {frequency}")
                schedule.frequency = frequency

            if enabled is not None:
                schedule.enabled = enabled

            schedule.updated_at = time.time()
            error = schedule.validate()
            if error:
                raise ValueError(error)

            await self._save_schedule(schedule)

            if self._running:
                await self._remove_job(schedule_id)
                if schedule.enabled:
                    await self._add_job(schedule)

        await self.audit_chain.append_async(
            {
                "type": "compliance_schedule_updated",
                "schedule_id": schedule_id,
                "tenant": schedule.tenant,
            }
        )
        return schedule

    async def delete_schedule(self, schedule_id: str) -> None:
        """Delete a schedule."""
        async with self._lock:
            schedule = self._schedules.pop(schedule_id, None)
            if not schedule:
                raise ValueError(f"schedule {schedule_id} not found")

            await self._remove_job(schedule_id)
            await self._delete_schedule(schedule_id)

        await self.audit_chain.append_async(
            {
                "type": "compliance_schedule_deleted",
                "schedule_id": schedule_id,
                "tenant": schedule.tenant,
            }
        )

    async def enable_schedule(self, schedule_id: str) -> ComplianceSchedule:
        """Enable a schedule."""
        return await self.update_schedule(schedule_id, enabled=True)

    async def disable_schedule(self, schedule_id: str) -> ComplianceSchedule:
        """Disable a schedule."""
        return await self.update_schedule(schedule_id, enabled=False)

    async def run_now(self, schedule_id: str) -> ComplianceReportResult:
        """Manually trigger a compliance report immediately."""
        schedule = self._schedules.get(schedule_id)
        if not schedule:
            raise ValueError(f"schedule {schedule_id} not found")
        return await self._execute_compliance_report(schedule)

    async def _run_compliance_report_async(self, tenant: str, schedule_id: str) -> None:
        """Internal async callback for APScheduler to run a compliance report."""
        schedule = self._schedules.get(schedule_id)
        if not schedule:
            log.warning("Compliance report run for unknown schedule %s", schedule_id)
            return
        if not schedule.enabled:
            log.info("Skipping disabled schedule %s", schedule_id)
            return

        await self._execute_compliance_report(schedule)

    async def _execute_compliance_report(self, schedule: ComplianceSchedule) -> ComplianceReportResult:
        """Execute a single compliance report generation for a schedule."""
        started_at = time.time()
        schedule.last_run = started_at
        schedule.run_count += 1
        schedule.next_run = schedule.compute_next_run(started_at)
        await self._save_schedule(schedule)

        log.info("Starting compliance report %s for tenant %s", schedule.id, schedule.tenant)

        try:
            jobs_list = await store.list_jobs(tenant=schedule.tenant, limit=1000)
            completed_jobs = [j for j in jobs_list if j.get("state") == "completed"]

            all_findings: list[Finding] = []
            for job_data in completed_jobs:
                job = await store.get_job(job_data["id"], tenant=schedule.tenant)
                if job:
                    findings = await store.get_findings(job["id"], tenant=schedule.tenant)
                    all_findings.extend(findings)

            report_id = await self._generate_trend_report(schedule, all_findings, started_at)

            await self._generate_csv_export(schedule, all_findings, report_id)

            finished_at = time.time()

            result = ComplianceReportResult(
                schedule_id=schedule.id,
                tenant=schedule.tenant,
                started_at=started_at,
                finished_at=finished_at,
                state="completed",
                report_id=report_id,
                total_findings=len(all_findings),
                frameworks_covered=schedule.frameworks,
            )

            await self.audit_chain.append_async(
                {
                    "type": "compliance_report_completed",
                    "schedule_id": schedule.id,
                    "tenant": schedule.tenant,
                    "report_id": report_id,
                    "total_findings": len(all_findings),
                    "frameworks": schedule.frameworks,
                    "duration_ms": round((finished_at - started_at) * 1000, 1),
                }
            )

            return result

        except Exception as exc:
            log.exception("Compliance report %s failed", schedule.id)
            finished_at = time.time()
            result = ComplianceReportResult(
                schedule_id=schedule.id,
                tenant=schedule.tenant,
                started_at=started_at,
                finished_at=finished_at,
                state="failed",
                report_id="",
                total_findings=0,
                frameworks_covered=[],
                error=str(exc),
            )

            await self.audit_chain.append_async(
                {
                    "type": "compliance_report_failed",
                    "schedule_id": schedule.id,
                    "tenant": schedule.tenant,
                    "error": str(exc),
                }
            )
            return result

    async def _generate_trend_report(
        self,
        schedule: ComplianceSchedule,
        findings: list[Finding],
        started_at: float,
    ) -> str:
        """Generate a compliance trend report using regulatory_summary."""

        summary = regulatory_summary(findings)

        now = time.time()
        if schedule.frequency == ReportFrequency.QUARTERLY:
            start_ts = now - (4 * 90 * 86400)
            bucket = "month"
        elif schedule.frequency == ReportFrequency.YEARLY:
            start_ts = now - (4 * 365 * 86400)
            bucket = "quarter"
        else:
            start_ts = now - (4 * 90 * 86400)
            bucket = "month"

        trends = await store.finding_trends(
            tenant=schedule.tenant,
            start=start_ts,
            end=now,
            bucket=bucket,
        )

        framework_trends = {}
        for fw in schedule.frameworks:
            fw_findings = [f for f in findings if fw.upper() in (f.compliance_refs or ())]
            if fw_findings:
                framework_trends[fw] = regulatory_summary(fw_findings)

        report_id = f"compliance_report_{schedule.tenant}_{schedule.id}_{int(start_ts)}"
        report_data = {
            "metadata": {
                "report_id": report_id,
                "schedule_id": schedule.id,
                "tenant": schedule.tenant,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "period_start": datetime.fromtimestamp(start_ts, UTC).isoformat() + "Z",
                "period_end": datetime.fromtimestamp(now, UTC).isoformat() + "Z",
                "frequency": schedule.frequency,
                "frameworks": schedule.frameworks,
            },
            "summary": summary,
            "trends": trends,
            "framework_trends": framework_trends,
            "total_findings": len(findings),
        }

        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO compliance_reports
                       (id, tenant, schedule_id, period_start, period_end, data, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                       data = excluded.data,
                       created_at = excluded.created_at""",
                report_id,
                schedule.tenant,
                schedule.id,
                start_ts,
                now,
                json.dumps(report_data),
                time.time(),
            )

        log.info("Generated compliance trend report %s for tenant %s", report_id, schedule.tenant)
        return report_id

    async def _generate_csv_export(
        self,
        schedule: ComplianceSchedule,
        findings: list[Finding],
        report_id: str,
    ) -> str:
        """Generate CSV export of findings by framework, severity, status over time."""
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(
            [
                "Report ID",
                "Tenant",
                "Framework",
                "Category",
                "Severity",
                "Status",
                "Title",
                "Location",
                "Evidence",
                "CWE",
                "CVSS Score",
                "Risk Rating",
                "Compliance Refs",
                "Discovered Date",
                "Job ID",
            ]
        )

        for finding in findings:
            for fw in schedule.frameworks:
                fw_upper = fw.upper()
                if any(ref.startswith(fw_upper) for ref in (finding.compliance_refs or ())):
                    writer.writerow(
                        [
                            report_id,
                            schedule.tenant,
                            fw.upper(),
                            finding.category,
                            finding.severity,
                            finding.status,
                            finding.title,
                            finding.location,
                            finding.evidence[:200],
                            finding.cwe,
                            finding.cvss_score,
                            finding.risk_rating,
                            ", ".join(finding.compliance_refs),
                            finding.discovered_date,
                            "",
                        ]
                    )
                    break

        csv_content = output.getvalue()

        async with store.get_db_async() as db, db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO compliance_exports
                       (report_id, tenant, format, data, created_at)
                       VALUES (?, ?, 'csv', ?, ?)
                       ON CONFLICT(report_id, format) DO UPDATE SET
                       data = excluded.data,
                       created_at = excluded.created_at""",
                report_id,
                schedule.tenant,
                csv_content,
                time.time(),
            )

        log.info("Generated CSV export for compliance report %s", report_id)
        return csv_content

    async def _run_evidence_pack_generation_async(self) -> None:
        """Generate monthly evidence packs for all tenants."""
        try:
            generated = await generate_monthly_evidence_packs(self.audit_chain)
            log.info("Generated %d monthly evidence packs via compliance scheduler", len(generated))
        except Exception as exc:
            log.exception("Failed to generate monthly evidence packs: %s", exc)
            await self.audit_chain.append_async(
                {
                    "type": "compliance_evidence_pack_generation_failed",
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
            "active_schedules": sum(1 for s in self._schedules.values() if s.enabled),
            "disabled_schedules": sum(1 for s in self._schedules.values() if not s.enabled),
        }


async def create_compliance_scheduler(
    audit_chain: AuditChain,
    monitor: Monitor,
    settings: Settings,
) -> ComplianceScheduler:
    """Factory function to create and initialize a compliance scheduler."""
    scheduler = ComplianceScheduler(
        audit_chain=audit_chain,
        monitor=monitor,
        settings=settings,
    )
    await scheduler.initialize()
    return scheduler


async def list_compliance_reports(tenant: str, limit: int = 50) -> list[dict[str, Any]]:
    """List available compliance reports for a tenant."""

    from ishastra.core import store

    async with store.get_db_async() as db, db.transaction() as conn:
        rows = await store._fetchall(
            conn,
            "SELECT id, tenant, schedule_id, period_start, period_end, created_at "
            "FROM compliance_reports WHERE tenant = ? "
            "ORDER BY period_start DESC LIMIT ?",
            tenant,
            limit,
        )
    return [
        {
            "report_id": row["id"],
            "tenant": row["tenant"],
            "schedule_id": row["schedule_id"],
            "period_start": row["period_start"],
            "period_end": row["period_end"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


async def get_compliance_report(report_id: str, tenant: str) -> dict[str, Any] | None:
    """Get a compliance report by ID."""
    import json

    from ishastra.core import store

    async with store.get_db_async() as db, db.transaction() as conn:
        row = await store._fetchone(
            conn,
            "SELECT data FROM compliance_reports WHERE id = ? AND tenant = ?",
            report_id,
            tenant,
        )
    if row:
        return json.loads(row["data"])
    return None


async def get_compliance_export(report_id: str, tenant: str, format: str = "csv") -> str | None:
    """Get a compliance report export (CSV/JSON)."""
    from ishastra.core import store

    async with store.get_db_async() as db, db.transaction() as conn:
        row = await store._fetchone(
            conn,
            "SELECT data FROM compliance_exports WHERE report_id = ? AND tenant = ? AND format = ?",
            report_id,
            tenant,
            format,
        )
    if row:
        return row["data"]
    return None


async def delete_old_compliance_reports(retention_days: int = COMPLIANCE_REPORT_RETENTION_DAYS) -> int:
    """Delete compliance reports older than retention_days."""
    from ishastra.core import store

    cutoff = time.time() - retention_days * 86400
    async with store.get_db_async() as db, db.transaction() as conn:
        result = await store._execute(
            conn,
            "DELETE FROM compliance_reports WHERE created_at < ?",
            cutoff,
        )
        await store._execute(
            conn,
            "DELETE FROM compliance_exports WHERE created_at < ?",
            cutoff,
        )
        return result.rowcount if hasattr(result, "rowcount") else 0


QUARTERLY_CRON = "0 6 1 */3 *"
YEARLY_CRON = "0 6 1 1 *"


def get_frequency_cron(frequency: str) -> str:
    """Get cron expression for a predefined frequency."""
    if frequency == ReportFrequency.QUARTERLY:
        return QUARTERLY_CRON
    if frequency == ReportFrequency.YEARLY:
        return YEARLY_CRON
    return ""
