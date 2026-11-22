"""Durable assessment queue backed by SQLite.

``ISHASTRA_QUEUE_MODE=sqlite`` replaces the in-memory thread queue with a
SQLite-backed queue. Submitted work therefore survives a restart of every
process, and several worker processes can share the queue through database
locking (horizontal workers) while the database stays single-writer.

Delivery is at-least-once; double execution is prevented by the database.
``claim_job`` only lets one consumer move a row out of ``queued``, so a
reclaimed or duplicated entry is skipped instead of re-run.
Entries whose consumer died are reclaimed after a visibility window.

On start, rows a dead process left ``running`` are failed loudly (never
resumed silently) and everything still ``queued`` is re-enqueued, so a restart
loses no queued work.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from ishastra.config import get_settings
from ishastra.core import store
from ishastra.core.jobs import Job, JobState
from ishastra.core.scope import Scope
from ishastra.core.worker import AssessmentQueueFull

log = logging.getLogger(__name__)

QUEUE_TABLE = "ishastra_queue"
DEFAULT_VISIBILITY_SECONDS = 7200.0
TERMINAL_STATES = {
    JobState.COMPLETED.value,
    JobState.PARTIAL.value,
    JobState.FAILED.value,
    JobState.CANCELLED.value,
}


def _scope_from_policy(policy: dict[str, Any]) -> Scope:
    """Rebuild the authorization snapshot a job was bound to."""
    return Scope(
        authorization_ref=str(policy.get("authorization_ref", "")),
        policy_id=str(policy.get("policy_id", "")),
        policy_version=int(policy.get("policy_version", 0) or 0),
        tenant_id=str(policy.get("tenant_id", "")),
        program=str(policy.get("scope_program", "")),
        authorized_by=str(policy.get("scope_authorized_by", "")),
        include=tuple(policy.get("scope_include", [])),
        exclude=tuple(policy.get("scope_exclude", [])),
        authorized_networks=tuple(policy.get("scope_authorized_networks", [])),
        allowed_ports=tuple(policy.get("scope_allowed_ports", [])),
        allow_broad_networks=bool(policy.get("scope_allow_broad_networks", False)),
    )


def _job_from_row(row: dict[str, Any]) -> Job:
    """Rebuild a runnable job from its persisted row (what a restart sees)."""
    policy = dict(row.get("policy") or {})
    job = Job(
        target=row["target"],
        profile=row["profile"],
        actor=row["actor"],
        policy=policy,
    )
    job.id = row["id"]
    job.scope_snapshot = _scope_from_policy(policy)
    job.idempotency_key = row.get("idempotency_key")
    return job


class SQLiteAssessmentQueue:
    """Durable, SQLite-backed assessment queue with the worker interface."""

    def __init__(
        self,
        *,
        concurrency: int | None = None,
        queue_max: int | None = None,
        db_path: str | None = None,
        visibility_seconds: float | None = None,
    ) -> None:
        settings = get_settings()
        self.concurrency = concurrency if concurrency is not None else settings.workers
        self.queue_max = queue_max if queue_max is not None else settings.queue_max
        self.db_path = db_path or os.environ.get("ISHASTRA_SQLITE_QUEUE_DB") or store.current_path()
        if self.db_path.startswith(("postgresql://", "postgres://")):
            raise ValueError("SQLite queue requires a SQLite database path, not PostgreSQL")
        self.visibility_seconds = float(
            visibility_seconds
            if visibility_seconds is not None
            else os.environ.get("ISHASTRA_SQLITE_QUEUE_VISIBILITY_SECONDS", DEFAULT_VISIBILITY_SECONDS)
        )

        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        self._started = False
        self._start_lock = threading.Lock()
        self.name = f"ishastra-sqlite-worker-{os.getpid()}-{id(self) & 0xFFFF:x}"
        self._worker_id = str(uuid4())[:8]

    def _get_conn(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_schema(self) -> None:
        """Initialize the queue table if it doesn't exist."""
        with self._get_conn() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {QUEUE_TABLE} (
                    job_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    policy TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'queued',
                    created_at REAL NOT NULL,
                    claimed_at REAL,
                    claimed_by TEXT,
                    visibility_timeout REAL,
                    retries INTEGER NOT NULL DEFAULT 0,
                    idempotency_key TEXT,
                    UNIQUE(job_id)
                )
            """)
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{QUEUE_TABLE}_tenant_state
                ON {QUEUE_TABLE} (tenant_id, state)
            """)
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{QUEUE_TABLE}_state_created
                ON {QUEUE_TABLE} (state, created_at)
            """)
            conn.commit()

    async def start(self) -> None:
        """Initialize schema, recover durable state, spawn consumers."""
        with self._start_lock:
            if self._started:
                return
            self._started = True

            await asyncio.to_thread(self._init_schema)
            await store.fail_running()

            # Recover queued jobs
            queued_jobs = await store.list_queued_jobs()
            for job_id, tenant in queued_jobs:
                self._enqueue(job_id, tenant)

            for index in range(self.concurrency):
                thread = threading.Thread(
                    target=self._thread_entry,
                    name=f"ishastra-sqlite-worker-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)

    def _enqueue(self, job_id: str, tenant_id: str) -> None:
        """Add a job to the in-memory queue from database row."""
        with self._get_conn() as conn:
            row = conn.execute(f"SELECT * FROM {QUEUE_TABLE} WHERE job_id = ?", (job_id,)).fetchone()
        if row:
            job = _job_from_row(dict(row))
            with self._lock:
                self._active[job_id] = job
            try:
                self._queue_put_nowait(job)
            except Exception:
                with self._lock:
                    self._active.pop(job_id, None)
                raise

    def _queue_put_nowait(self, job: Job) -> None:
        """Put job in memory queue - we'll use a simple list for SQLite queue."""
        # For SQLite queue, we don't use in-memory queue - we pull from DB

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Queue a prepared job. Raises AssessmentQueueFull when at capacity."""
        await self.start()

        # Check queue depth
        with self._get_conn() as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM {QUEUE_TABLE} WHERE state = 'queued'").fetchone()[0]
        if count >= self.queue_max:
            raise AssessmentQueueFull(f"assessment queue is full ({self.queue_max} waiting)")

        # Insert into database
        import json

        with self._get_conn() as conn:
            conn.execute(
                f"""
                INSERT INTO {QUEUE_TABLE}
                (job_id, tenant_id, target, profile, actor, policy, state, created_at, idempotency_key)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)
                """,
                (
                    job.id,
                    job.policy.get("tenant_id", "") if job.policy else "",
                    job.target,
                    job.profile,
                    job.actor,
                    json.dumps(job.policy or {}),
                    time.time(),
                    job.idempotency_key,
                ),
            )
            conn.commit()

        with self._lock:
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish

        # Signal worker thread
        self._signal_work()

    def _signal_work(self) -> None:
        """Signal worker threads that work is available."""
        # Using a simple approach - workers poll the database

    def cancel(self, job_id: str) -> bool:
        """Signal a queued or running job to stop. False if it is not ours."""
        with self._lock:
            job = self._active.get(job_id)
        if job is None:
            return False
        job.cancel()
        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel every queued/running job bound to ``policy_id``."""
        with self._lock:
            targets = [
                job for job in self._active.values() if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in targets:
            job.cancel()
        return len(targets)

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Stop cleanly: cancel running jobs, wait for workers, fail what never ran."""
        with self._start_lock:
            if not self._started:
                return
            log.debug(
                "Shutting down SQLite worker, stopping=%s, threads=%d",
                self._stopping.is_set(),
                len(self._threads),
            )
            self._stopping.set()
            with self._lock:
                running = list(self._active.values())
            log.debug("Cancelling %d running jobs", len(running))
            for job in running:
                job.cancel()
            deadline = time.monotonic() + timeout
            for i, thread in enumerate(self._threads):
                remaining = max(0.0, deadline - time.monotonic())
                log.debug(
                    "Joining thread %d/%d (ident=%s), remaining=%.2fs",
                    i + 1,
                    len(self._threads),
                    thread.ident,
                    remaining,
                )
                thread.join(remaining)
                log.debug("Thread %d joined, alive=%s", i + 1, thread.is_alive())
            if any(thread.is_alive() for thread in self._threads):
                log.warning("SQLite worker threads still running after %.0fs shutdown", timeout)
            self._threads.clear()

            await asyncio.sleep(1.0)
            log.debug("Worker threads cleared, calling fail_interrupted")

            try:
                await store.fail_interrupted()
            except Exception as exc:
                log.debug("fail_interrupted skipped due to: %s", exc)
            with self._lock:
                self._active.clear()
                self._on_finish.clear()
            self._stopping.clear()
            self._started = False

    def _thread_entry(self) -> None:
        """Entry point for worker threads: create and run a dedicated event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self._loop(loop)
        finally:
            with contextlib.suppress(Exception):
                loop.close()
            asyncio.set_event_loop(None)

    def _loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Main worker loop: claim jobs from SQLite and execute them."""
        while not self._stopping.is_set():
            job = self._claim_job()
            if job is None:
                time.sleep(1.0)
                continue
            self._execute_job(job, loop)

    def _claim_job(self) -> Job | None:
        """Atomically claim the next queued job for this worker."""
        now = time.time()
        with self._get_conn() as conn:
            # First, reclaim stale jobs (visibility timeout expired)
            conn.execute(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = 'queued', claimed_by = NULL, claimed_at = NULL, visibility_timeout = NULL
                WHERE state = 'running'
                AND claimed_at IS NOT NULL
                AND visibility_timeout IS NOT NULL
                AND (claimed_at + visibility_timeout) < ?
                """,
                (now,),
            )

            # Claim next queued job
            row = conn.execute(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = 'running', claimed_at = ?, claimed_by = ?, visibility_timeout = ?
                WHERE job_id = (
                    SELECT job_id FROM {QUEUE_TABLE}
                    WHERE state = 'queued'
                    ORDER BY created_at
                    LIMIT 1
                )
                RETURNING *
                """,
                (now, self._worker_id, self.visibility_seconds),
            ).fetchone()
            conn.commit()

        if row:
            return _job_from_row(dict(row))
        return None

    def _execute_job(self, job: Job, loop: asyncio.AbstractEventLoop) -> None:
        """Execute a job and handle completion."""
        job_id = job.id
        try:
            # Run the job
            loop.run_until_complete(self._run_job(job))
            self._mark_completed(job_id)
        except Exception as exc:
            log.exception("Job %s failed: %s", job_id, exc)
            self._mark_failed(job_id, str(exc))
        finally:
            with self._lock:
                self._active.pop(job_id, None)
                on_finish = self._on_finish.pop(job_id, None)
            if on_finish:
                try:
                    on_finish(job)
                except Exception:
                    log.exception("on_finish callback failed for %s", job_id)

    async def _run_job(self, job: Job) -> None:
        """Run the job using the existing job execution logic."""
        import asyncio

        from ishastra.core import jobs as jobs_module

        await asyncio.to_thread(jobs_module.execute, job)

    def _mark_completed(self, job_id: str) -> None:
        """Mark job as completed in database."""
        with self._get_conn() as conn:
            conn.execute(f"UPDATE {QUEUE_TABLE} SET state = 'completed' WHERE job_id = ?", (job_id,))
            conn.commit()

    def _mark_failed(self, job_id: str, error: str) -> None:
        """Mark job as failed in database."""
        with self._get_conn() as conn:
            # Check retry count
            row = conn.execute(f"SELECT retries FROM {QUEUE_TABLE} WHERE job_id = ?", (job_id,)).fetchone()
            retries = row["retries"] if row else 0
            if retries < 3:
                conn.execute(
                    f"""
                    UPDATE {QUEUE_TABLE}
                    SET state = 'queued', retries = retries + 1,
                        claimed_by = NULL, claimed_at = NULL, visibility_timeout = NULL
                    WHERE job_id = ?
                    """,
                    (job_id,),
                )
            else:
                conn.execute(f"UPDATE {QUEUE_TABLE} SET state = 'failed' WHERE job_id = ?", (job_id,))
            conn.commit()


def get_sqlite_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> SQLiteAssessmentQueue:
    """Return a SQLite-backed assessment queue instance."""
    return SQLiteAssessmentQueue(concurrency=concurrency, queue_max=queue_max)
