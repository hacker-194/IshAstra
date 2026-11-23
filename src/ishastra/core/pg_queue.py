"""Durable assessment queue backed by PostgreSQL.

``ISHASTRA_QUEUE_MODE=postgres`` replaces the SQLite queue with PostgreSQL's
``FOR UPDATE SKIP LOCKED``: several dispatcher/worker processes share one
queue without claiming the same job, and queued work survives every restart.

Delivery is at-least-once, execution at-most-once per claim: a row is moved
out of ``queued`` in the same transaction that locks it, so a duplicate
message is skipped. Each claim increments ``retries``; a lost worker is
recovered after its visibility timeout, and a row that runs out of attempts
fails with ``retries_exhausted`` instead of running forever.

Cancellation is persisted in the queue row. ``cancel`` also schedules the
database update on the running event loop (the public interface is sync);
callers that need the row updated before returning use ``cancel_async``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from ishastra.core import store
from ishastra.core.jobs import Job
from ishastra.core.sqlite_queue import _job_from_row
from ishastra.core.worker import AssessmentQueueFull

log = logging.getLogger(__name__)

QUEUE_TABLE = "ishastra_queue"
DEFAULT_VISIBILITY_SECONDS = 7200.0
DEFAULT_MAX_ATTEMPTS = 3


class PostgresAssessmentQueue:
    """PostgreSQL-backed assessment queue with the worker interface."""

    def __init__(
        self,
        *,
        concurrency: int | None = None,
        queue_max: int | None = None,
        visibility_seconds: float | None = None,
        max_attempts: int | None = None,
    ) -> None:
        from ishastra.config import get_settings

        settings = get_settings()
        self.concurrency = concurrency if concurrency is not None else settings.workers
        self.queue_max = queue_max if queue_max is not None else settings.queue_max
        self.visibility_seconds = float(
            visibility_seconds
            if visibility_seconds is not None
            else os.environ.get("ISHASTRA_PG_QUEUE_VISIBILITY_SECONDS", DEFAULT_VISIBILITY_SECONDS)
        )
        self.max_attempts = int(
            max_attempts
            if max_attempts is not None
            else os.environ.get("ISHASTRA_PG_QUEUE_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)
        )
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._tenants: dict[str, str] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        self._started = False
        self._start_lock = threading.Lock()
        self.name = f"ishastra-pg-worker-{os.getpid()}-{id(self) & 0xFFFF:x}"
        self._worker_id = str(uuid4())[:8]

    async def _db(self) -> Any:
        db = await store.get_database()
        if not db.is_postgresql():
            raise ValueError("PostgresAssessmentQueue requires a PostgreSQL database")
        return db

    async def _init_schema(self) -> None:
        db = await self._db()
        statements = [
            f"""
            CREATE TABLE IF NOT EXISTS {QUEUE_TABLE} (
                job_id             TEXT PRIMARY KEY,
                tenant_id          TEXT NOT NULL,
                target             TEXT NOT NULL,
                profile            TEXT NOT NULL,
                actor              TEXT NOT NULL,
                policy             TEXT NOT NULL,
                policy_id          TEXT NOT NULL DEFAULT '',
                state              TEXT NOT NULL DEFAULT 'queued',
                created_at         DOUBLE PRECISION NOT NULL,
                claimed_at         DOUBLE PRECISION,
                claimed_by         TEXT,
                visibility_timeout DOUBLE PRECISION,
                retries            INTEGER NOT NULL DEFAULT 0,
                max_attempts       INTEGER NOT NULL DEFAULT 3,
                idempotency_key    TEXT,
                cancel_requested   BOOLEAN NOT NULL DEFAULT FALSE,
                error              TEXT NOT NULL DEFAULT '',
                finished_at        DOUBLE PRECISION
            )
            """,
            f"""
            CREATE INDEX IF NOT EXISTS idx_{QUEUE_TABLE}_state_created
            ON {QUEUE_TABLE} (state, created_at)
            """,
            f"""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_{QUEUE_TABLE}_idempotency
            ON {QUEUE_TABLE} (idempotency_key) WHERE idempotency_key IS NOT NULL
            """,
            f"""
            CREATE INDEX IF NOT EXISTS idx_{QUEUE_TABLE}_policy
            ON {QUEUE_TABLE} (policy_id, state)
            """,
            """
            CREATE TABLE IF NOT EXISTS job_attempts (
                id          BIGSERIAL PRIMARY KEY,
                job_id      TEXT NOT NULL,
                attempt     INTEGER NOT NULL,
                worker      TEXT NOT NULL,
                state       TEXT NOT NULL DEFAULT 'running',
                started_at  DOUBLE PRECISION NOT NULL,
                finished_at DOUBLE PRECISION,
                error       TEXT NOT NULL DEFAULT '',
                UNIQUE (job_id, attempt)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_job_attempts_job
            ON job_attempts (job_id, attempt DESC)
            """,
        ]
        async with db.transaction() as conn:
            for statement in statements:
                await conn.execute(statement)

    async def start(self) -> None:
        """Create the queue table, recover expired claims, spawn consumers."""
        with self._start_lock:
            if self._started:
                return
            self._started = True
        try:
            await self._init_schema()
            db = await self._db()
            async with db.transaction() as conn:
                await self._recover_orphans(conn, time.time())
            for index in range(self.concurrency):
                thread = threading.Thread(
                    target=self._thread_entry,
                    name=f"{self.name}-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)
        except Exception:
            with self._start_lock:
                self._started = False
            raise

    async def clear(self) -> None:
        """Remove every queue row. Test helper; never called by the app."""
        db = await self._db()
        async with db.transaction() as conn:
            await conn.execute(f"DELETE FROM {QUEUE_TABLE}")
            await conn.execute("DELETE FROM job_attempts")

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Queue a prepared job. Raises AssessmentQueueFull when at capacity."""
        await self.start()
        with self._lock:
            if job.id in self._active:
                return
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish
            tenant = str((job.policy or {}).get("tenant_id") or job.actor)
            self._tenants[job.id] = tenant

        db = await self._db()
        async with db.transaction() as conn:
            row = await conn.fetchrow(
                f"""
                INSERT INTO {QUEUE_TABLE}
                    (job_id, tenant_id, target, profile, actor, policy, policy_id,
                     state, created_at, max_attempts, idempotency_key)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', $8, $9, $10)
                ON CONFLICT DO NOTHING
                RETURNING job_id
                """,
                job.id,
                tenant,
                job.target,
                job.profile,
                job.actor,
                json.dumps(job.policy or {}),
                str((job.policy or {}).get("policy_id") or ""),
                time.time(),
                self.max_attempts,
                job.idempotency_key,
            )
            if row is None:
                with self._lock:
                    self._active.pop(job.id, None)
                    self._on_finish.pop(job.id, None)
                    self._tenants.pop(job.id, None)
                log.info("duplicate queue message skipped", extra={"job_id": job.id})
                return
            queued = await conn.fetchval(
                f"SELECT count(*) FROM {QUEUE_TABLE} WHERE state = 'queued'"
            )
            if (queued or 0) > self.queue_max:
                await conn.execute(f"DELETE FROM {QUEUE_TABLE} WHERE job_id = $1", job.id)
                with self._lock:
                    self._active.pop(job.id, None)
                    self._on_finish.pop(job.id, None)
                    self._tenants.pop(job.id, None)
                raise AssessmentQueueFull(
                    f"assessment queue is full ({self.queue_max} waiting)"
                )

    def cancel(self, job_id: str) -> bool:
        """Signal a job to stop. Schedules the durable update when possible."""
        with self._lock:
            job = self._active.get(job_id)
        if job is not None:
            job.cancel()
        try:
            asyncio.get_running_loop().create_task(self.cancel_async(job_id))
            return True
        except RuntimeError:
            return job is not None

    async def cancel_async(self, job_id: str) -> bool:
        """Persist cancellation: queued rows stop, running rows get the flag."""
        db = await self._db()
        now = time.time()
        async with db.transaction() as conn:
            queued = await conn.fetchrow(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = 'cancelled', cancel_requested = TRUE, finished_at = $2
                WHERE job_id = $1 AND state = 'queued'
                RETURNING job_id
                """,
                job_id,
                now,
            )
            running = await conn.fetchrow(
                f"""
                UPDATE {QUEUE_TABLE}
                SET cancel_requested = TRUE
                WHERE job_id = $1 AND state = 'running'
                RETURNING job_id
                """,
                job_id,
            )
        with self._lock:
            job = self._active.get(job_id)
        if job is not None:
            job.cancel()
        return queued is not None or running is not None

    async def cancel_for_policy_async(self, policy_id: str) -> int:
        """Persist cancellation for every queued/running job of a policy."""
        db = await self._db()
        now = time.time()
        async with db.transaction() as conn:
            rows = await conn.fetch(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = 'cancelled', cancel_requested = TRUE, finished_at = $2
                WHERE policy_id = $1 AND state = 'queued'
                RETURNING job_id
                """,
                policy_id,
                now,
            )
            running = await conn.fetch(
                f"""
                UPDATE {QUEUE_TABLE}
                SET cancel_requested = TRUE
                WHERE policy_id = $1 AND state = 'running'
                RETURNING job_id
                """,
                policy_id,
            )
        with self._lock:
            local = [
                job
                for job in self._active.values()
                if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in local:
            job.cancel()
        return len(rows) + len(running)

    def cancel_for_policy(self, policy_id: str) -> int:
        """Signal local jobs now; schedule the durable update."""
        with self._lock:
            local = [
                job
                for job in self._active.values()
                if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in local:
            job.cancel()
        with contextlib.suppress(RuntimeError):
            asyncio.get_running_loop().create_task(
                self.cancel_for_policy_async(policy_id)
            )
        return len(local)

    async def _recover_orphans(self, conn: Any, now: float) -> None:
        """Requeue expired claims, or fail them once attempts are exhausted."""
        await conn.execute(
            """
            UPDATE job_attempts a
            SET state = 'orphaned', finished_at = $1,
                error = CASE WHEN q.retries >= q.max_attempts
                             THEN 'retries_exhausted' ELSE 'worker lost' END
            FROM ishastra_queue q
            WHERE q.state = 'running'
              AND q.claimed_at IS NOT NULL
              AND q.visibility_timeout IS NOT NULL
              AND q.claimed_at + q.visibility_timeout < $1
              AND a.job_id = q.job_id
              AND a.attempt = q.retries
              AND a.state = 'running'
            """,
            now,
        )
        await conn.execute(
            f"""
            UPDATE {QUEUE_TABLE}
            SET state = CASE WHEN retries >= max_attempts THEN 'failed' ELSE 'queued' END,
                error = CASE WHEN retries >= max_attempts
                             THEN 'retries_exhausted'
                             ELSE 'worker lost' END,
                finished_at = CASE WHEN retries >= max_attempts
                                   THEN $1::double precision ELSE NULL END,
                claimed_at = NULL, claimed_by = NULL, visibility_timeout = NULL
            WHERE state = 'running'
              AND claimed_at IS NOT NULL
              AND visibility_timeout IS NOT NULL
              AND claimed_at + visibility_timeout < $1
            """,
            now,
        )

    async def _claim_next(self) -> Job | None:
        """Atomically claim the oldest queued job; None when the queue is empty."""
        db = await self._db()
        now = time.time()
        async with db.transaction() as conn:
            await self._recover_orphans(conn, now)
            row = await conn.fetchrow(
                f"""
                WITH next AS (
                    SELECT job_id FROM {QUEUE_TABLE}
                    WHERE state = 'queued'
                    ORDER BY created_at
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE {QUEUE_TABLE} q
                SET state = 'running',
                    claimed_at = $1,
                    claimed_by = $2,
                    visibility_timeout = $3,
                    retries = q.retries + 1,
                    error = ''
                FROM next
                WHERE q.job_id = next.job_id
                RETURNING q.*
                """,
                now,
                self._worker_id,
                self.visibility_seconds,
            )
            if row is not None:
                await conn.execute(
                    """
                    INSERT INTO job_attempts (job_id, attempt, worker, started_at)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (job_id, attempt) DO NOTHING
                    """,
                    row["job_id"],
                    row["retries"],
                    self._worker_id,
                    now,
                )
        if row is None:
            return None
        data = dict(row)
        data["id"] = data["job_id"]
        data["policy"] = json.loads(data["policy"])
        job = _job_from_row(data)
        with self._lock:
            self._tenants.setdefault(job.id, data["tenant_id"])
        if data.get("cancel_requested"):
            job.cancel()
        return job

    def _thread_entry(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self._loop(loop)
        finally:
            with contextlib.suppress(Exception):
                loop.close()
            asyncio.set_event_loop(None)

    def _loop(self, loop: asyncio.AbstractEventLoop) -> None:
        while not self._stopping.is_set():
            try:
                job = loop.run_until_complete(self._claim_next())
            except Exception:
                log.exception("PostgreSQL queue claim failed")
                time.sleep(1.0)
                continue
            if job is None:
                time.sleep(0.5)
                continue
            self._execute_job(job, loop)

    def _execute_job(self, job: Job, loop: asyncio.AbstractEventLoop) -> None:
        job_id = job.id
        try:
            loop.run_until_complete(self._run_job(job))
        except Exception as exc:
            log.exception("job %s failed in the PostgreSQL queue", job_id)
            loop.run_until_complete(
                self._mark_failed(job_id, f"{type(exc).__name__}: {exc}")
            )
        else:
            loop.run_until_complete(self._finish(job))
        finally:
            with self._lock:
                self._active.pop(job_id, None)
                on_finish = self._on_finish.pop(job_id, None)
                tenant = self._tenants.pop(job_id, None)
            if on_finish is not None:
                try:
                    on_finish(job)
                except Exception:
                    log.exception("on_finish callback failed for %s", job_id)
            elif tenant is not None:
                try:
                    loop.run_until_complete(store.save_job(job, tenant=tenant))
                except Exception:
                    log.exception("could not persist recovered job %s", job_id)

    async def _run_job(self, job: Job) -> None:
        from ishastra.core import jobs as jobs_module

        timeout = float(job.policy.get("timeout", 300.0) or 300.0)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(jobs_module.execute, job),
                timeout=timeout + 60.0,
            )
        except TimeoutError:
            job.cancel()
            raise RuntimeError("wall-clock timeout") from None

    async def _finish(self, job: Job) -> None:
        state = job.state.value
        if state == "running":
            state = "failed"
            job.error = job.error or "job finished without a terminal state"
        db = await self._db()
        now = time.time()
        async with db.transaction() as conn:
            updated = await conn.fetchrow(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = $1, error = $2, finished_at = $3,
                    claimed_at = NULL, claimed_by = NULL, visibility_timeout = NULL
                WHERE job_id = $4 AND state = 'running' AND claimed_by = $5
                RETURNING job_id
                """,
                state,
                job.error or "",
                now,
                job.id,
                self._worker_id,
            )
            if updated is None:
                return
            await conn.execute(
                """
                UPDATE job_attempts
                SET state = $1, finished_at = $2, error = $3
                WHERE job_id = $4 AND state = 'running'
                  AND attempt = (SELECT max(attempt) FROM job_attempts WHERE job_id = $4)
                """,
                state,
                now,
                job.error or "",
                job.id,
            )

    async def _mark_failed(self, job_id: str, error: str) -> None:
        """Requeue while attempts remain; otherwise fail with retries_exhausted."""
        db = await self._db()
        now = time.time()
        async with db.transaction() as conn:
            row = await conn.fetchrow(
                f"""
                UPDATE {QUEUE_TABLE}
                SET state = CASE WHEN retries >= max_attempts THEN 'failed' ELSE 'queued' END,
                    error = CASE WHEN retries >= max_attempts
                                 THEN 'retries_exhausted'
                                 ELSE $2 END,
                    finished_at = CASE WHEN retries >= max_attempts
                                       THEN $3::double precision ELSE NULL END,
                    claimed_at = NULL, claimed_by = NULL, visibility_timeout = NULL
                WHERE job_id = $1 AND state = 'running' AND claimed_by = $4
                RETURNING retries, max_attempts
                """,
                job_id,
                error,
                now,
                self._worker_id,
            )
            if row is None:
                return
            outcome = "failed" if row["retries"] >= row["max_attempts"] else "retrying"
            await conn.execute(
                """
                UPDATE job_attempts
                SET state = $1, finished_at = $2,
                    error = CASE WHEN $1 = 'failed' THEN 'retries_exhausted' ELSE $3 END
                WHERE job_id = $4 AND state = 'running'
                  AND attempt = (SELECT max(attempt) FROM job_attempts WHERE job_id = $4)
                """,
                outcome,
                now,
                error,
                job_id,
            )

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Stop cleanly: cancel running jobs, join threads, requeue claims."""
        with self._start_lock:
            if not self._started:
                return
            self._stopping.set()
            with self._lock:
                running = list(self._active.values())
            for job in running:
                job.cancel()
            deadline = time.monotonic() + timeout
            for thread in self._threads:
                thread.join(max(0.0, deadline - time.monotonic()))
            if any(thread.is_alive() for thread in self._threads):
                log.warning("PostgreSQL queue threads still running after %.0fs", timeout)
            self._threads.clear()

            db = await self._db()
            async with db.transaction() as conn:
                await conn.execute(
                    f"""
                    UPDATE {QUEUE_TABLE}
                    SET state = CASE WHEN retries >= max_attempts THEN 'failed' ELSE 'queued' END,
                        error = CASE WHEN retries >= max_attempts
                                     THEN 'retries_exhausted'
                                     ELSE 'worker shut down' END,
                        finished_at = CASE WHEN retries >= max_attempts
                                           THEN $2::double precision ELSE NULL END,
                        claimed_at = NULL, claimed_by = NULL, visibility_timeout = NULL
                    WHERE state = 'running' AND claimed_by = $1
                    """,
                    self._worker_id,
                    time.time(),
                )
            with self._lock:
                self._active.clear()
                self._on_finish.clear()
                self._tenants.clear()
            self._stopping.clear()
            self._started = False


def get_postgres_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> PostgresAssessmentQueue:
    return PostgresAssessmentQueue(concurrency=concurrency, queue_max=queue_max)
