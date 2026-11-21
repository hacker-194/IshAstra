"""Durable assessment queue backed by a Redis Stream.

``ISHASTRA_QUEUE_MODE=redis-streams`` replaces the in-memory thread queue with a
stream entry per job. Submitted work therefore survives a restart of every
process, and several worker processes can share one stream through a consumer
group (horizontal workers) while the database stays single-writer.

Delivery is at-least-once; double execution is prevented by the database, not
by the stream. ``store.claim_job`` only lets one consumer move a row out of
``queued``, so a reclaimed or duplicated entry is skipped instead of re-run.
Entries whose consumer died are reclaimed after a visibility window.

On start, rows a dead process left ``running`` are failed loudly (never
resumed silently) and everything still ``queued`` is re-enqueued, so a restart
loses no queued work.

The worker now appends the audit chain entry atomically with the job save
via ``store.save_job(audit_chain_entry=...)`` so any process can seal the chain.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any

import redis as redis_lib

from ishastra.config import get_settings
from ishastra.core import jobs as jobs_module
from ishastra.core import store
from ishastra.core.jobs import Job, JobState
from ishastra.core.redaction import sanitize_target
from ishastra.core.scope import Scope
from ishastra.core.worker import AssessmentQueueFull

log = logging.getLogger(__name__)

DEFAULT_STREAM = "ishastra:assessments"
DEFAULT_GROUP = "ishastra-workers"


DEFAULT_VISIBILITY_SECONDS = 7200.0

_TERMINAL_STATES = {
    JobState.COMPLETED.value,
    JobState.PARTIAL.value,
    JobState.FAILED.value,
    JobState.CANCELLED.value,
}


def _scope_from_policy(policy: dict[str, Any]) -> Scope:
    """Rebuild the authorization snapshot a job was bound to.

    The snapshot is not serialized on its own; ``jobs.prepare`` copies these
    keys into the policy, which is what the job row persists.
    """
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


class RedisStreamsAssessmentQueue:
    """Durable, horizontally shared assessment queue with the worker interface."""

    def __init__(
        self,
        *,
        concurrency: int | None = None,
        queue_max: int | None = None,
        redis_client: Any = None,
        stream: str | None = None,
        group: str | None = None,
        visibility_seconds: float | None = None,
    ) -> None:
        settings = get_settings()
        self.concurrency = concurrency if concurrency is not None else settings.workers
        self.queue_max = queue_max if queue_max is not None else settings.queue_max
        self.stream = stream or os.environ.get("ISHASTRA_REDIS_QUEUE_STREAM", DEFAULT_STREAM)
        self.group = group or os.environ.get("ISHASTRA_REDIS_QUEUE_GROUP", DEFAULT_GROUP)
        self.visibility_seconds = float(
            visibility_seconds
            if visibility_seconds is not None
            else os.environ.get("ISHASTRA_REDIS_QUEUE_VISIBILITY_SECONDS", DEFAULT_VISIBILITY_SECONDS)
        )

        self.redis: Any = redis_client or redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        self._started = False
        self._start_lock = threading.Lock()
        self.name = f"ishastra-redis-worker-{os.getpid()}-{id(self) & 0xFFFF:x}"

    async def start(self) -> None:
        """Create the consumer group, recover durable state, spawn consumers."""
        with self._start_lock:
            if self._started:
                return
            self._started = True
            try:
                self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
            except redis_lib.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    self._started = False
                    raise

            await store.fail_running()
            for job_id, tenant in await store.list_queued_jobs():
                self._enqueue(job_id, tenant)
            for index in range(self.concurrency):
                thread = threading.Thread(
                    target=self._thread_entry,
                    name=f"ishastra-redis-worker-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)
            self._publish_occupancy()

    def _enqueue(self, job_id: str, tenant: str) -> None:
        """Publish one job. Duplicates are harmless: claim_job guards execution."""
        self.redis.xadd(self.stream, {"job_id": job_id, "tenant": tenant})

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Persist then publish a job. Raises AssessmentQueueFull at capacity."""
        await self.start()
        try:
            depth = int(self.redis.xlen(self.stream))
        except redis_lib.RedisError:
            depth = 0
        if depth >= self.queue_max:
            raise AssessmentQueueFull(f"assessment queue is full ({self.queue_max} waiting)")

        with self._lock:
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish
        try:
            await store.save_job(job, tenant=job.actor)
            self._enqueue(job.id, job.actor)
        except Exception:
            with self._lock:
                self._active.pop(job.id, None)
                self._on_finish.pop(job.id, None)
            raise
        self._publish_occupancy()

    def cancel(self, job_id: str) -> bool:
        """Signal a job this process is running to stop. False if it is not ours."""
        with self._lock:
            job = self._active.get(job_id)
        if job is None:
            return False
        job.cancel()
        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel every active job bound to ``policy_id``."""
        with self._lock:
            targets = [
                job for job in self._active.values() if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in targets:
            job.cancel()
        return len(targets)

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Stop consumers and cancel running jobs; leave queued work queued."""
        with self._start_lock:
            if not self._started:
                return
            self._started = False
        self._stopping.set()
        with self._lock:
            running = list(self._active.values())
        for job in running:
            job.cancel()
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self._threads):
            log.warning("redis queue threads still running after %.0fs shutdown", timeout)
        self._threads.clear()
        with self._lock:
            self._active.clear()
            self._on_finish.clear()
        self._stopping.clear()
        self._publish_occupancy()

    def _publish_occupancy(self) -> None:
        from ishastra import metrics

        with self._lock:
            active = len(self._active)
        try:
            depth = int(self.redis.xlen(self.stream))
        except redis_lib.RedisError:
            return
        metrics.record_queue_depth(depth, "redis-streams")
        metrics.record_worker_occupancy(self.concurrency, max(0, active - depth), "redis-streams")

    def _thread_entry(self) -> None:
        """Worker thread: create a dedicated event loop for the store calls."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self._consume(loop)
        finally:
            with contextlib.suppress(Exception):
                loop.close()
            asyncio.set_event_loop(None)

    def _consume(self, loop: asyncio.AbstractEventLoop) -> None:
        consumer = f"{self.name}-{threading.get_ident()}"
        last_reclaim = 0.0
        while not self._stopping.is_set():
            try:
                batches = self.redis.xreadgroup(self.group, consumer, {self.stream: ">"}, count=1, block=1000)
            except (redis_lib.ConnectionError, redis_lib.TimeoutError):
                log.warning("redis queue unavailable; retrying in 5s")
                self._stopping.wait(5.0)
                continue
            handled = 0
            for _stream, messages in batches or []:
                for message_id, fields in messages:
                    self._handle(loop, message_id, fields, consumer)
                    handled += 1
            if handled:
                self._publish_occupancy()
                continue
            if time.monotonic() - last_reclaim >= 30.0:
                last_reclaim = time.monotonic()
                self._reclaim(loop, consumer)

    def _reclaim(self, loop: asyncio.AbstractEventLoop, consumer: str) -> None:
        """Take over entries whose consumer died without acknowledging."""
        try:
            claimed = self.redis.xautoclaim(
                self.stream,
                self.group,
                consumer,
                min_idle_time=int(self.visibility_seconds * 1000),
                start_id="0-0",
                count=10,
            )
            messages = claimed[1]
        except redis_lib.ResponseError:
            return
        for message_id, fields in messages:
            self._handle(loop, message_id, fields, consumer)

    def _handle(
        self,
        loop: asyncio.AbstractEventLoop,
        message_id: str,
        fields: dict[str, str] | None,
        consumer: str,
    ) -> None:
        job_id = (fields or {}).get("job_id", "")
        tenant = (fields or {}).get("tenant", "")
        if not job_id or not tenant:
            log.warning("dropping malformed queue entry %s", message_id)
            self.redis.xack(self.stream, self.group, message_id)
            self.redis.xdel(self.stream, message_id)
            return
        try:
            self._run(loop, job_id, tenant, consumer)
        except Exception:
            log.exception("queue entry %s failed outside the job", message_id)
        finally:
            self.redis.xack(self.stream, self.group, message_id)
            self.redis.xdel(self.stream, message_id)
            with self._lock:
                self._on_finish.pop(job_id, None)
                self._active.pop(job_id, None)

    def _run(
        self,
        loop: asyncio.AbstractEventLoop,
        job_id: str,
        tenant: str,
        consumer: str,
    ) -> None:
        row = loop.run_until_complete(store.get_job(job_id, tenant=tenant))
        if row is None:
            log.warning("job %s is gone; dropping its queue entry", job_id)
            return
        if row["state"] in _TERMINAL_STATES:
            log.info("job %s already finished (%s); dropping its queue entry", job_id, row["state"])
            return

        job = _job_from_row(row)
        with self._lock:
            self._active[job.id] = job
            on_finish = self._on_finish.get(job.id)

        if not loop.run_until_complete(store.claim_job(job.id, tenant=tenant, worker=consumer)):
            log.info("job %s was claimed by another consumer; skipping", job_id)
            return

        job.attempts = int(row.get("attempts") or 0) + 1
        job.worker_id = consumer
        from ishastra import metrics

        created = row.get("created_at") or time.time()
        metrics.observe_job_queue(job.profile, time.time() - created)
        try:
            jobs_module.execute(job)
        except Exception as exc:
            log.exception("assessment %s crashed", job.id)
            job.state = JobState.FAILED
            job.error = f"internal error: {type(exc).__name__}"
            job.finished_at = time.time()

        audit_chain_entry = {
            "event": "assessment_job",
            "job": job.id,
            "target": sanitize_target(job.target),
            "state": job.state.value,
            "verdict": job.verdict,
            "findings": [finding.category for finding in job.findings],
        }
        audit_hmac_key = get_settings().audit_hmac_key
        try:
            loop.run_until_complete(
                store.save_job(
                    job,
                    tenant=tenant,
                    audit_chain_entry=audit_chain_entry,
                    audit_hmac_key=audit_hmac_key,
                )
            )
        except Exception:
            log.exception("failed to persist job %s", job.id)

        if on_finish is not None:
            try:
                on_finish(job)
            except Exception:
                log.exception("final save failed for %s", job.id)


def get_redis_streams_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> RedisStreamsAssessmentQueue:
    """Factory for the Redis Streams queue."""
    return RedisStreamsAssessmentQueue(concurrency=concurrency, queue_max=queue_max)
