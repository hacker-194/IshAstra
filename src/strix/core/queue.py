"""Celery + Redis queue for assessment jobs.

Replaces the in-process queue with a distributed Redis-backed queue.
Supports horizontal scaling, job persistence, rate limiting, and graceful shutdown.

Migration path: set STRIX_QUEUE_MODE=celery to enable (default: in-process).
Also supports STRIX_QUEUE_MODE=k8s-jobs for Kubernetes Jobs-based execution.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

try:  # celery is the optional "[celery]" extra; the in-process queue must import without it
    from celery import Celery
    from celery.signals import worker_init
    from kombu import Queue
except ImportError:  # pragma: no cover - minimal installs (the shipped image) take this path
    Celery = None  # type: ignore[assignment,misc]
    worker_init = None  # type: ignore[assignment]
    Queue = None  # type: ignore[assignment]

from strix.core import store
from strix.core.jobs import Job, JobState
from strix.core.worker import AssessmentWorker

if TYPE_CHECKING:
    from strix.core.k8s_queue import K8sAssessmentQueue

log = logging.getLogger(__name__)

# Queue mode: "inprocess" (default), "celery" (distributed), or "k8s-jobs" (K8s Jobs)
QUEUE_MODE = os.environ.get("STRIX_QUEUE_MODE", "inprocess").strip().lower()
QUEUE_MODE_K8S_JOBS = "k8s-jobs"

# Celery configuration defaults
CELERY_BROKER_URL = os.environ.get("STRIX_CELERY_BROKER_URL", "redis://localhost:6379/1")
CELERY_RESULT_BACKEND = os.environ.get("STRIX_CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
CELERY_TASK_ACKS_LATE = True  # Acknowledge after execution for at-least-once
CELERY_TASK_REJECT_ON_WORKER_LOST = True  # Requeue if worker dies mid-task
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Fair dispatch, one job per worker at a time
CELERY_TASK_DEFAULT_QUEUE = "strix_assessments"
CELERY_TASK_QUEUES = (Queue("strix_assessments", routing_key="assessment.#"),) if Queue else ()
CELERY_WORKER_MAX_TASKS_PER_CHILD = 50  # Recycle workers to prevent memory leaks
CELERY_WORKER_MAX_MEMORY_PER_CHILD = 1024 * 1024 * 1024  # 1GB soft limit
CELERY_TASK_TIME_LIMIT = 3600  # Hard timeout (1 hour)
CELERY_TASK_SOFT_TIME_LIMIT = 300  # Soft timeout (5 min) - graceful shutdown window
CELERY_BROKER_CONNECTION_RETRY = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BROKER_HEARTBEAT = 30


def create_celery_app() -> Celery:
    """Create and configure the Celery application from the environment."""
    if Celery is None:
        raise RuntimeError(
            "STRIX_QUEUE_MODE=celery requires the optional celery extra: pip install 'strix[celery]'"
        )
    app = Celery("strix")
    app.conf.update(
        broker_url=os.environ.get("STRIX_CELERY_BROKER_URL", CELERY_BROKER_URL),
        result_backend=os.environ.get("STRIX_CELERY_RESULT_BACKEND", CELERY_RESULT_BACKEND),
        task_acks_late=CELERY_TASK_ACKS_LATE,
        task_reject_on_worker_lost=CELERY_TASK_REJECT_ON_WORKER_LOST,
        worker_prefetch_multiplier=CELERY_WORKER_PREFETCH_MULTIPLIER,
        task_default_queue=CELERY_TASK_DEFAULT_QUEUE,
        task_queues=CELERY_TASK_QUEUES,
        worker_max_tasks_per_child=int(
            os.environ.get("STRIX_CELERY_MAX_TASKS_PER_CHILD", CELERY_WORKER_MAX_TASKS_PER_CHILD)
        ),
        worker_max_memory_per_child=int(
            os.environ.get("STRIX_CELERY_MAX_MEMORY_PER_CHILD", CELERY_WORKER_MAX_MEMORY_PER_CHILD)
        ),
        task_time_limit=int(os.environ.get("STRIX_CELERY_TASK_TIME_LIMIT", CELERY_TASK_TIME_LIMIT)),
        task_soft_time_limit=int(
            os.environ.get("STRIX_CELERY_TASK_SOFT_TIME_LIMIT", CELERY_TASK_SOFT_TIME_LIMIT)
        ),
        broker_connection_retry=CELERY_BROKER_CONNECTION_RETRY,
        broker_connection_retry_on_startup=CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP,
        broker_heartbeat=CELERY_BROKER_HEARTBEAT,
        result_expires=86400,
        result_extended=True,
        task_serializer="json",
        result_serializer="json",
        accept_content=("json",),
        timezone="UTC",
        enable_utc=True,
    )
    app.conf.task_routes = {
        "strix.core.queue.run_assessment_task": {"queue": "strix_assessments"},
    }
    return app


celery_app = create_celery_app() if Celery is not None else None


# ---------------------------------------------------------------------------
# Job serialization for Celery
# ---------------------------------------------------------------------------


def _job_to_dict(job: Job) -> dict[str, Any]:
    """Serialize a Job for Celery task transport."""
    return {
        "id": job.id,
        "target": job.target,
        "profile": job.profile,
        "actor": job.actor,
        "policy": job.policy,
        "scope_snapshot": {
            "authorization_ref": job.scope_snapshot.authorization_ref,
            "policy_id": job.scope_snapshot.policy_id,
            "policy_version": job.scope_snapshot.policy_version,
            "tenant_id": job.scope_snapshot.tenant_id,
            "program": job.scope_snapshot.program,
            "authorized_by": job.scope_snapshot.authorized_by,
            "include": list(job.scope_snapshot.include),
            "exclude": list(job.scope_snapshot.exclude),
            "authorized_networks": list(job.scope_snapshot.authorized_networks),
            "allowed_ports": list(job.scope_snapshot.allowed_ports),
            "allow_broad_networks": job.scope_snapshot.allow_broad_networks,
        }
        if job.scope_snapshot
        else None,
        "idempotency_key": job.idempotency_key,
    }


def _dict_to_job(data: dict[str, Any]) -> Job:
    """Deserialize a Job from Celery task transport."""
    from strix.core.scope import Scope

    scope_snapshot = None
    if data.get("scope_snapshot"):
        ss = data["scope_snapshot"]
        scope_snapshot = Scope(
            authorization_ref=ss.get("authorization_ref", ""),
            policy_id=ss.get("policy_id", ""),
            policy_version=ss.get("policy_version", 0),
            tenant_id=ss.get("tenant_id", ""),
            program=ss.get("program", ""),
            authorized_by=ss.get("authorized_by", ""),
            include=tuple(ss.get("include", [])),
            # Address policy must survive transport: dropping authorized
            # networks makes every loopback/private target out of scope in the
            # worker even though the submitter was authorized.
            exclude=tuple(ss.get("exclude", [])),
            authorized_networks=tuple(ss.get("authorized_networks", [])),
            allowed_ports=tuple(ss.get("allowed_ports", [])),
            allow_broad_networks=bool(ss.get("allow_broad_networks", False)),
        )

    return Job(
        target=data["target"],
        profile=data["profile"],
        actor=data["actor"],
        policy=data["policy"],
        id=data["id"],
        idempotency_key=data.get("idempotency_key"),
        scope_snapshot=scope_snapshot,
    )


# ---------------------------------------------------------------------------
# Celery task definition
# ---------------------------------------------------------------------------

# Defined above: Celery discovers the task by importing this module.


def _register_task(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Bind the task to Celery when available, else keep it a plain function."""
    if celery_app is None:
        return fn
    return celery_app.task(
        bind=True,
        name="strix.core.queue.run_assessment_task",
        queue="strix_assessments",
        acks_late=True,
        reject_on_worker_lost=True,
        autoretry_for=(Exception,),
        retry_backoff=True,
        retry_backoff_max=600,
        retry_jitter=True,
        max_retries=3,
    )(fn)


@_register_task
def run_assessment_task(self, job_data: dict[str, Any]) -> dict[str, Any]:
    """Celery task to execute an assessment job.

    Runs in a Celery worker process. Rehydrates the job, executes it,
    persists results to the database, and returns the job summary.
    """
    import strix.core.jobs as jobs_module
    from strix.core import store

    job = _dict_to_job(job_data)

    # Track the worker identity
    worker_name = f"celery-{os.getpid()}-{self.request.id[:8]}"
    job.worker_id = worker_name

    log.info("Celery worker %s starting job %s", worker_name, job.id)

    try:
        # Claim the job in the database (idempotent - safe for retries)
        import asyncio

        async def _claim_and_run():
            # Ensure store is configured in this process
            _ensure_store_configured()

            claimed = await store.claim_job(job.id, tenant=job.actor, worker=worker_name)
            if not claimed:
                existing = await store.get_job(job.id, tenant=job.actor)
                if existing and existing["state"] in ("completed", "partial", "failed", "cancelled"):
                    log.info("Job %s already in terminal state %s, skipping", job.id, existing["state"])
                    return existing
                log.warning("Job %s was already claimed; not executing again", job.id)
                job.state = JobState.FAILED
                job.error = "job was already claimed by another execution"
                job.finished_at = time.time()
                return None

            job.attempts += 1
            if await store.is_cancel_requested(job.id, tenant=job.actor):
                job.state = JobState.CANCELLED
                job.error = "cancelled by request"
                job.finished_at = time.time()
                await store.save_job(job, tenant=job.actor)
                return job.to_dict()

            # The API process and this worker do not share memory. Poll the
            # durable cancellation flag so a cancel/revoke reaches a task that
            # is already executing, including its adapter subprocess kill switch.
            stop_watching = threading.Event()

            def watch_cancel() -> None:
                async def poll() -> None:
                    while not stop_watching.is_set():
                        try:
                            if await store.is_cancel_requested(job.id, tenant=job.actor):
                                job.cancel()
                                return
                        except Exception:
                            log.exception("cancellation poll failed for job %s", job.id)
                        await asyncio.sleep(1.0)

                asyncio.run(poll())

            watcher = threading.Thread(
                target=watch_cancel,
                name=f"cancel-watch-{job.id[:8]}",
                daemon=True,
            )
            watcher.start()
            try:
                jobs_module.execute(job)
            except Exception as exc:
                log.exception("Assessment %s crashed", job.id)
                job.state = JobState.FAILED
                job.error = f"internal error: {type(exc).__name__}"
                job.finished_at = time.time()
            finally:
                stop_watching.set()
                watcher.join(timeout=2.0)

            # Persist the completed job
            await store.save_job(job, tenant=job.actor)
            return job.to_dict()

        result = asyncio.run(_claim_and_run())
        if result is None:
            return {"status": "skipped", "job_id": job.id}
        return result

    except Exception:
        log.exception("Celery task failed for job %s", job.id)
        # The task will be retried per autoretry config
        raise


# ---------------------------------------------------------------------------
# Celery worker lifecycle hooks
# ---------------------------------------------------------------------------

# Module-level flag to ensure store is configured once per process
_store_configured = False


def _ensure_store_configured() -> None:
    """Configure the store once per worker process."""
    global _store_configured
    if _store_configured:
        return
    from strix.config import get_settings
    from strix.core import store

    settings = get_settings()
    store.configure(settings.db_path)
    _store_configured = True
    log.info("Celery worker process %d store configured", os.getpid())


def _worker_init(**kwargs):
    """Called when worker starts (in each process)."""
    _ensure_store_configured()
    log.info("Celery worker starting (pid=%d)", os.getpid())


if worker_init is not None:
    worker_init.connect(_worker_init)


# ---------------------------------------------------------------------------
# AssessmentWorker-compatible interface for Celery mode
# ---------------------------------------------------------------------------


class CeleryAssessmentQueue:
    """Celery-backed assessment queue compatible with AssessmentWorker interface.

    Used when STRIX_QUEUE_MODE=celery. Submits jobs to Celery instead of
    an in-memory queue, enabling horizontal scaling.
    """

    def __init__(self, *, concurrency: int | None = None, queue_max: int | None = None) -> None:
        self.concurrency = concurrency or 1
        self.queue_max = queue_max or 32
        self._started = False
        self._start_lock = threading.Lock()
        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._task_ids: dict[str, str] = {}
        self._lock = threading.Lock()
        self.name = f"celery-queue-{os.getpid()}-{id(self) & 0xFFFF:x}"

    async def start(self) -> None:
        """Idempotent start: no-op for Celery (workers are separate processes)."""
        with self._start_lock:
            if self._started:
                return
            self._started = True
            # In Celery mode, we don't run local threads.
            # The sweep of interrupted jobs is handled by the API startup.
            await store.fail_interrupted(created_before=time.time())
            log.info("Celery assessment queue started (workers run as separate processes)")

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Queue a prepared job via Celery."""
        await self.start()

        # Persist job to database first (queued state)
        job.state = JobState.QUEUED
        await store.save_job(job, tenant=job.actor)

        with self._lock:
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish

        # Submit to Celery
        job_data = _job_to_dict(job)
        result = celery_app.send_task(
            "strix.core.queue.run_assessment_task",
            args=[job_data],
            queue="strix_assessments",
        )
        with self._lock:
            self._task_ids[job.id] = result.id
        log.info("Submitted job %s to Celery queue", job.id)

    def cancel(self, job_id: str) -> bool:
        """Signal a job to stop. Celery tasks cannot be cancelled mid-execution;
        this revokes the task if still queued."""

        with self._lock:
            job = self._active.get(job_id)

        if job is None:
            return False

        # Signal cancellation which the job will check on next re-validation.
        job.cancel()
        with self._lock:
            task_id = self._task_ids.get(job_id)
        if task_id:
            try:
                # Revoke only prevents an unacked task from starting; a task
                # already running is stopped by the durable flag the worker polls.
                celery_app.control.revoke(task_id, terminate=False)
            except Exception:
                log.exception("Failed to revoke Celery task %s", task_id)
        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel every queued/running job bound to policy_id."""
        with self._lock:
            targets = [
                job for job in self._active.values() if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in targets:
            self.cancel(job.id)
        return len(targets)

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Shutdown the local queue (Celery workers are separate)."""
        with self._start_lock:
            if not self._started:
                return
            log.debug("Shutting down Celery assessment queue")
            self._started = False
            with self._lock:
                self._active.clear()
                self._on_finish.clear()
                self._task_ids.clear()


# ---------------------------------------------------------------------------
# Factory function to get the right queue implementation
# ---------------------------------------------------------------------------


def get_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> AssessmentWorker | CeleryAssessmentQueue | K8sAssessmentQueue:
    """Factory returning the appropriate queue implementation based on STRIX_QUEUE_MODE.

    - inprocess (default): returns the original AssessmentWorker
    - celery: returns CeleryAssessmentQueue
    - k8s-jobs: returns K8sAssessmentQueue
    """
    if QUEUE_MODE == QUEUE_MODE_K8S_JOBS:
        log.info("Using K8s Jobs-backed assessment queue")
        from strix.core.k8s_queue import get_k8s_assessment_queue

        return get_k8s_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE == "celery":
        if celery_app is None:
            raise RuntimeError(
                "STRIX_QUEUE_MODE=celery requires the optional celery extra: pip install 'strix[celery]'"
            )
        log.info("Using Celery-backed assessment queue")
        return CeleryAssessmentQueue(concurrency=concurrency, queue_max=queue_max)
    log.info("Using in-process assessment queue")
    return AssessmentWorker(concurrency=concurrency, queue_max=queue_max)


# Lazily initialized so importing this module never starts a worker.
_assessment_queue: AssessmentWorker | CeleryAssessmentQueue | K8sAssessmentQueue | None = None


def get_assessment_worker() -> AssessmentWorker | CeleryAssessmentQueue | K8sAssessmentQueue:
    """Get the global assessment queue instance (lazy init)."""
    global _assessment_queue
    if _assessment_queue is None:
        from strix.config import get_settings

        settings = get_settings()
        _assessment_queue = get_assessment_queue(
            concurrency=settings.workers,
            queue_max=settings.queue_max,
        )
    return _assessment_queue
