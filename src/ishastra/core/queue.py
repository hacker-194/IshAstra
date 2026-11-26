"""Assessment queue selection.

``ISHASTRA_QUEUE_MODE`` chooses the implementation:

* ``inprocess`` (default for dev) - threads in this process, no external dependency.
* ``redis-streams`` - durable stream entry per job; queued work survives a
  restart and several worker processes can share the stream.
* ``k8s-jobs`` - one Kubernetes Job per assessment, for fleet deployments.
* ``sqlite`` - durable SQLite-backed queue; queued work survives a restart
  and several worker processes can share the queue through database locking.
* ``postgres`` - durable PostgreSQL queue using ``FOR UPDATE SKIP LOCKED``;
  queued work survives a restart and several processes claim distinct jobs.
  **Default for production (ISHASTRA_ENV=production).**

The Celery mode was removed: no shipped artefact installed the extra and no
worker command existed, so it could only ever raise at runtime.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ishastra.core.worker import AssessmentWorker

if TYPE_CHECKING:
    from ishastra.core.k8s_queue import K8sAssessmentQueue
    from ishastra.core.pg_queue import PostgresAssessmentQueue
    from ishastra.core.redis_queue import RedisStreamsAssessmentQueue
    from ishastra.core.sqlite_queue import SQLiteAssessmentQueue

log = logging.getLogger(__name__)

# Default queue mode: postgres for production, inprocess for dev
_env = os.environ.get("ISHASTRA_ENV", "development").strip().lower()
_default_mode = "postgres" if _env == "production" else "inprocess"
QUEUE_MODE = os.environ.get("ISHASTRA_QUEUE_MODE", _default_mode).strip().lower()
QUEUE_MODE_K8S_JOBS = "k8s-jobs"
QUEUE_MODE_REDIS_STREAMS = "redis-streams"
QUEUE_MODE_SQLITE = "sqlite"
QUEUE_MODE_POSTGRES = "postgres"
VALID_MODES = (
    "inprocess",
    QUEUE_MODE_REDIS_STREAMS,
    QUEUE_MODE_K8S_JOBS,
    QUEUE_MODE_SQLITE,
    QUEUE_MODE_POSTGRES,
)


def get_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> (
    AssessmentWorker
    | K8sAssessmentQueue
    | RedisStreamsAssessmentQueue
    | SQLiteAssessmentQueue
    | PostgresAssessmentQueue
):
    """Return the queue implementation named by ISHASTRA_QUEUE_MODE."""
    if QUEUE_MODE == QUEUE_MODE_REDIS_STREAMS:
        from ishastra.core.redis_queue import get_redis_streams_assessment_queue

        log.info("Using durable Redis Streams assessment queue")
        return get_redis_streams_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE == QUEUE_MODE_K8S_JOBS:
        from ishastra.core.k8s_queue import get_k8s_assessment_queue

        log.info("Using K8s Jobs-backed assessment queue")
        return get_k8s_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE == QUEUE_MODE_SQLITE:
        from ishastra.core.sqlite_queue import get_sqlite_assessment_queue

        log.info("Using durable SQLite-backed assessment queue")
        return get_sqlite_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE == QUEUE_MODE_POSTGRES:
        from ishastra.core.pg_queue import get_postgres_assessment_queue

        log.info("Using durable PostgreSQL assessment queue")
        return get_postgres_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE not in VALID_MODES:
        raise ValueError(f"ISHASTRA_QUEUE_MODE must be one of {', '.join(VALID_MODES)} (got {QUEUE_MODE!r})")
    log.info("Using in-process assessment queue")
    return AssessmentWorker(concurrency=concurrency, queue_max=queue_max)


_assessment_queue: (
    AssessmentWorker
    | K8sAssessmentQueue
    | RedisStreamsAssessmentQueue
    | SQLiteAssessmentQueue
    | PostgresAssessmentQueue
    | None
) = None


def get_assessment_worker() -> (
    AssessmentWorker
    | K8sAssessmentQueue
    | RedisStreamsAssessmentQueue
    | SQLiteAssessmentQueue
    | PostgresAssessmentQueue
):
    """Get the global assessment queue instance (lazy init)."""
    global _assessment_queue
    if _assessment_queue is None:
        from ishastra.config import get_settings

        settings = get_settings()
        _assessment_queue = get_assessment_queue(
            concurrency=settings.workers,
            queue_max=settings.queue_max,
        )
    return _assessment_queue
