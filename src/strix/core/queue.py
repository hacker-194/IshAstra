"""Assessment queue selection.

``STRIX_QUEUE_MODE`` chooses the implementation:

* ``inprocess`` (default) - threads in this process, no external dependency.
* ``k8s-jobs`` - one Kubernetes Job per assessment, for fleet deployments.

The Celery mode was removed: no shipped artefact installed the extra and no
worker command existed, so it could only ever raise at runtime.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from strix.core.worker import AssessmentWorker

if TYPE_CHECKING:
    from strix.core.k8s_queue import K8sAssessmentQueue

log = logging.getLogger(__name__)

QUEUE_MODE = os.environ.get("STRIX_QUEUE_MODE", "inprocess").strip().lower()
QUEUE_MODE_K8S_JOBS = "k8s-jobs"
VALID_MODES = ("inprocess", QUEUE_MODE_K8S_JOBS)


def get_assessment_queue(
    *, concurrency: int | None = None, queue_max: int | None = None
) -> AssessmentWorker | K8sAssessmentQueue:
    """Return the queue implementation named by STRIX_QUEUE_MODE."""
    if QUEUE_MODE == QUEUE_MODE_K8S_JOBS:
        from strix.core.k8s_queue import get_k8s_assessment_queue

        log.info("Using K8s Jobs-backed assessment queue")
        return get_k8s_assessment_queue(concurrency=concurrency, queue_max=queue_max)
    if QUEUE_MODE not in VALID_MODES:
        raise ValueError(f"STRIX_QUEUE_MODE must be one of {', '.join(VALID_MODES)} (got {QUEUE_MODE!r})")
    log.info("Using in-process assessment queue")
    return AssessmentWorker(concurrency=concurrency, queue_max=queue_max)


# Lazily initialized so importing this module never starts a worker.
_assessment_queue: AssessmentWorker | K8sAssessmentQueue | None = None


def get_assessment_worker() -> AssessmentWorker | K8sAssessmentQueue:
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
