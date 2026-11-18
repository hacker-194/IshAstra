"""Queue selection: two modes, one factory, loud failure on anything else."""

from __future__ import annotations

import pytest

from strix.core import queue


def test_default_mode_is_the_in_process_worker(monkeypatch):
    monkeypatch.setattr(queue, "QUEUE_MODE", "inprocess")
    worker = queue.get_assessment_queue(concurrency=2, queue_max=8)
    assert type(worker).__name__ == "AssessmentWorker"
    assert worker.concurrency == 2


def test_unknown_mode_fails_instead_of_silently_degrading(monkeypatch):
    monkeypatch.setattr(queue, "QUEUE_MODE", "celery")
    with pytest.raises(ValueError, match="STRIX_QUEUE_MODE must be one of"):
        queue.get_assessment_queue()


def test_k8s_jobs_mode_returns_the_job_queue(monkeypatch):
    import sys
    import types

    stub = types.ModuleType("strix.core.k8s_queue")
    stub.get_k8s_assessment_queue = lambda **kwargs: "k8s-queue"
    monkeypatch.setitem(sys.modules, "strix.core.k8s_queue", stub)
    monkeypatch.setattr(queue, "QUEUE_MODE", "k8s-jobs")
    assert queue.get_assessment_queue() == "k8s-queue"
