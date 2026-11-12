"""Job lifecycle: durable state transitions, one execution per job, retries.

The properties under test:

* a terminal row cannot be resurrected by a late or stale write;
* exactly one execution claims a queued job (no duplicate scans);
* a repeated submission with the same Idempotency-Key returns the same job;
* a failed job can be retried, and the retry is re-authorized, not resumed;
* one worker process per database, enforced by an advisory lease.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import jobs, store
from strix.core.adapters import Adapter, AdapterError, AdapterResult
from strix.core.worker import (
    AssessmentWorker,
    WorkerLeaseError,
    acquire_worker_lease,
    release_worker_lease,
)

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _app_lifespan():
    """TestClient runs lifespan (which starts the worker) only in a context."""
    with TestClient(app):
        yield


def run(coro):
    """Drive the async store from synchronous tests (private bridge)."""
    return store._run_async(coro)


def _auth(name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_keys.register(name, 'pro')}"}


class Noop(Adapter):
    id = "noop"

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(notes=["noop"])


class Failing(Adapter):
    id = "failing"

    def assess(self, target, *, timeout, cancel, context=None):
        raise AdapterError("tool crashed")


@pytest.fixture
def noop(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])


# ---------------------------------------------------------------------------
# Durable state
# ---------------------------------------------------------------------------
def test_schema_is_at_the_lifecycle_migration():
    assert run(store.schema_version()) >= 6
    with sqlite3.connect(store.current_path()) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}
    assert {"attempts", "worker", "idempotency_key"} <= columns


def test_finished_job_cannot_be_resurrected_by_a_stale_write():
    job = jobs.Job(target="http://example.com/", profile="web", actor="sticky", policy={})
    job.state = jobs.JobState.RUNNING
    job.started_at = 10.0
    run(store.save_job(job, tenant="sticky"))
    job.state = jobs.JobState.COMPLETED
    job.finished_at = 20.0
    run(store.save_job(job, tenant="sticky"))

    # A late write from a hung worker claiming it is running again...
    stale = jobs.Job(target="http://example.com/", profile="web", actor="sticky",
                     policy={}, id=job.id)
    stale.state = jobs.JobState.RUNNING
    run(store.save_job(stale, tenant="sticky"))

    row = run(store.get_job(job.id, tenant="sticky"))
    assert row["state"] == "completed"
    assert row["verdict"] == "no findings (complete coverage)"


def test_first_started_at_is_preserved_across_resaves():
    job = jobs.Job(target="http://example.com/", profile="web", actor="clock", policy={})
    job.state = jobs.JobState.RUNNING
    job.started_at = 100.0
    run(store.save_job(job, tenant="clock"))
    job.finished_at = 160.0
    job.state = jobs.JobState.COMPLETED
    run(store.save_job(job, tenant="clock"))
    row = run(store.get_job(job.id, tenant="clock"))
    assert row["started_at"] == 100.0
    assert row["duration_ms"] == pytest.approx(60_000.0, rel=1e-6)


def test_only_one_claim_wins_for_a_queued_job():
    job = jobs.prepare("http://example.com/", actor="claim")
    run(store.save_job(job, tenant="claim"))
    assert run(store.claim_job(job.id, tenant="claim", worker="first")) is True
    assert run(store.claim_job(job.id, tenant="claim", worker="second")) is False
    row = run(store.get_job(job.id, tenant="claim"))
    assert row["state"] == "running"
    assert row["worker"] == "first"
    assert row["attempts"] == 1


def test_unpersisted_job_is_still_runnable():
    """Direct worker use without a stored row must not deadlock on the claim."""
    job = jobs.prepare("http://example.com/", actor="unpersisted")
    assert run(store.claim_job(job.id, tenant="unpersisted", worker="w")) is True


@pytest.mark.asyncio
async def test_worker_records_the_claim_it_made(noop, monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])
    worker = AssessmentWorker(concurrency=1, queue_max=2)
    job = jobs.prepare("http://example.com/", actor="claim-worker", timeout=10)
    await store.save_job(job, tenant="claim-worker")
    done = []
    finished = threading.Event()

    def persist(result):
        # The production worker persists on finish (the API's record_job).
        store._run_async(store.save_job(result, tenant="claim-worker"))
        done.append(result)
        finished.set()

    await worker.submit(job, on_finish=persist)
    assert finished.wait(10)
    await worker.shutdown()
    assert done[0].attempts == 1
    assert done[0].worker_id.startswith("strix-worker-")
    row = await store.get_job(job.id, tenant="claim-worker")
    assert row["attempts"] == 1
    assert row["state"] == "completed"


# ---------------------------------------------------------------------------
# Idempotent submission
# ---------------------------------------------------------------------------
def test_repeated_submission_with_the_same_key_returns_the_same_job(noop, local_target):
    headers = {**_auth("idemco"), "Idempotency-Key": "scan-2026-10-26-a"}
    body = {"target": f"{local_target.url}/?q=1", "profile": "web"}
    first = client.post("/api/assess", json=body, headers=headers)
    assert first.status_code == 202
    second = client.post("/api/assess", json=body, headers=headers)
    assert second.status_code in (200, 202)
    payload = second.json()
    assert payload["id"] == first.json()["id"]
    assert payload["deduplicated"] is True
    assert len(run(store.list_jobs(tenant="idemco", limit=10))) == 1


def test_different_keys_create_different_jobs(noop, local_target):
    headers = _auth("idemco2")
    body = {"target": f"{local_target.url}/?q=1"}
    ids = {
        client.post("/api/assess", json=body,
                    headers={**headers, "Idempotency-Key": key}).json()["id"]
        for key in ("a", "b")
    }
    assert len(ids) == 2


def test_malformed_idempotency_key_is_refused(noop, local_target):
    headers = {**_auth("idemco3"), "Idempotency-Key": "bad\nkey"}
    res = client.post("/api/assess", json={"target": f"{local_target.url}/"}, headers=headers)
    assert res.status_code == 400
    assert "Idempotency-Key" in res.json()["detail"]


def test_idempotency_keys_are_scoped_to_the_tenant(noop, local_target):
    body = {"target": f"{local_target.url}/?q=1"}
    first = client.post("/api/assess", json=body,
                        headers={**_auth("tenant-a"), "Idempotency-Key": "shared"})
    second = client.post("/api/assess", json=body,
                         headers={**_auth("tenant-b"), "Idempotency-Key": "shared"})
    assert first.json()["id"] != second.json()["id"]


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------
def test_a_failed_job_can_be_retried_as_a_new_authorized_job(monkeypatch, local_target):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Failing()])
    headers = _auth("retryco")
    job = client.post("/api/assess",
                      json={"target": f"{local_target.url}/", "wait": True},
                      headers=headers).json()
    assert job["state"] == "failed"

    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])
    res = client.post(f"/api/assess/{job['id']}/retry", headers=headers)
    assert res.status_code == 202
    retried = res.json()
    assert retried["id"] != job["id"]
    assert retried["retry_of"] == job["id"]
    assert retried["policy"]["retry_attempt"] == 1
    assert retried["policy"]["retry_of"] == job["id"]

    deadline = time.time() + 15
    while time.time() < deadline:
        state = client.get(f"/api/assess/{retried['id']}", headers=headers).json()["state"]
        if state in ("completed", "partial", "failed", "cancelled"):
            break
        time.sleep(0.05)
    assert state in ("completed", "partial")


def test_completed_job_cannot_be_retried(noop, local_target):
    headers = _auth("retry-finished")
    job = client.post("/api/assess",
                      json={"target": f"{local_target.url}/", "wait": True},
                      headers=headers).json()
    assert client.post(f"/api/assess/{job['id']}/retry", headers=headers).status_code == 409


def test_retry_is_refused_when_authorization_is_gone(monkeypatch, local_target):
    """A retry is re-authorized: withdrawn authorization must not be revived."""
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Failing()])
    headers = _auth("retry-revoked")
    job = client.post("/api/assess",
                      json={"target": f"{local_target.url}/", "wait": True},
                      headers=headers).json()
    assert job["state"] == "failed"
    from strix.core import scope as scope_module
    scope_module.configure(program="narrowed", authorized_by="pytest",
                           authorization_ref="narrowed",
                           include=["other.example"],
                           authorized_networks=["127.0.0.0/8"])
    res = client.post(f"/api/assess/{job['id']}/retry", headers=headers)
    assert res.status_code == 403
    assert "not in the authorized scope" in res.json()["detail"]


# ---------------------------------------------------------------------------
# One worker process per database
# ---------------------------------------------------------------------------
def test_worker_lease_is_exclusive_across_processes(tmp_path):
    path = str(tmp_path / "lease.lock")
    asyncio.run(acquire_worker_lease(path))
    try:
        script = (
            "import asyncio, sys\n"
            "from strix.core.worker import acquire_worker_lease, WorkerLeaseError\n"
            "try:\n"
            f"    asyncio.run(acquire_worker_lease({path!r}))\n"
            "except WorkerLeaseError:\n"
            "    raise SystemExit(7)\n"
            "raise SystemExit(0)\n"
        )
        completed = subprocess.run([sys.executable, "-c", script], timeout=60,
                                   capture_output=True, text=True,
                                   env={**os.environ, "PYTHONPATH": str(_src_root())})
        assert completed.returncode == 7, completed.stderr
    finally:
        asyncio.run(release_worker_lease(path))
    # Released: a second process may now take it.
    completed = subprocess.run([sys.executable, "-c", script], timeout=60,
                               capture_output=True, text=True,
                               env={**os.environ, "PYTHONPATH": str(_src_root())})
    assert completed.returncode == 0, completed.stderr


def test_worker_lease_is_exclusive_within_one_process(tmp_path):
    """One writer per database, even inside a single process."""
    path = str(tmp_path / "lease.lock")
    run(acquire_worker_lease(path))
    try:
        with pytest.raises(WorkerLeaseError):
            run(acquire_worker_lease(path))
    finally:
        run(release_worker_lease(path))
    run(acquire_worker_lease(path))     # released: the lock is really gone
    run(release_worker_lease(path))


@pytest.mark.asyncio
async def test_worker_start_propagates_a_lease_conflict(monkeypatch):
    def held_elsewhere(path: str | None = None) -> str:
        raise WorkerLeaseError("another Strix worker process already owns the database")

    monkeypatch.setattr("strix.core.worker.acquire_worker_lease", held_elsewhere)
    worker = AssessmentWorker(concurrency=1, queue_max=1)
    with pytest.raises(WorkerLeaseError):
        await worker.start()
    # A failed start must leave the worker retryable, not half-started.
    assert worker._started is False
    assert worker._threads == []


def _src_root() -> Path:
    return Path(__file__).resolve().parents[1] / "src"
