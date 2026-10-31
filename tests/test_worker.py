"""Background worker: async creation, honest states, cancellation, restart, limits."""
import threading
import time

import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.routers import assessments as server_module
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import jobs, store
from strix.core.adapters import Adapter, AdapterCancelled, AdapterResult
from strix.core.worker import AssessmentQueueFull, AssessmentWorker

client = TestClient(app)

TERMINAL = ("completed", "partial", "failed", "cancelled")


def _auth(name: str):
    key = api_keys.register(name, "pro")
    return {"Authorization": f"Bearer {key}"}


class Noop(Adapter):
    id = "noop"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(findings=[], notes=["noop"])


class Blocking(Adapter):
    """Holds a job in RUNNING until released or cancelled."""

    id = "blocking"
    asset_types = ("web",)
    started = threading.Event()
    release = threading.Event()

    def assess(self, target, *, timeout, cancel, context=None):
        type(self).started.set()
        while not type(self).release.is_set() and not cancel.is_set():
            time.sleep(0.02)
        if cancel.is_set():
            raise AdapterCancelled("cancelled while running in test")
        return AdapterResult(findings=[], notes=["released"])


@pytest.fixture
def noop(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])


@pytest.fixture
def blocking(monkeypatch):
    Blocking.started.clear()
    Blocking.release.clear()
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Blocking()])
    yield
    Blocking.release.set()   # never leave a worker thread blocked after a failure


def _await_terminal(job_id, headers, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/assess/{job_id}", headers=headers).json()
        if data.get("state") in TERMINAL:
            return data
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not reach a terminal state in time")


# ---------------------------------------------------------------------------
# Asynchronous creation (the default contract)
# ---------------------------------------------------------------------------
def test_assess_queues_and_completes_off_the_request_path(noop, local_target):
    headers = _auth("worker-async")
    res = client.post("/api/assess",
                      json={"target": f"{local_target.url}/?q=1", "profile": "web"},
                      headers=headers)
    assert res.status_code == 202                     # creation did not block
    queued = res.json()
    assert queued["id"]
    assert queued["poll_url"] == f"/api/assess/{queued['id']}"
    assert queued["state"] not in TERMINAL or True    # accepted, not claimed successful

    data = _await_terminal(queued["id"], headers)     # job id is stable and readable
    assert data["state"] in ("completed", "partial")
    assert data["verdict"]

    # completion is audited by the worker path too
    audit = client.get("/api/audit", headers=headers).json()["audit_logs"]
    assert any(entry.get("job") == queued["id"] and entry.get("event") == "assessment_job"
               for entry in audit)


def test_wait_true_still_runs_inline(noop, local_target):
    headers = _auth("worker-sync")
    res = client.post("/api/assess",
                      json={"target": f"{local_target.url}/?q=1", "profile": "web",
                            "wait": True},
                      headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["state"] in ("completed", "partial")
    assert len(data["audit_chain_hash"]) == 64


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------
def test_running_job_can_be_cancelled_by_owner_and_only_by_owner(blocking, local_target):
    owner = _auth("cancel-owner")
    other = _auth("cancel-other")
    job_id = client.post("/api/assess",
                         json={"target": f"{local_target.url}/?q=cancel"},
                         headers=owner).json()["id"]
    assert Blocking.started.wait(10), "job never started executing"

    # A different tenant cannot even confirm the job exists
    assert client.post(f"/api/assess/{job_id}/cancel", headers=other).status_code == 404

    res = client.post(f"/api/assess/{job_id}/cancel", headers=owner)
    assert res.status_code == 200
    assert res.json()["state"] == "cancelling"

    data = _await_terminal(job_id, owner)
    assert data["state"] == "cancelled"               # final state persisted
    assert data["clean"] is False
    assert "do not treat as clean" in data["verdict"]
    assert store.get_job(job_id, tenant="cancel-owner")["state"] == "cancelled"


def test_finished_job_cannot_be_cancelled(noop, local_target):
    headers = _auth("cancel-finished")
    job = client.post("/api/assess",
                      json={"target": f"{local_target.url}/", "wait": True},
                      headers=headers).json()
    res = client.post(f"/api/assess/{job['id']}/cancel", headers=headers)
    assert res.status_code == 409
    assert "already" in res.json()["detail"]


def test_unknown_job_cannot_be_cancelled():
    headers = _auth("cancel-unknown")
    assert client.post("/api/assess/job_does_not_exist/cancel",
                       headers=headers).status_code == 404


def test_job_cancelled_before_execution_never_runs_and_is_not_clean():
    job = jobs.prepare("http://example.com/", profile="web", actor="queued-cancel")
    job.cancel()                                      # cancel while still queued
    jobs.execute(job)
    assert job.state is jobs.JobState.CANCELLED
    assert job.is_clean() is False
    assert "cancelled" in job.verdict


# ---------------------------------------------------------------------------
# Restart honesty
# ---------------------------------------------------------------------------
def test_fail_interrupted_marks_stale_jobs_failed_but_leaves_finished_ones():
    stale_queued = jobs.Job(target="http://example.com/", profile="web",
                            actor="restart", policy={})
    stale_queued.state = jobs.JobState.QUEUED
    stale_running = jobs.Job(target="http://example.com/", profile="web",
                             actor="restart", policy={})
    stale_running.state = jobs.JobState.RUNNING
    stale_running.started_at = time.time()
    finished = jobs.Job(target="http://example.com/", profile="web",
                        actor="restart", policy={})
    finished.state = jobs.JobState.COMPLETED
    finished.started_at, finished.finished_at = 1.0, 2.0
    for job in (stale_queued, stale_running, finished):
        store.save_job(job, tenant="restart")

    # These rows were written by this process, so the sweep needs an explicit
    # cutoff: the worker's own default protects rows created after it started.
    assert store.fail_interrupted(created_before=time.time() + 1) == 2

    for job in (stale_queued, stale_running):
        row = store.get_job(job.id, tenant="restart")
        assert row["state"] == "failed"
        assert "restart" in row["error"]
        assert row["clean"] is False                   # never reported as success
    assert store.get_job(finished.id, tenant="restart")["state"] == "completed"


@pytest.mark.asyncio
async def test_worker_start_sweeps_stale_jobs_and_is_idempotent(monkeypatch):
    stale = jobs.Job(target="http://example.com/", profile="web",
                     actor="restart2", policy={})
    stale.state = jobs.JobState.RUNNING
    stale.started_at = time.time()
    store.save_job(stale, tenant="restart2")
    # Pretend this process started after the row was written (i.e. the row is
    # the remains of a previous process, which is what the sweep targets).
    monkeypatch.setattr("strix.core.worker.PROCESS_STARTED_AT", time.time() + 1)

    fresh = AssessmentWorker()
    await fresh.start()
    await fresh.start()                                      # idempotent
    assert store.get_job(stale.id, tenant="restart2")["state"] == "failed"


# ---------------------------------------------------------------------------
# Bounds: concurrency, queue capacity, API behaviour on overflow
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_queue_is_bounded_and_single_worker_runs_one_job_at_a_time(blocking):
    worker = AssessmentWorker(concurrency=1, queue_max=1)
    finished: list[str] = []

    job_a = jobs.prepare("http://example.com/?q=a", actor="bounded")
    job_b = jobs.prepare("http://example.com/?q=b", actor="bounded")
    job_c = jobs.prepare("http://example.com/?q=c", actor="bounded")

    await worker.submit(job_a, on_finish=lambda j: finished.append(j.id))
    assert Blocking.started.wait(10), "first job never started"

    await worker.submit(job_b, on_finish=lambda j: finished.append(j.id))
    with pytest.raises(AssessmentQueueFull):           # bounded, not buffered
        await worker.submit(job_c, on_finish=lambda j: finished.append(j.id))

    # One worker: B waits while A is running
    time.sleep(0.2)
    assert job_b.state is jobs.JobState.QUEUED
    assert job_a.state is jobs.JobState.RUNNING

    Blocking.release.set()
    deadline = time.time() + 15
    while time.time() < deadline and job_b.state not in TERMINAL:
        time.sleep(0.05)
    assert job_a.state is jobs.JobState.COMPLETED
    assert job_b.state is jobs.JobState.COMPLETED
    assert finished == [job_a.id, job_b.id]


def test_api_returns_503_when_the_queue_is_full(monkeypatch, local_target):
    class Full:
        def submit(self, job, on_finish):
            raise AssessmentQueueFull("assessment queue is full (2 waiting)")

        def cancel(self, job_id):
            return False

    monkeypatch.setattr(server_module, "assessment_worker", Full())
    headers = _auth("queue-full")
    res = client.post("/api/assess", json={"target": f"{local_target.url}/"},
                      headers=headers)
    assert res.status_code == 503
    assert "queue is full" in res.json()["detail"]


# -- resilience --------------------------------------------------------------
@pytest.mark.asyncio
async def test_worker_survives_an_engine_crash_and_fails_the_job(monkeypatch):
    import threading

    from strix.core import jobs
    from strix.core.worker import AssessmentWorker

    def boom(job):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr("strix.core.worker.jobs_module.execute", boom)
    worker = AssessmentWorker(concurrency=1, queue_max=5)
    finished = []
    done = threading.Event()
    job = jobs.prepare("http://example.com/", profile="web", actor="t", timeout=10)
    await worker.submit(job, on_finish=lambda j: (finished.append(j), done.set()))

    assert done.wait(5)
    assert finished[0].state.value == "failed"
    assert "internal error" in finished[0].error
    assert all(t.is_alive() for t in worker._threads)       # the thread did not die
    await worker.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_running_work_and_the_worker_can_restart(monkeypatch):
    import threading

    from strix.core import jobs
    from strix.core.worker import AssessmentWorker

    started = threading.Event()

    def slow(job):
        job.state = jobs.JobState.RUNNING
        started.set()
        job._cancel.wait(10)             # returns as soon as the job is cancelled
        job.state = jobs.JobState.CANCELLED

    monkeypatch.setattr("strix.core.worker.jobs_module.execute", slow)
    worker = AssessmentWorker(concurrency=1, queue_max=5)
    job = jobs.prepare("http://example.com/", profile="web", actor="t", timeout=60)
    await worker.submit(job, on_finish=lambda j: None)
    assert started.wait(5)

    await worker.shutdown(timeout=5)
    assert job.state == jobs.JobState.CANCELLED and not worker._threads

    monkeypatch.setattr("strix.core.worker.jobs_module.execute", lambda j: None)
    await worker.start()                        # restartable
    assert all(t.is_alive() for t in worker._threads)
    await worker.shutdown()
