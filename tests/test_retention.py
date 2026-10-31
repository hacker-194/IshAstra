"""Retention: opt-in pruning of old finished jobs/findings and audit entries.

The sealed audit chain is never pruned (removing old links would break
verification from genesis), queued/running jobs are never pruned, and days=0
(the default) deletes nothing.
"""
import time

from strix.audit import AuditChain
from strix.core import jobs, store
from strix.core.findings import Finding
from strix.retention import RetentionWorker, prune

DAY = 86400.0


def _finished_job(target: str, *, finished_at: float,
                  state: jobs.JobState = jobs.JobState.COMPLETED) -> jobs.Job:
    job = jobs.Job(target=target, profile="web", actor="acme",
                   policy={"authorization_ref": "ENG-1", "profile": "web"})
    job.state = state
    if state in (jobs.JobState.QUEUED, jobs.JobState.RUNNING):
        job.started_at = finished_at - 2
    else:
        job.finished_at = finished_at
    job.findings = [Finding(asset=target, category="xss", title="Reflected XSS",
                            severity="high", confidence="high", detector="strix-http",
                            detector_version="3.1.0", evidence="marker reflected",
                            location="/?q", remediation="Encode output.", cwe="CWE-79")]
    job.runs = [jobs.AdapterRun("strix-http", jobs.RunState.OK, "completed",
                                findings=1, elapsed_ms=12.5)]
    return job


def test_prune_deletes_old_finished_jobs_and_cascades_findings():
    now = time.time()
    old = _finished_job("http://old.example.com/", finished_at=now - 100 * DAY)
    recent = _finished_job("http://recent.example.com/", finished_at=now - DAY)
    store.save_job(old, tenant="acme")
    store.save_job(recent, tenant="acme")

    removed = prune(days=30, now=now)

    assert removed == {"jobs": 1, "audit_entries": 0}
    assert store.get_job(old.id, tenant="acme") is None
    assert store.get_findings(old.id, tenant="acme") == []   # cascaded
    assert store.get_job(recent.id, tenant="acme") is not None


def test_prune_never_touches_jobs_that_are_still_live():
    now = time.time()
    queued = _finished_job("http://live.example.com/", finished_at=now - 100 * DAY,
                           state=jobs.JobState.QUEUED)
    running = _finished_job("http://busy.example.com/", finished_at=now - 100 * DAY,
                            state=jobs.JobState.RUNNING)
    store.save_job(queued, tenant="acme")
    store.save_job(running, tenant="acme")

    assert prune(days=30, now=now) == {"jobs": 0, "audit_entries": 0}
    assert store.get_job(queued.id, tenant="acme") is not None
    assert store.get_job(running.id, tenant="acme") is not None


def test_prune_removes_old_audit_entries_but_keeps_the_chain_intact():
    now = time.time()
    store.append_audit({"tenant": "acme", "event": "old_event", "timestamp": now - 100 * DAY})
    store.append_audit({"tenant": "acme", "event": "new_event", "timestamp": now})
    chain = AuditChain(persistent=True, hmac_key="k" * 32)
    chain.append({"event": "api_key_rotated", "tenant": "acme"})

    removed = prune(days=30, now=now)

    assert removed == {"jobs": 0, "audit_entries": 1}
    assert [entry["event"] for entry in store.recent_audit(10)] == ["new_event"]
    assert store.chain_count() == 1                       # chain rows are never pruned
    assert chain.verify() == (True, None)


def test_zero_days_disables_pruning_entirely():
    now = time.time()
    old = _finished_job("http://old.example.com/", finished_at=now - 3650 * DAY)
    store.save_job(old, tenant="acme")
    store.append_audit({"tenant": "acme", "event": "old", "timestamp": now - 3650 * DAY})

    assert prune(days=0, now=now) == {"jobs": 0, "audit_entries": 0}
    assert store.get_job(old.id, tenant="acme") is not None
    assert len(store.recent_audit(10)) == 1


def test_worker_sweeps_at_startup_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr("strix.retention.SWEEP_INTERVAL_SECONDS", 0.05)
    old = _finished_job("http://old.example.com/", finished_at=time.time() - 100 * DAY)
    store.save_job(old, tenant="acme")

    worker = RetentionWorker(days=30)
    worker.start()
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if store.get_job(old.id, tenant="acme") is None:
                break
            time.sleep(0.05)
        assert store.get_job(old.id, tenant="acme") is None, "first sweep never ran"
    finally:
        worker.shutdown()


def test_worker_is_a_noop_when_retention_is_disabled():
    worker = RetentionWorker(days=0)
    worker.start()          # must not spawn a thread or touch the database
    worker.shutdown()
    assert worker._thread is None
