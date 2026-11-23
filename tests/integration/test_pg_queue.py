"""PostgreSQL queue: duplicate messages, retries, recovery, cancellation.

Requires ``ISHASTRA_TEST_PG_DSN``; skipped otherwise. Exercises the queue's
async primitives directly (``concurrency=0``) so no background execution is
needed to prove the state machine.
"""

from __future__ import annotations

import os

import pytest

from ishastra.core import store
from ishastra.core.jobs import Job
from ishastra.core.pg_queue import PostgresAssessmentQueue
from ishastra.core.worker import AssessmentQueueFull

DSN = os.environ.get("ISHASTRA_TEST_PG_DSN")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="ISHASTRA_TEST_PG_DSN not set"),
]


def _job(job_id: str, key: str | None = None, policy_id: str = "pol-1") -> Job:
    job = Job(
        target="example.com",
        profile="web",
        actor="tenant-a",
        policy={
            "tenant_id": "tenant-a",
            "policy_id": policy_id,
            "policy_version": 1,
            "authorization_ref": "AUTH-PG-QUEUE",
            "scope_program": "PostgreSQL queue test",
            "scope_authorized_by": "Test",
            "scope_include": ["example.com"],
            "scope_allowed_ports": [443],
            "timeout": 1,
        },
    )
    job.id = job_id
    job.idempotency_key = key
    return job


@pytest.fixture
async def queue():
    previous = store.current_path()
    store.configure(DSN)
    q = PostgresAssessmentQueue(
        concurrency=0, queue_max=2, visibility_seconds=60.0, max_attempts=2
    )
    await q.start()
    await q.clear()
    try:
        yield q
    finally:
        await q.clear()
        await q.shutdown()
        await store.close_database()
        store.configure(previous)


async def _row(queue: PostgresAssessmentQueue, job_id: str):
    db = await store.get_database()
    async with db.transaction() as conn:
        return await conn.fetchrow(
            "SELECT * FROM ishastra_queue WHERE job_id = $1", job_id
        )


async def _count(queue: PostgresAssessmentQueue) -> int:
    db = await store.get_database()
    async with db.transaction() as conn:
        return await conn.fetchval("SELECT count(*) FROM ishastra_queue")


async def test_duplicate_idempotency_key_enqueues_once(queue) -> None:
    await queue.submit(_job("job-a", key="same-key"), on_finish=lambda job: None)
    await queue.submit(_job("job-b", key="same-key"), on_finish=lambda job: None)

    assert await _count(queue) == 1
    assert "job-b" not in queue._active


async def test_concurrent_claims_get_distinct_jobs(queue) -> None:
    await queue.submit(_job("job-1", key="k1"), on_finish=lambda job: None)
    await queue.submit(_job("job-2", key="k2"), on_finish=lambda job: None)

    first = await queue._claim_next()
    second = await queue._claim_next()
    third = await queue._claim_next()

    assert {first.id, second.id} == {"job-1", "job-2"}
    assert third is None
    assert (await _row(queue, "job-1"))["retries"] == 1


async def test_retry_then_retries_exhausted(queue) -> None:
    await queue.submit(_job("job-retry", key="retry"), on_finish=lambda job: None)

    claimed = await queue._claim_next()
    assert claimed is not None
    await queue._mark_failed("job-retry", "boom")
    row = await _row(queue, "job-retry")
    assert row["state"] == "queued"
    assert row["retries"] == 1

    claimed = await queue._claim_next()
    assert claimed is not None
    await queue._mark_failed("job-retry", "boom")
    row = await _row(queue, "job-retry")
    assert row["state"] == "failed"
    assert row["error"] == "retries_exhausted"
    assert await queue._claim_next() is None


async def test_expired_claim_is_recovered(queue) -> None:
    queue.visibility_seconds = 0.0
    await queue.submit(_job("job-orphan", key="orphan"), on_finish=lambda job: None)
    assert await queue._claim_next() is not None

    reclaimed = await queue._claim_next()
    assert reclaimed is not None
    assert reclaimed.id == "job-orphan"
    assert (await _row(queue, "job-orphan"))["retries"] == 2

    await queue._claim_next()
    row = await _row(queue, "job-orphan")
    assert row["state"] == "failed"
    assert row["error"] == "retries_exhausted"


async def test_queue_full_refuses_new_work(queue) -> None:
    queue.queue_max = 1
    await queue.submit(_job("job-full-1", key="f1"), on_finish=lambda job: None)
    with pytest.raises(AssessmentQueueFull):
        await queue.submit(_job("job-full-2", key="f2"), on_finish=lambda job: None)

    assert await _count(queue) == 1


async def test_cancel_marks_queued_job_cancelled(queue) -> None:
    await queue.submit(_job("job-cancel", key="c"), on_finish=lambda job: None)
    assert await queue.cancel_async("job-cancel") is True

    row = await _row(queue, "job-cancel")
    assert row["state"] == "cancelled"
    assert await queue._claim_next() is None


async def test_cancel_for_policy_cancels_its_jobs(queue) -> None:
    await queue.submit(_job("job-p1", key="p1"), on_finish=lambda job: None)
    await queue.submit(_job("job-p2", key="p2"), on_finish=lambda job: None)

    cancelled = await queue.cancel_for_policy_async("pol-1")
    assert cancelled == 2
    assert (await _row(queue, "job-p1"))["state"] == "cancelled"
    assert (await _row(queue, "job-p2"))["state"] == "cancelled"


async def test_attempt_history_records_each_claim(queue) -> None:
    await queue.submit(_job("job-attempts", key="attempts"), on_finish=lambda job: None)
    await queue._claim_next()

    db = await store.get_database()
    async with db.transaction() as conn:
        first = await conn.fetchrow(
            "SELECT * FROM job_attempts WHERE job_id = $1 AND attempt = 1",
            "job-attempts",
        )
    assert first is not None
    assert first["state"] == "running"

    await queue._mark_failed("job-attempts", "boom")
    claimed = await queue._claim_next()
    assert claimed is not None
    async with db.transaction() as conn:
        attempts = await conn.fetch(
            "SELECT attempt, state FROM job_attempts WHERE job_id = $1 ORDER BY attempt",
            "job-attempts",
        )
    assert [(row["attempt"], row["state"]) for row in attempts] == [
        (1, "retrying"),
        (2, "running"),
    ]


async def test_stale_worker_cannot_finish_a_recovered_job(queue) -> None:
    queue.visibility_seconds = 0.0
    await queue.submit(_job("job-stale", key="stale"), on_finish=lambda job: None)
    stale = await queue._claim_next()
    assert stale is not None

    replacement = PostgresAssessmentQueue(
        concurrency=0, queue_max=2, visibility_seconds=0.0, max_attempts=2
    )
    await replacement.start()
    reclaimed = await replacement._claim_next()
    assert reclaimed is not None
    assert reclaimed.id == "job-stale"

    await queue._finish(stale)
    assert (await _row(queue, "job-stale"))["state"] == "running"
    db = await store.get_database()
    async with db.transaction() as conn:
        states = await conn.fetch(
            "SELECT state FROM job_attempts WHERE job_id = $1 ORDER BY attempt",
            "job-stale",
        )
    assert [row["state"] for row in states] == ["orphaned", "running"]


async def test_queued_work_survives_a_new_queue_instance(queue) -> None:
    await queue.submit(_job("job-restart", key="restart"), on_finish=lambda job: None)

    restarted = PostgresAssessmentQueue(
        concurrency=0, queue_max=2, visibility_seconds=60.0, max_attempts=2
    )
    await restarted.start()
    claimed = await restarted._claim_next()
    assert claimed is not None
    assert claimed.id == "job-restart"
