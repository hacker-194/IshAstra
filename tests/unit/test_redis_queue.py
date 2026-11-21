"""Durable queue: queued work survives a restart and runs exactly once.

Needs a live Redis (the mode's whole point); skipped when there is none.
"""

from __future__ import annotations

import time
import uuid

import pytest
import redis as redis_lib

from ishastra.core import jobs as jobs_module
from ishastra.core import store
from ishastra.core.redis_queue import RedisStreamsAssessmentQueue
from ishastra.core.worker import AssessmentQueueFull

pytestmark = pytest.mark.asyncio


def _redis_or_skip() -> redis_lib.Redis:
    client = redis_lib.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
    try:
        client.ping()
    except redis_lib.RedisError:
        pytest.skip("no Redis server available for the durable queue test")
    return client


def _wait_for(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


async def test_queued_job_survives_a_restart_and_runs_once(store_with_scope, monkeypatch):
    client = _redis_or_skip()
    stream = f"ishastra:test:{uuid.uuid4().hex}"
    ran: list[str] = []
    monkeypatch.setattr(jobs_module, "execute", lambda job: ran.append(job.id))

    prepared = jobs_module.prepare("https://example.com", profile="web", actor="tenant-a")
    await store.save_job(prepared, tenant="tenant-a")

    assert client.xlen(stream) == 0

    queue = RedisStreamsAssessmentQueue(concurrency=1, redis_client=client, stream=stream, group="g")
    await queue.start()
    try:
        assert _wait_for(lambda: ran == [prepared.id]), "queued job was not replayed"
        assert _wait_for(lambda: client.xlen(stream) == 0), "acknowledged entry was not cleared"

        time.sleep(0.5)
        assert ran == [prepared.id]
    finally:
        await queue.shutdown(timeout=5.0)


async def test_submit_refuses_to_exceed_queue_max(store_with_scope):
    client = _redis_or_skip()
    stream = f"ishastra:test:{uuid.uuid4().hex}"

    queue = RedisStreamsAssessmentQueue(
        concurrency=0, queue_max=1, redis_client=client, stream=stream, group="g"
    )
    client.xadd(stream, {"job_id": "already-queued", "tenant": "tenant-b"})
    prepared = jobs_module.prepare("https://example.com", profile="web", actor="tenant-b")

    with pytest.raises(AssessmentQueueFull):
        await queue.submit(prepared, on_finish=lambda job: None)
    await queue.shutdown(timeout=1.0)
