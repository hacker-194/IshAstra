"""Compare-and-set job transitions against real PostgreSQL."""

from __future__ import annotations

import os

import pytest

from ishastra.core import store
from ishastra.core.jobs import Job

DSN = os.environ.get("ISHASTRA_TEST_PG_DSN")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN, reason="ISHASTRA_TEST_PG_DSN not set"),
]


@pytest.fixture
async def db():
    previous = store.current_path()
    store.configure(DSN)
    database = await store.get_database()
    try:
        yield database
    finally:
        await store.close_database()
        store.configure(previous)


async def test_postgres_transition_is_compare_and_set(db) -> None:
    job = Job(
        target="example.com",
        profile="web",
        actor="tenant-cas",
        policy={"tenant_id": "tenant-cas"},
    )
    await store.save_job(job, tenant="tenant-cas")

    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-cas",
            from_states=("queued",),
            to_state="running",
            worker="pg-worker",
        )
        is True
    )
    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-cas",
            from_states=("queued",),
            to_state="running",
            worker="other-worker",
        )
        is False
    )
    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-cas",
            from_states=("queued", "running"),
            to_state="failed",
            error="crashed",
        )
        is True
    )

    row = await store.get_job(job.id, tenant="tenant-cas")
    assert row is not None
    assert row["state"] == "failed"
    assert row["worker"] == "pg-worker"
    assert row["error"] == "crashed"
