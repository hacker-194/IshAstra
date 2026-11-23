"""Compare-and-set job transitions: one winner, no reopening terminal jobs."""

from __future__ import annotations

import pytest

from ishastra.core import store
from ishastra.core.jobs import Job


async def _job(tenant: str = "tenant-a") -> Job:
    job = Job(
        target="example.com",
        profile="web",
        actor=tenant,
        policy={"tenant_id": tenant},
    )
    await store.save_job(job, tenant=tenant)
    return job


async def test_only_one_racing_transition_wins() -> None:
    job = await _job()

    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-a",
            from_states=("queued",),
            to_state="running",
            worker="worker-1",
        )
        is True
    )
    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-a",
            from_states=("queued",),
            to_state="running",
            worker="worker-2",
        )
        is False
    )

    row = await store.get_job(job.id, tenant="tenant-a")
    assert row is not None
    assert row["state"] == "running"
    assert row["worker"] == "worker-1"


async def test_terminal_job_cannot_be_reopened_and_tenant_is_enforced() -> None:
    job = await _job()

    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-a",
            from_states=("queued", "running"),
            to_state="failed",
            error="scanner crashed",
        )
        is True
    )
    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-a",
            from_states=("queued", "running"),
            to_state="running",
        )
        is False
    )
    assert (
        await store.transition_job(
            job.id,
            tenant="tenant-b",
            from_states=("failed",),
            to_state="cancelled",
        )
        is False
    )


async def test_empty_or_unknown_from_states_are_rejected() -> None:
    with pytest.raises(ValueError, match="from_states"):
        await store.transition_job("job_x", tenant="t", from_states=(), to_state="running")
    with pytest.raises(ValueError, match="unknown job state"):
        await store.transition_job(
            "job_x", tenant="t", from_states=("bogus",), to_state="running"
        )
