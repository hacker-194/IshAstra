"""Finding triage must persist, enforce transitions, and stay tenant-scoped."""

import asyncio

import pytest

from strix.core import jobs, store
from strix.core.findings import Finding, allowed_transitions


def _completed_job() -> jobs.Job:
    job = jobs.Job(
        target="https://example.com/", profile="web", actor="pytest", policy={}
    )
    job.state = jobs.JobState.COMPLETED
    job.findings = [
        Finding(
            asset="https://example.com/",
            category="xss",
            title="Reflected cross-site scripting",
            severity="high",
            confidence="high",
            detector="pytest",
            detector_version="1",
            evidence="reflection observed",
            location="https://example.com/search",
        )
    ]
    return job


def test_transitions_are_enforced_and_persisted(tmp_path):
    async def scenario() -> None:
        store.configure(tmp_path / "lifecycle.db")
        job = _completed_job()
        fingerprint = job.findings[0].fingerprint
        await store.save_job(job, tenant="tenant-a")

        triaged = await store.update_finding_status(
            job.id, fingerprint, tenant="tenant-a", to_status="triaged"
        )
        assert triaged is not None
        assert triaged["status"] == "triaged"
        assert "in_progress" in triaged["allowed_transitions"]

        in_progress = await store.update_finding_status(
            job.id, fingerprint, tenant="tenant-a", to_status="in_progress"
        )
        assert in_progress is not None
        assert in_progress["remediation_status"] == "in_progress"

        # new -> closed is not a legal transition and must not be applied.
        with pytest.raises(ValueError, match="Invalid transition"):
            await store.update_finding_status(
                job.id, fingerprint, tenant="tenant-a", to_status="new"
            )

        # Another tenant cannot mutate the finding, and gets no existence oracle.
        assert (
            await store.update_finding_status(
                job.id, fingerprint, tenant="tenant-b", to_status="triaged"
            )
            is None
        )

        loaded = await store.get_findings(job.id, tenant="tenant-a")
        assert loaded[0].status == "in_progress"
        assert loaded[0].remediation_status == "in_progress"
        await store.close_db_pool()

    asyncio.run(scenario())


def test_closed_is_terminal():
    assert allowed_transitions("closed") == ()
    assert "closed" in allowed_transitions("triaged")
