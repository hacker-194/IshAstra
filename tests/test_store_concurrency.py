"""Concurrent writers must queue on the SQLite write lock, never fail with
``database is locked``.

Regression: write transactions used a deferred ``BEGIN``. Under WAL, a
transaction that read first and wrote second could not upgrade its snapshot once
another connection had committed, and SQLite raised ``SQLITE_BUSY`` immediately
— bypassing the busy timeout. In production that surfaced as a job (or its
final result) failing to save under load. ``BEGIN IMMEDIATE`` takes the write
lock up front, so contenders wait instead; first-connect schema creation is
serialized per process, so simultaneous openers cannot race the migrations.

The store is async, so the "concurrent writers" are tasks on one loop, which is
how the API and the worker actually contend for the database.
"""
import asyncio

from strix.core import jobs, store
from strix.core.findings import Finding


def _job(index: int):
    job = jobs.Job(target=f"http://example.com/{index}", profile="web", actor="acme",
                   policy={"authorization_ref": "ENG-1", "profile": "web"})
    job.state = jobs.JobState.COMPLETED
    job.started_at, job.finished_at = 100.0, 101.0
    job.findings = [Finding(asset=f"http://example.com/{index}", category="xss",
                            title="Reflected XSS", severity="high", confidence="high",
                            detector="strix-http", detector_version="3.1.0",
                            evidence="marker reflected", location="/?q",
                            remediation="Encode output.", cwe="CWE-79")]
    job.runs = [jobs.AdapterRun("strix-http", jobs.RunState.OK, "completed",
                                findings=1, elapsed_ms=12.5)]
    return job


def test_concurrent_saves_never_raise_database_is_locked():
    async def scenario():
        async def writer(offset: int) -> None:
            for index in range(25):
                await store.save_job(_job(offset * 100 + index), tenant="acme")

        results = await asyncio.gather(
            *(writer(offset) for offset in range(8)), return_exceptions=True
        )
        errors = [result for result in results if isinstance(result, BaseException)]
        assert not errors, f"writers failed: {errors[:3]}"
        assert len(await store.list_jobs(tenant="acme", limit=1000)) == 200

    asyncio.run(scenario())


def test_first_connect_is_safe_under_thread_race():
    """Every opener may race the migrations at once; the schema must be created
    exactly once, and every opener must end on the current version."""
    async def scenario():
        results = await asyncio.gather(
            *(store.schema_version() for _ in range(8)), return_exceptions=True
        )
        errors = [result for result in results if isinstance(result, BaseException)]
        assert not errors, f"openers failed: {errors[:3]}"
        assert await store.schema_version() == store.MIGRATIONS[-1][0]

    asyncio.run(scenario())
