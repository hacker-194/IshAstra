"""Remediation SLAs: every tracked finding gets a deadline, overdue ones surface.

The point of the SLA is that a finding cannot be filed and forgotten: assigning
an owner materialises a deadline derived from severity, and a deadline that
passes appears in the overdue report unless the finding was resolved or holds a
valid, approved risk exception.
"""

from __future__ import annotations

import time

import pytest

from ishastra.core import store
from ishastra.core.findings import SLA_DAYS, Finding, sla_due_at, sla_status
from ishastra.core.jobs import Job

TENANT = "sla-tenant"


def _finding(severity: str, location: str = "/login") -> Finding:
    return Finding(
        asset="https://app.example.com",
        category="sqli",
        title="SQL injection",
        severity=severity,
        confidence="high",
        detector="test",
        detector_version="1",
        evidence="payload returned rows",
        location=location,
    )


async def _seed(severity: str = "critical") -> str:
    finding = _finding(severity)
    await store.save_job(
        Job(
            id="job-sla",
            target="https://app.example.com",
            profile="standard",
            actor="sla-test",
            policy={},
            findings=[finding],
        ),
        tenant=TENANT,
    )
    return finding.fingerprint


def test_deadline_follows_severity():
    first_seen = 1_000_000.0
    assert sla_due_at("critical", first_seen) == first_seen + SLA_DAYS["critical"] * 86400
    assert sla_due_at("high", first_seen) == first_seen + SLA_DAYS["high"] * 86400

    assert sla_due_at("weird", first_seen) == first_seen + SLA_DAYS["medium"] * 86400
    assert sla_due_at("critical", first_seen, days=1) == first_seen + 86400


def test_status_boundaries():
    now = 2_000_000.0
    assert sla_status(None, now) == "none"
    assert sla_status(now, now) == "overdue"
    assert sla_status(now - 60, now) == "overdue"
    assert sla_status(now + 86400, now) == "due_soon"
    assert sla_status(now + 30 * 86400, now) == "on_track"

    assert sla_status(now - 86400, now, resolved=True) == "resolved"


@pytest.mark.asyncio
async def test_expired_deadline_is_reported(store_with_scope):
    fingerprint = await _seed("critical")
    now = time.time()
    await store.set_finding_record_remediation(
        tenant=TENANT, fingerprint=fingerprint, owner="ana", due_at=now - 3600
    )

    items = await store.overdue_findings(tenant=TENANT, now=now)

    assert len(items) == 1
    item = items[0]
    assert item["fingerprint"] == fingerprint
    assert item["severity"] == "critical"
    assert item["owner"] == "ana"
    assert item["title"] == "SQL injection"
    assert item["overdue_seconds"] == pytest.approx(3600, abs=5)


@pytest.mark.asyncio
async def test_future_deadline_is_not_reported(store_with_scope):
    fingerprint = await _seed("low")
    now = time.time()
    await store.set_finding_record_remediation(tenant=TENANT, fingerprint=fingerprint, due_at=now + 86400)

    assert await store.overdue_findings(tenant=TENANT, now=now) == []


@pytest.mark.asyncio
async def test_resolved_finding_leaves_the_overdue_list(store_with_scope):
    fingerprint = await _seed("high")
    now = time.time()
    await store.set_finding_record_remediation(tenant=TENANT, fingerprint=fingerprint, due_at=now - 60)

    db = await store.get_database()
    async with db.transaction() as conn:
        await store._execute(
            conn,
            "UPDATE finding_records SET resolution_state = 'resolved' WHERE tenant = ? AND fingerprint = ?",
            TENANT,
            fingerprint,
        )

    assert await store.overdue_findings(tenant=TENANT, now=now) == []


@pytest.mark.asyncio
async def test_only_a_valid_approved_exception_suppresses_overdue(store_with_scope):
    fingerprint = await _seed("medium")
    now = time.time()
    await store.set_finding_record_remediation(tenant=TENANT, fingerprint=fingerprint, due_at=now - 60)

    db = await store.get_database()

    async def set_exception(state: str, until: float) -> None:
        async with db.transaction() as conn:
            await store._execute(
                conn,
                "UPDATE finding_records SET exception_state = ?, exception_until = ? "
                "WHERE tenant = ? AND fingerprint = ?",
                state,
                until,
                TENANT,
                fingerprint,
            )

    await set_exception("approved", now + 86400)
    assert await store.overdue_findings(tenant=TENANT, now=now) == []

    await set_exception("approved", now - 1)
    assert len(await store.overdue_findings(tenant=TENANT, now=now)) == 1

    await set_exception("pending", now + 86400)
    assert len(await store.overdue_findings(tenant=TENANT, now=now)) == 1
