"""Integration tests for ISHASTRA_RETENTION_DAYS pruning behavior.

Verifies that:
- Raw findings (findings table) are pruned when jobs are pruned
- finding_records (tenant-level remediation metadata) survive pruning
- audit_chain (sealed hash chain) is NEVER pruned
- audit_log (plain audit entries) are pruned
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from ishastra.audit import GENESIS_HASH, AuditChain
from ishastra.core import store
from ishastra.retention import prune


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    yield path
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    asyncio.run(store.reset_database())


class TestRetentionPruning:
    """Test that retention pruning preserves finding_records and audit_chain."""

    async def _setup_data(self, temp_db, days_old=10):
        """Set up jobs, findings, finding_records, audit_log, and audit_chain."""

        await store.get_database()

        tenant = "test-tenant"
        now = time.time()
        old_time = now - (days_old * 86400) + 1000

        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                     verdict, error, started_at, finished_at, coverage,
                                     created_at, attempts, worker, idempotency_key,
                                     cancel_requested)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-1",
                tenant,
                "https://example.com/old",
                "web",
                "test-actor",
                "{}",
                "completed",
                "clean",
                "",
                old_time - 3600,
                old_time,
                "{}",
                old_time - 7200,
                0,
                "worker-1",
                None,
                0,
            )

            await store._execute(
                conn,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-1",
                tenant,
                "fp-old-1",
                "https://example.com/old",
                "xss",
                "Old XSS finding",
                "high",
                "confirmed",
                "observed",
                "new",
                "ishastra-test",
                "1.0",
                "https://example.com/old?param=1",
                "Old evidence",
                "Old description",
                "Fix it",
                "CWE-79",
                "[]",
            )

            await store._execute(
                conn,
                """INSERT INTO finding_records
                       (tenant, fingerprint, owner, due_at, exception_until,
                        exception_reason, exception_approved_by, exception_state,
                        exception_requested_by, exception_requested_at,
                        exception_decided_by, exception_decided_at, exception_note,
                        resolution_state, resolved_at, resolved_job_id,
                        resolution_evidence, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tenant,
                "fp-old-1",
                "old-owner",
                old_time + 86400,
                None,
                "",
                "",
                "none",
                "",
                None,
                "",
                None,
                "",
                "open",
                None,
                "",
                "{}",
                old_time,
            )

            await store._execute(
                conn,
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                     verdict, error, started_at, finished_at, coverage,
                                     created_at, attempts, worker, idempotency_key,
                                     cancel_requested)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "new-job-1",
                tenant,
                "https://example.com/new",
                "web",
                "test-actor",
                "{}",
                "completed",
                "clean",
                "",
                now - 3600,
                now,
                "{}",
                now - 7200,
                0,
                "worker-1",
                None,
                0,
            )

            await store._execute(
                conn,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "new-job-1",
                tenant,
                "fp-new-1",
                "https://example.com/new",
                "sqli",
                "New SQLi finding",
                "critical",
                "confirmed",
                "observed",
                "new",
                "ishastra-test",
                "1.0",
                "https://example.com/new?id=1",
                "New evidence",
                "New description",
                "Fix it",
                "CWE-89",
                "[]",
            )

            await store._execute(
                conn,
                """INSERT INTO finding_records
                       (tenant, fingerprint, owner, due_at, exception_until,
                        exception_reason, exception_approved_by, exception_state,
                        exception_requested_by, exception_requested_at,
                        exception_decided_by, exception_decided_at, exception_note,
                        resolution_state, resolved_at, resolved_job_id,
                        resolution_evidence, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tenant,
                "fp-new-1",
                "new-owner",
                now + 86400,
                None,
                "",
                "",
                "none",
                "",
                None,
                "",
                None,
                "",
                "open",
                None,
                "",
                "{}",
                now,
            )

            await store._execute(
                conn,
                "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
                tenant,
                "old_event",
                old_time,
                '{"event": "old_event", "tenant": "test-tenant"}',
            )

            await store._execute(
                conn,
                "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
                tenant,
                "new_event",
                now,
                '{"event": "new_event", "tenant": "test-tenant"}',
            )

            body1 = {
                "event": "chain_old",
                "sequence": 1,
                "previous_hash": GENESIS_HASH,
                "timestamp": old_time,
            }
            import hashlib
            import json

            digest1 = hashlib.sha256(json.dumps(body1, sort_keys=True).encode()).hexdigest()
            await store._execute(
                conn,
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                1,
                GENESIS_HASH,
                digest1,
                json.dumps(body1, sort_keys=True),
            )

            body2 = {"event": "chain_new", "sequence": 2, "previous_hash": digest1, "timestamp": now}
            digest2 = hashlib.sha256(json.dumps(body2, sort_keys=True).encode()).hexdigest()
            await store._execute(
                conn,
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                2,
                digest1,
                digest2,
                json.dumps(body2, sort_keys=True),
            )

    async def _count_rows(self, table, where=None, params=None):
        """Count rows in a table."""
        db = await store.get_database()
        async with db.transaction() as conn:
            sql = f"SELECT COUNT(*) FROM {table}"
            if where:
                sql += f" WHERE {where}"
            row = await store._fetchone(conn, sql, *(params or []))
        return row[0] if row else 0

    async def _get_finding_records(self, tenant):
        """Get all finding_records for a tenant."""
        db = await store.get_database()
        async with db.transaction() as conn:
            rows = await store._fetchall(conn, "SELECT * FROM finding_records WHERE tenant = ?", tenant)
        return [dict(row) for row in rows]

    async def _get_audit_chain_count(self):
        """Get audit_chain count."""
        return await self._count_rows("audit_chain")

    @pytest.mark.asyncio
    async def test_retention_prunes_findings_but_keeps_finding_records(self, temp_db):
        """Raw findings are pruned with jobs, but finding_records persist."""
        await self._setup_data(temp_db, days_old=10)

        old_jobs = await self._count_rows("jobs", "id = ?", ["old-job-1"])
        new_jobs = await self._count_rows("jobs", "id = ?", ["new-job-1"])
        old_findings = await self._count_rows("findings", "fingerprint = ?", ["fp-old-1"])
        new_findings = await self._count_rows("findings", "fingerprint = ?", ["fp-new-1"])
        finding_records_before = await self._get_finding_records("test-tenant")

        assert old_jobs == 1, "Old job should exist before prune"
        assert new_jobs == 1, "New job should exist before prune"
        assert old_findings == 1, "Old finding should exist before prune"
        assert new_findings == 1, "New finding should exist before prune"
        assert len(finding_records_before) == 2, "Both finding_records should exist before prune"

        cutoff_days = 5
        result = prune(cutoff_days)

        assert result["jobs"] >= 1, f"Expected at least 1 job pruned, got {result['jobs']}"
        pruned_entries = result["audit_entries"]
        assert pruned_entries >= 1, f"Expected at least 1 audit entry pruned, got {pruned_entries}"

        old_jobs_after = await self._count_rows("jobs", "id = ?", ["old-job-1"])
        old_findings_after = await self._count_rows("findings", "fingerprint = ?", ["fp-old-1"])

        assert old_jobs_after == 0, "Old job should be pruned"
        assert old_findings_after == 0, "Old finding should be pruned (CASCADE)"

        new_jobs_after = await self._count_rows("jobs", "id = ?", ["new-job-1"])
        new_findings_after = await self._count_rows("findings", "fingerprint = ?", ["fp-new-1"])

        assert new_jobs_after == 1, "New job should survive"
        assert new_findings_after == 1, "New finding should survive"

        finding_records_after = await self._get_finding_records("test-tenant")
        record_count = len(finding_records_after)
        assert record_count == 2, f"finding_records should NOT be pruned: got {record_count}"

        old_record = next(r for r in finding_records_after if r["fingerprint"] == "fp-old-1")
        assert old_record["owner"] == "old-owner"
        assert old_record["resolution_state"] == "open"

        new_record = next(r for r in finding_records_after if r["fingerprint"] == "fp-new-1")
        assert new_record["owner"] == "new-owner"

    @pytest.mark.asyncio
    async def test_retention_keeps_audit_chain(self, temp_db):
        """audit_chain (sealed hash chain) is NEVER pruned by retention."""
        await self._setup_data(temp_db, days_old=10)

        chain_count_before = await self._get_audit_chain_count()
        assert chain_count_before == 2, "Chain should have 2 entries before prune"

        prune(5)

        chain_count_after = await self._get_audit_chain_count()
        assert chain_count_after == 2, f"audit_chain must NEVER be pruned: got {chain_count_after}"

    @pytest.mark.asyncio
    async def test_retention_prunes_audit_log_not_chain(self, temp_db):
        """audit_log (plain entries) are pruned, but audit_chain is not."""
        await self._setup_data(temp_db, days_old=10)

        old_audit_log = await self._count_rows("audit_log", "ts < ?", [time.time() - 5 * 86400])
        new_audit_log = await self._count_rows("audit_log", "ts >= ?", [time.time() - 5 * 86400])

        assert old_audit_log >= 1, "Should have old audit_log entries"
        assert new_audit_log >= 1, "Should have new audit_log entries"

        prune(5)

        old_audit_log_after = await self._count_rows("audit_log", "ts < ?", [time.time() - 5 * 86400])
        assert old_audit_log_after == 0, "Old audit_log should be pruned"

        new_audit_log_after = await self._count_rows("audit_log", "ts >= ?", [time.time() - 5 * 86400])
        assert new_audit_log_after >= 1, "New audit_log should survive"

        chain_count = await self._get_audit_chain_count()
        assert chain_count == 2, "audit_chain must survive"

    @pytest.mark.asyncio
    async def test_audit_chain_verification_after_prune(self, temp_db):
        """audit_chain should still verify correctly after retention pruning."""
        await self._setup_data(temp_db, days_old=10)

        chain = AuditChain(persistent=True, hmac_key="")
        ok, reason = await chain.verify_async()
        assert ok is True, f"Chain should be valid before prune: {reason}"

        prune(5)

        ok, reason = await chain.verify_async()
        assert ok is True, f"Chain should still verify after prune: {reason}"

        chain_count = await self._get_audit_chain_count()
        assert chain_count == 2, "Chain entries should not be deleted"

    @pytest.mark.asyncio
    async def test_finding_records_with_exceptions_survive(self, temp_db):
        """finding_records with exceptions/remediation data survive pruning."""
        await store.get_database()

        tenant = "test-tenant"
        now = time.time()
        old_time = now - 86400 * 10

        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                     verdict, error, started_at, finished_at, coverage,
                                     created_at, attempts, worker, idempotency_key,
                                     cancel_requested)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-exc",
                tenant,
                "https://example.com/old",
                "web",
                "test-actor",
                "{}",
                "completed",
                "clean",
                "",
                old_time - 3600,
                old_time,
                "{}",
                old_time - 7200,
                0,
                "worker-1",
                None,
                0,
            )

            await store._execute(
                conn,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-exc",
                tenant,
                "fp-exc-1",
                "https://example.com/old",
                "rce",
                "Old RCE",
                "critical",
                "confirmed",
                "observed",
                "new",
                "ishastra-test",
                "1.0",
                "https://example.com/old",
                "Old RCE evidence",
                "Old RCE desc",
                "Fix it",
                "CWE-94",
                "[]",
            )

            await store._execute(
                conn,
                """INSERT INTO finding_records
                       (tenant, fingerprint, owner, due_at, exception_until,
                        exception_reason, exception_approved_by, exception_state,
                        exception_requested_by, exception_requested_at,
                        exception_decided_by, exception_decided_at, exception_note,
                        resolution_state, resolved_at, resolved_job_id,
                        resolution_evidence, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tenant,
                "fp-exc-1",
                "sec-team",
                old_time + 86400 * 30,
                old_time + 86400 * 90,
                "Business critical system, cannot patch immediately",
                "ciso@company.com",
                "approved",
                "dev-lead@company.com",
                old_time,
                "ciso@company.com",
                old_time,
                "Approved by CISO for 90 days",
                "open",
                None,
                "",
                "{}",
                old_time,
            )

        prune(5)

        records = await self._get_finding_records(tenant)
        assert len(records) == 1, "finding_record with exception must survive"

        record = records[0]
        assert record["fingerprint"] == "fp-exc-1"
        assert record["owner"] == "sec-team"
        assert record["exception_state"] == "approved"
        assert record["exception_approved_by"] == "ciso@company.com"
        assert record["exception_reason"] == "Business critical system, cannot patch immediately"
        assert record["exception_note"] == "Approved by CISO for 90 days"
        assert record["exception_until"] is not None
        assert record["exception_until"] > old_time

    @pytest.mark.asyncio
    async def test_resolved_finding_records_survive(self, temp_db):
        """finding_records with resolution evidence survive pruning."""
        await store.get_database()

        tenant = "test-tenant"
        now = time.time()
        old_time = now - 86400 * 10

        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                     verdict, error, started_at, finished_at, coverage,
                                     created_at, attempts, worker, idempotency_key,
                                     cancel_requested)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-res",
                tenant,
                "https://example.com/old",
                "web",
                "test-actor",
                "{}",
                "completed",
                "clean",
                "",
                old_time - 3600,
                old_time,
                "{}",
                old_time - 7200,
                0,
                "worker-1",
                None,
                0,
            )

            await store._execute(
                conn,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                "old-job-res",
                tenant,
                "fp-res-1",
                "https://example.com/old",
                "xss",
                "Old XSS",
                "high",
                "confirmed",
                "observed",
                "new",
                "ishastra-test",
                "1.0",
                "https://example.com/old",
                "Old XSS evidence",
                "Old XSS desc",
                "Fix it",
                "CWE-79",
                "[]",
            )

            import json

            resolution_evidence = json.dumps(
                {
                    "verified_by": "pen-tester-1",
                    "verification_method": "manual",
                    "evidence_ref": "PR-1234",
                    "notes": "Fixed in commit abc123",
                }
            )
            await store._execute(
                conn,
                """INSERT INTO finding_records
                       (tenant, fingerprint, owner, due_at, exception_until,
                        exception_reason, exception_approved_by, exception_state,
                        exception_requested_by, exception_requested_at,
                        exception_decided_by, exception_decided_at, exception_note,
                        resolution_state, resolved_at, resolved_job_id,
                        resolution_evidence, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tenant,
                "fp-res-1",
                "dev-team",
                old_time + 86400,
                None,
                "",
                "",
                "none",
                "",
                None,
                "",
                None,
                "",
                "resolved",
                old_time,
                "old-job-res",
                resolution_evidence,
                old_time,
            )

        prune(5)

        records = await self._get_finding_records(tenant)
        assert len(records) == 1, "Resolved finding_record must survive"

        record = records[0]
        assert record["resolution_state"] == "resolved"
        assert record["resolved_at"] == old_time
        assert record["resolved_job_id"] == "old-job-res"

        evidence = json.loads(record["resolution_evidence"])
        assert evidence["verified_by"] == "pen-tester-1"
        assert evidence["verification_method"] == "manual"
        assert evidence["evidence_ref"] == "PR-1234"
