"""Unit tests for Ishastra Store (database operations)."""

import asyncio
import tempfile
import time
from pathlib import Path

import pytest
import pytest_asyncio

from ishastra.core.findings import Finding
from ishastra.core.jobs import Job, JobState
from ishastra.core.store import (
    MIGRATIONS,
    MIGRATIONS_PG,
    JobConflict,
    _adapt_placeholders,
    _run_async,
    append_audit,
    chain_count,
    chain_insert,
    chain_rows,
    chain_tip,
    claim_job,
    close_database,
    configure,
    count_cross_job_findings,
    count_findings,
    count_jobs,
    decide_finding_exception,
    delete_monitor_baseline,
    delete_webhook_sink,
    fail_interrupted,
    find_job_id_by_idempotency,
    finding_trends,
    findings_by_severity,
    get_asset,
    get_cross_job_finding,
    get_database,
    get_finding_remediation,
    get_findings,
    get_job,
    jobs_by_state,
    latest_finished_job,
    list_assets,
    list_cross_job_findings,
    list_finding_events,
    list_jobs,
    load_api_keys,
    load_monitor_baseline,
    load_monitor_config,
    load_policies,
    load_webhook_sinks,
    mark_running,
    prune_audit_log,
    prune_finished_jobs,
    recent_audit,
    request_finding_exception,
    save_api_key,
    save_job,
    save_monitor_baseline,
    save_monitor_config,
    save_policy,
    save_webhook_sink,
    set_finding_record_remediation,
    set_finding_remediation,
    set_finding_resolution,
    update_asset_metadata,
    update_finding_status,
    vacuum,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    configure(path)
    yield path
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    asyncio.run(close_database())


class TestMigrations:
    """Test migration definitions."""

    def test_sqlite_migrations_exist(self):
        """SQLite migrations are defined."""
        assert MIGRATIONS[-1][0] == 30
        for target, script in MIGRATIONS:
            assert isinstance(target, int)
            assert isinstance(script, str)
            assert len(script) > 0

    def test_pg_migrations_exist(self):
        """PostgreSQL migrations exist through SCIM (version 34)."""
        expected_targets = {
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
        }
        assert {target for target, _script in MIGRATIONS_PG} == expected_targets
        for target, script in MIGRATIONS_PG:
            assert isinstance(target, int)
            assert isinstance(script, str)
            assert len(script) > 0

    def test_migrations_have_create_statements(self):
        """Migrations contain CREATE statements."""
        for _target, script in MIGRATIONS:
            upper = script.upper()
            assert any(kw in upper for kw in ("CREATE TABLE", "CREATE INDEX", "ALTER TABLE"))


class TestPlaceholderAdaptation:
    """Test SQL placeholder adaptation."""

    def test_sqlite_placeholders_unchanged(self):
        """SQLite placeholders unchanged."""
        sql = "SELECT * FROM jobs WHERE id = ? AND tenant = ?"
        result = _adapt_placeholders(sql, False)
        assert result == sql

    def test_postgresql_placeholders_converted(self):
        """PostgreSQL placeholders converted to $1, $2, ..."""
        sql = "SELECT * FROM jobs WHERE id = ? AND tenant = ?"
        result = _adapt_placeholders(sql, True)
        assert result == "SELECT * FROM jobs WHERE id = $1 AND tenant = $2"

    def test_no_placeholders_unchanged(self):
        """SQL without placeholders unchanged."""
        sql = "SELECT * FROM jobs"
        assert _adapt_placeholders(sql, True) == sql
        assert _adapt_placeholders(sql, False) == sql


class TestDatabaseLifecycle:
    """Test database configuration and lifecycle."""

    @pytest_asyncio.fixture
    async def temp_db(self):
        """Create a temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            configure(db_path)
            db = await get_database()
            await db.migrate()
            yield str(db_path)
            await close_database()

    @pytest.mark.asyncio
    async def test_configure_creates_database(self, temp_db):
        """Configure creates database file."""
        db = await get_database()
        assert db is not None

        rows = await db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in rows}
        expected = {
            "jobs",
            "findings",
            "audit_log",
            "audit_chain",
            "api_keys",
            "engagement_policies",
            "webhook_sinks",
            "monitor_baseline",
            "assessment_schedules",
        }
        assert expected.issubset(tables)

    @pytest.mark.asyncio
    async def test_configure_resets_connection(self, temp_db):
        """Reconfiguring resets connection."""
        db1 = await get_database()

        configure(temp_db)
        db2 = await get_database()

        assert db2 is not None
        assert db1 is not db2

    @pytest.mark.asyncio
    async def test_close_database(self, temp_db):
        """Close database releases resources."""
        await close_database()

        configure(temp_db)
        db = await get_database()
        assert db is not None


class TestJobOperations:
    """Test job CRUD operations."""

    @pytest_asyncio.fixture
    async def db_with_job(self, temp_db):
        """Database with a test job."""
        job = Job(
            id="test-job-1",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.QUEUED,
        )
        await save_job(job, tenant="test-tenant")
        yield job

    @pytest.mark.asyncio
    async def test_save_and_get_job(self, temp_db):
        """Save and retrieve job."""
        job = Job(
            id="test-job-1",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.QUEUED,
        )
        await save_job(job, tenant="test-tenant")

        retrieved = await get_job("test-job-1", tenant="test-tenant")
        assert retrieved is not None
        assert retrieved["id"] == "test-job-1"
        assert retrieved["target"] == "https://example.com/"
        assert retrieved["profile"] == "web"
        assert retrieved["state"] == "queued"
        assert retrieved["tenant"] == "test-tenant"

    @pytest.mark.asyncio
    async def test_get_nonexistent_job(self, temp_db):
        """Get nonexistent job returns None."""
        retrieved = await get_job("nonexistent", tenant="test-tenant")
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_list_jobs(self, temp_db):
        """List jobs."""
        for i in range(3):
            job = Job(
                id=f"test-job-{i}",
                target=f"https://example{i}.com/",
                profile="web",
                actor="test-actor",
                policy={},
                state=JobState.QUEUED,
            )
            await save_job(job, tenant="test-tenant")

        jobs = await list_jobs(tenant="test-tenant", limit=10)
        assert len(jobs) == 3

    @pytest.mark.asyncio
    async def test_latest_finished_job(self, temp_db):
        """Get latest finished job for target."""

        job = Job(
            id="test-job-finished",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
        )
        await save_job(job, tenant="test-tenant")

        latest = await latest_finished_job("https://example.com/", tenant="test-tenant")
        assert latest is not None
        assert latest["id"] == "test-job-finished"

    @pytest.mark.asyncio
    async def test_fail_interrupted(self, temp_db):
        """Fail interrupted jobs."""
        job = Job(
            id="test-job-interrupted",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.RUNNING,
        )
        await save_job(job, tenant="test-tenant")

        count = await fail_interrupted()
        assert count >= 1

        retrieved = await get_job("test-job-interrupted", tenant="test-tenant")
        assert retrieved["state"] == "failed"

    @pytest.mark.asyncio
    async def test_mark_running(self, temp_db):
        """Mark job as running."""
        job = Job(
            id="test-job-mark",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.QUEUED,
        )
        await save_job(job, tenant="test-tenant")

        success = await mark_running("test-job-mark", tenant="test-tenant", worker="worker-1")
        assert success is True

        retrieved = await get_job("test-job-mark", tenant="test-tenant")
        assert retrieved["state"] == "running"
        assert retrieved["worker"] == "worker-1"

    @pytest.mark.asyncio
    async def test_claim_job(self, temp_db):
        """Claim job for execution."""
        job = Job(
            id="test-job-claim",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.QUEUED,
        )
        await save_job(job, tenant="test-tenant")

        claimed = await claim_job("test-job-claim", tenant="test-tenant", worker="worker-1")
        assert claimed is True

        claimed_again = await claim_job("test-job-claim", tenant="test-tenant", worker="worker-2")
        assert claimed_again is False

    @pytest.mark.asyncio
    async def test_claim_nonexistent_job(self, temp_db):
        """Claim nonexistent job returns True (allows creation)."""
        claimed = await claim_job("nonexistent", tenant="test-tenant", worker="worker-1")
        assert claimed is True

    @pytest.mark.asyncio
    async def test_find_job_by_idempotency(self, temp_db):
        """Find job by idempotency key."""
        job = Job(
            id="test-job-idempotent",
            target="https://example.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.QUEUED,
            idempotency_key="idem-key-123",
        )
        await save_job(job, tenant="test-tenant")

        job_id = await find_job_id_by_idempotency("idem-key-123", tenant="test-tenant")
        assert job_id == "test-job-idempotent"

        job_id2 = await find_job_id_by_idempotency("idem-key-123", tenant="other-tenant")
        assert job_id2 is None


class TestJobAggregations:
    """Test job aggregation queries."""

    @pytest_asyncio.fixture
    async def db_with_jobs(self, temp_db):
        """Database with multiple test jobs."""
        for i in range(5):
            job = Job(
                id=f"job-{i}",
                target=f"https://example{i}.com/",
                profile="web",
                actor="test-actor",
                policy={},
                state=JobState.COMPLETED if i < 3 else JobState.QUEUED,
            )
            await save_job(job, tenant="test-tenant")

    @pytest.mark.asyncio
    async def test_count_jobs(self, temp_db, db_with_jobs):
        """Count jobs for tenant."""
        count = await count_jobs(tenant="test-tenant")
        assert count == 5

    @pytest.mark.asyncio
    async def test_count_findings(self, temp_db, db_with_jobs):
        """Count findings for tenant."""

        from ishastra.core.findings import Finding

        job = Job(
            id="job-with-findings",
            target="https://findings.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
        )
        finding = Finding(
            asset="https://findings.com/",
            category="xss",
            title="XSS found",
            severity="high",
            confidence="high",
            verification="observed",
            detector="test",
            detector_version="1.0",
            evidence="<script>alert(1)</script>",
        )
        job.findings.append(finding)
        await save_job(job, tenant="test-tenant")

        count = await count_findings(tenant="test-tenant")
        assert count >= 1

    @pytest.mark.asyncio
    async def test_jobs_by_state(self, temp_db, db_with_jobs):
        """Jobs grouped by state."""
        result = await jobs_by_state(tenant="test-tenant")
        assert "completed" in result
        assert "queued" in result
        assert result["completed"] == 3
        assert result["queued"] == 2

    @pytest.mark.asyncio
    async def test_findings_by_severity(self, temp_db, db_with_jobs):
        """Findings grouped by severity."""

        job = Job(
            id="job-severity",
            target="https://severity.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
        )
        for i, sev in enumerate(["critical", "high", "medium", "low", "info"]):
            finding = Finding(
                asset="https://severity.com/",
                category="test",
                title=f"Finding {sev}",
                severity=sev,
                confidence="high",
                verification="observed",
                detector="test",
                detector_version="1.0",
                evidence="evidence",
                location=f"/path{i}",
            )
            job.findings.append(finding)
        await save_job(job, tenant="test-tenant")

        result = await findings_by_severity(tenant="test-tenant")
        assert result["critical"] >= 1
        assert result["high"] >= 1
        assert result["medium"] >= 1
        assert result["low"] >= 1
        assert result["info"] >= 1


class TestFindingsOperations:
    """Test findings operations."""

    @pytest_asyncio.fixture
    async def job_with_findings(self, temp_db):
        """Create job with findings."""
        job = Job(
            id="job-findings-test",
            target="https://findings.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
        )
        finding1 = Finding(
            asset="https://findings.com/",
            category="xss",
            title="XSS in search",
            severity="high",
            confidence="high",
            verification="observed",
            detector="xss-scanner",
            detector_version="1.0",
            evidence="<script>alert(1)</script>",
            location="/search?q=<script>",
        )
        finding2 = Finding(
            asset="https://findings.com/",
            category="sqli",
            title="SQL Injection",
            severity="critical",
            confidence="high",
            verification="observed",
            detector="sqli-scanner",
            detector_version="1.0",
            evidence="' OR 1=1--",
            location="/login",
        )
        job.findings.extend([finding1, finding2])
        await save_job(job, tenant="test-tenant")
        return job

    @pytest.mark.asyncio
    async def test_get_findings(self, temp_db, job_with_findings):
        """Get findings for job."""
        findings = await get_findings("job-findings-test", tenant="test-tenant")
        assert len(findings) == 2
        categories = {f.category for f in findings}
        assert categories == {"xss", "sqli"}
        severities = {f.severity for f in findings}
        assert severities == {"high", "critical"}

    @pytest.mark.asyncio
    async def test_update_finding_status(self, temp_db, job_with_findings):
        """Update finding status through lifecycle."""

        findings = await get_findings("job-findings-test", tenant="test-tenant")
        fingerprint = findings[0].fingerprint

        updated = await update_finding_status(
            "job-findings-test",
            fingerprint,
            tenant="test-tenant",
            to_status="triaged",
        )
        assert updated is not None
        assert updated["status"] == "triaged"
        assert updated["remediation_status"] == "pending"

        findings2 = await get_findings("job-findings-test", tenant="test-tenant")
        updated_finding = next(f for f in findings2 if f.fingerprint == fingerprint)
        assert updated_finding.status == "triaged"

    @pytest.mark.asyncio
    async def test_update_finding_invalid_transition(self, temp_db, job_with_findings):
        """Invalid status transition raises ValueError."""
        findings = await get_findings("job-findings-test", tenant="test-tenant")
        fingerprint = findings[0].fingerprint

        with pytest.raises(ValueError, match="Invalid transition"):
            await update_finding_status(
                "job-findings-test",
                fingerprint,
                tenant="test-tenant",
                to_status="closed",
            )

    @pytest.mark.asyncio
    async def test_update_nonexistent_finding(self, temp_db, job_with_findings):
        """Update nonexistent finding returns None."""
        result = await update_finding_status(
            "job-findings-test",
            "nonexistent-fingerprint",
            tenant="test-tenant",
            to_status="triaged",
        )
        assert result is None


class TestAPIKeys:
    """Test API key operations."""

    @pytest.mark.asyncio
    async def test_save_and_load_api_keys(self, temp_db):
        """Save and load API keys."""
        import hashlib

        key_hash = hashlib.sha256(b"test-key").hexdigest()

        await save_api_key(
            tenant_id="tenant-1",
            key_hash=key_hash,
            tier="elevated",
            admin=True,
            active=True,
            created_at=1234567890.0,
            project="default",
        )

        keys = await load_api_keys()
        assert len(keys) >= 1
        found = next((k for k in keys if k["tenant_id"] == "tenant-1"), None)
        assert found is not None
        assert found["key_hash"] == key_hash
        assert found["tier"] == "elevated"
        assert found["admin"] == 1
        assert found["scope"] == "write"


class TestAuditTrail:
    """Test audit log and chain."""

    @pytest.mark.asyncio
    async def test_append_and_recent_audit(self, temp_db):
        """Append audit entry and retrieve recent."""
        await append_audit({"event": "test_event", "tenant": "test-tenant", "data": "value"})
        await append_audit({"event": "test_event2", "tenant": "test-tenant", "data": "value2"})

        recent = await recent_audit(10)
        assert len(recent) >= 2
        events = [e["event"] for e in recent]
        assert "test_event" in events
        assert "test_event2" in events

    @pytest.mark.asyncio
    async def test_chain_tip_empty(self, temp_db):
        """Chain tip is None for empty chain."""
        tip = await chain_tip()
        assert tip is None

    @pytest.mark.asyncio
    async def test_chain_insert_and_tip(self, temp_db):
        """Insert chain entry and get tip."""
        await chain_insert(1, "0" * 64, "hash1", {"event": "test"})
        tip = await chain_tip()
        assert tip is not None
        assert tip[0] == 1
        assert tip[1] == "hash1"

    @pytest.mark.asyncio
    async def test_chain_rows(self, temp_db):
        """Stream chain rows."""
        await chain_insert(1, "0" * 64, "hash1", {"event": "test1"})
        await chain_insert(2, "hash1", "hash2", {"event": "test2"})

        rows = []
        async for row in chain_rows():
            rows.append(row)
        assert len(rows) == 2
        assert rows[0]["sequence"] == 1
        assert rows[1]["sequence"] == 2

    @pytest.mark.asyncio
    async def test_chain_count(self, temp_db):
        """Count chain entries."""
        await chain_insert(1, "0" * 64, "hash1", {"event": "test1"})
        await chain_insert(2, "hash1", "hash2", {"event": "test2"})

        count = await chain_count()
        assert count == 2


class TestRetention:
    """Test retention/pruning operations."""

    @pytest.mark.asyncio
    async def test_prune_finished_jobs(self, temp_db):
        """Prune old finished jobs."""
        import time

        old_time = time.time() - 86400 * 30

        job = Job(
            id="old-job",
            target="https://old.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
            finished_at=old_time,
        )
        await save_job(job, tenant="test-tenant")

        job2 = Job(
            id="recent-job",
            target="https://recent.com/",
            profile="web",
            actor="test-actor",
            policy={},
            state=JobState.COMPLETED,
            finished_at=time.time(),
        )
        await save_job(job2, tenant="test-tenant")

        cutoff = time.time() - 86400 * 7
        count = await prune_finished_jobs(cutoff)
        assert count >= 1

        retrieved = await get_job("old-job", tenant="test-tenant")
        assert retrieved is None

        retrieved2 = await get_job("recent-job", tenant="test-tenant")
        assert retrieved2 is not None

    @pytest.mark.asyncio
    async def test_prune_audit_log(self, temp_db):
        """Prune old audit log entries."""
        import time

        old_time = time.time() - 86400 * 30

        await append_audit({"event": "old_event", "timestamp": old_time})
        await append_audit({"event": "recent_event", "timestamp": time.time()})

        cutoff = time.time() - 86400 * 7
        count = await prune_audit_log(cutoff)
        assert count >= 1


class TestMonitorConfig:
    """Test monitor configuration."""

    @pytest.mark.asyncio
    async def test_save_and_load_monitor_config(self, temp_db):
        """Save and load monitor config."""
        await save_monitor_config(["https://example.com/", "https://test.com/"], 3600)

        targets, interval = await load_monitor_config()
        assert targets == ["https://example.com/", "https://test.com/"]
        assert interval == 3600

    @pytest.mark.asyncio
    async def test_save_and_load_monitor_baseline(self, temp_db):
        """Save and load monitor baseline."""
        await save_monitor_baseline("https://example.com/", {"fp1", "fp2", "fp3"})

        baseline = await load_monitor_baseline()
        assert "https://example.com/" in baseline
        assert baseline["https://example.com/"] == {"fp1", "fp2", "fp3"}

    @pytest.mark.asyncio
    async def test_delete_monitor_baseline(self, temp_db):
        """Delete monitor baseline."""
        await save_monitor_baseline("https://example.com/", {"fp1"})
        await delete_monitor_baseline("https://example.com/")

        baseline = await load_monitor_baseline()
        assert "https://example.com/" not in baseline


class TestEngagementPolicies:
    """Test engagement policy storage."""

    @pytest.mark.asyncio
    async def test_save_and_load_policies(self, temp_db):
        """Save and load engagement policies."""
        policy = {
            "policy_id": "pol-1",
            "tenant_id": "tenant-1",
            "program": "Test Program",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [80, 443],
            "allow_broad_networks": False,
            "status": "active",
            "version": 1,
            "created_at": 1234567890.0,
            "updated_at": 1234567890.0,
        }
        await save_policy(policy)

        policies = await load_policies()
        assert len(policies) >= 1
        found = next((p for p in policies if p["policy_id"] == "pol-1"), None)
        assert found is not None
        assert found["program"] == "Test Program"
        assert found["include"] == ["example.com"]
        assert found["allowed_ports"] == [80, 443]


class TestWebhookSinks:
    """Test webhook sink storage."""

    @pytest.mark.asyncio
    async def test_save_delete_load_webhook_sinks(self, temp_db):
        """Save, delete, and load webhook sinks."""
        await save_webhook_sink("sink1", "https://webhook.example.com/")
        await save_webhook_sink("sink2", "https://webhook2.example.com/")

        sinks = await load_webhook_sinks()
        assert len(sinks) >= 2
        names = {s["name"] for s in sinks}
        assert "sink1" in names
        assert "sink2" in names

        await delete_webhook_sink("sink1")
        sinks = await load_webhook_sinks()
        names = {s["name"] for s in sinks}
        assert "sink1" not in names
        assert "sink2" in names


class TestVacuum:
    """Test vacuum operation."""

    @pytest.mark.asyncio
    async def test_vacuum_runs(self, temp_db):
        """Vacuum runs without error."""

        for i in range(10):
            job = Job(
                id=f"vac-job-{i}",
                target=f"https://vac{i}.com/",
                profile="web",
                actor="test-actor",
                policy={},
                state=JobState.COMPLETED,
            )
            await save_job(job, tenant="test-tenant")

        for i in range(10):
            db = await get_database()
            async with db.transaction() as conn:
                await conn.execute("DELETE FROM jobs WHERE id = ?", (f"vac-job-{i}",))

        await vacuum()


class TestSyncBridge:
    """Test _run_async sync bridge."""

    def test_run_async_in_new_loop(self, temp_db):
        """_run_async works when no event loop running."""

        async def async_op():
            db = await get_database()
            row = await db.fetchone("SELECT 1 as val")
            return row["val"]

        result = _run_async(async_op())
        assert result == 1


class TestJobConflict:
    """Test JobConflict exception."""

    def test_job_conflict_is_runtime_error(self):
        """JobConflict is a RuntimeError."""
        exc = JobConflict("test")
        assert isinstance(exc, RuntimeError)
        assert str(exc) == "test"


class TestAssetInventoryAndHistory:
    """Asset inventory, remediation metadata and finding history."""

    @staticmethod
    async def _job(
        job_id: str,
        tenant: str,
        target: str = "http://127.0.0.1:9/",
        finished_at: float = 1234567890.0,
    ) -> Job:
        job = Job(
            id=job_id,
            target=target,
            profile="web",
            actor=tenant,
            policy={},
            state=JobState.COMPLETED,
        )
        job.finished_at = finished_at
        job.findings = [
            Finding(
                asset=target,
                category="missing_csp",
                title="Missing CSP",
                severity="low",
                confidence="high",
                detector="test",
                detector_version="1",
                evidence="no header",
                location="/",
            )
        ]
        await save_job(job, tenant=tenant)
        return job

    @pytest.mark.asyncio
    async def test_assets_and_history_are_tenant_scoped(self, temp_db):
        first = await self._job("asset-job-1", "tenant-1")
        await self._job("asset-job-2", "tenant-2", "http://127.0.0.1:10/")
        fingerprint = first.findings[0].fingerprint

        assets = await list_assets(tenant="tenant-1")
        assert len(assets) == 1
        key = assets[0]["asset_key"]
        assert assets[0]["open_finding_count"] == 1

        assert await get_asset(tenant="tenant-2", key=key) is None
        assert await update_asset_metadata(tenant="tenant-2", key=key, owner="x") is None
        assert await list_finding_events(tenant="tenant-2", job_id=first.id, fingerprint=fingerprint) == []
        assert (
            await set_finding_remediation(
                tenant="tenant-2", job_id=first.id, fingerprint=fingerprint, owner="x"
            )
            is None
        )

        updated = await update_asset_metadata(tenant="tenant-1", key=key, owner="alice", criticality="high")
        assert updated is not None and updated["owner"] == "alice"

    @pytest.mark.asyncio
    async def test_cross_job_finding_record_is_tenant_scoped(self, temp_db):
        first = await self._job("cross-job-1", "tenant-1")
        await self._job("cross-job-2", "tenant-1", finished_at=1234567920.0)
        fingerprint = first.findings[0].fingerprint

        records = await list_cross_job_findings(tenant="tenant-1")
        assert len(records) == 1
        record = records[0]
        assert record["fingerprint"] == fingerprint
        assert record["occurrence_count"] == 2
        assert record["first_seen"] == 1234567890.0
        assert record["last_seen"] == 1234567920.0
        assert record["last_job"]["id"] == "cross-job-2"
        assert await count_cross_job_findings(tenant="tenant-1") == 1

        detail = await get_cross_job_finding(tenant="tenant-1", fingerprint=fingerprint)
        assert detail is not None
        assert [item["job_id"] for item in detail["history"]] == ["cross-job-1", "cross-job-2"]

        assert await list_cross_job_findings(tenant="tenant-2") == []
        assert await get_cross_job_finding(tenant="tenant-2", fingerprint=fingerprint) is None

    @pytest.mark.asyncio
    async def test_cross_job_remediation_and_resolution(self, temp_db):
        job = await self._job("record-job-1", "tenant-1")
        fingerprint = job.findings[0].fingerprint

        await set_finding_remediation(
            tenant="tenant-1",
            job_id=job.id,
            fingerprint=fingerprint,
            owner="alice",
        )
        detail = await get_cross_job_finding(tenant="tenant-1", fingerprint=fingerprint)
        assert detail is not None and detail["owner"] == "alice"

        updated = await set_finding_record_remediation(
            tenant="tenant-1", fingerprint=fingerprint, owner="bob", due_at=1234569000.0
        )
        assert updated is not None and updated["owner"] == "bob"

        resolved = await set_finding_resolution(
            tenant="tenant-1",
            fingerprint=fingerprint,
            resolved_at=1234569100.0,
            job_id="verify-job",
            evidence={"detector_states": {"test": "ok"}},
        )
        assert resolved is not None and resolved["resolution"]["state"] == "resolved"
        detail = await get_cross_job_finding(tenant="tenant-1", fingerprint=fingerprint)
        assert detail is not None and detail["resolution"]["job_id"] == "verify-job"

        requested = await request_finding_exception(
            tenant="tenant-1",
            fingerprint=fingerprint,
            until=time.time() + 86400,
            reason="accepted for 30 days",
            requested_by="alice",
        )
        assert requested is not None and requested["exception"]["state"] == "pending"
        decided = await decide_finding_exception(
            tenant="tenant-1",
            fingerprint=fingerprint,
            approved=True,
            decided_by="admin",
            note="approved",
        )
        assert decided is not None and decided["exception"]["state"] == "approved"
        with pytest.raises(ValueError):
            await decide_finding_exception(
                tenant="tenant-1",
                fingerprint=fingerprint,
                approved=False,
                decided_by="admin",
            )

        await self._job("record-job-2", "tenant-1", finished_at=1234569200.0)
        detail = await get_cross_job_finding(tenant="tenant-1", fingerprint=fingerprint)
        assert detail is not None and detail["resolution"]["state"] == "open"

    @pytest.mark.asyncio
    async def test_finding_trends_counts_observations_and_new_findings(self, temp_db):
        await self._job("trend-job-1", "tenant-1", finished_at=1704067200.0)
        await self._job("trend-job-2", "tenant-1", finished_at=1704153600.0)
        fingerprint = (await list_cross_job_findings(tenant="tenant-1"))[0]["fingerprint"]
        await set_finding_resolution(
            tenant="tenant-1",
            fingerprint=fingerprint,
            resolved_at=1704240000.0,
            job_id="trend-verify",
            evidence={"detector_states": {"test": "ok"}},
        )

        trends = await finding_trends(tenant="tenant-1", start=1704067200.0, end=1704326400.0, bucket="day")
        buckets = {item["bucket"]: item for item in trends["buckets"]}
        assert buckets["2024-01-01"]["observations"] == 1
        assert buckets["2024-01-01"]["new_findings"] == 1
        assert buckets["2024-01-02"]["observations"] == 1
        assert buckets["2024-01-02"]["new_findings"] == 0
        assert buckets["2024-01-03"]["resolved_findings"] == 1

    @pytest.mark.asyncio
    async def test_status_and_remediation_create_history(self, temp_db):
        job = await self._job("asset-job-3", "tenant-1")
        fingerprint = job.findings[0].fingerprint

        events = await list_finding_events(tenant="tenant-1", job_id=job.id, fingerprint=fingerprint)
        assert [event["event"] for event in events] == ["created"]

        await update_finding_status(
            job.id,
            fingerprint,
            tenant="tenant-1",
            to_status="triaged",
            actor="alice",
            note="reviewed",
        )
        await set_finding_remediation(
            tenant="tenant-1",
            job_id=job.id,
            fingerprint=fingerprint,
            owner="alice",
            due_at=1234567890.0,
        )

        events = await list_finding_events(tenant="tenant-1", job_id=job.id, fingerprint=fingerprint)
        assert [event["event"] for event in events] == ["created", "status_changed"]
        assert events[-1]["actor"] == "alice"
        remediation = await get_finding_remediation(tenant="tenant-1", job_id=job.id, fingerprint=fingerprint)
        assert remediation is not None and remediation["owner"] == "alice"
        loaded = await get_job(job.id, tenant="tenant-1")
        assert loaded["findings"][0]["owner"] == "alice"
        assert loaded["findings"][0]["status"] == "triaged"
