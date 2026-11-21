"""Tests for ishastra.core.exceptions_worker module."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from ishastra.audit import AuditChain
from ishastra.config import Settings
from ishastra.core import exceptions as exceptions_module
from ishastra.core import exceptions_worker, store
from ishastra.core.exceptions import (
    EVENT_EXCEPTION_EXPIRED,
    EXCEPTION_APPROVED,
    EXCEPTION_EXPIRED,
    EXCEPTION_NONE,
    EXCEPTION_PENDING,
    EXCEPTION_REJECTED,
)


@pytest_asyncio.fixture
async def test_db():
    """Create a temporary database for testing."""
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    db = await store.get_database()
    await db.migrate()
    yield path
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    await store.close_database()


@pytest_asyncio.fixture
async def mock_audit_chain():
    """Create a mock audit chain."""
    audit = AsyncMock(spec=AuditChain)
    audit.append_async = AsyncMock()
    return audit


@pytest_asyncio.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock(spec=Settings)
    settings.audit_hmac_key = "test-key"
    settings.webhook_secret = ""
    return settings


@pytest_asyncio.fixture
async def worker(mock_audit_chain, mock_settings):
    """Create ExceptionsWorker instance."""
    w = exceptions_worker.ExceptionsWorker(
        audit_chain=mock_audit_chain,
        settings=mock_settings,
    )
    await w.initialize()
    yield w
    await w.stop()


async def _create_finding_and_record(
    tenant: str,
    fingerprint: str,
    exception_state: str,
    exception_until: float | None = None,
    resolution_state: str = "open",
):
    """Helper to create a job, finding, and finding record in the database."""
    db = await store.get_database()
    now = time.time()
    job_id = "test-job-" + fingerprint
    async with db.transaction() as conn:
        await store._execute(
            conn,
            """INSERT INTO jobs
                   (id, tenant, target, profile, actor, policy, state, verdict,
                    error, started_at, finished_at, coverage, created_at,
                    attempts, worker, idempotency_key, cancel_requested)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (id) DO NOTHING""",
            job_id,
            tenant,
            "https://example.com/",
            "web",
            "test-actor",
            "{}",
            "completed",
            "clean",
            "",
            now,
            now,
            "{}",
            now,
            0,
            "",
            None,
            0,
        )

        await store._execute(
            conn,
            """INSERT INTO findings
                   (job_id, tenant, fingerprint, asset, category, title,
                    severity, confidence, verification, status, detector,
                    detector_version, location, evidence, description,
                    remediation, cwe, sources)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (job_id, fingerprint) DO NOTHING""",
            job_id,
            tenant,
            fingerprint,
            "https://example.com/",
            "xss",
            "Test XSS",
            "high",
            "high",
            "observed",
            "open",
            "test-detector",
            "1.0",
            "/test",
            "test evidence",
            "test description",
            "test remediation",
            "CWE-79",
            "[]",
        )

        await store._execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, exception_state, exception_until,
                    exception_reason, exception_requested_by, exception_decided_by,
                    exception_note, exception_requested_at, exception_decided_at,
                    resolution_state, resolved_at, resolved_job_id,
                    resolution_evidence, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   exception_state = excluded.exception_state,
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_requested_by = excluded.exception_requested_by,
                   exception_decided_by = excluded.exception_decided_by,
                   exception_note = excluded.exception_note,
                   exception_requested_at = excluded.exception_requested_at,
                   exception_decided_at = excluded.exception_decided_at,
                   resolution_state = excluded.resolution_state,
                   resolved_at = excluded.resolved_at,
                   resolved_job_id = excluded.resolved_job_id,
                   resolution_evidence = excluded.resolution_evidence,
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            exception_state,
            exception_until,
            "test reason",
            "requester",
            "approver",
            "test note",
            now if exception_state != "none" else None,
            now if exception_state == "approved" else None,
            resolution_state,
            now if resolution_state != "open" else None,
            "verify-job" if resolution_state != "open" else "",
            '{"evidence": "test"}' if resolution_state != "open" else "{}",
            now,
        )


@pytest_asyncio.fixture(autouse=True)
async def mock_notify_exception_event():
    """Mock the webhook notification to avoid database locks."""
    with patch.object(exceptions_module, "_notify_exception_event", new_callable=AsyncMock) as mock:
        yield mock


class TestExceptionsWorkerResult:
    """Tests for ExceptionsWorkerResult dataclass."""

    def test_default_creation(self):
        """Test default ExceptionsWorkerResult creation."""
        result = exceptions_worker.ExceptionsWorkerResult()
        assert result.expired_count == 0
        assert result.auto_closed_count == 0
        assert result.errors == []

    def test_custom_creation(self):
        """Test ExceptionsWorkerResult with custom values."""
        result = exceptions_worker.ExceptionsWorkerResult(
            expired_count=5,
            auto_closed_count=3,
            errors=["error1", "error2"],
        )
        assert result.expired_count == 5
        assert result.auto_closed_count == 3
        assert result.errors == ["error1", "error2"]


class TestExceptionsWorker:
    """Tests for ExceptionsWorker class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_audit_chain, mock_settings):
        """Test worker initialization."""
        worker = exceptions_worker.ExceptionsWorker(
            audit_chain=mock_audit_chain,
            settings=mock_settings,
        )
        assert worker._running is False
        await worker.initialize()
        assert worker._running is True
        assert exceptions_worker._exceptions_worker is worker
        await worker.stop()
        assert worker._running is False

    @pytest.mark.asyncio
    async def test_stop(self, worker):
        """Test worker stop."""
        assert worker._running is True
        await worker.stop()
        assert worker._running is False

    @pytest.mark.asyncio
    async def test_running_property(self, worker):
        """Test running property."""
        assert worker.running is True
        await worker.stop()
        assert worker.running is False


class TestExceptionExpiration:
    """Tests for exception expiration logic."""

    @pytest.mark.asyncio
    async def test_expire_pending_exception(self, test_db, worker):
        """Test expiring a pending exception past its timestamp."""
        now = time.time()
        fingerprint = "test-fp-1"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_PENDING,
            exception_until=now - 100,
        )

        expired = await worker._expire_exceptions()

        assert expired == 1

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["exception"]["state"] == EXCEPTION_EXPIRED

    @pytest.mark.asyncio
    async def test_expire_approved_exception(self, test_db, worker):
        """Test expiring an approved exception past its timestamp."""
        now = time.time()
        fingerprint = "test-fp-2"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=now - 100,
        )

        expired = await worker._expire_exceptions()

        assert expired == 1

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["exception"]["state"] == EXCEPTION_EXPIRED

    @pytest.mark.asyncio
    async def test_do_not_expire_future_exception(self, test_db, worker):
        """Test that future exceptions are not expired."""
        now = time.time()
        fingerprint = "test-fp-3"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_PENDING,
            exception_until=now + 86400,
        )

        expired = await worker._expire_exceptions()

        assert expired == 0

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["exception"]["state"] == EXCEPTION_PENDING

    @pytest.mark.asyncio
    async def test_do_not_expire_none_state(self, test_db, worker):
        """Test that 'none' state exceptions are not processed."""
        fingerprint = "test-fp-4"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state="none",
            exception_until=None,
        )

        expired = await worker._expire_exceptions()

        assert expired == 0

    @pytest.mark.asyncio
    async def test_do_not_expire_rejected_state(self, test_db, worker):
        """Test that 'rejected' state exceptions are not processed."""
        now = time.time()
        fingerprint = "test-fp-5"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_REJECTED,
            exception_until=now - 100,
        )

        expired = await worker._expire_exceptions()

        assert expired == 0

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["exception"]["state"] == EXCEPTION_REJECTED

    @pytest.mark.asyncio
    async def test_do_not_expire_already_expired(self, test_db, worker):
        """Test that already expired exceptions are not processed again."""
        now = time.time()
        fingerprint = "test-fp-6"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_EXPIRED,
            exception_until=now - 100,
        )

        expired = await worker._expire_exceptions()

        assert expired == 0

    @pytest.mark.asyncio
    async def test_expire_multiple_exceptions(self, test_db, worker):
        """Test expiring multiple exceptions at once."""
        now = time.time()

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="fp-1",
            exception_state=EXCEPTION_PENDING,
            exception_until=now - 100,
        )
        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="fp-2",
            exception_state=EXCEPTION_APPROVED,
            exception_until=now - 200,
        )
        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="fp-3",
            exception_state=EXCEPTION_PENDING,
            exception_until=now + 86400,
        )

        expired = await worker._expire_exceptions()

        assert expired == 2

        record1 = await store.get_finding_record(tenant="test-tenant", fingerprint="fp-1")
        record2 = await store.get_finding_record(tenant="test-tenant", fingerprint="fp-2")
        record3 = await store.get_finding_record(tenant="test-tenant", fingerprint="fp-3")

        assert record1["exception"]["state"] == EXCEPTION_EXPIRED
        assert record2["exception"]["state"] == EXCEPTION_EXPIRED
        assert record3["exception"]["state"] == EXCEPTION_PENDING

    @pytest.mark.asyncio
    async def test_audit_chain_called_on_expiration(self, test_db, worker, mock_audit_chain):
        """Test that audit chain is called when exception expires."""
        now = time.time()
        fingerprint = "test-fp-audit"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=now - 100,
        )

        await worker._expire_exceptions()

        mock_audit_chain.append_async.assert_called()
        call_args = mock_audit_chain.append_async.call_args[0][0]
        assert call_args["event"] == EVENT_EXCEPTION_EXPIRED
        assert call_args["tenant"] == "test-tenant"
        assert call_args["fingerprint"] == fingerprint
        assert call_args["previous_state"] == EXCEPTION_APPROVED


class TestAutoCloseFixVerified:
    """Tests for auto-closing fix_verified findings with approved exceptions."""

    @pytest.mark.asyncio
    async def test_auto_close_fix_verified_with_approved_exception(self, test_db, worker):
        """Test auto-closing fix_verified finding with approved exception."""
        fingerprint = "test-fp-close-1"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=time.time() + 86400,
            resolution_state="fix_verified",
        )

        auto_closed = await worker._auto_close_fix_verified()

        assert auto_closed == 1

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["resolution"]["state"] == "closed"

    @pytest.mark.asyncio
    async def test_do_not_close_open_resolution(self, test_db, worker):
        """Test that open resolution state is not auto-closed."""
        fingerprint = "test-fp-close-2"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=time.time() + 86400,
            resolution_state="open",
        )

        auto_closed = await worker._auto_close_fix_verified()

        assert auto_closed == 0

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["resolution"]["state"] == "open"

    @pytest.mark.asyncio
    async def test_do_not_close_without_approved_exception(self, test_db, worker):
        """Test that findings without approved exception are not auto-closed."""
        fingerprint = "test-fp-close-3"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_PENDING,
            exception_until=time.time() + 86400,
            resolution_state="fix_verified",
        )

        auto_closed = await worker._auto_close_fix_verified()

        assert auto_closed == 0

        record = await store.get_finding_record(tenant="test-tenant", fingerprint=fingerprint)
        assert record is not None
        assert record["resolution"]["state"] == "fix_verified"

    @pytest.mark.asyncio
    async def test_do_not_close_expired_exception(self, test_db, worker):
        """Test that fix_verified with expired exception is not auto-closed."""
        fingerprint = "test-fp-close-4"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_EXPIRED,
            exception_until=time.time() - 100,
            resolution_state="fix_verified",
        )

        auto_closed = await worker._auto_close_fix_verified()

        assert auto_closed == 0

    @pytest.mark.asyncio
    async def test_do_not_close_already_closed(self, test_db, worker):
        """Test that already closed findings are not processed."""
        fingerprint = "test-fp-close-5"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=time.time() + 86400,
            resolution_state="closed",
        )

        auto_closed = await worker._auto_close_fix_verified()

        assert auto_closed == 0

    @pytest.mark.asyncio
    async def test_audit_chain_called_on_auto_close(self, test_db, worker, mock_audit_chain):
        """Test that audit chain is called on auto-close."""
        fingerprint = "test-fp-close-audit"

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint=fingerprint,
            exception_state=EXCEPTION_APPROVED,
            exception_until=time.time() + 86400,
            resolution_state="fix_verified",
        )

        await worker._auto_close_fix_verified()

        mock_audit_chain.append_async.assert_called()
        call_args = mock_audit_chain.append_async.call_args[0][0]
        assert call_args["event"] == "exception_auto_closed"
        assert call_args["tenant"] == "test-tenant"
        assert call_args["fingerprint"] == fingerprint
        assert call_args["previous_resolution_state"] == "fix_verified"
        assert call_args["exception_state"] == EXCEPTION_APPROVED


class TestWorkerIteration:
    """Tests for full worker iteration."""

    @pytest.mark.asyncio
    async def test_run_iteration_combined(self, test_db, worker):
        """Test running a full iteration with both expiration and auto-close."""
        now = time.time()

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="expire-fp",
            exception_state=EXCEPTION_PENDING,
            exception_until=now - 100,
        )

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="close-fp",
            exception_state=EXCEPTION_APPROVED,
            exception_until=now + 86400,
            resolution_state="fix_verified",
        )

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="ignore-fp",
            exception_state=EXCEPTION_PENDING,
            exception_until=now + 86400,
            resolution_state="open",
        )

        result = await worker._run_iteration_async()

        assert result.expired_count == 1
        assert result.auto_closed_count == 1
        assert result.errors == []

        expire_record = await store.get_finding_record(tenant="test-tenant", fingerprint="expire-fp")
        close_record = await store.get_finding_record(tenant="test-tenant", fingerprint="close-fp")
        ignore_record = await store.get_finding_record(tenant="test-tenant", fingerprint="ignore-fp")

        assert expire_record["exception"]["state"] == EXCEPTION_EXPIRED
        assert close_record["resolution"]["state"] == "closed"
        assert ignore_record["exception"]["state"] == EXCEPTION_PENDING
        assert ignore_record["resolution"]["state"] == "open"

    @pytest.mark.asyncio
    async def test_run_once(self, test_db, worker):
        """Test run_once method."""
        now = time.time()

        await _create_finding_and_record(
            tenant="test-tenant",
            fingerprint="run-once-fp",
            exception_state=EXCEPTION_APPROVED,
            exception_until=now - 100,
        )

        result = await worker.run_once()

        assert result.expired_count == 1


class TestSchedulerRegistration:
    """Tests for scheduler registration."""

    @pytest.mark.asyncio
    async def test_scheduler_job_callback(self, test_db, mock_audit_chain, mock_settings):
        """Test the module-level scheduler job callback."""

        worker = exceptions_worker.ExceptionsWorker(
            audit_chain=mock_audit_chain,
            settings=mock_settings,
        )
        await worker.initialize()

        with patch.object(worker, "_run_iteration_async", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = exceptions_worker.ExceptionsWorkerResult()

            exceptions_worker._run_exceptions_worker_job()

            assert exceptions_worker._exceptions_worker is worker

        await worker.stop()

    @pytest.mark.asyncio
    async def test_scheduler_job_callback_no_worker(self, test_db):
        """Test scheduler job callback when worker is not initialized."""

        exceptions_worker._exceptions_worker = None

        exceptions_worker._run_exceptions_worker_job()

    @pytest.mark.asyncio
    async def test_factory_function(self, test_db, mock_audit_chain, mock_settings):
        """Test create_exceptions_worker factory function."""
        worker = await exceptions_worker.create_exceptions_worker(
            audit_chain=mock_audit_chain,
            settings=mock_settings,
        )

        assert isinstance(worker, exceptions_worker.ExceptionsWorker)
        assert worker._running is True
        assert exceptions_worker._exceptions_worker is worker

        await worker.stop()


class TestExceptionStates:
    """Tests for exception state constants."""

    def test_exception_states(self):
        """Test exception state constants."""
        assert EXCEPTION_NONE == "none"
        assert EXCEPTION_PENDING == "pending"
        assert EXCEPTION_APPROVED == "approved"
        assert EXCEPTION_REJECTED == "rejected"
        assert EXCEPTION_EXPIRED == "expired"

    def test_resolution_states(self):
        """Test resolution state constants."""
        assert exceptions_worker.RESOLUTION_OPEN == "open"
        assert exceptions_worker.RESOLUTION_FIX_VERIFIED == "fix_verified"
        assert exceptions_worker.RESOLUTION_CLOSED == "closed"

    def test_valid_exception_states(self):
        """Test that all expected states are in the valid set."""
        from ishastra.core.exceptions import VALID_EXCEPTION_STATES

        assert EXCEPTION_NONE in VALID_EXCEPTION_STATES
        assert EXCEPTION_PENDING in VALID_EXCEPTION_STATES
        assert EXCEPTION_APPROVED in VALID_EXCEPTION_STATES
        assert EXCEPTION_REJECTED in VALID_EXCEPTION_STATES
        assert EXCEPTION_EXPIRED in VALID_EXCEPTION_STATES


class TestWorkerErrorHandling:
    """Tests for worker error handling."""

    @pytest.mark.asyncio
    async def test_iteration_handles_database_error(self, test_db, worker):
        """Test that iteration handles database errors gracefully."""
        with patch("ishastra.core.store.get_database", side_effect=Exception("DB error")):
            result = await worker._run_iteration_async()

        assert result.expired_count == 0
        assert result.auto_closed_count == 0
        assert len(result.errors) == 1
        assert "DB error" in result.errors[0]

    @pytest.mark.asyncio
    async def test_iteration_cancelled(self, test_db, worker):
        """Test that iteration handles cancellation."""

        async def cancelled_run():
            raise asyncio.CancelledError()

        with (
            patch.object(worker, "_expire_exceptions", side_effect=cancelled_run),
            pytest.raises(asyncio.CancelledError),
        ):
            await worker._run_iteration_async()
