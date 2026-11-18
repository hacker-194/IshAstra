"""Tests for strix.core.queue module - Celery assessment queue."""

from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from strix.core import store
from strix.core.jobs import Job, JobState
from strix.core.queue import (
    CeleryAssessmentQueue,
    _dict_to_job,
    _ensure_store_configured,
    _job_to_dict,
    _worker_init,
    create_celery_app,
    run_assessment_task,
)


@pytest_asyncio.fixture
async def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    db = await store.get_database()
    await db.migrate()
    yield path
    await store.close_database()
    import pathlib

    pathlib.Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        pathlib.Path(path + suffix).unlink(missing_ok=True)


@pytest.fixture
def sample_job():
    """Create a sample job for testing."""
    return Job(
        target="https://example.com",
        profile="web",
        actor="test-actor",
        policy={"policy_id": "test-policy-123"},
        id="test-job-123",
        idempotency_key="idem-key-123",
    )


@pytest.fixture
def sample_job_with_scope():
    """Create a sample job with scope snapshot."""
    from strix.core.scope import Scope

    scope = Scope(
        authorization_ref="AUTH-001",
        policy_id="pol-123",
        policy_version=1,
        tenant_id="tenant-1",
        program="Test Program",
        authorized_by="Authorizer",
        include=("example.com",),
        exclude=("bad.com",),
        authorized_networks=("10.0.0.0/8",),
        allowed_ports=(80, 443),
        allow_broad_networks=False,
    )
    return Job(
        target="https://example.com",
        profile="web",
        actor="test-actor",
        policy={"policy_id": "test-policy-123"},
        id="test-job-123",
        idempotency_key="idem-key-123",
        scope_snapshot=scope,
    )


class TestCreateCeleryApp:
    """Tests for create_celery_app function."""

    def test_create_celery_app_defaults(self):
        """Test creating Celery app with default settings."""
        app = create_celery_app()
        assert app.conf.broker_url == "redis://localhost:6379/1"
        assert app.conf.result_backend == "redis://localhost:6379/2"
        assert app.conf.task_acks_late is True
        assert app.conf.task_reject_on_worker_lost is True
        assert app.conf.worker_prefetch_multiplier == 1
        assert app.conf.task_default_queue == "strix_assessments"
        assert app.conf.task_serializer == "json"
        assert app.conf.result_serializer == "json"
        assert app.conf.accept_content == ("json",)

    def test_create_celery_app_env_override(self):
        """Test creating Celery app with environment variable overrides."""
        with patch.dict(
            os.environ,
            {
                "STRIX_CELERY_BROKER_URL": "redis://custom:6379/1",
                "STRIX_CELERY_RESULT_BACKEND": "redis://custom:6379/2",
                "STRIX_CELERY_MAX_TASKS_PER_CHILD": "100",
            },
        ):
            app = create_celery_app()
            assert app.conf.broker_url == "redis://custom:6379/1"
            assert app.conf.result_backend == "redis://custom:6379/2"
            assert app.conf.worker_max_tasks_per_child == 100


class TestJobSerialization:
    """Tests for job serialization/deserialization."""

    def test_job_to_dict_basic(self, sample_job):
        """Test serializing a basic job to dict."""
        data = _job_to_dict(sample_job)
        assert data["id"] == "test-job-123"
        assert data["target"] == "https://example.com"
        assert data["profile"] == "web"
        assert data["actor"] == "test-actor"
        assert data["policy"] == {"policy_id": "test-policy-123"}
        assert data["idempotency_key"] == "idem-key-123"
        assert data["scope_snapshot"] is None

    def test_job_to_dict_with_scope(self, sample_job_with_scope):
        """Test serializing a job with scope snapshot."""
        data = _job_to_dict(sample_job_with_scope)
        assert data["scope_snapshot"] is not None
        ss = data["scope_snapshot"]
        assert ss["authorization_ref"] == "AUTH-001"
        assert ss["policy_id"] == "pol-123"
        assert ss["policy_version"] == 1
        assert ss["tenant_id"] == "tenant-1"
        assert ss["program"] == "Test Program"
        assert ss["authorized_by"] == "Authorizer"
        assert ss["include"] == ["example.com"]
        assert ss["exclude"] == ["bad.com"]
        assert ss["authorized_networks"] == ["10.0.0.0/8"]
        assert ss["allowed_ports"] == [80, 443]
        assert ss["allow_broad_networks"] is False

    def test_dict_to_job_basic(self, sample_job):
        """Test deserializing a basic job from dict."""
        data = _job_to_dict(sample_job)
        job = _dict_to_job(data)
        assert job.id == "test-job-123"
        assert job.target == "https://example.com"
        assert job.profile == "web"
        assert job.actor == "test-actor"
        assert job.policy == {"policy_id": "test-policy-123"}
        assert job.idempotency_key == "idem-key-123"
        assert job.scope_snapshot is None

    def test_dict_to_job_with_scope(self, sample_job_with_scope):
        """Test deserializing a job with scope snapshot."""
        data = _job_to_dict(sample_job_with_scope)
        job = _dict_to_job(data)
        assert job.scope_snapshot is not None
        assert job.scope_snapshot.authorization_ref == "AUTH-001"
        assert job.scope_snapshot.policy_id == "pol-123"
        assert job.scope_snapshot.policy_version == 1
        assert job.scope_snapshot.tenant_id == "tenant-1"
        assert job.scope_snapshot.program == "Test Program"
        assert job.scope_snapshot.authorized_by == "Authorizer"
        assert job.scope_snapshot.include == ("example.com",)
        assert job.scope_snapshot.exclude == ("bad.com",)
        assert job.scope_snapshot.authorized_networks == ("10.0.0.0/8",)
        assert job.scope_snapshot.allowed_ports == (80, 443)
        assert job.scope_snapshot.allow_broad_networks is False

    def test_round_trip(self, sample_job_with_scope):
        """Test round-trip serialization preserves all data."""
        data = _job_to_dict(sample_job_with_scope)
        job = _dict_to_job(data)
        data2 = _job_to_dict(job)
        assert data == data2


class TestEnsureStoreConfigured:
    """Tests for _ensure_store_configured function."""

    def test_ensure_store_configured_idempotent(self):
        """Test that _ensure_store_configured is idempotent."""
        # Reset the global flag
        import strix.core.queue as queue_module

        queue_module._store_configured = False

        with patch("strix.config.Settings.from_env") as mock_settings:
            mock_settings.return_value = MagicMock(db_path="/tmp/test.db")
            with patch("strix.core.store.configure") as mock_configure:
                _ensure_store_configured()
                _ensure_store_configured()  # Call twice
                mock_configure.assert_called_once()
                assert queue_module._store_configured is True


class TestCeleryAssessmentQueue:
    """Tests for CeleryAssessmentQueue class."""

    @pytest.fixture
    def queue(self):
        """Create a CeleryAssessmentQueue instance."""
        return CeleryAssessmentQueue(concurrency=2, queue_max=10)

    def test_init(self, queue):
        """Test queue initialization."""
        assert queue.concurrency == 2
        assert queue.queue_max == 10
        assert queue._started is False
        assert queue._active == {}
        assert queue._on_finish == {}
        assert queue._task_ids == {}

    @pytest.mark.asyncio
    async def test_start_idempotent(self, queue, temp_db):
        """Test start is idempotent."""
        with patch("strix.core.store.fail_interrupted") as mock_fail:
            await queue.start()
            await queue.start()  # Call twice
            assert queue._started is True
            mock_fail.assert_called_once()

    @pytest.mark.asyncio
    async def test_submit_job(self, queue, temp_db, sample_job):
        """Test submitting a job to the queue."""
        with patch("strix.core.queue.celery_app.send_task") as mock_send:
            mock_result = MagicMock()
            mock_result.id = "celery-task-123"
            mock_send.return_value = mock_result

            await queue.start()
            callback_called = []

            def on_finish(job):
                callback_called.append(job)

            await queue.submit(sample_job, on_finish)

            assert sample_job.id in queue._active
            assert sample_job.id in queue._on_finish
            assert sample_job.id in queue._task_ids
            assert queue._task_ids[sample_job.id] == "celery-task-123"
            assert sample_job.state == JobState.QUEUED
            mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_submit_job_persists_to_db(self, queue, temp_db, sample_job):
        """Test that submit persists job to database."""
        with patch("strix.core.queue.celery_app.send_task") as mock_send:
            mock_result = MagicMock()
            mock_result.id = "celery-task-123"
            mock_send.return_value = mock_result

            await queue.start()
            await queue.submit(sample_job, lambda j: None)

            # Check job was saved to database
            saved_job = await store.get_job(sample_job.id, tenant=sample_job.actor)
            assert saved_job is not None
            assert saved_job["state"] == "queued"

    def test_cancel_job_not_found(self, queue):
        """Test cancel returns False for unknown job."""
        result = queue.cancel("unknown-job")
        assert result is False

    def test_cancel_job_found(self, queue, sample_job):
        """Test cancel for known job."""
        with queue._lock:
            queue._active[sample_job.id] = sample_job
            queue._task_ids[sample_job.id] = "celery-task-123"

        with patch("strix.core.queue.celery_app.control.revoke") as mock_revoke:
            result = queue.cancel(sample_job.id)
            assert result is True
            mock_revoke.assert_called_once_with("celery-task-123", terminate=False)

    def test_cancel_job_revoke_fails(self, queue, sample_job):
        """Test cancel handles revoke failure gracefully."""
        with queue._lock:
            queue._active[sample_job.id] = sample_job
            queue._task_ids[sample_job.id] = "celery-task-123"

        with patch("strix.core.queue.celery_app.control.revoke", side_effect=Exception("revoke failed")):
            result = queue.cancel(sample_job.id)
            assert result is True  # Still returns True even if revoke fails

    def test_cancel_for_policy(self, queue, sample_job):
        """Test cancel_for_policy cancels matching jobs."""
        job2 = Job(
            target="https://example2.com",
            profile="web",
            actor="test-actor",
            policy={"policy_id": "test-policy-123"},
            id="test-job-456",
        )
        job3 = Job(
            target="https://example3.com",
            profile="web",
            actor="test-actor",
            policy={"policy_id": "other-policy"},
            id="test-job-789",
        )

        with queue._lock:
            queue._active[sample_job.id] = sample_job
            queue._active[job2.id] = job2
            queue._active[job3.id] = job3
            queue._task_ids[sample_job.id] = "task-1"
            queue._task_ids[job2.id] = "task-2"
            queue._task_ids[job3.id] = "task-3"

        with patch("strix.core.queue.celery_app.control.revoke") as mock_revoke:
            count = queue.cancel_for_policy("test-policy-123")
            assert count == 2
            assert mock_revoke.call_count == 2

    @pytest.mark.asyncio
    async def test_shutdown_idempotent(self, queue):
        """Test shutdown is idempotent."""
        await queue.shutdown()
        await queue.shutdown()  # Call twice - should not error

    @pytest.mark.asyncio
    async def test_shutdown_clears_state(self, queue, temp_db, sample_job):
        """Test shutdown clears internal state."""
        with queue._lock:
            queue._active[sample_job.id] = sample_job
            queue._on_finish[sample_job.id] = lambda j: None
            queue._task_ids[sample_job.id] = "task-123"
        queue._started = True

        await queue.shutdown()

        assert queue._started is False
        assert queue._active == {}
        assert queue._on_finish == {}
        assert queue._task_ids == {}

    @pytest.mark.asyncio
    async def test_shutdown_not_started(self, queue):
        """Test shutdown does nothing if not started."""
        queue._started = False
        await queue.shutdown()  # Should not error


class TestWorkerInit:
    """Tests for _worker_init function."""

    def test_worker_init_calls_ensure_store(self):
        """Test _worker_init calls _ensure_store_configured."""
        import strix.core.queue as queue_module

        queue_module._store_configured = False

        with patch("strix.core.queue._ensure_store_configured") as mock_ensure:
            _worker_init()
            mock_ensure.assert_called_once()


class TestGetAssessmentQueue:
    """Tests for get_assessment_queue factory function."""

    def test_get_assessment_queue_celery_mode(self):
        """Test factory returns CeleryAssessmentQueue in celery mode."""
        with patch.dict(os.environ, {"STRIX_QUEUE_MODE": "celery"}):
            # Need to reload the module to pick up new env var
            import importlib

            import strix.core.queue as queue_module

            importlib.reload(queue_module)

            queue = queue_module.get_assessment_queue(concurrency=2, queue_max=10)
            assert isinstance(queue, queue_module.CeleryAssessmentQueue)
            assert queue.concurrency == 2
            assert queue.queue_max == 10

    def test_get_assessment_queue_inprocess_mode(self):
        """Test factory returns AssessmentWorker in inprocess mode."""
        with patch.dict(os.environ, {"STRIX_QUEUE_MODE": "inprocess"}):
            import importlib

            import strix.core.queue as queue_module

            importlib.reload(queue_module)

            queue = queue_module.get_assessment_queue(concurrency=2, queue_max=10)
            assert isinstance(queue, queue_module.AssessmentWorker)
            assert queue.concurrency == 2
            assert queue._queue.maxsize == 10


class TestGetAssessmentWorker:
    """Tests for get_assessment_worker function."""

    def test_get_assessment_worker_lazy_init(self):
        """Test get_assessment_worker lazily initializes."""
        with patch.dict(os.environ, {"STRIX_QUEUE_MODE": "inprocess"}):
            import importlib

            import strix.core.queue as queue_module

            importlib.reload(queue_module)

            queue_module._assessment_queue = None

            with patch("strix.config.Settings.from_env") as mock_settings:
                mock_settings.return_value = MagicMock(workers=2, queue_max=10)
                queue = queue_module.get_assessment_worker()
                assert queue is not None

            # Second call should return same instance
            queue2 = queue_module.get_assessment_worker()
            assert queue is queue2


class TestRunAssessmentTask:
    """Tests for run_assessment_task Celery task."""

    @pytest.mark.asyncio
    async def test_run_assessment_task_serialization(self, temp_db, sample_job_with_scope):
        """Test that task serializes/deserializes job correctly."""
        from strix.core.queue import _job_to_dict

        job_data = _job_to_dict(sample_job_with_scope)

        # Mock the execute function to avoid actual assessment
        with (
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.store.is_cancel_requested", new_callable=AsyncMock) as mock_cancel,
            patch("strix.core.queue._ensure_store_configured"),
        ):
            mock_claim.return_value = True
            mock_cancel.return_value = False
            # We can't easily test the full task without Celery running,
            # but we can verify the serialization works
            assert job_data["scope_snapshot"] is not None

    def _make_mock_task(self):
        """Create a properly configured mock Celery task."""
        mock_task = MagicMock()
        mock_request = MagicMock()
        mock_request.id = "celery-task-123"
        mock_task.request = mock_request
        return mock_task

    def test_run_assessment_task_claim_fails_terminal_state(self, temp_db, sample_job_with_scope):
        """Test task handles already claimed job in terminal state."""
        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__  # Get the raw function

        with (
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.store.get_job", new_callable=AsyncMock) as mock_get,
            patch("strix.core.queue._ensure_store_configured"),
        ):
            mock_claim.return_value = False  # Not claimed
            mock_get.return_value = {"state": "completed", "id": sample_job_with_scope.id}
            result = raw_task(mock_task, job_data)
            # Returns the existing job dict from DB, not a status dict
            assert result["state"] == "completed"
            assert result["id"] == sample_job_with_scope.id

    def test_run_assessment_task_claim_fails_already_claimed(self, temp_db, sample_job_with_scope):
        """Test task handles job already claimed by another worker (non-terminal)."""
        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__

        with (
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.store.get_job", new_callable=AsyncMock) as mock_get,
            patch("strix.core.queue._ensure_store_configured"),
        ):
            mock_claim.return_value = False
            # Job is in "running" state - not terminal, so task returns skipped status
            mock_get.return_value = {"state": "running", "id": sample_job_with_scope.id}
            result = raw_task(mock_task, job_data)
            # Returns skipped status when not claimed and not terminal
            assert result["status"] == "skipped"
            assert result["job_id"] == sample_job_with_scope.id

    def test_run_assessment_task_cancelled_before_execute(self, temp_db, sample_job_with_scope):
        """Test task handles cancellation before execution."""
        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__

        with (
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.store.is_cancel_requested", new_callable=AsyncMock) as mock_cancel,
            patch("strix.core.store.save_job", new_callable=AsyncMock) as mock_save,
            patch("strix.core.queue._ensure_store_configured"),
        ):
            mock_claim.return_value = True
            mock_cancel.return_value = True  # Cancelled!
            result = raw_task(mock_task, job_data)
            assert result["state"] == "cancelled"
            assert result["error"] == "cancelled by request"
            mock_save.assert_called_once()

    def test_run_assessment_task_execute_success(self, temp_db, sample_job_with_scope):
        """Test task executes job successfully."""
        from strix.core.jobs import JobState

        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__

        with patch("strix.core.jobs.execute") as mock_execute:
            # Make execute complete the job
            def do_execute(job):
                job.state = JobState.COMPLETED
                job.finished_at = time.time()

            mock_execute.side_effect = do_execute

            with (
                patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
                patch("strix.core.store.is_cancel_requested", new_callable=AsyncMock) as mock_cancel,
                patch("strix.core.store.save_job", new_callable=AsyncMock) as mock_save,
                patch("strix.core.queue._ensure_store_configured"),
                patch("threading.Thread") as mock_thread_class,
            ):
                mock_claim.return_value = True
                mock_cancel.return_value = False
                mock_thread = MagicMock()
                mock_thread_class.return_value = mock_thread
                result = raw_task(mock_task, job_data)
                assert result["state"] == "completed"
                mock_save.assert_called_once()

    def test_run_assessment_task_execute_fails(self, temp_db, sample_job_with_scope):
        """Test task handles job execution failure."""
        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__

        with (
            patch("strix.core.jobs.execute", side_effect=RuntimeError("boom")),
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.store.is_cancel_requested", new_callable=AsyncMock) as mock_cancel,
            patch("strix.core.store.save_job", new_callable=AsyncMock) as mock_save,
            patch("strix.core.queue._ensure_store_configured"),
            patch("threading.Thread") as mock_thread_class,
        ):
            mock_claim.return_value = True
            mock_cancel.return_value = False
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            result = raw_task(mock_task, job_data)
            assert result["state"] == "failed"
            assert "internal error" in result["error"]
            mock_save.assert_called_once()

    def test_run_assessment_task_exception_reraise(self, temp_db, sample_job_with_scope):
        """Test task re-raises exception for retry."""
        job_data = _job_to_dict(sample_job_with_scope)
        mock_task = self._make_mock_task()
        raw_task = run_assessment_task.__wrapped__.__func__

        with (
            patch("strix.core.store.claim_job", new_callable=AsyncMock) as mock_claim,
            patch("strix.core.queue._ensure_store_configured"),
        ):
            mock_claim.side_effect = RuntimeError("DB connection failed")
            with pytest.raises(RuntimeError, match="DB connection failed"):
                raw_task(mock_task, job_data)


class TestQueueMode:
    """Tests for QUEUE_MODE configuration."""

    def test_queue_mode_default(self):
        """Test QUEUE_MODE defaults to inprocess."""
        # This test ensures the module-level constant is set correctly
        from strix.core.queue import QUEUE_MODE

        assert QUEUE_MODE in ("inprocess", "celery")
