"""Unit tests for Ishastra Assessments Router."""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from ishastra.api.routers import assessments
from ishastra.api.schemas import (
    AssessRequest,
    AssessResponse,
    FindingStatusUpdate,
    Page,
    ReportRequest,
)
from ishastra.core import jobs
from ishastra.core.findings import Finding
from ishastra.core.jobs import Job, JobState, RunState
from ishastra.security.authorization.scope import Scope


@pytest.fixture
def mock_tenant() -> dict[str, Any]:
    """Mock tenant for authentication."""
    return {
        "tenant_id": "test-tenant-1",
        "tier": "standard",
        "admin": False,
        "record": {
            "key_hash": "abc123",
            "tier": "standard",
            "admin": False,
            "active": True,
            "created_at": time.time(),
        },
    }


@pytest.fixture
def admin_tenant() -> dict[str, Any]:
    """Mock admin tenant."""
    return {
        "tenant_id": "admin-tenant",
        "tier": "unlimited",
        "admin": True,
        "record": {
            "key_hash": "admin123",
            "tier": "unlimited",
            "admin": True,
            "active": True,
            "created_at": time.time(),
        },
    }


@pytest.fixture
def mock_scope() -> Scope:
    """Mock scope that allows test targets."""
    scope = MagicMock(spec=Scope)
    scope.check = MagicMock(return_value=(None, "ok"))
    scope.program = "Test Program"
    scope.authorized_by = "Test Authorizer"
    scope.authorization_ref = "TEST-001"
    scope.include = ["example.com", "*.example.com", "httpbin.org", "*.httpbin.org"]
    return scope


@pytest.fixture
def mock_job() -> Job:
    """Create a mock job for testing."""
    job = Job(
        target="https://example.com",
        profile="web",
        actor="test-tenant-1",
        policy={"policy_id": "pol-1", "policy_version": 1, "timeout": 120.0},
        scope_snapshot=None,
    )
    job.id = "job_abc123"
    job.state = JobState.QUEUED
    job.started_at = None
    job.finished_at = None
    job.runs = []
    job.findings = []
    job.error = ""
    job.attempts = 0
    job.worker_id = ""
    job.idempotency_key = "test-key-123"
    return job


@pytest.fixture
def mock_completed_job() -> Job:
    """Create a mock completed job with findings."""
    job = Job(
        target="https://example.com",
        profile="web",
        actor="test-tenant-1",
        policy={"policy_id": "pol-1", "policy_version": 1, "timeout": 120.0},
        scope_snapshot=None,
    )
    job.id = "job_completed_1"
    job.state = JobState.COMPLETED
    job.started_at = time.time() - 100
    job.finished_at = time.time()
    job.runs = [jobs.AdapterRun(adapter="ishastra-http", state=RunState.OK, findings=2, elapsed_ms=5000.0)]
    job.findings = [
        Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing Content-Security-Policy header",
            severity="low",
            confidence="medium",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence="HTTP 200 response carries no Content-Security-Policy header",
            location="https://example.com/",
            cwe="CWE-693",
            verification="observed",
        ),
        Finding(
            asset="https://example.com/",
            category="missing_hsts",
            title="Missing Strict-Transport-Security header",
            severity="low",
            confidence="medium",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence="HTTPS response 200 carries no Strict-Transport-Security header",
            location="https://example.com/",
            cwe="CWE-319",
            verification="observed",
        ),
    ]
    job.error = ""
    job.attempts = 1
    job.worker_id = "worker-1"
    job.idempotency_key = "test-key-456"
    return job


@pytest.fixture
def mock_failed_job() -> Job:
    """Create a mock failed job."""
    job = Job(
        target="https://example.com",
        profile="web",
        actor="test-tenant-1",
        policy={"policy_id": "pol-1", "policy_version": 1, "timeout": 120.0},
        scope_snapshot=None,
    )
    job.id = "job_failed_1"
    job.state = JobState.FAILED
    job.started_at = time.time() - 50
    job.finished_at = time.time()
    job.runs = []
    job.findings = []
    job.error = "Worker crashed"
    job.attempts = 1
    job.worker_id = "worker-1"
    job.idempotency_key = "test-key-789"
    return job


@pytest.fixture
def sample_findings() -> list[dict[str, Any]]:
    """Sample findings for testing."""
    return [
        {
            "fingerprint": "a" * 32,
            "asset": "https://example.com/",
            "category": "missing_csp",
            "title": "Missing Content-Security-Policy header",
            "severity": "low",
            "confidence": "medium",
            "detector": "ishastra-http",
            "detector_version": "1.0.0",
            "evidence": "No CSP header",
            "location": "https://example.com/",
            "cwe": "CWE-693",
            "verification": "observed",
            "status": "new",
        },
        {
            "fingerprint": "b" * 32,
            "asset": "https://example.com/",
            "category": "missing_hsts",
            "title": "Missing Strict-Transport-Security header",
            "severity": "low",
            "confidence": "medium",
            "detector": "ishastra-http",
            "detector_version": "1.0.0",
            "evidence": "No HSTS header",
            "location": "https://example.com/",
            "cwe": "CWE-319",
            "verification": "observed",
            "status": "new",
        },
    ]


class TestIdempotencyKey:
    """Test the _idempotency_key helper function."""

    def test_none_key(self):
        """None key returns None."""
        assert assessments._idempotency_key(None) is None

    def test_empty_string(self):
        """Empty string returns None."""
        assert assessments._idempotency_key("") is None

    def test_whitespace_only(self):
        """Whitespace-only string returns None."""
        assert assessments._idempotency_key("   ") is None

    def test_valid_key(self):
        """Valid key returns stripped key."""
        assert assessments._idempotency_key("  valid-key_123  ") == "valid-key_123"

    def test_valid_special_chars(self):
        """Key with allowed special chars works."""
        assert assessments._idempotency_key("test.key:_value-123") == "test.key:_value-123"

    def test_invalid_key_too_long(self):
        """Key longer than 128 chars raises 400."""
        long_key = "a" * 129
        with pytest.raises(HTTPException) as exc:
            assessments._idempotency_key(long_key)
        assert exc.value.status_code == 400
        assert "1-128 characters" in exc.value.detail

    def test_invalid_key_bad_chars(self):
        """Key with invalid chars raises 400."""
        with pytest.raises(HTTPException) as exc:
            assessments._idempotency_key("invalid@key#")
        assert exc.value.status_code == 400
        assert "A-Z a-z 0-9 . _ : -" in exc.value.detail


class TestLinks:
    """Test the _links helper function."""

    def test_links_generated(self):
        """Links are generated correctly."""
        links = assessments._links("job_123")
        assert links["sarif_url"] == "/api/assess/job_123/sarif"
        assert links["report_url"] == "/api/assess/job_123/report.html"


class TestCreateAssessment:
    """Test POST /api/assess endpoint."""

    @pytest.mark.asyncio
    async def test_create_assessment_happy_path_wait_false(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test creating an assessment with wait=False (queued)."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job) as mock_prepare,
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock) as mock_save,
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                timeout=120.0,
                wait=False,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 202
            content = json.loads(result.body)
            assert content["id"] == "job_abc123"
            assert content["target"] == "https://example.com"
            assert content["profile"] == "web"
            assert content["state"] == "queued"
            assert content["deduplicated"] is False
            assert "poll_url" in content
            assert "cancel_url" in content

            mock_prepare.assert_called_once()
            mock_save.assert_called_once()
            mock_worker.submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_assessment_wait_true_inline(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_completed_job: Job,
    ):
        """Test creating an assessment with wait=True (inline execution)."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch(
                "ishastra.api.routers.assessments.jobs.run_assessment", return_value=mock_completed_job
            ) as mock_run,
            patch(
                "ishastra.api.routers.assessments.record_job",
                new_callable=AsyncMock,
                return_value={
                    **mock_completed_job.to_dict(),
                    **assessments._links(mock_completed_job.id),
                    "poll_url": f"/api/assess/{mock_completed_job.id}",
                    "cancel_url": f"/api/assess/{mock_completed_job.id}/cancel",
                    "audit_chain_hash": "hash123",
                },
            ) as mock_record,
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                timeout=120.0,
                wait=True,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, AssessResponse)
            assert result.id == "job_completed_1"
            assert result.state == "completed"
            assert result.deduplicated is False

            mock_run.assert_called_once()
            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_assessment_wait_true_timeout_limit(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test wait=True with timeout exceeding MAX_INLINE_TIMEOUT raises 400."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                timeout=200.0,
                wait=True,
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 400
            assert "wait=true is limited to 120s" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_empty_target(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test empty target raises 400."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            req = AssessRequest(
                target="   ",
                profile="web",
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 400
            assert "Target cannot be empty" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_unknown_profile(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test unknown profile raises 400."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="unknown-profile",
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 400
            assert "unknown profile" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_idempotency_duplicate_queued(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test idempotency key returns existing job when queued."""
        existing_job = {
            **mock_job.to_dict(),
            **assessments._links(mock_job.id),
            "poll_url": f"/api/assess/{mock_job.id}",
            "cancel_url": f"/api/assess/{mock_job.id}/cancel",
            "deduplicated": True,
        }

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=existing_job,
            ),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=False,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 202
            content = json.loads(result.body)
            assert content["deduplicated"] is True

    @pytest.mark.asyncio
    async def test_create_assessment_idempotency_duplicate_completed(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test idempotency key returns existing job when completed."""
        existing_job = {
            **mock_completed_job.to_dict(),
            **assessments._links(mock_completed_job.id),
            "poll_url": f"/api/assess/{mock_completed_job.id}",
            "cancel_url": f"/api/assess/{mock_completed_job.id}/cancel",
            "deduplicated": True,
        }

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=existing_job,
            ),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=False,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 200
            content = json.loads(result.body)
            assert content["deduplicated"] is True

    @pytest.mark.asyncio
    async def test_create_assessment_target_refused(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test refused target raises 403."""
        mock_scope.check.return_value = ("out_of_scope", "Target not in scope")

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            req = AssessRequest(
                target="https://evil.com",
                profile="web",
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_create_assessment_invalid_target_format(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test invalid target format raises 400."""
        mock_scope.check.return_value = ("invalid_target", "Invalid URL")

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            req = AssessRequest(
                target="not-a-url",
                profile="web",
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_create_assessment_auth_config_encrypts(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test auth config is encrypted when provided."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch("ishastra.api.routers.assessments.deps_settings") as mock_settings,
            patch("ishastra.api.routers.assessments.create_authenticator_from_dict") as mock_create_auth,
            patch("ishastra.api.routers.assessments.EncryptedAuthConfig.create") as mock_encrypt,
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            mock_settings.encryption_key = "test-key"
            mock_create_auth.return_value = MagicMock()
            mock_encrypt.return_value = MagicMock(
                principal_id="auth-1",
                authenticator_type="token",
                encrypted_config="encrypted",
                created_at=time.time(),
            )

            req = AssessRequest(
                target="https://example.com",
                profile="web",
                auth={"type": "token", "bearer": "secret-token"},
            )

            await assessments.create_assessment(req, mock_tenant)

            mock_create_auth.assert_called_once()
            mock_encrypt.assert_called_once()
            mock_worker.submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_assessment_auth_missing_encryption_key(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test auth config fails when encryption key not configured."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.deps_settings") as mock_settings,
        ):
            mock_settings.encryption_key = None

            req = AssessRequest(
                target="https://example.com",
                profile="web",
                auth={"type": "token", "bearer": "secret-token"},
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 500
            assert "encryption key not configured" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_queue_full(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test queue full raises 503."""
        from ishastra.core.worker import AssessmentQueueFull

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_worker.submit.side_effect = AssessmentQueueFull("queue full")
            mock_get_worker.return_value = mock_worker

            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=False,
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 503
            assert "queue is full" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_worker_lease_error(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test worker lease error raises 503."""
        from ishastra.core.worker import WorkerLeaseError

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_worker.submit.side_effect = WorkerLeaseError("another worker owns the lease")
            mock_get_worker.return_value = mock_worker

            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=False,
            )

            with pytest.raises(HTTPException) as exc:
                await assessments.create_assessment(req, mock_tenant)

            assert exc.value.status_code == 503
            assert "worker unavailable" in exc.value.detail

    @pytest.mark.asyncio
    async def test_create_assessment_job_conflict_wait_true(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_completed_job: Job,
    ):
        """Test job conflict on inline execution falls back to existing job."""
        from ishastra.core.store import JobConflict

        existing_job = {
            **mock_completed_job.to_dict(),
            **assessments._links(mock_completed_job.id),
            "poll_url": f"/api/assess/{mock_completed_job.id}",
            "cancel_url": f"/api/assess/{mock_completed_job.id}/cancel",
            "deduplicated": True,
        }

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.run_assessment", return_value=mock_completed_job),
            patch(
                "ishastra.api.routers.assessments.record_job",
                new_callable=AsyncMock,
                side_effect=JobConflict("conflict"),
            ),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=existing_job,
            ),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=True,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 200
            content = json.loads(result.body)
            assert content["deduplicated"] is True

    @pytest.mark.asyncio
    async def test_create_assessment_job_conflict_queued(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test job conflict on queued execution falls back to existing job."""
        from ishastra.core.store import JobConflict

        existing_job = {
            **mock_job.to_dict(),
            **assessments._links(mock_job.id),
            "poll_url": f"/api/assess/{mock_job.id}",
            "cancel_url": f"/api/assess/{mock_job.id}/cancel",
            "deduplicated": True,
        }

        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value="test-key"),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch(
                "ishastra.api.routers.assessments.store.save_job",
                new_callable=AsyncMock,
                side_effect=JobConflict("conflict"),
            ),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=existing_job,
            ),
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                wait=False,
            )

            result = await assessments.create_assessment(req, mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 202
            content = json.loads(result.body)
            assert content["deduplicated"] is True


class TestListAssessments:
    """Test GET /api/assess endpoint."""

    @pytest.mark.asyncio
    async def test_list_assessments_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test listing assessments."""
        job_dict = mock_job.to_dict()
        job_dict["findings"] = []

        with (
            patch(
                "ishastra.api.routers.assessments.store.list_jobs",
                new_callable=AsyncMock,
                return_value=[job_dict],
            ),
            patch(
                "ishastra.api.routers.assessments.store.count_jobs",
                new_callable=AsyncMock,
                return_value=1,
            ),
        ):
            result = await assessments.list_assessments(page=1, page_size=20, tenant=mock_tenant)

            assert isinstance(result, Page)
            assert result.total == 1
            assert result.page == 1
            assert result.page_size == 20
            assert len(result.items) == 1
            assert result.items[0].id == "job_abc123"
            assert result.items[0].target == "https://example.com"
            assert result.has_next is False

    @pytest.mark.asyncio
    async def test_list_assessments_pagination(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test pagination has_next calculation."""
        job_dict = mock_job.to_dict()
        job_dict["findings"] = []

        with (
            patch(
                "ishastra.api.routers.assessments.store.list_jobs",
                new_callable=AsyncMock,
                return_value=[job_dict, job_dict],
            ) as mock_list,
            patch(
                "ishastra.api.routers.assessments.store.count_jobs",
                new_callable=AsyncMock,
                return_value=50,
            ),
        ):
            result = await assessments.list_assessments(page=2, page_size=20, tenant=mock_tenant)

            assert result.total == 50
            assert result.page == 2
            assert result.has_next is True
            assert mock_list.call_args.kwargs["offset"] == 20

    @pytest.mark.asyncio
    async def test_list_assessments_empty(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test empty list."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.list_jobs",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "ishastra.api.routers.assessments.store.count_jobs",
                new_callable=AsyncMock,
                return_value=0,
            ),
        ):
            result = await assessments.list_assessments(page=1, page_size=20, tenant=mock_tenant)

            assert result.total == 0
            assert len(result.items) == 0
            assert result.has_next is False


class TestGetAssessment:
    """Test GET /api/assess/{job_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_assessment_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test getting a job by ID."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_completed_job.to_dict(),
        ):
            result = await assessments.get_assessment("job_completed_1", mock_tenant)

            assert result["id"] == "job_completed_1"
            assert result["target"] == "https://example.com"
            assert result["state"] == "completed"

    @pytest.mark.asyncio
    async def test_get_assessment_not_found(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test getting non-existent job raises 404."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=None,
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.get_assessment("job_nonexistent", mock_tenant)

            assert exc.value.status_code == 404
            assert "Unknown job" in exc.value.detail


class TestGetSarif:
    """Test GET /api/assess/{job_id}/sarif endpoint."""

    @pytest.mark.asyncio
    async def test_get_sarif_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
        sample_findings: list[dict[str, Any]],
    ):
        """Test getting SARIF export."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_findings",
                new_callable=AsyncMock,
                return_value=mock_completed_job.findings,
            ),
            patch("ishastra.api.routers.assessments.to_sarif", return_value={"version": "2.1.0", "runs": []}),
        ):
            result = await assessments.get_sarif("job_completed_1", mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.media_type == "application/sarif+json"
            content = json.loads(result.body)
            assert "version" in content

    @pytest.mark.asyncio
    async def test_get_sarif_job_not_found(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test SARIF for non-existent job raises 404."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=None,
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.get_sarif("job_nonexistent", mock_tenant)

            assert exc.value.status_code == 404


class TestUpdateFindingStatus:
    """Test PATCH /api/assess/{job_id}/findings/{fingerprint} endpoint."""

    @pytest.mark.asyncio
    async def test_update_finding_status_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test updating finding status."""
        finding = mock_completed_job.findings[0]
        fingerprint = finding.fingerprint
        updated_finding = finding.to_dict()
        updated_finding["status"] = "triaged"

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.update_finding_status",
                new_callable=AsyncMock,
                return_value=updated_finding,
            ) as mock_update,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments.redact_text", return_value="note"),
        ):
            update = FindingStatusUpdate(status="triaged", note="Looking into it")
            result = await assessments.update_finding_status(
                "job_completed_1", fingerprint, update, mock_tenant
            )

            assert result["status"] == "triaged"
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_finding_status_active_job_rejected(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test updating finding on active job raises 409."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_job.to_dict(),
        ):
            update = FindingStatusUpdate(status="triaged")
            with pytest.raises(HTTPException) as exc:
                await assessments.update_finding_status("job_abc123", "a" * 32, update, mock_tenant)

            assert exc.value.status_code == 409
            assert "Wait for the assessment to finish" in exc.value.detail

    @pytest.mark.asyncio
    async def test_update_finding_status_invalid_fingerprint(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test invalid fingerprint format raises 404."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_completed_job.to_dict(),
        ):
            update = FindingStatusUpdate(status="triaged")
            with pytest.raises(HTTPException) as exc:
                await assessments.update_finding_status(
                    "job_completed_1", "invalid-fingerprint", update, mock_tenant
                )

            assert exc.value.status_code == 404
            assert "Unknown finding" in exc.value.detail

    @pytest.mark.asyncio
    async def test_update_finding_status_not_found(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test fingerprint not in job raises 404."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.update_finding_status",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            update = FindingStatusUpdate(status="triaged")
            with pytest.raises(HTTPException) as exc:
                await assessments.update_finding_status("job_completed_1", "c" * 32, update, mock_tenant)

            assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_update_finding_status_invalid_transition(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test invalid status transition raises 409."""

        finding = mock_completed_job.findings[0]
        fingerprint = finding.fingerprint

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.update_finding_status",
                new_callable=AsyncMock,
                side_effect=ValueError("Invalid transition"),
            ),
        ):
            update = FindingStatusUpdate(status="closed")
            with pytest.raises(HTTPException) as exc:
                await assessments.update_finding_status("job_completed_1", fingerprint, update, mock_tenant)

            assert exc.value.status_code == 409
            assert "Invalid transition" in exc.value.detail


class TestCancelAssessment:
    """Test POST /api/assess/{job_id}/cancel endpoint."""

    @pytest.mark.asyncio
    async def test_cancel_assessment_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test cancelling a queued job."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
        ):
            mock_worker = AsyncMock()
            mock_worker.cancel.return_value = True
            mock_get_worker.return_value = mock_worker
            result = await assessments.cancel_assessment("job_abc123", mock_tenant)

            assert result["id"] == "job_abc123"
            assert result["state"] == "cancelling"
            assert "cancellation signalled" in result["detail"]
            mock_worker.cancel.assert_called_once_with("job_abc123")

    @pytest.mark.asyncio
    async def test_cancel_assessment_not_active(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test cancelling completed job raises 409."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_completed_job.to_dict(),
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.cancel_assessment("job_completed_1", mock_tenant)

            assert exc.value.status_code == 409
            assert "already completed" in exc.value.detail

    @pytest.mark.asyncio
    async def test_cancel_assessment_not_running_on_worker(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test cancelling job not on this worker raises 409."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.request_cancel",
                new_callable=AsyncMock,
            ) as mock_request_cancel,
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
        ):
            mock_request_cancel.return_value = False
            mock_worker = MagicMock()
            mock_worker.cancel.return_value = False
            mock_get_worker.return_value = mock_worker
            with pytest.raises(HTTPException) as exc:
                await assessments.cancel_assessment("job_abc123", mock_tenant)

            assert exc.value.status_code == 409
            assert "not running on this worker" in exc.value.detail


class TestRetryAssessment:
    """Test POST /api/assess/{job_id}/retry endpoint."""

    @pytest.mark.asyncio
    async def test_retry_assessment_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_failed_job: Job,
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test retrying a failed job."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_failed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job) as mock_prepare,
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock) as mock_save,
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            result = await assessments.retry_assessment("job_failed_1", mock_tenant)

            assert isinstance(result, assessments.JSONResponse)
            assert result.status_code == 202
            content = json.loads(result.body)
            assert content["retry_of"] == "job_failed_1"
            assert "poll_url" in content
            assert "cancel_url" in content

            mock_prepare.assert_called_once()
            mock_save.assert_called_once()
            mock_worker.submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_assessment_not_retryable_state(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test retrying completed job raises 409."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_completed_job.to_dict(),
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.retry_assessment("job_completed_1", mock_tenant)

            assert exc.value.status_code == 409
            assert "only a failed, partial or cancelled job can be retried" in exc.value.detail

    @pytest.mark.asyncio
    async def test_retry_assessment_empty_target(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test retrying job with empty stored target raises 409."""
        job_dict = {"id": "job_failed", "state": "failed", "target": "  ", "policy": {}}

        with patch(
            "ishastra.api.routers.assessments.store.get_job", new_callable=AsyncMock, return_value=job_dict
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.retry_assessment("job_failed", mock_tenant)

            assert exc.value.status_code == 409
            assert "Stored target is empty" in exc.value.detail

    @pytest.mark.asyncio
    async def test_retry_assessment_target_refused(
        self,
        mock_tenant: dict[str, Any],
        mock_failed_job: Job,
        mock_scope: Scope,
    ):
        """Test retry with refused target raises 403."""
        mock_scope.check.return_value = ("out_of_scope", "Target not in scope")

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_failed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.retry_assessment("job_failed_1", mock_tenant)

            assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_retry_assessment_queue_full(
        self,
        mock_tenant: dict[str, Any],
        mock_failed_job: Job,
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test retry when queue is full raises 503."""
        from ishastra.core.worker import AssessmentQueueFull

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_failed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
        ):
            mock_worker = AsyncMock()
            mock_worker.submit.side_effect = AssessmentQueueFull("queue full")
            mock_get_worker.return_value = mock_worker

            with pytest.raises(HTTPException) as exc:
                await assessments.retry_assessment("job_failed_1", mock_tenant)

            assert exc.value.status_code == 503
            assert "queue is full" in exc.value.detail


class TestBoundAuthorization:
    """Test _bound_authorization helper function."""

    def test_bound_authorization_complete(self):
        """Test complete authorization metadata."""
        job = {
            "policy": {
                "scope_program": "Test Program",
                "scope_authorized_by": "Test Authorizer",
                "authorization_ref": "TEST-001",
                "scope_include": ["example.com"],
                "policy_id": "pol-1",
                "policy_version": 1,
            }
        }

        result = assessments._bound_authorization(job)

        assert result["program"] == "Test Program"
        assert result["authorized_by"] == "Test Authorizer"
        assert result["authorization_ref"] == "TEST-001"
        assert result["scope_include"] == ["example.com"]
        assert result["policy_id"] == "pol-1"
        assert result["policy_version"] == 1
        assert result["available"] is True

    def test_bound_authorization_missing_fields(self):
        """Test incomplete authorization metadata."""
        job = {
            "policy": {
                "scope_program": "",
                "scope_authorized_by": None,
                "authorization_ref": "TEST-001",
                "scope_include": "not-a-list",
                "policy_id": "pol-1",
            }
        }

        result = assessments._bound_authorization(job)

        assert result["program"] == ""
        assert result["authorized_by"] == ""
        assert result["authorization_ref"] == "TEST-001"
        assert result["scope_include"] == []
        assert result["policy_id"] == "pol-1"
        assert result["policy_version"] is None
        assert result["available"] is False

    def test_bound_authorization_no_policy(self):
        """Test job with no policy."""
        job = {}

        result = assessments._bound_authorization(job)

        assert result["program"] == ""
        assert result["authorized_by"] == ""
        assert result["authorization_ref"] == ""
        assert result["scope_include"] == []
        assert result["policy_id"] is None
        assert result["policy_version"] is None
        assert result["available"] is False


class TestBuildReport:
    """Test POST /api/report endpoint."""

    @pytest.mark.asyncio
    async def test_build_report_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
        sample_findings: list[dict[str, Any]],
    ):
        """Test building a report for a finished job."""
        mock_completed_job.findings = [
            Finding(
                asset="https://example.com/",
                category="missing_csp",
                title="Missing CSP",
                severity="low",
                confidence="medium",
                detector="ishastra-http",
                detector_version="1.0.0",
                evidence="No CSP",
                location="https://example.com/",
                cwe="CWE-693",
                verification="observed",
            )
        ]

        with (
            patch(
                "ishastra.api.routers.assessments.store.latest_finished_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_findings",
                new_callable=AsyncMock,
                return_value=mock_completed_job.findings,
            ),
            patch(
                "ishastra.api.routers.assessments.deps.audit_chain.append_async",
                new_callable=AsyncMock,
                return_value="chain-hash-123",
            ),
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.deps.audit_chain.verify_async",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
        ):
            req = ReportRequest(target="https://example.com")
            result = await assessments.build_report(req, mock_tenant)

            assert result["target"] == "https://example.com"
            assert result["job_id"] == "job_completed_1"
            assert result["state"] == "completed"
            assert "severity_counts" in result
            assert result["severity_counts"]["low"] == 1
            assert "findings" in result
            assert len(result["findings"]) == 1
            assert "integrity" in result
            assert result["integrity"]["chain_hash"] == "chain-hash-123"

    @pytest.mark.asyncio
    async def test_build_report_no_finished_job(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
    ):
        """Test report when no finished job exists raises 404."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.latest_finished_job",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch("ishastra.api.routers.assessments.check_scope_or_raise_async", new_callable=AsyncMock),
        ):
            req = ReportRequest(target="https://example.com")
            with pytest.raises(HTTPException) as exc:
                await assessments.build_report(req, mock_tenant)

            assert exc.value.status_code == 404
            assert "No finished assessment" in exc.value.detail


class TestTriageAssessment:
    """Test POST /api/assess/{job_id}/triage endpoint."""

    @pytest.mark.asyncio
    async def test_triage_assessment_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test AI triage on finished job."""

        mock_triage = MagicMock()
        mock_triage.ai_enriched = False
        mock_triage.to_dict.return_value = {
            "findings": [],
            "ai_enriched": False,
        }

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.analyst.analyze_findings", return_value=mock_triage),
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
        ):
            result = await assessments.triage_assessment("job_completed_1", mock_tenant)

            assert result["job_id"] == "job_completed_1"
            assert result["findings_count"] == 2
            assert result["ai_enriched"] is False

    @pytest.mark.asyncio
    async def test_triage_assessment_wrong_state(
        self,
        mock_tenant: dict[str, Any],
        mock_job: Job,
    ):
        """Test triage on active job raises 409."""
        with patch(
            "ishastra.api.routers.assessments.store.get_job",
            new_callable=AsyncMock,
            return_value=mock_job.to_dict(),
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.triage_assessment("job_abc123", mock_tenant)

            assert exc.value.status_code == 409
            assert "triage needs findings" in exc.value.detail


class TestGetHtmlReport:
    """Test GET /api/assess/{job_id}/report.html endpoint."""

    @pytest.mark.asyncio
    async def test_get_html_report_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
        sample_findings: list[dict[str, Any]],
    ):
        """Test getting HTML report."""
        mock_completed_job.findings = [
            Finding(
                asset="https://example.com/",
                category="missing_csp",
                title="Missing CSP",
                severity="low",
                confidence="medium",
                detector="ishastra-http",
                detector_version="1.0.0",
                evidence="No CSP",
                location="https://example.com/",
                cwe="CWE-693",
                verification="observed",
            )
        ]

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_findings",
                new_callable=AsyncMock,
                return_value=mock_completed_job.findings,
            ),
            patch(
                "ishastra.api.routers.assessments.render_html_report", return_value="<html>Report</html>"
            ) as mock_render,
            patch("ishastra.api.routers.assessments.record_report") as mock_record,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.deps.audit_chain.verify_cached_async",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ),
        ):
            result = await assessments.get_html_report("job_completed_1", mock_tenant)

            assert isinstance(result, assessments.HTMLResponse)
            assert result.body == b"<html>Report</html>"
            mock_render.assert_called_once()
            mock_record.assert_called_once_with("html")


class TestGetPdfReport:
    """Test GET /api/assess/{job_id}/report.pdf endpoint."""

    @pytest.mark.asyncio
    async def test_get_pdf_report_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
        sample_findings: list[dict[str, Any]],
    ):
        """Test getting PDF report."""
        mock_completed_job.findings = [
            Finding(
                asset="https://example.com/",
                category="missing_csp",
                title="Missing CSP",
                severity="low",
                confidence="medium",
                detector="ishastra-http",
                detector_version="1.0.0",
                evidence="No CSP",
                location="https://example.com/",
                cwe="CWE-693",
                verification="observed",
            )
        ]

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_findings",
                new_callable=AsyncMock,
                return_value=mock_completed_job.findings,
            ),
            patch(
                "ishastra.api.routers.assessments.generate_pdf_from_job", return_value=b"%PDF-1.4\n..."
            ) as mock_pdf,
            patch("ishastra.api.routers.assessments.record_report") as mock_record,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
        ):
            result = await assessments.get_pdf_report("job_completed_1", mock_tenant)

            assert isinstance(result, assessments.Response)
            assert result.media_type == "application/pdf"
            assert result.body == b"%PDF-1.4\n..."
            assert "Content-Disposition" in result.headers
            mock_pdf.assert_called_once()
            mock_record.assert_called_once_with("pdf")

    @pytest.mark.asyncio
    async def test_get_pdf_report_generation_fails(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
        sample_findings: list[dict[str, Any]],
    ):
        """Test PDF generation failure raises 501."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_findings",
                new_callable=AsyncMock,
                return_value=mock_completed_job.findings,
            ),
            patch(
                "ishastra.api.routers.assessments.generate_pdf_from_job",
                side_effect=RuntimeError("WeasyPrint not available"),
            ),
        ):
            with pytest.raises(HTTPException) as exc:
                await assessments.get_pdf_report("job_completed_1", mock_tenant)

            assert exc.value.status_code == 501
            assert "PDF generation unavailable" in exc.value.detail


class TestRecordJob:
    """Test record_job and record_job_sync functions."""

    @pytest.mark.asyncio
    async def test_record_job_happy_path(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test recording a finished job."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.save_job",
                new_callable=AsyncMock,
                return_value="chain-hash",
            ) as mock_save,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock) as mock_audit,
        ):
            result = await assessments.record_job(mock_completed_job, mock_tenant)

            assert result["id"] == "job_completed_1"
            assert result["audit_chain_hash"] == "chain-hash"
            mock_save.assert_called_once()
            mock_audit.assert_called_once()

    def test_record_job_sync_with_running_loop(self):
        """Test sync wrapper when event loop is running."""
        mock_job = MagicMock()
        mock_tenant = {"tenant_id": "test"}

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_loop.is_running.return_value = True
            mock_get_loop.return_value = mock_loop

            with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
                mock_future = MagicMock()
                mock_future.result.return_value = {"id": "job_1"}
                mock_executor.return_value.__enter__.return_value.submit.return_value = mock_future

                result = assessments.record_job_sync(mock_job, mock_tenant)

                assert result == {"id": "job_1"}

    def test_record_job_sync_no_running_loop(self):
        """Test sync wrapper when no event loop is running."""
        mock_job = MagicMock()
        mock_tenant = {"tenant_id": "test"}

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_loop.is_running.return_value = False
            mock_loop.run_until_complete.return_value = {"id": "job_1"}
            mock_get_loop.return_value = mock_loop

            result = assessments.record_job_sync(mock_job, mock_tenant)

            assert result == {"id": "job_1"}
            mock_loop.run_until_complete.assert_called_once()

    def test_record_job_sync_runtime_error(self):
        """Test sync wrapper when no event loop exists."""
        mock_job = MagicMock()
        mock_tenant = {"tenant_id": "test"}

        with (
            patch("asyncio.get_event_loop", side_effect=RuntimeError("no loop")),
            patch("asyncio.run", return_value={"id": "job_1"}) as mock_run,
        ):
            result = assessments.record_job_sync(mock_job, mock_tenant)

            assert result == {"id": "job_1"}
            mock_run.assert_called_once()


class TestExistingSubmission:
    """Test _existing_submission helper function."""

    @pytest.mark.asyncio
    async def test_existing_submission_found(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test finding existing submission by idempotency key."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value="job_completed_1",
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
        ):
            result = await assessments._existing_submission("test-key", mock_tenant)

            assert result is not None
            assert result["id"] == "job_completed_1"
            assert result["deduplicated"] is True
            assert "poll_url" in result
            assert "cancel_url" in result

    @pytest.mark.asyncio
    async def test_existing_submission_not_found(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test no existing submission."""
        with patch(
            "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = await assessments._existing_submission("test-key", mock_tenant)

            assert result is None

    @pytest.mark.asyncio
    async def test_existing_submission_job_deleted(
        self,
        mock_tenant: dict[str, Any],
    ):
        """Test existing submission but job deleted."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value="job_deleted",
            ),
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await assessments._existing_submission("test-key", mock_tenant)

            assert result is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_create_assessment_with_policy_id(
        self,
        mock_tenant: dict[str, Any],
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test creating assessment with specific policy_id."""
        with (
            patch("ishastra.api.routers.assessments._idempotency_key", return_value=None),
            patch(
                "ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope
            ) as mock_scope_fn,
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            req = AssessRequest(
                target="https://example.com",
                profile="web",
                policy_id="pol-specific",
            )

            await assessments.create_assessment(req, mock_tenant)

            mock_scope_fn.assert_called_once_with(mock_tenant, "pol-specific")
            mock_worker.submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_preserves_encrypted_auth(
        self,
        mock_tenant: dict[str, Any],
        mock_failed_job: Job,
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test retry preserves encrypted auth config from original job."""
        mock_failed_job.policy = {
            "policy_id": "pol-1",
            "encrypted_auth_config": {
                "principal_id": "auth-1",
                "authenticator_type": "token",
                "encrypted_config": "encrypted-data",
                "created_at": time.time(),
            },
        }

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_failed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job) as mock_prepare,
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            await assessments.retry_assessment("job_failed_1", mock_tenant)

            call_args = mock_prepare.call_args
            policy_arg = call_args.kwargs.get("policy")
            assert policy_arg is not None
            assert "encrypted_auth_config" in policy_arg
            assert policy_arg["encrypted_auth_config"]["principal_id"] == "auth-1"
            mock_worker.submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_increments_attempt(
        self,
        mock_tenant: dict[str, Any],
        mock_failed_job: Job,
        mock_scope: Scope,
        mock_job: Job,
    ):
        """Test retry increments attempt counter."""
        mock_failed_job.attempts = 2

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_failed_job.to_dict(),
            ),
            patch("ishastra.api.routers.assessments.tenant_scope_async", return_value=mock_scope),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare", return_value=mock_job),
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments._existing_submission",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            await assessments.retry_assessment("job_failed_1", mock_tenant)

            assert mock_job.policy["retry_attempt"] == 3

    @pytest.mark.asyncio
    async def test_list_assessments_with_findings_count(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test list includes findings count."""
        job_dict = mock_completed_job.to_dict()

        with (
            patch(
                "ishastra.api.routers.assessments.store.list_jobs",
                new_callable=AsyncMock,
                return_value=[job_dict],
            ),
            patch(
                "ishastra.api.routers.assessments.store.count_jobs",
                new_callable=AsyncMock,
                return_value=1,
            ),
        ):
            result = await assessments.list_assessments(page=1, page_size=20, tenant=mock_tenant)

            assert result.items[0].findings_count == 2

    @pytest.mark.asyncio
    async def test_update_finding_status_redacts_note(
        self,
        mock_tenant: dict[str, Any],
        mock_completed_job: Job,
    ):
        """Test finding status update redacts note."""
        finding = mock_completed_job.findings[0]
        fingerprint = finding.fingerprint
        updated_finding = finding.to_dict()
        updated_finding["status"] = "triaged"

        with (
            patch(
                "ishastra.api.routers.assessments.store.get_job",
                new_callable=AsyncMock,
                return_value=mock_completed_job.to_dict(),
            ),
            patch(
                "ishastra.api.routers.assessments.store.update_finding_status",
                new_callable=AsyncMock,
                return_value=updated_finding,
            ),
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock) as mock_audit,
            patch("ishastra.api.routers.assessments.redact_text", return_value="[REDACTED]"),
        ):
            update = FindingStatusUpdate(status="triaged", note="Password is secret123")
            await assessments.update_finding_status("job_completed_1", fingerprint, update, mock_tenant)

            audit_call = mock_audit.call_args
            assert audit_call.args[1]["note"] == "[REDACTED]"


class TestAssessmentsIntegration:
    """Integration-style tests using TestClient."""

    @pytest.fixture
    def client(self):
        """Create test client with mocked dependencies."""
        from fastapi import FastAPI

        from ishastra.api.routers import assessments as assessments_module

        app = FastAPI()
        app.include_router(assessments_module.router)

        async def mock_require_auth():
            return {"tenant_id": "test-tenant", "tier": "standard", "admin": False}

        app.dependency_overrides[assessments_module.require_auth] = mock_require_auth

        with TestClient(app) as client:
            yield client

    def test_create_assessment_endpoint(self, client):
        """Test POST /api/assess via TestClient."""
        with (
            patch(
                "ishastra.api.routers.assessments.tenant_scope_async",
                new_callable=AsyncMock,
                return_value=MagicMock(check=MagicMock(return_value=(None, "ok"))),
            ),
            patch("ishastra.api.routers.assessments.check_target_or_raise"),
            patch("ishastra.api.routers.assessments.jobs.prepare") as mock_prepare,
            patch("ishastra.api.routers.assessments.store.save_job", new_callable=AsyncMock),
            patch("ishastra.api.routers.assessments._get_assessment_worker") as mock_get_worker,
            patch("ishastra.api.routers.assessments.audit_async", new_callable=AsyncMock),
            patch(
                "ishastra.api.routers.assessments.store.find_job_id_by_idempotency",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            mock_worker = AsyncMock()
            mock_get_worker.return_value = mock_worker
            mock_job = MagicMock()
            mock_job.id = "job_123"
            mock_job.target = "https://example.com"
            mock_job.profile = "web"
            mock_job.actor = "test-tenant"
            mock_job.policy = {}
            mock_job.state = MagicMock(value="queued")
            mock_job.started_at = None
            mock_job.finished_at = None
            mock_job.runs = []
            mock_job.findings = []
            mock_job.error = ""
            mock_job.attempts = 0
            mock_job.worker_id = ""
            mock_job.idempotency_key = None
            mock_job.coverage.return_value = {"total": 0, "adapters": []}
            mock_job.verdict = "queued"
            mock_job.to_dict.return_value = {
                "id": "job_123",
                "target": "https://example.com",
                "profile": "web",
                "actor": "test-tenant",
                "policy": {},
                "state": "queued",
                "started_at": None,
                "finished_at": None,
                "runs": [],
                "findings": [],
                "error": "",
                "attempts": 0,
                "worker": "",
                "idempotency_key": None,
                "coverage": {"total": 0, "adapters": []},
                "verdict": "queued",
            }
            mock_prepare.return_value = mock_job

            response = client.post(
                "/api/assess",
                json={"target": "https://example.com", "profile": "web", "wait": False},
                headers={"Authorization": "Bearer test-key"},
            )

            assert response.status_code == 202
            data = response.json()
            assert data["id"] == "job_123"
            assert data["state"] == "queued"

    def test_list_assessments_endpoint(self, client):
        """Test GET /api/assess via TestClient."""
        with (
            patch(
                "ishastra.api.routers.assessments.store.list_jobs",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "ishastra.api.routers.assessments.store.count_jobs",
                new_callable=AsyncMock,
                return_value=0,
            ),
        ):
            response = client.get(
                "/api/assess",
                headers={"Authorization": "Bearer test-key"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["items"] == []
            assert data["total"] == 0


class TestConstants:
    """Test module constants."""

    def test_active_states(self):
        """Test _ACTIVE_STATES constant."""
        assert assessments._ACTIVE_STATES == ("queued", "running")

    def test_retryable_states(self):
        """Test _RETRYABLE_STATES constant."""
        assert assessments._RETRYABLE_STATES == ("failed", "partial", "cancelled")

    def test_max_inline_timeout(self):
        """Test MAX_INLINE_TIMEOUT constant."""
        assert assessments.MAX_INLINE_TIMEOUT == 120.0

    def test_idempotency_key_pattern(self):
        """Test _IDEMPOTENCY_KEY pattern."""

        pattern = assessments._IDEMPOTENCY_KEY
        assert pattern.fullmatch("valid-key_123") is not None
        assert pattern.fullmatch("a" * 128) is not None
        assert pattern.fullmatch("a" * 129) is None
        assert pattern.fullmatch("invalid@key") is None
        assert pattern.fullmatch("") is None
