"""Unit tests for Policy and ScanResult CRD reconcilers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ishastra.operator.controllers.policy import PolicyReconciler
from ishastra.operator.controllers.scan_result import ScanResultReconciler


class TestPolicyReconciler:
    """Tests for PolicyReconciler."""

    @pytest.fixture
    def reconciler(self):
        with (
            patch("ishastra.operator.controllers.base.config.load_incluster_config"),
            patch("ishastra.operator.controllers.base.config.load_kube_config"),
        ):
            return PolicyReconciler(namespace="ishastra-system")

    @pytest.mark.asyncio
    async def test_validate_dns_label(self, reconciler):
        """Test DNS-1123 label validation."""
        assert reconciler._is_valid_dns_label("valid-name") is True
        assert reconciler._is_valid_dns_label("valid123") is True
        assert reconciler._is_valid_dns_label("a") is True
        assert reconciler._is_valid_dns_label("a-b-c") is True

        assert reconciler._is_valid_dns_label("Invalid") is False
        assert reconciler._is_valid_dns_label("-invalid") is False
        assert reconciler._is_valid_dns_label("invalid-") is False
        assert reconciler._is_valid_dns_label("in_valid") is False
        assert reconciler._is_valid_dns_label("a" * 64) is False

    @pytest.mark.asyncio
    async def test_compute_hash(self, reconciler):
        """Test spec hash computation."""
        spec1 = {"name": "test", "tier": "free", "checks": {}, "limits": {}}
        spec2 = {"name": "test", "tier": "free", "checks": {}, "limits": {}}
        spec3 = {"name": "test", "tier": "pro", "checks": {}, "limits": {}}

        hash1 = reconciler._compute_hash(spec1)
        hash2 = reconciler._compute_hash(spec2)
        hash3 = reconciler._compute_hash(spec3)

        assert hash1 == hash2
        assert hash1 != hash3
        assert len(hash1) == 16

    @pytest.mark.asyncio
    async def test_now_iso_format(self, reconciler):
        """Test ISO timestamp format."""
        ts = reconciler._now_iso()
        assert "T" in ts
        assert ts.endswith("+00:00") or "Z" in ts

    @pytest.mark.asyncio
    async def test_reconcile_missing_name(self, reconciler):
        """Test reconciliation fails when name is missing."""
        resource = {
            "metadata": {"name": "test-policy"},
            "spec": {"tier": "free"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert call_args[0] == "test-policy"
            assert call_args[1]["phase"] == "Pending"
            assert "spec.name is required" in call_args[1]["message"]

    @pytest.mark.asyncio
    async def test_reconcile_missing_tier(self, reconciler):
        """Test reconciliation fails when tier is missing."""
        resource = {
            "metadata": {"name": "test-policy"},
            "spec": {"name": "mypolicy"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert "spec.tier is required" in call_args[1]["message"]

    @pytest.mark.asyncio
    async def test_reconcile_invalid_tier(self, reconciler):
        """Test reconciliation fails with invalid tier."""
        resource = {
            "metadata": {"name": "test-policy"},
            "spec": {"name": "mypolicy", "tier": "invalid"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert "spec.tier must be one of" in call_args[1]["message"]

    @pytest.mark.asyncio
    async def test_reconcile_invalid_name_format(self, reconciler):
        """Test reconciliation fails with invalid DNS label."""
        resource = {
            "metadata": {"name": "test-policy"},
            "spec": {"name": "Invalid_Name", "tier": "free"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert "must be a valid DNS-1123 label" in call_args[1]["message"]

    @pytest.mark.asyncio
    async def test_pending_to_ready_transition(self, reconciler):
        """Test Pending -> Ready transition."""
        resource = {
            "metadata": {"name": "test-policy"},
            "spec": {
                "name": "mypolicy",
                "displayName": "My Policy",
                "description": "Test policy",
                "tier": "free",
                "checks": {"xss": True},
                "limits": {"maxTargets": 100},
                "notifications": {},
                "compliance": {},
            },
            "status": {"phase": "Pending"},
        }

        reconciler.core_api = MagicMock()
        with (
            patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch,
            patch.object(reconciler, "_store_policy_configmap", new_callable=AsyncMock),
        ):
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert call_args[1]["phase"] == "Ready"
            assert call_args[1]["specHash"] is not None


class TestScanResultReconciler:
    """Tests for ScanResultReconciler."""

    @pytest.fixture
    def reconciler(self):
        with (
            patch("ishastra.operator.controllers.base.config.load_incluster_config"),
            patch("ishastra.operator.controllers.base.config.load_kube_config"),
        ):
            return ScanResultReconciler(namespace="ishastra-system")

    @pytest.mark.asyncio
    async def test_now_iso_format(self, reconciler):
        """Test ISO timestamp format."""
        ts = reconciler._now_iso()
        assert "T" in ts
        assert ts.endswith("+00:00") or "Z" in ts

    @pytest.mark.asyncio
    async def test_reconcile_missing_job_ref(self, reconciler):
        """Test reconciliation fails when jobRef is missing."""
        resource = {
            "metadata": {"name": "test-scan"},
            "spec": {"tenantId": "tenant-1"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert call_args[1]["phase"] == "Failed"
            conditions = call_args[1].get("conditions", [])
            assert any("jobRef is required" in c.get("message", "") for c in conditions)

    @pytest.mark.asyncio
    async def test_reconcile_missing_tenant_id(self, reconciler):
        """Test reconciliation fails when tenantId is missing."""
        resource = {
            "metadata": {"name": "test-scan"},
            "spec": {"jobRef": "job-1"},
            "status": {"phase": "Pending"},
        }

        with patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch:
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            conditions = call_args[1].get("conditions", [])
            assert any("tenantId is required" in c.get("message", "") for c in conditions)

    @pytest.mark.asyncio
    async def test_pending_to_processing_transition(self, reconciler):
        """Test Pending -> Processing transition."""
        resource = {
            "metadata": {"name": "test-scan"},
            "spec": {
                "jobRef": "job-1",
                "tenantId": "tenant-1",
                "assessmentId": "assess-1",
                "findings": [
                    {"id": "f1", "severity": "critical", "title": "SQLi"},
                    {"id": "f2", "severity": "high", "title": "XSS"},
                ],
                "summary": {},
            },
            "status": {"phase": "Pending"},
        }

        reconciler.core_api = MagicMock()
        with (
            patch.object(reconciler, "_patch_status", new_callable=AsyncMock) as mock_patch,
            patch.object(reconciler, "_store_findings", new_callable=AsyncMock),
        ):
            await reconciler.reconcile(resource)
            mock_patch.assert_called_once()
            call_args = mock_patch.call_args[0]
            assert call_args[1]["phase"] == "Processing"
            assert call_args[1]["storedAt"] is not None


class TestMainEntrypoint:
    """Tests for operator main entrypoint."""

    def test_parse_args_defaults(self):
        """Test default argument parsing."""
        from ishastra.operator.main import parse_args

        with patch("sys.argv", ["ishastra-operator"]):
            args = parse_args()
            assert args.leader_elect is False
            assert args.metrics_bind_address == ":8080"
            assert args.health_probe_bind_address == ":8081"
            assert args.webhook_port == 9443
            assert args.webhook_cert_dir == "/tmp/k8s-webhook-server/serving-certs"
            assert args.enable_k8s_jobs_mode is False
            assert args.enable_redis_streams_mode is False
            assert args.redis_address == "redis://localhost:6379"
            assert args.log_level == "INFO"
            assert args.log_format == "text"

    def test_parse_args_custom(self):
        """Test custom argument parsing."""
        from ishastra.operator.main import parse_args

        with patch(
            "sys.argv",
            [
                "ishastra-operator",
                "--leader-elect",
                "--metrics-bind-address=:9090",
                "--health-probe-bind-address=:9091",
                "--webhook-port=8443",
                "--enable-k8s-jobs-mode",
                "--log-level=DEBUG",
                "--log-format=json",
            ],
        ):
            args = parse_args()
            assert args.leader_elect is True
            assert args.metrics_bind_address == ":9090"
            assert args.health_probe_bind_address == ":9091"
            assert args.webhook_port == 8443
            assert args.enable_k8s_jobs_mode is True
            assert args.log_level == "DEBUG"
            assert args.log_format == "json"
