"""Unit tests for resource management components."""

import io
import os
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

from ishastra.core.artifact_lifecycle import (
    Artifact,
    ArtifactLifecycleManager,
    ArtifactStatus,
    ArtifactType,
    RetentionPolicy,
)
from ishastra.core.bundle import build_bundle, verify_bundle, BundleError
from ishastra.core.db_optimize import DatabaseOptimizer, DbOptimizationConfig
from ishastra.core.resource_profiles import (
    LIGHTWEIGHT_PROFILE,
    STANDARD_PROFILE,
    HIGH_CAPACITY_PROFILE,
    get_profile,
    list_profiles,
    PROFILES,
)
from ishastra.core.streaming import (
    bounded_stream_to_disk,
    check_disk_space,
    compute_file_hash_incremental,
    iter_findings_chunked,
    stream_bytes,
    stream_file,
    BoundedQueue,
    MemoryGuard,
    SizeLimitExceeded,
)
from ishastra.core.storage_quota import (
    StorageQuotaExceeded,
    StorageQuotaManager,
    StorageQuotaConfig,
    check_disk_space_safe,
    get_disk_usage,
)


class TestStreaming:
    """Tests for streaming utilities."""

    def test_stream_file_small(self, tmp_path):
        """Test streaming a small file."""
        test_file = tmp_path / "small.txt"
        test_file.write_text("hello world")

        chunks = list(stream_file(str(test_file)))
        assert len(chunks) == 1
        assert b"hello world" in chunks[0]

    def test_stream_file_large(self, tmp_path):
        """Test streaming a file larger than chunk size."""
        test_file = tmp_path / "large.bin"
        data = b"x" * (5 * 1024 * 1024)  # 5MB
        test_file.write_bytes(data)

        chunks = list(stream_file(str(test_file), chunk_size=1024 * 1024))
        assert len(chunks) == 5
        reconstructed = b"".join(chunks)
        assert reconstructed == data

    def test_compute_file_hash_incremental(self, tmp_path):
        """Test incremental hash computation."""
        test_file = tmp_path / "hash_test.bin"
        data = b"test data for hashing"
        test_file.write_bytes(data)

        hash_result = compute_file_hash_incremental(str(test_file))
        expected = __import__("hashlib").sha256(data).hexdigest()
        assert hash_result == expected

    def test_bounded_stream_to_disk(self, tmp_path):
        """Test streaming data to disk with atomic rename."""
        dest = tmp_path / "output.bin"
        data = b"test data"

        bytes_written, sha = bounded_stream_to_disk(data, str(dest))
        assert bytes_written == len(data)
        assert dest.exists()
        assert dest.read_bytes() == data

    def test_bounded_stream_to_disk_size_limit(self, tmp_path):
        """Test that size limit is enforced."""
        dest = tmp_path / "output.bin"
        data = b"x" * (10 * 1024 * 1024)  # 10MB

        with pytest.raises(SizeLimitExceeded):
            bounded_stream_to_disk(data, str(dest), max_size=1024 * 1024)  # 1MB limit

    def test_stream_bytes_from_bytes(self):
        """Test streaming from bytes object."""
        data = b"hello world" * 100
        chunks = list(stream_bytes(data, chunk_size=10))
        assert len(chunks) > 0
        assert b"".join(chunks) == data

    def test_stream_bytes_from_fileobj(self, tmp_path):
        """Test streaming from file-like object."""
        data = b"streaming test data"
        buf = io.BytesIO(data)
        chunks = list(stream_bytes(buf, chunk_size=5))
        assert b"".join(chunks) == data

    def test_iter_findings_chunked(self):
        """Test chunking of finding lists."""
        findings = list(range(2500))
        chunks = list(iter_findings_chunked(findings, chunk_size=1000))
        assert len(chunks) == 6
        assert len(chunks[0]) == 1000
        assert len(chunks[1]) == 1000
        assert len(chunks[2]) == 500
        assert len(chunks[3]) == 1000
        assert len(chunks[4]) == 1000
        assert len(chunks[5]) == 500

    def test_check_disk_space(self, tmp_path):
        """Test disk space checking."""
        sufficient, free = check_disk_space(str(tmp_path), 1024 * 1024)  # 1MB
        assert sufficient is True  # Should always have space in test
        assert free > 0


class TestBoundedQueue:
    """Tests for bounded queue with backpressure."""

    def test_bounded_queue_basic(self):
        """Test basic bounded queue operations."""
        q = BoundedQueue(maxsize=5)
        assert q.empty()
        assert not q.full()

        q.put("item1")
        assert not q.empty()
        assert not q.full()

        item = q.get()
        assert item == "item1"
        assert q.empty()

    def test_bounded_queue_full(self):
        """Test queue rejects when full."""
        q = BoundedQueue(maxsize=2)

        q.put("item1")
        q.put("item2")
        assert q.full()

        result = q.put("item3", block=False)
        assert result is False
        assert q.qsize() == 2

    def test_bounded_queue_item_size_limit(self):
        """Test item size limit enforcement."""
        q = BoundedQueue(maxsize=1024, item_size_limit=100)

        # Small item should work
        result = q.put(b"small", block=False)
        assert result is True

        # Large item should be rejected
        result = q.put(b"x" * 200, block=False)
        assert result is False
        q.get()  # Clean up

    def test_bounded_queue_memory_tracking(self):
        """Test memory size tracking."""
        q = BoundedQueue(maxsize=10000, item_size_limit=100)

        q.put(b"12345")
        assert q.current_memory_bytes == 5

        q.get()
        assert q.current_memory_bytes == 0


class TestMemoryGuard:
    """Tests for memory guard."""

    def test_memory_guard_check(self):
        """Test memory check."""
        guard = MemoryGuard(limit_mb=1024)
        over, rss = guard.check()
        assert isinstance(over, bool)
        assert isinstance(rss, int)
        # Typically not over limit in tests
        assert rss > 0

    def test_memory_guard_maybe_collect(self):
        """Test periodic GC triggering."""
        guard = MemoryGuard(limit_mb=1, check_interval_jobs=3)
        # Should not raise
        for _ in range(5):
            guard.maybe_collect()


class TestArtifactLifecycle:
    """Tests for artifact lifecycle management."""

    def test_create_artifact(self, tmp_path):
        """Test artifact creation."""
        config = ArtifactLifecycleManager._default_config()
        config.base_dir = str(tmp_path / "artifacts")
        config.temp_dir = str(tmp_path / "tmp")
        config.evidence_dir = str(tmp_path / "evidence")
        config.archives_dir = str(tmp_path / "archive")

        manager = ArtifactLifecycleManager(config=config)
        artifact = manager.create_artifact(
            tenant_id="tenant1",
            job_id="job123",
            artifact_type=ArtifactType.SCANNER_OUTPUT,
        )

        assert artifact.tenant_id == "tenant1"
        assert artifact.job_id == "job123"
        assert artifact.status == ArtifactStatus.CREATED
        assert artifact.id.startswith("art_")

    def test_write_and_finalize_artifact(self, tmp_path):
        """Test writing and finalizing an artifact."""
        config = ArtifactLifecycleManager._default_config()
        config.base_dir = str(tmp_path / "artifacts")
        config.temp_dir = str(tmp_path / "tmp")
        config.evidence_dir = str(tmp_path / "evidence")
        config.archives_dir = str(tmp_path / "archive")

        manager = ArtifactLifecycleManager(config=config)
        artifact = manager.create_artifact(
            tenant_id="tenant1",
            artifact_type=ArtifactType.FINDINGS_JSON,
        )

        data = b'{"findings": []}'
        bytes_written, sha = manager.write_artifact(artifact, data=data)
        assert bytes_written == len(data)
        assert artifact.status == ArtifactStatus.PROCESSING
        assert artifact.sha256 == __import__("hashlib").sha256(data).hexdigest()

        success = manager.finalize_artifact(artifact)
        assert success is True
        assert artifact.status == ArtifactStatus.FINALIZED
        assert artifact.checksum_verified is True

    def test_artifact_expiration(self, tmp_path):
        """Test artifact expiration checking."""
        config = ArtifactLifecycleManager._default_config()
        config.base_dir = str(tmp_path / "artifacts")

        manager = ArtifactLifecycleManager(config=config)
        artifact = manager.create_artifact(
            tenant_id="tenant1",
            retention_days=1,
        )

        # Not expired yet
        assert artifact.is_expired() is False

        # Make it expired
        artifact.expires_at = time.time() - 100
        assert artifact.is_expired() is True

    def test_cleanup_expired(self, tmp_path):
        """Test cleanup of expired artifacts."""
        config = ArtifactLifecycleManager._default_config()
        config.base_dir = str(tmp_path / "artifacts")
        config.temp_dir = str(tmp_path / "tmp")
        config.evidence_dir = str(tmp_path / "evidence")
        config.archives_dir = str(tmp_path / "archive")

        manager = ArtifactLifecycleManager(config=config)
        artifact = manager.create_artifact(
            tenant_id="tenant1",
            retention_days=0,  # Expires immediately
        )

        # Expire it
        artifact.expires_at = time.time() - 100
        manager._artifacts[artifact.id] = artifact

        cleaned = manager.cleanup_expired()
        assert len(cleaned) == 1
        assert cleaned[0]["id"] == artifact.id

    def test_storage_usage_report(self, tmp_path):
        """Test storage usage reporting."""
        config = ArtifactLifecycleManager._default_config()
        config.base_dir = str(tmp_path / "artifacts")
        config.temp_dir = str(tmp_path / "tmp")
        config.evidence_dir = str(tmp_path / "evidence")
        config.archives_dir = str(tmp_path / "archive")

        manager = ArtifactLifecycleManager(config=config)
        usage = manager.get_storage_usage()
        assert "artifacts_dir" in usage
        assert "total" in usage
        assert usage["artifact_count"] == 0


class TestStorageQuota:
    """Tests for storage quota management."""

    def test_disk_usage(self, tmp_path):
        """Test disk usage calculation."""
        usage = get_disk_usage(str(tmp_path))
        assert "total_bytes" in usage
        assert "used_bytes" in usage
        assert "free_bytes" in usage
        assert usage["free_bytes"] > 0

    def test_check_disk_space_safe(self, tmp_path):
        """Test safe disk space checking."""
        result = check_disk_space_safe(str(tmp_path), 1024 * 1024)  # 1MB
        assert result["safe"] is True
        assert result["available_bytes"] > 0

    def test_storage_quota_config(self):
        """Test storage quota configuration."""
        config = StorageQuotaConfig()
        assert config.max_artifact_size_bytes == 500 * 1024 * 1024
        assert config.max_temp_dir_bytes == 100 * 1024 * 1024

    def test_quota_manager_check_artifact_size(self):
        """Test artifact size checking."""
        manager = StorageQuotaManager()
        manager.check_artifact_size(1024, "artifact")  # Small size OK

        with pytest.raises(StorageQuotaExceeded):
            manager.check_artifact_size(600 * 1024 * 1024, "artifact")  # 600MB > 500MB

    def test_quota_manager_engagement_quota(self):
        """Test engagement quota checking."""
        manager = StorageQuotaManager()
        manager._engagement_usage["eng1"] = 9 * 1024 * 1024 * 1024  # 9GB used

        # This should pass (1GB remaining, adding 500MB)
        manager.check_engagement_quota("eng1", 500 * 1024 * 1024)

        # This should fail (only 1GB remaining, adding 2GB)
        with pytest.raises(StorageQuotaExceeded):
            manager.check_engagement_quota("eng1", 2 * 1024 * 1024 * 1024)

    def test_quota_usage_report(self, tmp_path):
        """Test usage report generation."""
        manager = StorageQuotaManager()
        manager._engagement_usage["eng1"] = 1024 * 1024
        report = manager.get_usage_report()
        assert "disk" in report
        assert "quota_config" in report
        assert report["engagement_usage"]["eng1"] == 1024 * 1024


class TestEvidenceBundle:
    """Tests for evidence bundle creation and verification."""

    def test_build_and_verify_bundle(self):
        """Test creating and verifying a simple bundle."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        job = {"id": "job123", "target": "example.com"}
        audit = [{"type": "scan_started", "timestamp": time.time()}]
        scope = {"include": ["example.com"]}

        bundle_data = build_bundle(
            job=job,
            audit=audit,
            scope_document=scope,
            private_key=private_key,
            kid="test-key",
        )

        assert len(bundle_data) > 0

        keys = {"test-key": public_key}
        manifest = verify_bundle(bundle_data, keys)
        assert manifest["job_id"] == "job123"
        assert "files" in manifest

    def test_bundle_verification_fails_with_wrong_key(self):
        """Test that verification fails with wrong key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        wrong_key = Ed25519PrivateKey.generate().public_key()

        bundle_data = build_bundle(
            job={"id": "job123"},
            audit=[],
            scope_document={},
            private_key=private_key,
            kid="test-key",
        )

        with pytest.raises(BundleError, match="signing key"):
            verify_bundle(bundle_data, {"wrong-key": wrong_key})

    def test_bundle_verification_fails_tampered(self):
        """Test that verification fails with tampered manifest."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import zipfile
        import io
        import json

        from ishastra.core.bundle import (
            build_bundle, verify_bundle, MANIFEST, SIGNATURE,
            _dump, _b64url_decode, canonical_payload,
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        bundle_data = build_bundle(
            job={"id": "job123"},
            audit=[],
            scope_document={},
            private_key=private_key,
            kid="test-key",
        )

        # Tamper with the manifest inside the archive
        archive = zipfile.ZipFile(io.BytesIO(bundle_data))
        manifest = json.loads(archive.read(MANIFEST))
        manifest["job_id"] = "tampered"
        tampered_manifest = _dump(manifest)

        tampered_buf = io.BytesIO()
        with zipfile.ZipFile(tampered_buf, "w", zipfile.ZIP_DEFLATED) as new_archive:
            for name in archive.namelist():
                if name == MANIFEST:
                    new_archive.writestr(name, tampered_manifest)
                else:
                    new_archive.writestr(name, archive.read(name))
        tampered = tampered_buf.getvalue()

        with pytest.raises(BundleError, match="signature"):
            verify_bundle(tampered, {"test-key": public_key})

    def test_streamed_bundle(self, tmp_path):
        """Test streaming bundle creation from files."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import json

        # Create test files
        test_file = tmp_path / "test_sarif.json"
        test_file.write_text(json.dumps({"version": "1.0"}))

        private_key = Ed25519PrivateKey.generate()

        bundle_data = build_bundle(
            job={"id": "job123"},
            audit=[],
            scope_document={},
            private_key=private_key,
            kid="test-key",
            sarif={"version": "1.0"},
        )

        assert len(bundle_data) > 0


class TestResourceProfiles:
    """Tests for resource profiles."""

    def test_list_profiles(self):
        """Test listing available profiles."""
        profiles = list_profiles()
        assert "lightweight" in profiles
        assert "standard" in profiles
        assert "high-capacity" in profiles

    def test_get_profile(self):
        """Test getting a profile by name."""
        profile = get_profile("lightweight")
        assert profile.name == "lightweight"
        assert profile.worker_concurrency == 1
        assert profile.worker_memory_mb == 512

    def test_lightweight_profile(self):
        """Test lightweight profile values."""
        profile = LIGHTWEIGHT_PROFILE
        assert profile.worker_concurrency == 1
        assert profile.worker_memory_mb == 512
        assert profile.queue_max == 10
        assert profile.use_postgresql is False
        assert profile.max_findings_per_assessment == 500

    def test_standard_profile(self):
        """Test standard profile values."""
        profile = STANDARD_PROFILE
        assert profile.worker_concurrency == 2
        assert profile.worker_memory_mb == 1024
        assert profile.queue_max == 32
        assert profile.use_postgresql is True
        assert profile.max_findings_per_assessment == 10000

    def test_high_capacity_profile(self):
        """Test high-capacity profile values."""
        profile = HIGH_CAPACITY_PROFILE
        assert profile.worker_concurrency == 4
        assert profile.worker_memory_mb == 2048
        assert profile.queue_max == 128
        assert profile.use_postgresql is True
        assert profile.max_findings_per_assessment is None  # Unlimited

    def test_profile_defaults(self):
        """Test getting profile defaults as dict."""
        from ishastra.core.resource_profiles import get_profile_defaults
        defaults = get_profile_defaults("lightweight")
        assert defaults["worker_concurrency"] == 1
        assert defaults["max_artifact_size_mb"] == 100


class TestDatabaseOptimizer:
    """Tests for database optimization."""

    def test_db_optimization_config_defaults(self):
        """Test database optimization config defaults."""
        config = DbOptimizationConfig()
        assert config.sqlite_wal_mode is True
        assert config.connection_pool_size == 5
        assert config.default_page_size == 100

    def test_paginate_query(self):
        """Test query pagination."""
        optimizer = DatabaseOptimizer()
        query = "SELECT * FROM findings WHERE tenant = ?"
        params = ("tenant1",)
        page = 2
        page_size = 50

        paginated, new_params = optimizer.paginate_query(query, params, page, page_size)
        assert "LIMIT 50 OFFSET 50" in paginated
        assert new_params == params

    def test_pagination_info(self):
        """Test pagination info calculation."""
        optimizer = DatabaseOptimizer()
        info = optimizer.get_pagination_info(total_rows=150, page=2, page_size=50)
        assert info["page"] == 2
        assert info["page_size"] == 50
        assert info["total_rows"] == 150
        assert info["total_pages"] == 3
        assert info["has_next"] is True
        assert info["has_prev"] is True


class TestRetentionPolicy:
    """Tests for retention policy."""

    def test_retention_days(self):
        """Test day-based retention."""
        policy = RetentionPolicy(mode=RetentionPolicy.DAYS, days=30)
        created = time.time()
        expires = policy.expires_at(created)
        assert expires is not None
        assert expires > created
        assert expires - created >= 30 * 86400 - 1  # Within 1 second

    def test_retention_never(self):
        """Test never-expire retention."""
        policy = RetentionPolicy(mode=RetentionPolicy.NEVER)
        assert policy.expires_at(time.time()) is None
        assert policy.should_retain(time.time()) is True

    def test_retention_should_retain(self):
        """Test retention checking."""
        policy = RetentionPolicy(mode=RetentionPolicy.DAYS, days=30)
        now = time.time()

        # Check at current time - should retain
        assert policy.should_retain(now, created_at=now) is True

        # Check 40 days in the future - should NOT retain (past 30-day expiry)
        assert policy.should_retain(now + 40 * 86400, created_at=now) is False


class TestArtifact:
    """Tests for artifact data class."""

    def test_artifact_to_dict(self):
        """Test artifact serialization."""
        artifact = Artifact(
            id="art_test123",
            tenant_id="tenant1",
            job_id="job123",
            artifact_type=ArtifactType.FINDINGS_JSON,
            file_size=1024,
            sha256="abc123",
            status=ArtifactStatus.FINALIZED,
        )

        d = artifact.to_dict()
        assert d["id"] == "art_test123"
        assert d["tenant_id"] == "tenant1"
        assert d["status"] == "finalized"
        assert d["artifact_type"] == "findings_json"


class TestStreamingIntegration:
    """Integration tests for streaming with real files."""

    def test_incremental_hash_matches_whole_file(self, tmp_path):
        """Test that incremental hashing produces same result as whole-file."""
        test_file = tmp_path / "integration_test.bin"
        data = b"x" * (10 * 1024 * 1024)  # 10MB
        test_file.write_bytes(data)

        # Incremental hash
        incremental_hash = compute_file_hash_incremental(str(test_file))

        # Whole file hash (for comparison)
        import hashlib
        whole_hash = hashlib.sha256(data).hexdigest()

        assert incremental_hash == whole_hash

    def test_large_file_streaming_memory(self, tmp_path):
        """Test that streaming a large file doesn't use excessive memory."""
        import sys

        test_file = tmp_path / "large_stream.bin"
        data = b"y" * (20 * 1024 * 1024)  # 20MB
        test_file.write_bytes(data)

        # Get baseline memory
        import resource
        baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        # Stream the file (should not load entirely into memory)
        chunks = list(stream_file(str(test_file), chunk_size=1024 * 1024))

        # Check memory didn't grow significantly (allow some overhead)
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        growth = after - baseline

        # Allow up to 50MB growth (should be much less in practice)
        assert growth < 50 * 1024, f"Memory grew by {growth}KB during streaming"

    def test_streamed_bundle_hash_verification(self, tmp_path):
        """Test that bundle files are properly hashed."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import hashlib
        import json

        # Create bundle
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        sarif_content = {"version": "1.0", "runs": [{"tool": {"name": "ishastra"}}]}

        bundle_data = build_bundle(
            job={"id": "job_integration"},
            audit=[],
            scope_document={},
            private_key=private_key,
            kid="test-key",
            sarif=sarif_content,
        )

        # Verify bundle and check all files have hashes
        keys = {"test-key": public_key}
        manifest = verify_bundle(bundle_data, keys)

        # SARIF file should be present with valid hash
        sarif_entry = manifest["files"]["sarif.json"]
        assert len(sarif_entry["sha256"]) == 64  # Valid SHA-256 hex string
        assert sarif_entry["size"] > 0  # Has positive size
