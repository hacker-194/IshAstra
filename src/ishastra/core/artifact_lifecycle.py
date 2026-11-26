"""Artifact lifecycle management for IshAstra assessments."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from ishastra.config import Settings
from ishastra.core.streaming import SizeLimitExceeded, check_disk_space, compute_file_hash_incremental

log = logging.getLogger(__name__)


class ArtifactStatus(str, Enum):
    CREATED = "created"
    PROCESSING = "processing"
    FINALIZED = "finalized"
    RETAINED = "retained"
    ARCHIVED = "archived"
    EXPIRED = "expired"
    DELETED = "deleted"
    FAILED = "failed"


class RetentionPolicy:
    """Defines how long an artifact should be retained."""

    NEVER = "never"
    DAYS = "days"
    ENGAGEMENT = "engagement"
    ASSESSMENT = "assessment"

    def __init__(
        self,
        mode: str = DAYS,
        days: int | None = None,
        max_size_mb: int | None = None,
        compress: bool = True,
        include_in_evidence: bool = True,
    ):
        self.mode = mode
        self.days = days
        self.max_size_mb = max_size_mb
        self.compress = compress
        self.include_in_evidence = include_in_evidence

    def expires_at(self, created_at: float) -> float | None:
        if self.mode == self.NEVER:
            return None
        if self.mode == self.DAYS and self.days:
            return created_at + (self.days * 86400)
        return None

    def should_retain(
        self, check_time: float, created_at: float | None = None, now: float | None = None
    ) -> bool:
        """Check if the artifact should be retained.

        Args:
            check_time: The time to check retention against (typically now or future time).
            created_at: The creation time of the artifact. Defaults to check_time.
            now: Legacy parameter, same as check_time. Use check_time instead.

        Returns:
            True if the artifact should be retained at check_time, False otherwise.
        """
        if created_at is None:
            created_at = check_time
        if self.mode == self.NEVER:
            return True
        expires = self.expires_at(created_at)
        if expires is None:
            return True
        t = check_time if check_time is not None else (now if now is not None else time.time())
        return t < expires


class ArtifactType(str, Enum):
    RAW_ASSESSMENT = "raw_assessment"
    SCANNER_OUTPUT = "scanner_output"
    PACKET_CAPTURE = "packet_capture"
    EVIDENCE_BUNDLE = "evidence_bundle"
    REPORT_HTML = "report_html"
    REPORT_PDF = "report_pdf"
    FINDINGS_JSON = "findings_json"
    SARIF = "sarif"
    AUDIT_CHAIN = "audit_chain"
    TEMP_WORKING = "temp_working"
    LOG_FILE = "log_file"


@dataclass
class Artifact:
    """Represents an assessment artifact with full metadata."""

    id: str = field(default_factory=lambda: f"art_{uuid4().hex[:16]}")
    tenant_id: str = ""
    engagement_id: str = ""
    job_id: str = ""
    artifact_type: ArtifactType = ArtifactType.RAW_ASSESSMENT
    file_path: str = ""
    file_size: int = 0
    mime_type: str = "application/octet-stream"
    sha256: str = ""
    storage_location: str = ""
    status: ArtifactStatus = ArtifactStatus.CREATED
    created_at: float = field(default_factory=time.time)
    finalized_at: float | None = None
    expires_at: float | None = None
    retention_policy: str = RetentionPolicy.DAYS
    retention_days: int = 90
    compression_enabled: bool = True
    compressed_size: int = 0
    processing_error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    checksum_verified: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) > self.expires_at

    def is_active(self) -> bool:
        return self.status in (ArtifactStatus.CREATED, ArtifactStatus.PROCESSING,
                                ArtifactStatus.FINALIZED, ArtifactStatus.RETAINED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "job_id": self.job_id,
            "artifact_type": self.artifact_type.value,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "sha256": self.sha256,
            "storage_location": self.storage_location,
            "status": self.status.value,
            "created_at": self.created_at,
            "finalized_at": self.finalized_at,
            "expires_at": self.expires_at,
            "retention_policy": self.retention_policy,
            "retention_days": self.retention_days,
            "compression_enabled": self.compression_enabled,
            "compressed_size": self.compressed_size,
            "processing_error": self.processing_error,
            "checksum_verified": self.checksum_verified,
        }


@dataclass
class ArtifactStoreConfig:
    """Configuration for artifact storage behavior."""

    base_dir: str = "./artifacts"
    temp_dir: str = "./artifacts/tmp"
    evidence_dir: str = "./artifacts/evidence"
    archives_dir: str = "./artifacts/archive"
    max_artifact_size_mb: int = 500
    max_temp_size_mb: int = 100
    max_evidence_bundle_size_mb: int = 200
    max_packet_capture_size_mb: int = 100
    max_scanner_output_size_mb: int = 200
    max_total_engagement_storage_mb: int = 10000
    max_total_tenant_storage_mb: int | None = None
    delete_temp_after_hours: int = 24
    cleanup_interval_hours: int = 6
    compress_artifacts: bool = True
    compress_min_size_kb: int = 100
    compress_algorithm: str = "gzip"


class ArtifactLifecycleManager:
    """Manages the complete lifecycle of assessment artifacts."""

    def __init__(self, config: ArtifactStoreConfig | None = None, settings: Settings | None = None):
        self.config = config or self._default_config(settings)
        self._artifacts: dict[str, Artifact] = {}
        self._artifact_dir = Path(self.config.base_dir)
        self._temp_dir = Path(self.config.temp_dir)
        self._evidence_dir = Path(self.config.evidence_dir)
        self._archives_dir = Path(self.config.archives_dir)
        self._setup_directories()

    @staticmethod
    def _default_config(settings: Settings | None = None) -> ArtifactStoreConfig:
        if settings:
            return ArtifactStoreConfig(
                base_dir=settings.object_store_local_root or "./artifacts",
                temp_dir=os.path.join(settings.object_store_local_root or "./artifacts", "tmp"),
                evidence_dir=os.path.join(settings.object_store_local_root or "./artifacts", "evidence"),
                archives_dir=os.path.join(settings.object_store_local_root or "./artifacts", "archive"),
                max_artifact_size_mb=(
                min(settings.worker_memory_mb // 2, 500)
                if settings.worker_memory_mb
                else 500
            ),
                max_temp_size_mb=100,
                max_evidence_bundle_size_mb=200,
                max_packet_capture_size_mb=100,
                max_scanner_output_size_mb=200,
                max_total_engagement_storage_mb=10000,
                compress_artifacts=True,
            )
        return ArtifactStoreConfig()

    def _setup_directories(self) -> None:
        for directory in [self._artifact_dir, self._temp_dir, self._evidence_dir, self._archives_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def create_artifact(
        self,
        tenant_id: str,
        job_id: str | None = None,
        artifact_type: ArtifactType = ArtifactType.RAW_ASSESSMENT,
        retention_days: int | None = None,
        max_size_mb: int | None = None,
    ) -> Artifact:
        """Create a new artifact record and temporary file placeholder."""
        artifact = Artifact(
            tenant_id=tenant_id,
            job_id=job_id or "",
            artifact_type=artifact_type,
            status=ArtifactStatus.CREATED,
            retention_days=retention_days if retention_days is not None else 90,
            file_path="",
        )

        artifact.retention_policy = RetentionPolicy.DAYS
        artifact.expires_at = time.time() + ((retention_days or 90) * 86400)
        self._artifacts[artifact.id] = artifact
        return artifact

    def write_artifact(
        self,
        artifact: Artifact,
        data: bytes | None = None,
        source_path: str | Path | None = None,
        chunk_size: int = 1024 * 1024,
        max_size_mb: int | None = None,
    ) -> tuple[int, str]:
        """Write artifact data to temporary storage."""
        if artifact.status != ArtifactStatus.CREATED:
            raise ValueError(f"Cannot write to artifact in status {artifact.status}")

        if data is not None:
            required = len(data) if isinstance(data, bytes) else sum(1 for _ in data)
        elif source_path is not None:
            required = Path(source_path).stat().st_size
        else:
            required = 0

        sufficient, free = check_disk_space(self._temp_dir, required)
        if not sufficient:
            artifact.status = ArtifactStatus.FAILED
            artifact.processing_error = f"Insufficient disk space: need {required}, have {free}"
            raise OSError(artifact.processing_error)

        limit_mb = max_size_mb if max_size_mb is not None else self.config.max_artifact_size_mb
        max_bytes = limit_mb * 1024 * 1024
        if required > max_bytes:
            artifact.status = ArtifactStatus.FAILED
            artifact.processing_error = f"Artifact exceeds max size: {required} > {max_bytes}"
            raise SizeLimitExceeded(limit=max_bytes, actual=required,
                                    description=f"{artifact.artifact_type} exceeds maximum size")

        temp_path = self._temp_dir / f"{artifact.id}.tmp"
        artifact.file_path = str(temp_path)

        sha256_hash = hashlib.sha256()

        if source_path:
            with open(source_path, "rb") as src, open(temp_path, "wb") as dst:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    sha256_hash.update(chunk)
        elif data:
            with open(temp_path, "wb") as f:
                if isinstance(data, bytes):
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        f.write(chunk)
                        sha256_hash.update(chunk)
                else:
                    while True:
                        chunk = data.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        sha256_hash.update(chunk)
        else:
            raise ValueError("Either data or source_path must be provided")

        artifact.file_size = temp_path.stat().st_size
        artifact.sha256 = sha256_hash.hexdigest()
        artifact.status = ArtifactStatus.PROCESSING

        return artifact.file_size, artifact.sha256

    def finalize_artifact(self, artifact: Artifact, verify_checksum: bool = True) -> bool:
        """Finalize an artifact."""
        if artifact.status != ArtifactStatus.PROCESSING:
            raise ValueError(f"Cannot finalize artifact in status {artifact.status}")

        try:
            if verify_checksum and artifact.file_path:
                actual_hash = compute_file_hash_incremental(artifact.file_path)
                if actual_hash != artifact.sha256:
                    artifact.status = ArtifactStatus.FAILED
                    artifact.processing_error = "Checksum mismatch"
                    return False
                artifact.checksum_verified = True

            if artifact.artifact_type in (
                ArtifactType.EVIDENCE_BUNDLE,
                ArtifactType.FINDINGS_JSON,
                ArtifactType.SARIF,
                ArtifactType.REPORT_HTML,
                ArtifactType.REPORT_PDF,
            ):
                dest_path = self._evidence_dir / f"{artifact.id}_{artifact.artifact_type.value}.dat"
            else:
                dest_path = self._artifact_dir / f"{artifact.id}_{artifact.artifact_type.value}.dat"

            shutil.move(artifact.file_path, str(dest_path))
            artifact.file_path = str(dest_path)
            artifact.storage_location = "local"
            artifact.status = ArtifactStatus.FINALIZED
            artifact.finalized_at = time.time()

            if artifact.expires_at is None:
                artifact.expires_at = artifact.finalized_at + (artifact.retention_days * 86400)

            self._artifacts[artifact.id] = artifact
            return True

        except Exception as e:
            artifact.status = ArtifactStatus.FAILED
            artifact.processing_error = str(e)
            return False

    def archive_artifact(self, artifact: Artifact) -> bool:
        """Move artifact to archive storage."""
        if artifact.status != ArtifactStatus.FINALIZED:
            raise ValueError("Can only archive finalized artifacts")

        try:
            if not self._archives_dir.exists():
                self._archives_dir.mkdir(parents=True)

            archive_path = self._archives_dir / f"{artifact.id}.archived"
            if artifact.file_path and Path(artifact.file_path).exists():
                shutil.move(artifact.file_path, str(archive_path))
                artifact.file_path = str(archive_path)
                artifact.storage_location = "archive"
                artifact.status = ArtifactStatus.ARCHIVED
                self._artifacts[artifact.id] = artifact
                return True
            return False
        except Exception as e:
            log.error("Failed to archive artifact %s: %s", artifact.id, e)
            return False

    def delete_artifact(self, artifact: Artifact, secure: bool | None = None) -> bool:
        """Delete an artifact and its record."""
        if artifact.status == ArtifactStatus.DELETED:
            return True

        try:
            if artifact.file_path and Path(artifact.file_path).exists():
                if secure:
                    file_size = Path(artifact.file_path).stat().st_size
                    with open(artifact.file_path, "wb") as f:
                        f.write(os.urandom(min(file_size, 1024 * 1024)))
                    with open(artifact.file_path, "wb") as f:
                        f.write(b"\x00" * file_size)
                Path(artifact.file_path).unlink(missing_ok=True)

            artifact.status = ArtifactStatus.DELETED
            if artifact.id in self._artifacts:
                del self._artifacts[artifact.id]
            return True
        except Exception as e:
            log.error("Failed to delete artifact %s: %s", artifact.id, e)
            return False

    def cleanup_expired(self, dry_run: bool = False) -> list[dict[str, Any]]:
        """Remove expired artifacts."""
        now = time.time()
        cleaned = []

        for artifact_id, artifact in list(self._artifacts.items()):
            if artifact.status in (ArtifactStatus.DELETED, ArtifactStatus.EXPIRED):
                if artifact.id in self._artifacts:
                    del self._artifacts[artifact_id]
                continue

            if artifact.is_expired(now):
                if not dry_run:
                    self.delete_artifact(artifact)
                cleaned.append({
                    "id": artifact_id,
                    "type": artifact.artifact_type.value,
                    "created": artifact.created_at,
                    "expired": artifact.expires_at,
                    "dry_run": dry_run,
                })
                if artifact.id in self._artifacts:
                    del self._artifacts[artifact_id]

        if not dry_run:
            self._cleanup_temp_files()

        return cleaned

    def _cleanup_temp_files(self, older_than_hours: int | None = None) -> list[dict[str, Any]]:
        """Remove temporary files older than the specified age."""
        older_than = older_than_hours if older_than_hours is not None else self.config.delete_temp_after_hours
        cutoff = time.time() - (older_than * 3600)
        cleaned: list[dict[str, Any]] = []

        if not self._temp_dir.exists():
            return cleaned

        for f in self._temp_dir.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                try:
                    f.unlink()
                    cleaned.append({"path": str(f), "size": f.stat().st_size if f.exists() else 0})
                except Exception as e:
                    log.warning("Failed to delete temp file %s: %s", f, e)

        return cleaned

    def get_storage_usage(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Get storage usage statistics."""
        usage: dict[str, Any] = {
            "artifacts_dir": 0,
            "temp_dir": 0,
            "evidence_dir": 0,
            "archive_dir": 0,
            "total": 0,
            "artifact_count": len(self._artifacts),
            "by_status": {},
            "by_type": {},
        }

        for directory, key in [(self._artifact_dir, "artifacts_dir"),
                                (self._temp_dir, "temp_dir"),
                                (self._evidence_dir, "evidence_dir"),
                                (self._archives_dir, "archive_dir")]:
            if directory.exists():
                for f in directory.iterdir():
                    if f.is_file():
                        usage[key] += f.stat().st_size
                        usage["total"] += f.stat().st_size

        for artifact in self._artifacts.values():
            status = artifact.status.value
            usage["by_status"][status] = usage["by_status"].get(status, 0) + 1
            art_type = artifact.artifact_type.value
            usage["by_type"][art_type] = usage["by_type"].get(art_type, 0) + 1

        return usage

    def check_disk_space(self, path: str | None = None) -> dict[str, Any]:
        """Check disk space availability."""
        check_path = Path(path or self._temp_dir)
        try:
            stat = os.statvfs(str(check_path))
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bavail * stat.f_frsize
            used = total - free
            usage_percent = (used / total * 100) if total > 0 else 0
            low_space = free < (100 * 1024 * 1024)

            return {
                "path": str(check_path),
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "usage_percent": usage_percent,
                "low_space": low_space,
                "warning": "Disk space critically low" if low_space else None,
            }
        except Exception as e:
            return {"error": str(e)}

    def list_artifacts(self, tenant_id: str | None = None,
                       status: ArtifactStatus | None = None,
                       artifact_type: ArtifactType | None = None,
                       limit: int = 100) -> list[Artifact]:
        """List artifacts with optional filtering."""
        results = []
        for artifact in self._artifacts.values():
            if tenant_id and artifact.tenant_id != tenant_id:
                continue
            if status and artifact.status != status:
                continue
            if artifact_type and artifact.artifact_type != artifact_type:
                continue
            results.append(artifact)
            if len(results) >= limit:
                break
        return results

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        """Get an artifact by ID."""
        return self._artifacts.get(artifact_id)


_artifact_lifecycle: ArtifactLifecycleManager | None = None


def get_artifact_lifecycle() -> ArtifactLifecycleManager:
    """Get the global artifact lifecycle manager."""
    global _artifact_lifecycle
    if _artifact_lifecycle is None:
        _artifact_lifecycle = ArtifactLifecycleManager()
    return _artifact_lifecycle


def set_artifact_lifecycle(manager: ArtifactLifecycleManager) -> None:
    """Set the global artifact lifecycle manager (for testing)."""
    global _artifact_lifecycle
    _artifact_lifecycle = manager
