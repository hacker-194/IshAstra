"""Disk usage protection and quota enforcement for IshAstra.

Provides:
- Configurable storage quotas per engagement and tenant
- Disk-space monitoring with low-space warnings
- Safe rejection of new work when storage is exhausted
- Storage usage reporting
- Log rotation integration
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from ishastra.config import Settings

log = logging.getLogger(__name__)


def get_disk_usage(path: str | Path) -> dict[str, Any]:
    """Get disk usage statistics for a path.

    Returns total, used, free in bytes and percentage.
    """
    path = Path(path)
    try:
        stat = os.statvfs(str(path.parent if path.is_file() else path))
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used = total - free
        return {
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "usage_percent": (used / total * 100) if total > 0 else 0,
        }
    except Exception as e:
        return {"error": str(e)}


def check_disk_space_safe(
    path: str | Path,
    required_bytes: int,
    warning_threshold_percent: float = 90.0,
) -> dict[str, Any]:
    """Check disk space and return safety assessment.

    Returns dict with:
    - safe: bool - whether the operation is safe to proceed
    - required_bytes: int
    - available_bytes: int
    - shortfall_bytes: int (0 if safe)
    - warning: str | None
    """
    usage = get_disk_usage(path)
    if "error" in usage:
        return {
            "safe": False,
            "required_bytes": required_bytes,
            "available_bytes": 0,
            "shortfall_bytes": required_bytes,
            "warning": f"Cannot check disk space: {usage['error']}",
        }

    available = usage["free_bytes"]
    shortfall = max(0, required_bytes - available)
    warning = None

    if usage["usage_percent"] > warning_threshold_percent:
        warning = f"Disk usage at {usage['usage_percent']:.1f}%"

    return {
        "safe": shortfall == 0,
        "required_bytes": required_bytes,
        "available_bytes": available,
        "shortfall_bytes": shortfall,
        "warning": warning,
    }


class StorageQuotaExceeded(Exception):
    """Raised when a storage operation would exceed quota."""

    def __init__(self, message: str = "Storage quota exceeded"):
        super().__init__(message)


@dataclass
class StorageQuotaConfig:
    """Configuration for storage quotas."""

    max_artifact_size_mb: int = 500
    max_total_engagement_storage_mb: int = 10000
    max_total_tenant_storage_mb: int | None = None
    max_temp_dir_size_mb: int = 100
    max_log_size_mb: int = 50
    max_evidence_bundle_size_mb: int = 200
    max_packet_capture_size_mb: int = 100
    max_scanner_output_size_mb: int = 200
    max_assessment_output_size_mb: int = 500

    # Low disk space thresholds
    low_disk_warning_gb: float = 1.0
    critical_disk_gb: float = 0.5

    @property
    def max_artifact_size_bytes(self) -> int:
        return self.max_artifact_size_mb * 1024 * 1024

    @property
    def max_temp_dir_bytes(self) -> int:
        return self.max_temp_dir_size_mb * 1024 * 1024

    @property
    def max_engagement_bytes(self) -> int:
        return self.max_total_engagement_storage_mb * 1024 * 1024

    @property
    def max_tenant_bytes(self) -> int | None:
        if self.max_total_tenant_storage_mb is None:
            return None
        return self.max_total_tenant_storage_mb * 1024 * 1024

    @property
    def max_evidence_bundle_size_bytes(self) -> int:
        return self.max_evidence_bundle_size_mb * 1024 * 1024

    @property
    def max_packet_capture_size_bytes(self) -> int:
        return self.max_packet_capture_size_mb * 1024 * 1024

    @property
    def max_scanner_output_size_bytes(self) -> int:
        return self.max_scanner_output_size_mb * 1024 * 1024

    @property
    def max_assessment_output_size_bytes(self) -> int:
        return self.max_assessment_output_size_mb * 1024 * 1024


class StorageQuotaManager:
    """Manages storage quotas and disk space monitoring."""

    def __init__(self, config: StorageQuotaConfig | None = None, settings: Settings | None = None):
        self.config = config or self._from_settings(settings)
        self._engagement_usage: dict[str, int] = {}
        self._tenant_usage: dict[str, int] = {}
        self._last_check: float = 0
        self._check_interval: int = 60

    @staticmethod
    def _from_settings(settings: Settings | None = None) -> StorageQuotaConfig:
        if settings:
            return StorageQuotaConfig(
                max_artifact_size_mb=min(
                    settings.worker_memory_mb // 4 if settings.worker_memory_mb else 500, 500
                ),
                max_temp_dir_size_mb=min(
                    100,
                    settings.worker_memory_mb // 8 if settings.worker_memory_mb else 100,
                ),
                max_evidence_bundle_size_mb=min(
                    200,
                    settings.worker_memory_mb // 2 if settings.worker_memory_mb else 200,
                ),
                max_packet_capture_size_mb=min(
                    100,
                    settings.worker_memory_mb // 4 if settings.worker_memory_mb else 100,
                ),
                max_scanner_output_size_mb=min(
                    200,
                    settings.worker_memory_mb // 2 if settings.worker_memory_mb else 200,
                ),
                max_assessment_output_size_mb=min(
                    500,
                    settings.worker_memory_mb if settings.worker_memory_mb else 500,
                ),
            )
        return StorageQuotaConfig()

    def record_artifact_size(self, tenant_id: str, engagement_id: str | None, artifact_size: int) -> None:
        if engagement_id:
            self._engagement_usage[engagement_id] = (
                self._engagement_usage.get(engagement_id, 0) + artifact_size
            )
        if tenant_id:
            self._tenant_usage[tenant_id] = self._tenant_usage.get(tenant_id, 0) + artifact_size

    def remove_artifact_size(self, tenant_id: str, engagement_id: str | None, artifact_size: int) -> None:
        if engagement_id:
            self._engagement_usage[engagement_id] = max(
                0, self._engagement_usage.get(engagement_id, 0) - artifact_size
            )
        if tenant_id:
            self._tenant_usage[tenant_id] = max(0, self._tenant_usage.get(tenant_id, 0) - artifact_size)

    def check_artifact_size(self, artifact_size: int, artifact_type: str = "artifact") -> None:
        config = self.config

        max_sizes = {
            "artifact": config.max_artifact_size_bytes,
            "evidence_bundle": config.max_evidence_bundle_size_bytes,
            "packet_capture": config.max_packet_capture_size_bytes,
            "scanner_output": config.max_scanner_output_size_bytes,
            "assessment_output": config.max_assessment_output_size_bytes,
        }

        max_size = max_sizes.get(artifact_type, config.max_artifact_size_bytes)
        if artifact_size > max_size:
            raise StorageQuotaExceeded(
                f"{artifact_type} size ({artifact_size} bytes) exceeds maximum ({max_size} bytes)"
            )

    def check_engagement_quota(self, engagement_id: str, additional_bytes: int) -> None:
        current = self._engagement_usage.get(engagement_id, 0)
        if current + additional_bytes > self.config.max_engagement_bytes:
            raise StorageQuotaExceeded(
                f"Engagement '{engagement_id}' would exceed storage quota: "
                f"current={current}, adding={additional_bytes}, max={self.config.max_engagement_bytes}"
            )

    def check_tenant_quota(self, tenant_id: str, additional_bytes: int) -> None:
        if self.config.max_tenant_bytes is None:
            return

        current = self._tenant_usage.get(tenant_id, 0)
        if current + additional_bytes > self.config.max_tenant_bytes:
            raise StorageQuotaExceeded(
                f"Tenant '{tenant_id}' would exceed storage quota: "
                f"current={current}, adding={additional_bytes}, max={self.config.max_tenant_bytes}"
            )

    def check_disk_space(self, path: str | Path, required_bytes: int) -> dict[str, Any]:
        now = time.time()
        if now - self._last_check < self._check_interval:
            return {"safe": True, "cached": True}

        self._last_check = now
        safety = check_disk_space_safe(path, required_bytes)

        critical_threshold = self.config.critical_disk_gb * 1024 * 1024 * 1024
        if safety["available_bytes"] < critical_threshold:
            log.critical(
                "Disk space critically low: %.2f GB available, %.2f GB required",
                safety["available_bytes"] / (1024**3),
                required_bytes / (1024**3),
            )
            safety["safe"] = False
            safety["warning"] = "CRITICAL: Disk space exhausted, rejecting new work"

        if (
            safety["safe"]
            and safety["available_bytes"] < self.config.low_disk_warning_gb * 1024 * 1024 * 1024
        ):
            log.warning(
                "Low disk space warning: %.2f GB available",
                safety["available_bytes"] / (1024**3),
            )

        return safety

    def check_can_write(
        self,
        path: str | Path,
        required_bytes: int,
        tenant_id: str | None = None,
        engagement_id: str | None = None,
        artifact_type: str = "artifact",
    ) -> dict[str, Any]:
        self.check_artifact_size(required_bytes, artifact_type)

        if engagement_id:
            self.check_engagement_quota(engagement_id, required_bytes)

        if tenant_id:
            self.check_tenant_quota(tenant_id, required_bytes)

        return self.check_disk_space(path, required_bytes)

    def get_usage_report(self) -> dict[str, Any]:
        disk = get_disk_usage(Path.cwd())

        return {
            "disk": disk,
            "quota_config": {
                "max_artifact_size_mb": self.config.max_artifact_size_mb,
                "max_engagement_storage_mb": self.config.max_total_engagement_storage_mb,
                "max_tenant_storage_mb": self.config.max_total_tenant_storage_mb,
                "max_temp_dir_mb": self.config.max_temp_dir_size_mb,
                "max_evidence_bundle_mb": self.config.max_evidence_bundle_size_mb,
                "max_packet_capture_mb": self.config.max_packet_capture_size_mb,
                "max_scanner_output_mb": self.config.max_scanner_output_size_mb,
            },
            "engagement_usage": dict(self._engagement_usage),
            "tenant_usage": dict(self._tenant_usage),
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def clear_usage(self, engagement_id: str | None = None, tenant_id: str | None = None) -> None:
        if engagement_id:
            self._engagement_usage.pop(engagement_id, None)
        if tenant_id:
            self._tenant_usage.pop(tenant_id, None)


class SafeStorageWriter:
    """A wrapper that ensures safe writes with quota and disk space checks."""

    def __init__(self, quota_manager: StorageQuotaManager, base_path: str | Path):
        self.quota = quota_manager
        self.base_path = Path(base_path)

    def write_artifact(
        self,
        tenant_id: str,
        engagement_id: str | None,
        artifact_type: str,
        data: bytes | None = None,
        source_path: str | Path | None = None,
        dest_path: str | Path | None = None,
        chunk_size: int = 1024 * 1024,
    ) -> tuple[int, str]:
        if data is not None:
            size = len(data) if isinstance(data, bytes) else sum(1 for _ in data)
        elif source_path:
            size = Path(source_path).stat().st_size
        else:
            raise ValueError("Either data or source_path must be provided")

        safety = self.quota.check_can_write(self.base_path, size, tenant_id, engagement_id, artifact_type)
        if not safety["safe"]:
            raise StorageQuotaExceeded(safety.get("warning", "Storage write not safe"))

        from uuid import uuid4

        artifact_id = f"art_{uuid4().hex[:16]}"

        if dest_path:
            final_path = Path(dest_path)
        else:
            safe_type = artifact_type.replace("/", "_").replace("\\", "_")
            final_path = self.base_path / f"{artifact_id}_{safe_type}.dat"

        final_path.parent.mkdir(parents=True, exist_ok=True)

        tmp_path = str(final_path) + ".tmp"
        bytes_written = 0
        checksum = __import__("hashlib").sha256()

        try:
            if source_path:
                with open(source_path, "rb") as src, open(tmp_path, "wb") as dst:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(chunk)
                        checksum.update(chunk)
                        bytes_written += len(chunk)
            elif isinstance(data, bytes):
                with open(tmp_path, "wb") as f:
                    for i in range(0, len(data), chunk_size):
                        chunk = data[i : i + chunk_size]
                        f.write(chunk)
                        checksum.update(chunk)
                        bytes_written += len(chunk)
            elif isinstance(data, BytesIO):
                with open(tmp_path, "wb") as f:
                    while True:
                        chunk = data.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        checksum.update(chunk)
                        bytes_written += len(chunk)

            os.replace(tmp_path, str(final_path))
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise

        self.quota.record_artifact_size(tenant_id, engagement_id, bytes_written)
        return bytes_written, artifact_id

    def delete_artifact(
        self, tenant_id: str, engagement_id: str | None, artifact_path: str | Path, artifact_size: int
    ) -> bool:
        try:
            Path(artifact_path).unlink(missing_ok=True)
            self.quota.remove_artifact_size(tenant_id, engagement_id, artifact_size)
            return True
        except Exception as e:
            log.error("Failed to delete artifact %s: %s", artifact_path, e)
            return False


def get_storage_quota_manager(settings: Settings | None = None) -> StorageQuotaManager:
    return StorageQuotaManager(settings=settings)
