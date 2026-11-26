"""Resource profiles for IshAstra deployments.

Provides three tested configuration profiles:

1. Lightweight Profile: Personal computers and small VPS instances
2. Standard Profile: Small security teams
3. High-Capacity Profile: Dedicated assessment servers

These are configuration profiles, not claims of tested capacity.
Benchmark each profile on documented hardware before publishing resource requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResourceProfile:
    """A resource profile configuration."""

    name: str
    description: str
    target: str

    # Worker configuration
    worker_concurrency: int = 1
    worker_memory_mb: int = 1024
    queue_max: int = 32

    # Storage configuration
    max_artifact_size_mb: int = 500
    max_temp_dir_mb: int = 100
    max_evidence_bundle_mb: int = 200
    max_packet_capture_mb: int = 100
    max_scanner_output_mb: int = 200
    max_assessment_output_mb: int = 500
    max_engagement_storage_mb: int = 10000
    max_tenant_storage_mb: int | None = None

    # Retention
    retention_days: int = 90
    temp_cleanup_hours: int = 24

    # Database
    db_path: str = "ishastra.db"
    use_postgresql: bool = False
    enable_wal: bool = True
    wal_autocheckpoint: int = 1000

    # HTTP/response limits
    max_body_bytes: int = 1048576  # 1MB
    max_response_buffer_mb: int = 10
    max_request_size_mb: int = 10

    # Assessment limits
    max_assessment_timeout_seconds: int = 300
    max_findings_per_assessment: int | None = None
    max_assets_per_assessment: int | None = None

    # Compression
    compress_evidence: bool = True
    compression_threshold_kb: int = 100

    # Monitoring
    enable_disk_monitoring: bool = True
    disk_warning_gb: float = 1.0
    disk_critical_gb: float = 0.5

    # Packet capture
    max_capture_size_mb: int = 100
    capture_rotation: bool = True
    capture_retention_days: int = 7

    # Scanner output
    max_scanner_output_lines: int | None = None
    truncate_scanner_output: bool = False
    scanner_output_warning_threshold_kb: int = 10240

    additional_config: dict[str, Any] = field(default_factory=dict)


LIGHTWEIGHT_PROFILE = ResourceProfile(
    name="lightweight",
    description="Personal computers and small VPS instances (2GB RAM, 2 CPU cores minimum)",
    target="development, personal use, small VPS",
    worker_concurrency=1,
    worker_memory_mb=512,
    queue_max=10,
    max_artifact_size_mb=100,
    max_temp_dir_mb=50,
    max_evidence_bundle_mb=50,
    max_packet_capture_mb=25,
    max_scanner_output_mb=50,
    max_assessment_output_mb=100,
    max_engagement_storage_mb=1000,
    retention_days=30,
    temp_cleanup_hours=12,
    db_path="ishastra.db",
    use_postgresql=False,
    enable_wal=True,
    wal_autocheckpoint=500,
    max_body_bytes=262144,
    max_response_buffer_mb=5,
    max_request_size_mb=5,
    max_assessment_timeout_seconds=120,
    max_findings_per_assessment=500,
    max_assets_per_assessment=100,
    compress_evidence=True,
    compression_threshold_kb=50,
    enable_disk_monitoring=True,
    disk_warning_gb=0.5,
    disk_critical_gb=0.25,
    max_capture_size_mb=25,
    capture_rotation=True,
    capture_retention_days=3,
    max_scanner_output_lines=10000,
    truncate_scanner_output=True,
    scanner_output_warning_threshold_kb=1024,
    additional_config={
        "sqlite_max_connections": 1,
        "connection_pool_size": 1,
        "log_retention_days": 7,
        "max_log_size_mb": 10,
        "audit_max_entries": 1000,
    },
)


STANDARD_PROFILE = ResourceProfile(
    name="standard",
    description="Small security teams (4-8GB RAM, 2-4 CPU cores)",
    target="small teams, regular assessments, PostgreSQL recommended",
    worker_concurrency=2,
    worker_memory_mb=1024,
    queue_max=32,
    max_artifact_size_mb=500,
    max_temp_dir_mb=100,
    max_evidence_bundle_mb=200,
    max_packet_capture_mb=100,
    max_scanner_output_mb=200,
    max_assessment_output_mb=500,
    max_engagement_storage_mb=10000,
    max_tenant_storage_mb=50000,
    retention_days=90,
    temp_cleanup_hours=24,
    db_path="ishastra.db",
    use_postgresql=True,
    enable_wal=True,
    wal_autocheckpoint=1000,
    max_body_bytes=1048576,
    max_response_buffer_mb=10,
    max_request_size_mb=10,
    max_assessment_timeout_seconds=300,
    max_findings_per_assessment=10000,
    max_assets_per_assessment=500,
    compress_evidence=True,
    compression_threshold_kb=100,
    enable_disk_monitoring=True,
    disk_warning_gb=1.0,
    disk_critical_gb=0.5,
    max_capture_size_mb=100,
    capture_rotation=True,
    capture_retention_days=7,
    max_scanner_output_lines=100000,
    truncate_scanner_output=False,
    scanner_output_warning_threshold_kb=10240,
    additional_config={
        "sqlite_max_connections": 5,
        "connection_pool_size": 5,
        "log_retention_days": 30,
        "max_log_size_mb": 50,
        "audit_max_entries": 10000,
        "postgresql_pool_size": 10,
        "postgresql_max_connections": 20,
    },
)


HIGH_CAPACITY_PROFILE = ResourceProfile(
    name="high-capacity",
    description="Dedicated assessment servers (16GB+ RAM, 4+ CPU cores, separate storage volume)",
    target="dedicated assessment servers, high-volume operations",
    worker_concurrency=4,
    worker_memory_mb=2048,
    queue_max=128,
    max_artifact_size_mb=1000,
    max_temp_dir_mb=500,
    max_evidence_bundle_mb=500,
    max_packet_capture_mb=500,
    max_scanner_output_mb=1000,
    max_assessment_output_mb=2000,
    max_engagement_storage_mb=100000,
    max_tenant_storage_mb=500000,
    retention_days=365,
    temp_cleanup_hours=48,
    db_path="ishastra.db",
    use_postgresql=True,
    enable_wal=True,
    wal_autocheckpoint=5000,
    max_body_bytes=10485760,
    max_response_buffer_mb=50,
    max_request_size_mb=50,
    max_assessment_timeout_seconds=900,
    max_findings_per_assessment=None,
    max_assets_per_assessment=None,
    compress_evidence=True,
    compression_threshold_kb=250,
    enable_disk_monitoring=True,
    disk_warning_gb=5.0,
    disk_critical_gb=2.0,
    max_capture_size_mb=500,
    capture_rotation=True,
    capture_retention_days=30,
    max_scanner_output_lines=None,
    truncate_scanner_output=False,
    scanner_output_warning_threshold_kb=25600,
    additional_config={
        "sqlite_max_connections": 20,
        "connection_pool_size": 20,
        "log_retention_days": 90,
        "max_log_size_mb": 200,
        "audit_max_entries": 100000,
        "postgresql_pool_size": 20,
        "postgresql_max_connections": 50,
        "separate_artifact_volume": "/mnt/artifacts",
        "backup_retention_days": 30,
        "backup_schedule": "daily",
    },
)


PROFILES: dict[str, ResourceProfile] = {
    "lightweight": LIGHTWEIGHT_PROFILE,
    "standard": STANDARD_PROFILE,
    "high-capacity": HIGH_CAPACITY_PROFILE,
}


def get_profile(name: str) -> ResourceProfile:
    """Get a resource profile by name."""
    if name not in PROFILES:
        available = ", ".join(PROFILES.keys())
        raise ValueError(f"Unknown profile '{name}'. Available profiles: {available}")
    return PROFILES[name]


def list_profiles() -> list[str]:
    """List available profile names."""
    return list(PROFILES.keys())


def get_profile_defaults(profile_name: str) -> dict[str, Any]:
    """Get the default configuration values for a profile as a dict."""
    profile = get_profile(profile_name)
    return {
        "worker_concurrency": profile.worker_concurrency,
        "worker_memory_mb": profile.worker_memory_mb,
        "queue_max": profile.queue_max,
        "max_artifact_size_mb": profile.max_artifact_size_mb,
        "max_temp_dir_mb": profile.max_temp_dir_mb,
        "max_evidence_bundle_mb": profile.max_evidence_bundle_mb,
        "max_packet_capture_mb": profile.max_packet_capture_mb,
        "max_scanner_output_mb": profile.max_scanner_output_mb,
        "max_assessment_output_mb": profile.max_assessment_output_mb,
        "max_engagement_storage_mb": profile.max_engagement_storage_mb,
        "max_tenant_storage_mb": profile.max_tenant_storage_mb,
        "retention_days": profile.retention_days,
        "temp_cleanup_hours": profile.temp_cleanup_hours,
        "use_postgresql": profile.use_postgresql,
        "enable_wal": profile.enable_wal,
        "wal_autocheckpoint": profile.wal_autocheckpoint,
        "max_body_bytes": profile.max_body_bytes,
        "max_response_buffer_mb": profile.max_response_buffer_mb,
        "max_request_size_mb": profile.max_request_size_mb,
        "max_assessment_timeout_seconds": profile.max_assessment_timeout_seconds,
        "max_findings_per_assessment": profile.max_findings_per_assessment,
        "max_assets_per_assessment": profile.max_assets_per_assessment,
        "compress_evidence": profile.compress_evidence,
        "compression_threshold_kb": profile.compression_threshold_kb,
        "enable_disk_monitoring": profile.enable_disk_monitoring,
        "disk_warning_gb": profile.disk_warning_gb,
        "disk_critical_gb": profile.disk_critical_gb,
        "max_capture_size_mb": profile.max_capture_size_mb,
        "capture_rotation": profile.capture_rotation,
        "capture_retention_days": profile.capture_retention_days,
        "max_scanner_output_lines": profile.max_scanner_output_lines,
        "truncate_scanner_output": profile.truncate_scanner_output,
        "scanner_output_warning_threshold_kb": profile.scanner_output_warning_threshold_kb,
        "additional_config": profile.additional_config,
    }
