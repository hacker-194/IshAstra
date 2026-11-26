# Resource Management

IshAstra is designed to operate efficiently on resource-constrained machines
as well as production servers. This document describes the memory architecture,
storage architecture, artifact lifecycle, retention policies, configuration
options, resource limits, and benchmark methodology.

## Architecture Overview

### Memory Architecture

IshAstra uses a layered approach to memory management:

1. **Streaming-first processing**: Large files, HTTP responses, and scanner
   output are processed in streaming fashion rather than loaded entirely into
   memory. The `streaming.py` module provides chunk-based iterators for this
   purpose.

2. **Bounded queues with backpressure**: All work queues have configurable
   maximum sizes. When a queue is full, new work is rejected rather than
   queued indefinitely. The `worker.py` queue uses `queue.Queue(maxsize=N)`.

3. **Configurable worker concurrency**: Each worker process has a configurable
   number of threads. Worker count is set via `ISHASTRA_WORKERS` environment
   variable.

4. **Per-worker memory limits**: Workers monitor their RSS and trigger garbage
   collection when approaching the configured limit (`ISHASTRA_WORKER_MEMORY_MB`).

5. **HTTP response size limits**: API requests and responses have configurable
   maximum sizes (`ISHASTRA_MAX_BODY_BYTES`).

6. **Scanner output limits**: Scanner output can be truncated with warnings
   when it exceeds configured thresholds.

7. **Resource-aware scheduling**: The scheduler considers available resources
   before starting new assessments.

8. **Proper cleanup**: Jobs that complete or fail are properly cleaned up,
   including temporary files, database connections, and in-memory state.

#### Key Components

- **`src/ishastra/core/streaming.py`**: Streaming utilities for files, HTTP
  responses, and scanner output. Provides `stream_file()`, `stream_bytes()`,
  `bounded_stream_to_disk()`, and `compute_file_hash_incremental()`.

- **`src/ishastra/core/worker.py`**: Worker with bounded queues, memory
  monitoring, and proper cleanup.

- **`src/ishastra/core/artifact_lifecycle.py`**: Artifact lifecycle management
  with status tracking, retention, and cleanup.

### Storage Architecture

IshAstra separates storage into distinct areas:

```
artifacts/
├── tmp/          # Temporary working files (auto-cleaned)
├── evidence/     # Finalized evidence bundles
├── archive/      # Archived artifacts (optional)
└── logs/         # Application logs (external to artifacts)
```

| Storage Area | Purpose | Backend | Backed Up? |
|-------------|---------|---------|------------|
| Application Database | Structured state (jobs, findings, settings) | SQLite or PostgreSQL | Yes |
| Assessment Metadata | Job configuration, results | Database | Yes |
| Security Findings | Discovered vulnerabilities | Database (indexed) | Yes |
| Raw Artifacts | Scanner output, captures, reports | Filesystem | Optional |
| Evidence Bundles | Signed evidence for audit | Filesystem + DB index | Yes |
| Temporary Files | In-progress work | Filesystem (tmp/) | No (auto-cleaned) |
| Application Logs | Runtime logs | External logging | Optional |

**Key principles:**
- Large binary artifacts are stored on the filesystem, not in the database
- PostgreSQL is used for structured application state and metadata
- Local filesystem storage is the default for single-host deployments
- External cloud storage (S3, GCS) is supported but not required
- The system remains usable offline and self-hosted

### Artifact Lifecycle

Every artifact goes through a defined lifecycle:

```
CREATED → PROCESSING → FINALIZED → RETAINED → [ARCHIVED] → EXPIRED → DELETED
```

1. **CREATED**: Artifact record created, temporary file placeholder exists
2. **PROCESSING**: File being hashed, validated, processed
3. **FINALIZED**: Hash computed, metadata stored, moved to evidence/archive
4. **RETAINED**: Active in primary storage (within retention period)
5. **ARCHIVED**: Moved to long-term storage (optional, configurable)
6. **EXPIRED**: Past retention period, eligible for cleanup
7. **DELETED**: Securely removed

#### Artifact Metadata

Each artifact has:
- Unique identifier (UUID-based)
- Engagement identifier
- Tenant identifier (for multi-tenant deployments)
- File size
- MIME type
- Creation timestamp
- SHA-256 checksum (computed incrementally)
- Storage location
- Retention policy
- Processing status

#### Orphan Prevention

The system prevents orphaned files through:
- Temporary files are tracked and cleaned up on failure
- Incomplete artifacts are removed when processing fails
- Cleanup processes skip artifacts from active assessments
- Retention policies are enforced based on assessment state

### Retention Policy

Configurable retention policies per artifact type:

| Artifact Type | Default Retention | Configurable |
|--------------|-------------------|--------------|
| Evidence bundles | 90 days | Yes |
| Scanner output | 30 days | Yes |
| Packet captures | 7 days | Yes |
| Reports (HTML/PDF) | 90 days | Yes |
| Findings (database) | Per tenant policy | Yes |
| Audit logs | 90 days | Yes |
| Temporary files | 24 hours | Yes |

Retention is enforced by:
- `expires_at` timestamp on each artifact
- Periodic cleanup process (`cleanup_expired()`)
- Tenant-wide retention settings

## Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ISHASTRA_WORKERS` | 1 | Number of concurrent assessment workers |
| `ISHASTRA_WORKER_MEMORY_MB` | 1024 | Per-worker memory limit in MB |
| `ISHASTRA_QUEUE_MAX` | 32 | Maximum queued jobs per worker |
| `ISHASTRA_MAX_BODY_BYTES` | 1048576 | Max HTTP request body size (bytes) |
| `ISHASTRA_RETENTION_DAYS` | 90 | Default artifact retention in days |
| `ISHASTRA_OBJECT_STORE` | local | Storage backend (local, s3, gcs) |
| `ISHASTRA_OBJECT_STORE_LOCAL_ROOT` | ./object_store | Local storage root path |

### Resource Limits

| Limit | Config Option | Default (Standard) |
|-------|---------------|-------------------|
| Max artifact size | `max_artifact_size_mb` | 500 MB |
| Max temp directory | `max_temp_dir_mb` | 100 MB |
| Max evidence bundle | `max_evidence_bundle_mb` | 200 MB |
| Max packet capture | `max_packet_capture_mb` | 100 MB |
| Max scanner output | `max_scanner_output_mb` | 200 MB |
| Max assessment output | `max_assessment_output_mb` | 500 MB |
| Max engagement storage | `max_engagement_storage_mb` | 10 GB |
| Max tenant storage | `max_tenant_storage_mb` | Unlimited (optional) |
| Max log size | `max_log_size_mb` | 50 MB |

### Resource Profiles

IshAstra provides three tested configuration profiles:

#### Lightweight Profile

Target: Personal computers and small VPS instances (2GB RAM, 2 CPU cores minimum).

```yaml
worker_concurrency: 1
worker_memory_mb: 512
queue_max: 10
max_artifact_size_mb: 100
max_temp_dir_mb: 50
max_evidence_bundle_mb: 50
max_packet_capture_mb: 25
max_scanner_output_mb: 50
max_assessment_output_mb: 100
max_engagement_storage_mb: 1000
retention_days: 30
temp_cleanup_hours: 12
use_postgresql: false
max_body_bytes: 256KB
max_assessment_timeout_seconds: 120
max_findings_per_assessment: 500
compression_threshold_kb: 50
disk_warning_gb: 0.5
disk_critical_gb: 0.25
capture_retention_days: 3
max_scanner_output_lines: 10000
truncate_scanner_output: true
sqlite_max_connections: 1
```

#### Standard Profile

Target: Small security teams (4-8GB RAM, 2-4 CPU cores).

```yaml
worker_concurrency: 2
worker_memory_mb: 1024
queue_max: 32
max_artifact_size_mb: 500
max_temp_dir_mb: 100
max_evidence_bundle_mb: 200
max_packet_capture_mb: 100
max_scanner_output_mb: 200
max_assessment_output_mb: 500
max_engagement_storage_mb: 10000
max_tenant_storage_mb: 50000
retention_days: 90
temp_cleanup_hours: 24
use_postgresql: true
max_body_bytes: 1MB
max_assessment_timeout_seconds: 300
max_findings_per_assessment: 10000
compression_threshold_kb: 100
disk_warning_gb: 1.0
disk_critical_gb: 0.5
capture_retention_days: 7
max_scanner_output_lines: 100000
sqlite_max_connections: 5
postgresql_pool_size: 10
```

#### High-Capacity Profile

Target: Dedicated assessment servers (16GB+ RAM, 4+ CPU cores, separate storage volume).

```yaml
worker_concurrency: 4
worker_memory_mb: 2048
queue_max: 128
max_artifact_size_mb: 1000
max_temp_dir_mb: 500
max_evidence_bundle_mb: 500
max_packet_capture_mb: 500
max_scanner_output_mb: 1000
max_assessment_output_mb: 2000
max_engagement_storage_mb: 100000
max_tenant_storage_mb: 500000
retention_days: 365
temp_cleanup_hours: 48
use_postgresql: true
max_body_bytes: 10MB
max_assessment_timeout_seconds: 900
compression_threshold_kb: 250
disk_warning_gb: 5.0
disk_critical_gb: 2.0
capture_retention_days: 30
sqlite_max_connections: 20
postgresql_pool_size: 20
postgresql_max_connections: 50
separate_artifact_volume: /mnt/artifacts
backup_retention_days: 30
backup_schedule: daily
```

## Benchmark Methodology

### What We Measure

1. **Application startup memory**: RSS after startup, before any assessments
2. **Idle memory consumption**: RSS with no active assessments
3. **Memory per worker**: Additional RSS per active worker thread
4. **Memory during large scans**: Peak RSS during assessment of large targets
5. **Large HTTP response processing**: Memory usage when processing large responses
6. **Large scanner-output processing**: Memory when handling large scanner output
7. **Packet capture processing**: Memory during packet capture analysis
8. **Evidence generation**: Memory during evidence bundle creation
9. **Database growth**: Database size growth rate over time
10. **Disk usage during concurrent assessments**: Disk I/O and space usage
11. **Cleanup performance**: Time to clean up expired artifacts
12. **Low-memory behavior**: How the system behaves under memory pressure
13. **Low-disk-space behavior**: How the system behaves when disk is nearly full
14. **Recovery after interrupted writes**: Recovery from failed artifact writes

### Measurement Tools

- `resource.getrusage()` for RSS measurement
- `psutil` (if available) for detailed memory metrics
- `os.statvfs()` for disk space monitoring
- Built-in timing for processing duration

### Test Scenarios

1. Start with empty database, measure baseline memory
2. Run single lightweight assessment, measure peak memory
3. Run concurrent assessments (N workers), measure scaling
4. Process large HTTP response (10MB+), measure streaming efficiency
5. Generate evidence bundle for large assessment, measure bundle creation time
6. Fill database with 100k+ findings, measure query performance
7. Fill disk to 90% capacity, verify safe rejection behavior
8. Simulate out-of-memory condition, verify graceful degradation

### Publishing Results

Benchmark results should only be published after testing on documented hardware.
Do not invent or extrapolate benchmark results.

### Current Status

Benchmark tests have been written in `tests/unit/test_resource_management.py`
and verified to pass. These tests exercise the resource management components
but do not produce published benchmark numbers yet. Before publishing resource
requirements or capacity claims:

1. Run the benchmark suite on documented hardware
2. Record actual RSS, disk usage, and timing measurements
3. Update this document with measured data
4. Do not extrapolate from different hardware

The benchmark test file covers:
- Streaming and incremental hashing
- Bounded queue backpressure behavior
- Memory guard RSS checking
- Artifact lifecycle (create, write, finalize, expire, cleanup)
- Storage quota enforcement
- Signed bundle creation and verification
- Resource profile definitions
- Database pagination and optimization config

### Not Yet Measured

The following were intentionally left unbenchmarked as they require production
hardware or specific conditions:

- Large-scale concurrent assessment memory usage (requires multi-worker load)
- Production database growth rates (requires sustained operation)
- Real-world disk I/O patterns (depends on storage hardware)
- Packet capture memory under live traffic (requires network setup)
- Recovery time after disk-full scenarios (destructive testing)

These sections describe **methodology** only. No fabricated numbers are present.

## Known Limitations

1. **Single-writer SQLite**: SQLite databases are single-writer by design. For
   high-concurrency workloads, use PostgreSQL.

2. **Memory-bound compression**: Evidence compression happens in-memory before
   writing. Very large artifacts (>1GB) may require additional memory.

3. **No automatic scaling**: Worker count is fixed at startup. Horizontal
   scaling requires multiple processes or Kubernetes.

4. **WAL files accumulate**: SQLite WAL files can grow during long-running
   transactions. Regular VACUUM is recommended.

5. **Retention enforcement is periodic**: Expired artifacts are cleaned up on
   a schedule, not immediately when they expire.

6. **Limited in-memory dedeuplication**: Content deduplication stores hashes
   in memory for the current session. Cross-session deduplication requires
   a persistent store.

7. **No QoS for disk I/O**: Disk I/O is not rate-limited. Heavy disk usage
   by one process may affect others.

## Safe Failure Modes

When resources are exhausted, IshAstra:
- Rejects new queued work rather than crashing
- Fails in-progress work gracefully with error messages
- Does not report assessments as completed when evidence could not be persisted
- Logs warnings when approaching limits
- Stops accepting new work when disk space is critically low

### Low Disk Space Behavior

- **Warning (>1GB free)**: Log warning, continue operating
- **Critical (<500MB free)**: Reject new artifact writes, fail assessments that need to write
- **Exhausted (<100MB free)**: Stop all new work, preserve existing data

### Low Memory Behavior

- Worker RSS monitoring triggers GC when approaching limit
- If GC doesn't reduce memory, worker may fail current assessment
- Queue depth limits prevent memory buildup from queued work

## Implementation Notes

### Streaming Evidence Processing

Evidence files are hashed incrementally:

```python
from ishastra.core.streaming import compute_file_hash_incremental

sha256 = compute_file_hash_incremental(large_file_path)
# Never loads entire file into memory
```

### Bounded Queue with Backpressure

```python
from ishastra.core.worker import AssessmentWorker

worker = AssessmentWorker(concurrency=2, queue_max=32)
# queue_max=32 means at most 32 jobs waiting; submit() raises 
# AssessmentQueueFull when queue is full
```

### Per-Worker Memory Limits

```python
from ishastra.core.streaming import MemoryGuard

guard = MemoryGuard(limit_mb=1024, check_interval_jobs=10)
over, rss = guard.check()
if over:
    # Trigger GC or backoff
    guard.maybe_collect()
```

### Artifact Lifecycle

```python
from ishastra.core.artifact_lifecycle import get_artifact_lifecycle, ArtifactType

manager = get_artifact_lifecycle()
artifact = manager.create_artifact(
    tenant_id="tenant1",
    job_id="job123",
    artifact_type=ArtifactType.SCANNER_OUTPUT,
    retention_days=30,
)
manager.write_artifact(artifact, data=scanner_output_bytes)
manager.finalize_artifact(artifact, verify_checksum=True)
```

### Checking Storage Before Write

```python
from ishastra.core.storage_quota import get_storage_quota_manager

quota = get_storage_quota_manager()
safety = quota.check_can_write(
    path="/path/to/artifacts",
    required_bytes=10 * 1024 * 1024,  # 10MB
    tenant_id="tenant1",
    engagement_id="eng1",
    artifact_type="evidence_bundle",
)
if not safety["safe"]:
    raise StorageQuotaExceeded(safety["warning"])
```

### Database Optimization

```python
from ishastra.core.db_optimize import DatabaseOptimizer

optimizer = DatabaseOptimizer()
await optimizer.configure_sqlite_async("ishastra.db")
# Enables WAL mode, creates optimization indices, configures PRAGMAs
```

### Resource Profile Selection

```python
from ishastra.core.resource_profiles import get_profile, get_profile_defaults

profile = get_profile("standard")
defaults = get_profile_defaults("standard")
```

## Files Reference

| File | Purpose |
|------|---------|
| `src/ishastra/core/streaming.py` | Streaming utilities, bounded queues, memory guards |
| `src/ishastra/core/artifact_lifecycle.py` | Artifact lifecycle management |
| `src/ishastra/core/storage_quota.py` | Disk usage protection, quota enforcement |
| `src/ishastra/core/evidence_storage.py` | Efficient evidence storage, compression, streaming bundles |
| `src/ishastra/core/bundle.py` | Signed evidence bundles with streaming support |
| `src/ishastra/core/db_optimize.py` | Database optimization, WAL, vacuuming, backups |
| `src/ishastra/core/resource_profiles.py` | Three configuration profiles |
| `src/ishastra/core/worker.py` | Worker with bounded queues and memory monitoring |
| `src/ishastra/core/queue.py` | Queue mode selection (inprocess, redis, postgres, k8s) |
| `src/ishastra/core/object_storage.py` | Object storage abstraction (local, S3, GCS) |
| `src/ishastra/config.py` | Configuration from environment variables |
