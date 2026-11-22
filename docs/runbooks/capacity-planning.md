# Capacity Planning Runbook

> **Metric note (verified 2026-11-17):** every `ishastra_*` series this page queries
> is defined in `src/ishastra/metrics.py` and has a data source.
> `ishastra_queue_depth` and `ishastra_worker_*` publish in `inprocess` queue mode only.


## Overview
Guidance for sizing, monitoring, and scaling Ishastra deployments.

---

## Resource Requirements

### Minimum Production Specs

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 vCPU | 4+ vCPU |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 20 GB SSD | 50+ GB SSD (NVMe) |
| **Network** | 1 Gbps | 10 Gbps |

### Per-Job Resource Usage

| Profile | Avg Duration | Peak RAM | CPU | Disk I/O |
|---------|--------------|----------|-----|----------|
| `web` | 15-30s | 150 MB | 0.5 core | Low |
| `web-deep` | 60-180s | 300 MB | 1 core | Medium |
| `api-deep` | 60-300s | 400 MB | 1.5 cores | Medium |
| `network` | 30-120s | 200 MB | 0.5 core | Low |
| `nuclei` (in web-deep) | +30-60s | +100 MB | +0.5 core | Medium |

---

## Database Sizing

### SQLite (Default)

| Metric | Estimation |
|--------|------------|
| **Per job** | ~5-15 KB (findings + runs + metadata) |
| **Per finding** | ~2-5 KB |
| **Per audit entry** | ~1 KB |
| **10K jobs + 100K findings** | ~500 MB |
| **Audit chain (1M entries)** | ~50 MB |

### Growth Projections

```sql
-- Estimate database size
SELECT 
  (SELECT COUNT(*) FROM jobs) * 10 as est_jobs_kb,
  (SELECT COUNT(*) FROM findings) * 3 as est_findings_kb,
  (SELECT COUNT(*) FROM audit_log) * 1 as est_audit_kb;
```

### Retention Impact

| Retention | Jobs/Month | DB Size/Year |
|-----------|------------|--------------|
| 30 days | 1,000 | ~200 MB |
| 90 days | 1,000 | ~600 MB |
| 365 days | 1,000 | ~2.4 GB |
| 2555 days (7yr) | 1,000 | ~17 GB |

---

## Queue Capacity

### In-Memory Queue (Default)

| Setting | Default | Max Recommended |
|---------|---------|-----------------|
| `ISHASTRA_QUEUE_MAX` | 32 | 100 |
| Concurrent workers | 1 | 1 (single-process) |

**Queue Full Behavior**: Returns 503 Service Unavailable

### Sizing Formula

```
Max Concurrent Jobs = ISHASTRA_WORKERS * ISHASTRA_QUEUE_MAX
Throughput (jobs/hour) = 3600 / Avg_Job_Duration * Workers
```

**Examples**:
- Web profile (30s avg): 120 jobs/hour per worker
- Web-deep (120s avg): 30 jobs/hour per worker

---

## Rate Limiting Capacity

### Per-Tier Limits

| Tier | General requests/min | Assessment submissions/min |
|------|----------------------|----------------------------|
| Free | 5 | 5 |
| Pro | 60 | 20 |
| Enterprise | 300 | 60 |

Tier names are rate-limit profiles, not editions. Concurrency is controlled by
`ISHASTRA_WORKERS`, not by tier; all features remain MIT-licensed.

### Redis Rate Limiter (Multi-Worker)

When `ISHASTRA_REDIS_REQUIRED=true` or `ISHASTRA_WORKERS>1`:

- **Redis memory**: ~1 KB per active key
- **10K tenants** ≈ 10 MB Redis
- **Key TTL**: 60 seconds (sliding window)

---

## Monitoring Metrics

### Key Metrics to Alert On

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| `ishastra_queue_depth` | > 20 | > 40 | Scale workers / investigate stuck jobs |
| `ishastra_job_duration_seconds` (p95) | > 300s | > 600s | Profile optimization / timeout increase |
| `ishastra_active_jobs` | > 8 | > 15 | Queue saturation |
| `ishastra_db_size_bytes` | > 5 GB | > 15 GB | Prune / archive |
| `ishastra_audit_chain_length` | N/A | N/A | Monitor for gaps |
| `ishastra_worker_heartbeat_age` | > 60s | > 120s | Worker dead |
| `ishastra_rate_limit_exceeded_total` | > 10/min | > 100/min | Capacity / abuse |

### Prometheus Queries

```promql
# Queue depth
ishastra_queue_depth

# Job duration p95
histogram_quantile(0.95, rate(ishastra_job_duration_seconds_bucket[5m]))

# Active jobs by tenant
ishastra_active_jobs{tenant="acme-corp"}

# Database size
ishastra_db_size_bytes / 1024 / 1024 / 1024 > 5

# Worker health
time() - ishastra_worker_heartbeat_timestamp > 60

# Rate limit hits
rate(ishastra_rate_limit_exceeded_total[5m]) > 0.16
```

### Grafana Dashboard Panels

1. **Queue Health**: Depth, enqueue rate, dequeue rate
2. **Job Performance**: Duration histogram, success rate, by profile
3. **Resource Usage**: CPU, RAM, disk, network
4. **Database**: Size, connections, query latency
5. **Rate Limiting**: Requests by tier, 429 rate
6. **Audit Chain**: Length, verification status, last verified

---

## Scaling Strategies

### Vertical Scaling (Single Process)

```bash
# Increase resources
# CPU: More cores → faster parallel adapter execution (limited)
# RAM: Larger → more concurrent jobs, bigger tool output buffers
# Disk: Faster I/O → better SQLite performance, tool temp files

# Tune timeouts for larger jobs
export ISHASTRA_JOB_TIMEOUT=900  # 15 min max
```

### Horizontal Scaling (Requires Redis + Shared Queue)

```yaml
# docker-compose.scale.yml
services:
  ishastra:
    deploy:
      replicas: 3
    environment:
      - ISHASTRA_REDIS_URL=redis://redis:6379/0
      - ISHASTRA_REDIS_REQUIRED=true
      - ISHASTRA_WORKERS=1  # Per container
      - ISHASTRA_QUEUE_MODE=k8s-jobs  # If using k8s-jobs extra
  redis:
    # Redis cluster for HA
```

**Current limitation:** the default queue is in-process and SQLite is
single-writer. Kubernetes Jobs and PostgreSQL now have tested single-host paths
(including durable cancellation and an assessment benchmark), but neither has
HA, multi-node scheduling or exactly-once execution. Do not scale this manifest
in production yet.

True horizontal scaling still requires:
1. Multi-node Kubernetes Jobs scheduling, idempotency and crash-recovery tests.
2. PostgreSQL HA/failover and a worker/database soak test.
3. Organization/RBAC and usage metering before a multi-tenant service.

### Profile-Based Scaling

| Workload | Currently supported setup |
|----------|---------------------------|
| Light (web, probe) | 1 host, 1 worker, 2 vCPU, 4 GB |
| Mixed (web + api-deep) | 1 host, 1 worker, 4 vCPU, 8 GB |
| Heavy (continuous web-deep) | 1 host, higher `ISHASTRA_WORKERS`, measured scanner concurrency |
| Multi-tenant SaaS | **Not supported yet**; requires organizations, metering and HA |

---

## Capacity Planning Checklist

### Monthly
- [ ] Review database growth trend
- [ ] Check audit chain size
- [ ] Verify retention policy working
- [ ] Review rate limit utilization by tier
- [ ] Check queue depth percentiles

### Quarterly
- [ ] Load test with production-like profiles
- [ ] Review and update resource limits
- [ ] Test backup/restore procedure
- [ ] Evaluate horizontal scaling need
- [ ] Update runbook with new thresholds

### Pre-Launch (New Tenant/High Volume)
- [ ] Estimate job volume × profile mix
- [ ] Calculate required workers
- [ ] Provision Redis if >1 worker
- [ ] Configure tier-appropriate rate limits
- [ ] Set up dedicated monitoring alerts
- [ ] Run integration test with their scope

---

## Cost Optimization

### Reduce Resource Usage
```bash
# Shorter timeouts for faster queue turnover
export ISHASTRA_JOB_TIMEOUT=120

# Disable expensive profiles if not needed
# Remove nuclei from web-deep if not required
# Reduce crawler max pages
```

### Database Maintenance
```bash
# Weekly vacuum (run during low traffic)
sqlite3 /data/ishastra.db "VACUUM;"

# Monthly analyze
sqlite3 /data/ishastra.db "ANALYZE;"

# Prune old data (automatic via retention worker)
# Manual trigger:
curl -X POST http://localhost:8000/api/admin/prune \
  -H "Authorization: Bearer $ADMIN_KEY"
```

---

## Troubleshooting Capacity Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Jobs queueing, not running | Worker dead / stuck | Restart worker, check logs |
| 503 Service Unavailable | Queue full (ISHASTRA_QUEUE_MAX) | Increase limit or add workers |
| High job latency | Slow external tools (nmap/nuclei) | Increase timeout, reduce profile scope |
| OOM kills | Tool output too large | Reduce `max_output_bytes` in adapters |
| SQLite locked | Concurrent writes | Single writer; check for leaked connections |
| Rate limit false positives | Clock skew / Redis lag | Sync NTP, check Redis latency |
