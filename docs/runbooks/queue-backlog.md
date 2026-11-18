# Queue Backlog Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/strix/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `StrixQueueBacklogHigh` | warning | > 50 queued jobs per tenant | 5m |
| `StrixQueueBacklogCritical` | critical | > 200 queued jobs per tenant | 2m |

---

## Symptoms & Impact

**Symptoms:**
- API returns 503 Service Unavailable for new assessment requests
- Queue depth metric (`strix_queue_depth`) growing
- Jobs stuck in `started` state for extended periods
- Worker logs show slow processing or repeated failures
- Increased job latency (p95 > 300s)

**Impact:**
- **SEV-2**: Tenants cannot submit new assessments
- Existing queued jobs will complete but with delays
- SLA breach for assessment turnaround time
- Potential cascading failure if workers crash under load

---

## Diagnosis Commands

### 1. Check Queue Metrics (PromQL)
```promql
# Current queue depth by tenant
strix_queue_depth{tenant="acme-corp"}

# Enqueue vs dequeue rate (5m)
rate(strix_jobs_total{state="started"}[5m]) - rate(strix_jobs_total{state=~"completed|failed|cancelled"}[5m])

# Jobs by state
sum by (state) (strix_jobs_total)

# Worker count and health
strix_worker_count
time() - strix_worker_heartbeat_timestamp
```

### 2. Kubernetes & Pod Health
```bash
# Check API pod status
kubectl get pods -n strix -l app.kubernetes.io/name=strix,component=api

# Check worker pods (if using Celery)
kubectl get pods -n strix -l app.kubernetes.io/name=strix,component=worker

# Check HPA status
kubectl get hpa -n strix

# Check pod logs for errors
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=100 | grep -iE "queue|worker|error|timeout"
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=worker --tail=100 | grep -iE "queue|worker|error|timeout"

# Check resource usage
kubectl top pods -n strix -l app.kubernetes.io/name=strix
```

### 3. Database & Redis Checks
```bash
# Check SQLite database size and locks
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# Check for stuck jobs in DB
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "SELECT id, state, created_at, updated_at FROM jobs WHERE state='started' ORDER BY created_at LIMIT 20;"

# Check Redis connectivity (if using Redis queue)
kubectl exec -n strix strix-api-xxx -- redis-cli -u redis://redis-master:6379/0 ping
kubectl exec -n strix strix-api-xxx -- redis-cli -u redis://redis-master:6379/0 INFO memory
```

### 4. Application-Level Diagnosis
```bash
# Get queue status via API
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/status | jq .

# Check running jobs
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  "http://strix.example.com/api/assess?state=running" | jq .

# Check worker status
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/workers | jq .
```

---

## Resolution Procedures

### Immediate Mitigation (SEV-2: < 1 hour)

#### Option 1: Scale Workers (Preferred)
```bash
# Scale API deployment (if HPA not scaling fast enough)
kubectl scale deployment strix-api -n strix --replicas=5

# Or scale worker deployment (if using Celery)
kubectl scale deployment strix-worker -n strix --replicas=10

# Verify scaling
kubectl get pods -n strix -l app.kubernetes.io/name=strix -w
```

#### Option 2: Pause Queue Intake (If workers cannot scale)
```bash
# Pause new job acceptance via API
curl -X POST http://strix.example.com/api/admin/queue/pause \
  -H "Authorization: Bearer $ADMIN_KEY"

# Verify paused
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/status | jq .queue_paused
```

#### Option 3: Cancel Stuck Jobs
```bash
# List stuck jobs (> 30 min running)
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  "http://strix.example.com/api/assess?state=running" | \
  jq '.[] | select(.started_at < (now - 1800)) | .id'

# Cancel specific stuck job
curl -X POST http://strix.example.com/api/assess/<JOB_ID>/cancel \
  -H "Authorization: Bearer $ADMIN_KEY"

# Bulk cancel (use with caution)
for job_id in $(curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  "http://strix.example.com/api/assess?state=running" | jq -r '.[] | select(.started_at < (now - 1800)) | .id'); do
  curl -X POST "http://strix.example.com/api/assess/$job_id/cancel" \
    -H "Authorization: Bearer $ADMIN_KEY"
done
```

### Root Cause Resolution

#### Cause 1: Worker OOM Kills
```bash
# Check for OOM kills
kubectl describe pods -n strix -l app.kubernetes.io/name=strix | grep -i oom
dmesg -T | grep -i kill

# Fix: Increase memory limits
# Edit values.yaml: api.resources.limits.memory: "4Gi"
helm upgrade strix ./deploy/helm/strix -n strix -f values.yaml
```

#### Cause 2: External Tool Timeouts (nmap, nuclei, etc.)
```bash
# Check adapter duration metrics
# PromQL: histogram_quantile(0.95, rate(strix_adapter_duration_seconds_bucket[5m])) by (adapter)

# Increase job timeout
kubectl set env deployment/strix-api -n strix STRIX_JOB_TIMEOUT=900

# Or reduce profile scope (web-deep -> web)
```

#### Cause 3: Database Contention
```bash
# Check for long-running transactions
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA busy_timeout;"

# Vacuum database (during maintenance window)
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "VACUUM;"

# Enable WAL mode if not already
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA journal_mode=WAL;"
```

#### Cause 4: Redis Connection Issues (Distributed Queue)
```bash
# Check Redis latency
kubectl exec -n strix redis-master-0 -- redis-cli --latency-history -i 1

# Check Redis memory
kubectl exec -n strix redis-master-0 -- redis-cli INFO memory

# Restart Redis if needed
kubectl rollout restart statefulset/redis-master -n strix
```

### Recovery Verification
```bash
# 1. Verify queue draining
watch -n 10 'curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/status | jq .queue_depth'

# 2. Verify job completion rate
# PromQL: rate(strix_jobs_total{state="completed"}[5m])

# 3. Resume queue if paused
curl -X POST http://strix.example.com/api/admin/queue/resume \
  -H "Authorization: Bearer $ADMIN_KEY"

# 4. Scale down after backlog cleared
kubectl scale deployment strix-api -n strix --replicas=3
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Warning** (High) | 1 hour | On-call engineer |
| **Critical** | 15 minutes | On-call → Platform Lead → VP Engineering |

**SLA Targets:**
- Queue backlog < 50 jobs: 99.9% of time
- Job queue time < 5 min: 95th percentile
- Time to scale workers: < 5 min (HPA), < 15 min (manual)

**Contacts:**
- Platform On-Call: `platform-oncall@example.com` (PagerDuty)
- Platform Lead: `platform-lead@example.com`
- Infrastructure: `infrastructure@example.com`

---

## Post-Incident Actions

1. **Root Cause Analysis** within 48 hours
2. **Update runbook** with new findings
3. **Review HPA thresholds** and scaling policies
4. **Capacity planning** review if recurring
5. **Add regression test** for identified failure mode

---

## Grafana Dashboard Links

- **Strix Queue Health**: `https://grafana.example.com/d/strix-queue/queue-health`
- **Strix Job Performance**: `https://grafana.example.com/d/strix-jobs/job-performance`
- **Strix Worker Status**: `https://grafana.example.com/d/strix-workers/worker-status`
- **Kubernetes Resources**: `https://grafana.example.com/d/k8s-resources/pod-resources`

**Key Panels:**
- Queue Depth by Tenant (time series)
- Enqueue/Dequeue Rate (rate)
- Job Duration p50/p95/p99 (histogram)
- Active Workers Count (stat)
- Worker Heartbeat Age (time series)
