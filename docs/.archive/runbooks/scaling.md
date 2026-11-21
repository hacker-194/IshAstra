# Scaling Procedures Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/ishastra/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Overview

This runbook covers horizontal and vertical scaling procedures for Ishastra platform components.

**Current Architecture:**
- **Queue Mode:** In-process (default) or Kubernetes Jobs (distributed)
- **Database:** SQLite (single-writer) or PostgreSQL (multi-writer)
- **Workers:** `ISHASTRA_WORKERS` per API pod
- **Rate Limiting:** In-memory (single) or Redis (distributed)

---

## Prerequisites

- **Access:** Kubernetes cluster admin, cloud provider console
- **Tools:** `kubectl`, `helm`, `aws/gcloud/az cli`, `redis-cli`
- **Monitoring:** Prometheus/Grafana access for metrics
- **Capacity:** Available node resources / cluster autoscaler enabled
- **Configuration:** Environment variables for scaling mode

---

## Current Capacity Baseline

| Component | Current | Max (In-Process) | Max (k8s-jobs) |
|-----------|---------|------------------|--------------|
| API Replicas | 3 | 3 (single-writer SQLite) | 10+ (with PostgreSQL) |
| Workers per API | 1 | 4 | 4 per pod |
| Queue Depth | 32 | 100 | cluster-bound |
| Concurrent Jobs | 3 | 12 | 40+ |
| Jobs/hour (web) | ~360 | ~1,440 | ~4,800+ |

---

## Vertical Scaling (Single Process)

### When to Use
- Queue depth consistently > 20
- Job duration p95 > 300s
- CPU/Memory utilization > 70%
- Single-node deployment

### Procedure

```bash
#!/bin/bash
# vertical-scale.sh

set -euo pipefail

NAMESPACE="ishastra"

# 1. Check current resource usage
echo "=== Current Resource Usage ==="
kubectl top pods -n $NAMESPACE -l app.kubernetes.io/name=ishastra
kubectl top nodes

# 2. Update resource requests/limits
# For Deployment (API, Scheduler)
kubectl patch deployment ishastra-api -n $NAMESPACE -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "ishastra-api",
          "resources": {
            "requests": {"cpu": "2000m", "memory": "4Gi"},
            "limits": {"cpu": "4000m", "memory": "8Gi"}
          }
        }]
      }
    }
  }
}'

kubectl patch deployment ishastra-scheduler -n $NAMESPACE -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "ishastra-scheduler",
          "resources": {
            "requests": {"cpu": "1000m", "memory": "2Gi"},
            "limits": {"cpu": "2000m", "memory": "4Gi"}
          }
        }]
      }
    }
  }
}'

# 3. Increase worker count per pod
kubectl patch deployment ishastra-api -n $NAMESPACE -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "ishastra-api",
          "env": [{"name": "ISHASTRA_WORKERS", "value": "2"}]
        }]
      }
    }
  }
}'

# 4. Increase queue max
kubectl patch deployment ishastra-api -n $NAMESPACE -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "ishastra-api",
          "env": [{"name": "ISHASTRA_QUEUE_MAX", "value": "64"}]
        }]
      }
    }
  }
}'

# 5. Rollout restart
kubectl rollout restart deployment/ishastra-api deployment/ishastra-scheduler -n $NAMESPACE
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=300s

# 6. Verify
echo "=== Post-Scale Verification ==="
kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=ishastra -o wide
kubectl exec -n $NAMESPACE ishastra-api-0 -- env | grep -E 'ISHASTRA_(WORKERS|QUEUE_MAX)'
```

### Vertical Scaling Limits

| Resource | Limit | Reason |
|----------|-------|--------|
| `ISHASTRA_WORKERS` | 4 | SQLite write contention, GIL |
| `ISHASTRA_QUEUE_MAX` | 100 | Memory for job metadata |
| CPU per pod | 4 cores | Diminishing returns |
| RAM per pod | 8 GB | Tool output buffers, SQLite cache |

---

## Horizontal Scaling (Kubernetes Jobs + PostgreSQL)

Assessments scale by running each one as a Kubernetes Job, so the API process only
submits work. The Job manifest and the supported values are in
`docs/k8s-jobs-architecture.md` and `deploy/helm/ishastra/values-k8s-jobs.yaml`.

### Prerequisites for Horizontal Scaling

- [ ] **PostgreSQL** deployed (HA recommended)
- [ ] **Kubernetes Jobs** permitted for the `ishastra` service account
- [ ] **Idempotency keys** implemented for all jobs
- [ ] **ISHASTRA_QUEUE_MODE=k8s-jobs** configured

### Enable k8s-jobs Mode

```bash
helm upgrade ishastra deploy/helm/ishastra -n ishastra \
  -f deploy/helm/ishastra/values-prod.yaml \
  -f deploy/helm/ishastra/values-k8s-jobs.yaml
```

### Scale the API

```bash
kubectl scale deployment ishastra-api -n ishastra --replicas=10
```

Job concurrency is bounded by the cluster, not by API replicas.

---

## Database Scaling

### SQLite → PostgreSQL Migration

```bash
#!/bin/bash
# migrate-to-postgresql.sh

set -euo pipefail

NAMESPACE="ishastra"
PG_HOST="postgresql"
PG_DB="ishastra"
PG_USER="postgres"
PG_PASS="$POSTGRES_PASSWORD"

# 1. Stop writers
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=0
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=0

# 2. Dump SQLite
kubectl exec -n $NAMESPACE ishastra-api-0 -- sqlite3 /var/lib/ishastra/ishastra.db .dump > /tmp/ishastra-sqlite-dump.sql

# 3. Convert for PostgreSQL (adjust types, sequences)
# This is simplified - use proper migration tool in production
sed -i 's/AUTOINCREMENT/SERIAL/g' /tmp/ishastra-sqlite-dump.sql
sed -i 's/INTEGER PRIMARY KEY/BIGSERIAL PRIMARY KEY/g' /tmp/ishastra-sqlite-dump.sql

# 4. Load into PostgreSQL
kubectl cp /tmp/ishastra-sqlite-dump.sql $NAMESPACE/postgresql-0:/tmp/dump.sql
kubectl exec -n $NAMESPACE postgresql-0 -- psql -U $PG_USER -d $PG_DB -f /tmp/dump.sql

# 5. Verify row counts match
SQLITE_JOBS=$(kubectl exec -n $NAMESPACE ishastra-api-0 -- sqlite3 /var/lib/ishastra/ishastra.db "SELECT COUNT(*) FROM jobs;")
PG_JOBS=$(kubectl exec -n $NAMESPACE postgresql-0 -- psql -U $PG_USER -d $PG_DB -t -c "SELECT COUNT(*) FROM jobs;")
echo "SQLite jobs: $SQLITE_JOBS, PostgreSQL jobs: $PG_JOBS"

# 6. Update config to use PostgreSQL
kubectl patch configmap ishastra-config -n $NAMESPACE -p '{
  "data": {
    "ISHASTRA_DATABASE_URL": "postgresql://postgres:password@postgresql:5432/ishastra"
  }
}'

# 7. Restart with PostgreSQL
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=3
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=1
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=300s

echo "Migration to PostgreSQL complete"
```

### PostgreSQL Read Replicas (For Read Scaling)

```bash
# Add read replica to Bitnami PostgreSQL
helm upgrade postgresql bitnami/postgresql -n ishastra \
  --set replication.enabled=true \
  --set replication.replicaCount=2 \
  --set primary.persistence.enabled=true

# Update API to use read replica for SELECT queries (requires code change)
# Or use PgBouncer with read/write split
```

---

## Redis Scaling

### Redis Cluster Mode

```bash
# Upgrade to Redis Cluster (6+ shards)
helm upgrade redis bitnami/redis -n ishastra \
  --set cluster.enabled=true \
  --set cluster.slaveCount=1 \
  --set cluster.nodes=6 \
  --set auth.enabled=true \
  --set auth.password="$REDIS_PASSWORD"
```

### Redis Sentinel (HA)

```bash
# For non-cluster HA
helm upgrade redis bitnami/redis -n ishastra \
  --set architecture=replication \
  --set sentinel.enabled=true \
  --set sentinel.replicaCount=3
```

---

## Rate Limiter Scaling

### Enable Redis Rate Limiter

```bash
# When scaling beyond single API pod
kubectl patch configmap ishastra-config -n ishastra -p '{
  "data": {
    "ISHASTRA_REDIS_URL": "redis://:password@redis-master:6379/0",
    "ISHASTRA_REDIS_REQUIRED": "true"
  }
}'

kubectl rollout restart deployment/ishastra-api -n ishastra
```

### Rate Limit Tier Configuration

```bash
# Adjust tier limits via ConfigMap
kubectl patch configmap ishastra-config -n ishastra -p '{
  "data": {
    "ISHASTRA_RATE_LIMIT_FREE_RPM": "10",
    "ISHASTRA_RATE_LIMIT_FREE_ASSESSMENTS": "10",
    "ISHASTRA_RATE_LIMIT_PRO_RPM": "120",
    "ISHASTRA_RATE_LIMIT_PRO_ASSESSMENTS": "40",
    "ISHASTRA_RATE_LIMIT_ENTERPRISE_RPM": "600",
    "ISHASTRA_RATE_LIMIT_ENTERPRISE_ASSESSMENTS": "120"
  }
}'
```

---

## Monitoring & Scaling Triggers

### Key Metrics to Watch

| Metric | Scale Up Trigger | Scale Down Trigger |
|--------|------------------|-------------------|
| `strix_queue_depth` | > 20 for 5 min | < 5 for 15 min |
| `strix_job_duration_seconds` p95 | > 300s | < 60s |
| `strix_active_jobs` | > 80% of max | < 30% of max |
| `strix_worker_heartbeat_age` | > 60s (worker dead) | N/A |
| `strix_rate_limit_exceeded_total` | > 10/min | < 1/min |
| CPU utilization | > 70% | < 30% |
| Memory utilization | > 80% | < 40% |

### Prometheus Alert Rules

```yaml
# scaling-alerts.yaml
groups:
- name: ishastra-scaling
  rules:
  - alert: IshastraQueueDepthHigh
    expr: strix_queue_depth > 20
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Queue depth high ({{ $value }})"
      description: "Consider scaling workers or increasing ISHASTRA_WORKERS"

  - alert: IshastraJobDurationHigh
    expr: histogram_quantile(0.95, rate(strix_job_duration_seconds_bucket[5m])) > 300
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Job duration p95 > 5 minutes"

  - alert: IshastraWorkerDown
    expr: time() - strix_worker_heartbeat_timestamp > 120
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Worker {{ $labels.worker_id }} heartbeat lost"

  - alert: IshastraRateLimitExceeded
    expr: rate(strix_rate_limit_exceeded_total[5m]) > 0.16
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Rate limit exceeded frequently"
```

---

## Verification

### Post-Scale Verification Checklist

```bash
#!/bin/bash
# verify-scaling.sh

set -euo pipefail

API_URL="http://ishastra.example.com"
ADMIN_KEY="${ISHASTRA_API_KEY}"

echo "=== Post-Scale Verification ==="

# 1. Health checks
curl -sf "$API_URL/api/health" | jq -e '.status == "healthy"'
curl -sf "$API_URL/api/ready" | jq -e '.ready == true'

# 2. Worker count
WORKERS=$(curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/admin/workers" | jq '.workers | length')
echo "Active workers: $WORKERS"

# 3. Queue depth
QUEUE_DEPTH=$(curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/admin/queue" | jq '.depth')
echo "Queue depth: $QUEUE_DEPTH"

# 4. Submit test jobs (concurrent)
echo "Submitting 10 concurrent test jobs..."
for i in {1..10}; do
    curl -sf -X POST "$API_URL/api/assess" \
      -H "Authorization: Bearer $ADMIN_KEY" \
      -H "Content-Type: application/json" \
      -d '{"target": "https://example.com", "profile": "web"}' &
done
wait

# 5. Verify all completed
sleep 10
COMPLETED=$(curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/jobs?state=completed&limit=20" | jq 'length')
echo "Completed jobs in last batch: $COMPLETED"

# 6. Check metrics
echo "Current metrics:"
curl -sf "$API_URL/metrics" | grep -E 'strix_(queue_depth|active_jobs|worker_)'

echo "=== Verification Complete ==="
```

---

## Rollback

### Rollback Vertical Scale

```bash
# Revert resource limits and worker count
kubectl patch deployment ishastra-api -n ishastra -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "ishastra-api",
          "resources": {
            "requests": {"cpu": "1000m", "memory": "2Gi"},
            "limits": {"cpu": "2000m", "memory": "4Gi"}
          },
          "env": [
            {"name": "ISHASTRA_WORKERS", "value": "1"},
            {"name": "ISHASTRA_QUEUE_MAX", "value": "32"}
          ]
        }]
      }
    }
  }
}'

kubectl rollout restart deployment/ishastra-api -n ishastra
```

### Rollback Horizontal Scale

```bash
# Drop back to the in-process queue
helm upgrade ishastra deploy/helm/ishastra -n ishastra -f deploy/helm/ishastra/values-prod.yaml

kubectl rollout restart deployment/ishastra-api deployment/ishastra-scheduler -n ishastra
```

### Rollback Database Migration

```bash
# If PostgreSQL migration fails
# 1. Revert ConfigMap to SQLite
kubectl patch configmap ishastra-config -n ishastra -p '{
  "data": {
    "ISHASTRA_DATABASE_URL": "sqlite:///var/lib/ishastra/ishastra.db"
  }
}'

# 2. Restore from SQLite backup (see restore.md)
# 3. Scale up API with SQLite
kubectl scale deployment ishastra-api -n ishastra --replicas=3
```

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Platform On-Call | `platform-oncall@example.com` | Primary |
| Platform Lead | `platform-lead@example.com` | Secondary |
| Kubernetes Admin | `k8s-admin@example.com` | HPA/Cluster issues |
| Database Admin | `dba@example.com` | PostgreSQL scaling |
| Cloud Provider Support | AWS/GCP/Azure Enterprise Support | Node/Infrastructure scaling |

---

## Related Runbooks

- [capacity-planning.md](./capacity-planning.md) - Capacity planning guidelines
- [failover.md](./failover.md) - Warm standby (alternative to scaling for HA)
- [disaster-recovery.md](./disaster-recovery.md) - Full DR scenarios
- [queue-backlog.md](./queue-backlog.md) - Queue backlog troubleshooting
- [redis-issues.md](./redis-issues.md) - Redis troubleshooting
