# Warm Standby Failover Runbook

## Overview

This runbook covers warm standby failover procedures using the `standby.py` module for rapid promotion of a standby instance.

**RTO Target: < 5 minutes** (standby promotion + readiness checks)
**RPO: 1 hour** (based on hourly backup frequency)

### Architecture

```
Primary (Active)          Standby (Warm)
┌─────────────────┐       ┌─────────────────┐
│ strix-api (3)   │       │ standby-api (0) │  ← Scaled to 0, ready to promote
│ strix-scheduler │       │ standby-sched   │
│ strix-worker    │       │                 │
│ SQLite DB (PVC) │  ──▶  │ Backup files    │  ← Hourly SQLite backups synced
│ Redis           │       │ (read-only)     │
└─────────────────┘       └─────────────────┘
        │                         │
        │   Async replication     │
        ▼                         ▼
   S3/GCS Bucket            Same S3/GCS Bucket
   (strix-backups/db)  ◀───  (read access)
```

### Standby Promotion Flow (`standby.py`)

```
promote_standby()
  ├── verify_backup()          # Validate backup integrity, schema, audit chain
  ├── restore_database()       # SQLite backup API → target DB (atomic)
  ├── acquire_standby_lease()  # Exclusive worker lease (prevents split-brain)
  └── run_readiness_checks()   # Audit chain, schema, scope, API keys
```

---

## Prerequisites

- **Standby Environment:** Pre-provisioned Kubernetes namespace/cluster with:
  - `strix` namespace created
  - PVC for database (`strix-db-pvc`) 
  - ConfigMaps for scope (`strix-config`)
  - Secrets (`strix-secrets`, `strix-redis-secret`, etc.)
  - Network policies allowing standby ↔ primary communication
- **Backup Access:** Standby has read access to `s3://strix-backups/db/`
- **Standby Image:** Same Docker image tag as primary (`3.5.0`)
- **Lease Lock:** Redis or database-based lease mechanism functional
- **Tools:** `kubectl`, `aws cli`, `python` with `strix` package installed
- **Permissions:** Admin access to both primary and standby namespaces/clusters

---

## Alert Triggers

| Alert | Severity | Action |
|-------|----------|--------|
| `StrixPrimaryDown` | critical | Primary API health checks failing > 2 min |
| `StrixPrimaryDatabaseCorrupt` | critical | Audit chain verification failed on primary |
| `StrixPrimaryClusterUnhealthy` | critical | Kubernetes cluster issues (nodes NotReady, etc.) |
| Manual trigger | - | Planned maintenance, DR test |

---

## Diagnosis Commands

### 1. Confirm Primary Failure

```bash
# Check primary API health
curl -sf http://strix-primary.example.com/api/health
curl -sf http://strix-primary.example.com/api/ready

# Check primary pods
kubectl get pods -n strix -l app.kubernetes.io/name=strix -o wide

# Check primary database
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# Check audit chain on primary
curl -sf -H "Authorization: Bearer $ADMIN_KEY" http://strix-primary.example.com/api/audit/verify | jq .
```

### 2. Verify Standby Readiness

```bash
# Check standby namespace exists
kubectl get ns strix-standby

# Check standby PVC bound
kubectl get pvc -n strix-standby

# Check standby ConfigMaps/Secrets
kubectl get configmap,secret -n strix-standby

# Check backup bucket accessibility from standby
aws s3 ls s3://strix-backups/db/daily/ --recursive | tail -5

# Verify latest backup exists and is recent (< 2 hours old)
LATEST=$(aws s3 ls s3://strix-backups/db/daily/ --recursive | sort | tail -n 1)
echo "Latest backup: $LATEST"
```

### 3. Check for Split-Brain Risk

```bash
# Ensure primary is TRULY down (not just slow)
# Check if primary still holds worker lease
kubectl exec -n strix strix-api-0 -- cat /var/run/strix/worker-lease.lock 2>/dev/null || echo "No lease file"

# Check Redis for active lease
redis-cli -h redis-primary -a $REDIS_PASSWORD GET "strix:worker:lease"

# If primary might recover, consider: wait 5 min, verify, then failover
```

---

## Steps

### Automated Failover (Recommended)

```bash
#!/bin/bash
# /opt/strix/scripts/failover-standby.sh
# Run from standby environment or jump host

set -euo pipefail

# Configuration
BACKUP_DIR="/var/lib/strix/backups"  # Local path where backups are synced
DB_PATH="/var/lib/strix/strix.db"    # Target database path on standby
SCOPE_FILE="/etc/strix/scope.json"   # Scope file path
TIMEOUT=30                           # Readiness check timeout (seconds)
NAMESPACE="strix-standby"            # Standby namespace

echo "=== Starting Warm Standby Failover ==="
echo "Backup dir: $BACKUP_DIR"
echo "DB path: $DB_PATH"
echo "Scope file: $SCOPE_FILE"
echo "Namespace: $NAMESPACE"

# 1. Ensure backup directory has latest backups (sync from S3 if needed)
echo "Syncing latest backups from S3..."
aws s3 sync s3://strix-backups/db/daily/ "$BACKUP_DIR/" --exclude "*" --include "strix-*.db" --no-progress

# Verify at least one backup exists
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "strix-*.db" | wc -l)
[[ $BACKUP_COUNT -gt 0 ]] || { echo "ERROR: No backup files found in $BACKUP_DIR"; exit 1; }

# 2. Run standby promotion via Python module
echo "Running standby promotion..."
cd /opt/strix  # Where strix package is installed

PROMOTION_RESULT=$(python -c "
import asyncio
import json
import sys
sys.path.insert(0, '/opt/strix')
from strix.core.standby import promote_standby
from pathlib import Path

async def main():
    result = await promote_standby(
        backup_dir=Path('$BACKUP_DIR'),
        db_path=Path('$DB_PATH'),
        scope_file='$SCOPE_FILE',
        timeout=$TIMEOUT
    )
    print(json.dumps(result, default=str))

asyncio.run(main())
")

echo "Promotion result:"
echo "$PROMOTION_RESULT" | jq .

# 3. Check promotion success
OK=$(echo "$PROMOTION_RESULT" | jq -r '.ok')
if [[ "$OK" != "true" ]]; then
    echo "ERROR: Standby promotion failed"
    echo "$PROMOTION_RESULT" | jq -r '.error // .'
    exit 1
fi

RTO_MS=$(echo "$PROMOTION_RESULT" | jq -r '.rto_ms')
echo "Standby promoted successfully in ${RTO_MS}ms"

# 4. Scale up standby deployments
echo "Scaling up standby deployments..."
kubectl scale deployment strix-api -n $NAMESPACE --replicas=3
kubectl scale deployment strix-scheduler -n $NAMESPACE --replicas=1
kubectl scale deployment strix-worker -n $NAMESPACE --replicas=2 2>/dev/null || true

# 5. Wait for rollout
echo "Waiting for rollout..."
kubectl rollout status deployment/strix-api -n $NAMESPACE --timeout=300s
kubectl rollout status deployment/strix-scheduler -n $NAMESPACE --timeout=300s

# 6. Update DNS / Load Balancer to point to standby
echo "Updating DNS to standby..."
# Example for Route53
# aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXX --change-batch file://dns-failover-standby.json

# 7. Verify standby is serving traffic
echo "Verifying standby health..."
STANDBY_URL="http://strix-standby.example.com"
for i in {1..30}; do
    if curl -sf "$STANDBY_URL/api/health" | jq -e '.status == "healthy"' >/dev/null; then
        echo "Standby health check PASSED"
        break
    fi
    sleep 2
done

echo "=== Warm Standby Failover Complete ==="
echo "RTO achieved: ${RTO_MS}ms"
```

### Manual Failover (Step-by-Step)

#### Step 1: Verify Backup & Prepare

```bash
# On standby host
BACKUP_DIR="/var/lib/strix/backups"
DB_PATH="/var/lib/strix/strix.db"

# Sync latest backups
aws s3 sync s3://strix-backups/db/daily/ "$BACKUP_DIR/" --exclude "*" --include "strix-*.db"

# List available backups
ls -la "$BACKUP_DIR"/strix-*.db

# Verify latest backup manually
LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/strix-*.db | head -1)
python -c "
from strix.core.standby import verify_backup
from pathlib import Path
import asyncio
result = asyncio.run(verify_backup(Path('$LATEST_BACKUP')))
print(result)
"
```

#### Step 2: Restore Database

```bash
# Restore using SQLite backup API
python -c "
from strix.core.standby import restore_database
from pathlib import Path
restore_database(Path('$LATEST_BACKUP'), Path('$DB_PATH'))
print('Database restored')
"

# Verify restored database
python -c "
from strix.core.standby import verify_backup
from pathlib import Path
import asyncio
result = asyncio.run(verify_backup(Path('$DB_PATH')))
print('Restored DB:', result)
"
```

#### Step 3: Acquire Worker Lease

```bash
# This prevents split-brain - only one instance can hold the lease
python -c "
from strix.core.standby import acquire_standby_lease
import asyncio
lease_path = asyncio.run(acquire_standby_lease('$DB_PATH'))
print(f'Lease acquired: {lease_path}')
"
```

#### Step 4: Run Readiness Checks

```bash
# Post-restore readiness checks
python -c "
from strix.core.standby import run_readiness_checks
import asyncio
result = asyncio.run(run_readiness_checks('$DB_PATH', scope_file='$SCOPE_FILE', timeout=30))
import json
print(json.dumps(result, default=str, indent=2))
"
```

Expected readiness output:
```json
{
  "audit_chain": {"ok": true, "reason": "chain valid"},
  "schema_version": 7,
  "scope": {"mode": "managed", "active_policies": 3, "ok": true},
  "api_keys": {"admin_count": 1, "ok": true},
  "audit_chain_entries": 15420
}
```

#### Step 5: Promote Standby Services

```bash
# Scale up standby deployments
kubectl scale deployment strix-api -n strix-standby --replicas=3
kubectl scale deployment strix-scheduler -n strix-standby --replicas=1

# Wait for ready
kubectl rollout status deployment/strix-api -n strix-standby --timeout=300s
```

#### Step 6: Cutover Traffic

```bash
# Update DNS / Load Balancer
# Route53 example:
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXX --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "strix.example.com",
      "Type": "CNAME",
      "TTL": 60,
      "ResourceRecords": [{"Value": "strix-standby-ingress.example.com"}]
    }
  }]
}'

# Verify DNS propagation
dig strix.example.com
```

---

## Verification

### Post-Failover Verification Checklist

```bash
#!/bin/bash
# verify-failover.sh

STANDBY_URL="http://strix-standby.example.com"
ADMIN_KEY="${STRIX_API_KEY}"

echo "=== Post-Failover Verification ==="

# 1. Health & Ready
curl -sf "$STANDBY_URL/api/health" | jq -e '.status == "healthy"'
curl -sf "$STANDBY_URL/api/ready" | jq -e '.ready == true'

# 2. Audit chain
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$STANDBY_URL/api/audit/verify" | jq -e '.ok == true'

# 3. Database stats
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$STANDBY_URL/api/admin/stats" | jq .

# 4. Policies loaded
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$STANDBY_URL/api/policies" | jq -e 'length > 0'

# 5. Functional test
JOB_ID=$(curl -sf -X POST "$STANDBY_URL/api/assess" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web", "wait": true}' | jq -r '.job_id')

# Wait for completion
for i in {1..30}; do
    STATE=$(curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$STANDBY_URL/api/jobs/$JOB_ID" | jq -r '.state')
    [[ "$STATE" == "completed" ]] && break
    [[ "$STATE" == "failed" ]] && { echo "FAIL: Test job failed"; exit 1; }
    sleep 2
done
[[ "$STATE" == "completed" ]] || { echo "FAIL: Test job timeout"; exit 1; }

echo "=== All Verification Checks PASSED ==="
```

### Grafana Dashboards

- **Failover Status**: `https://grafana.example.com/d/strix-failover/failover-status`
- **Key Panels:**
  - Last Failover Timestamp
  - Promotion Duration (RTO)
  - Standby Sync Lag (backup age)
  - Standby Deployment Health

---

## Rollback

### Rollback to Primary (If Primary Recovers)

```bash
#!/bin/bash
# rollback-to-primary.sh

echo "=== Rolling Back to Primary ==="

# 1. Verify primary is healthy
curl -sf http://strix-primary.example.com/api/health | jq -e '.status == "healthy"'
curl -sf http://strix-primary.example.com/api/ready | jq -e '.ready == true'

# 2. Scale down standby
kubectl scale deployment strix-api -n strix-standby --replicas=0
kubectl scale deployment strix-scheduler -n strix-standby --replicas=0

# 3. Scale up primary
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1
kubectl rollout status deployment/strix-api -n strix --timeout=300s

# 4. Update DNS back to primary
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXX --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "strix.example.com",
      "Type": "CNAME",
      "TTL": 60,
      "ResourceRecords": [{"Value": "strix-primary-ingress.example.com"}]
    }
  }]
}'

echo "=== Rollback to Primary Complete ==="
```

### If Failover Fails Mid-Process

| Stage | Rollback Action |
|-------|-----------------|
| Backup sync failed | Retry sync, use older backup |
| Promotion failed (verify_backup) | Try previous hourly backup |
| Promotion failed (restore) | Delete target DB, retry with different backup |
| Promotion failed (lease) | Check primary is truly down, force lease release |
| Promotion failed (readiness) | Check scope file, audit HMAC key, admin keys |
| Standby pods won't start | Check logs, verify ConfigMaps/Secrets, check image pull |
| DNS cutover failed | Verify DNS records, check health endpoints directly |

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Platform On-Call | `platform-oncall@example.com` | Primary |
| Platform Lead | `platform-lead@example.com` | Secondary |
| Kubernetes Admin | `k8s-admin@example.com` | Cluster issues |
| DNS/Network Admin | `net-admin@example.com` | DNS cutover issues |
| Cloud Provider Support | AWS/GCP/Azure Enterprise Support | Infrastructure issues |

---

## Standby Maintenance (Pre-Failover)

### Weekly
- [ ] Verify standby namespace resources exist
- [ ] Check backup sync cron job succeeding
- [ ] Verify standby Docker image matches primary
- [ ] Test `verify_backup()` on latest backup

### Monthly
- [ ] Full failover test (DR test)
- [ ] Measure actual RTO
- [ ] Verify standby can handle production load
- [ ] Update runbook with findings

### Pre-Planned Maintenance
- [ ] Sync latest backups to standby
- [ ] Run `verify_backup()` on latest
- [ ] Confirm standby ConfigMaps/Secrets match primary
- [ ] Notify on-call of planned failover window

---

## Related Runbooks

- [backup.md](./backup.md) - Automated backup procedures (feeds standby)
- [restore.md](./restore.md) - Point-in-time restore (alternative to failover)
- [disaster-recovery.md](./disaster-recovery.md) - Full DR scenarios
- [scaling.md](./scaling.md) - Horizontal scaling (Celery workers)