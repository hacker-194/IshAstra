# Point-in-Time Restore Procedures Runbook

## Overview

This runbook covers point-in-time restore procedures for Ishastra platform components from automated backups.

**RTO Targets:**
- Database restore: < 30 minutes
- Configuration restore: < 10 minutes
- Secrets restore: < 15 minutes
- Full stack restore: < 1 hour

**RPO:** 1 hour (hourly database backups)

---

## Prerequisites

- **Access:** AWS/GCP/Azure credentials with S3/GCS bucket read access
- **Tools:** `aws cli` / `gcloud` / `az cli`, `sqlite3`, `kubectl`, `vault`, `age`/`gpg`
- **Environment:** `ISHASTRA_BACKUP_BUCKET`, `ISHASTRA_DB_PATH`, `ISHASTRA_AUDIT_HMAC_KEY` configured
- **Permissions:** Read access to backup bucket; write access to target database/PVC/ConfigMaps
- **Downtime Window:** Scheduled maintenance or emergency change approved

---

## Diagnosis: Select Restore Point

### 1. List Available Backups

```bash
# Database backups (daily)
aws s3 ls s3://ishastra-backups/db/daily/ --recursive --human-readable --summarize

# Database backups (hourly - for finer RPO)
aws s3 ls s3://ishastra-backups/db/hourly/ --recursive --human-readable | tail -20

# Configuration backups
aws s3 ls s3://ishastra-backups/config/ --recursive --human-readable | tail -10

# Secrets backups
aws s3 ls s3://ishastra-backups/secrets/ --recursive --human-readable | tail -10
```

### 2. Choose Restore Timestamp

| Scenario | Recommended Source |
|----------|-------------------|
| Database corruption | Latest **verified** daily backup |
| Accidental deletion (known time) | Hourly backup closest to **before** deletion |
| Ransomware (known encryption time) | Backup **before** earliest encryption timestamp |
| Config drift | Daily config backup from **known good state** |
| Secret compromise | Secrets backup from **before** compromise |

### 3. Verify Backup Before Restore

```bash
# Download and verify database backup
BACKUP_FILE="ishastra-20240115-020000.db"
aws s3 cp s3://ishastra-backups/db/daily/2024/01/15/${BACKUP_FILE} /tmp/verify-restore.db

# Integrity check
sqlite3 /tmp/verify-restore.db "PRAGMA integrity_check;" | grep -q "ok" || { echo "FAIL: Integrity check"; exit 1; }

# Verify integrity and audit chain without interpolating the key into SQL
python scripts/operational_check.py \
  --db /tmp/verify-restore.db \
  --out /tmp/verify-restore-copy.db

# Row counts
sqlite3 /tmp/verify-restore.db "
SELECT 'jobs' as table, COUNT(*) FROM jobs
UNION ALL SELECT 'findings', COUNT(*) FROM findings
UNION ALL SELECT 'audit_chain', COUNT(*) FROM audit_chain
UNION ALL SELECT 'audit_log', COUNT(*) FROM audit_log;
"

# Schema version
sqlite3 /tmp/verify-restore.db "SELECT value FROM settings WHERE key = 'schema_version';"

echo "Backup verification PASSED - safe to restore"
```

---

## Steps

### Scenario 1: Database Restore (PVC-based Deployment)

```bash
#!/bin/bash
# Restore database to Kubernetes PVC

set -euo pipefail

BACKUP_FILE="${1:-ishastra-20240115-020000.db}"  # Pass as argument or use latest
NAMESPACE="ishastra"
PVC_NAME="ishastra-db-pvc"  # Or deployment-specific
POD_NAME="ishastra-api-0"   # Any pod mounting the PVC
CONTAINER="ishastra-api"
DB_PATH_IN_POD="/var/lib/ishastra/ishastra.db"

echo "=== Starting Database Restore ==="
echo "Backup: $BACKUP_FILE"
echo "Target: $NAMESPACE/$POD_NAME:$DB_PATH_IN_POD"

# 1. Scale down ALL writers to prevent writes during restore
echo "Scaling down writers..."
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=0
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=0
# If k8s-jobs workers exist
kubectl scale deployment ishastra-worker -n $NAMESPACE --replicas=0 2>/dev/null || true

# Wait for pods to terminate
kubectl wait --for=delete pod -l app.kubernetes.io/name=ishastra,component=api -n $NAMESPACE --timeout=60s

# 2. Download backup
echo "Downloading backup..."
aws s3 cp "s3://ishastra-backups/db/daily/$(date -u +%Y/%m/%d)/${BACKUP_FILE}" /tmp/restore.db

# 3. Verify once more
sqlite3 /tmp/restore.db "PRAGMA integrity_check;" | grep -q "ok" || { echo "FAIL: Integrity check"; exit 1; }

# 4. Copy to PVC via kubectl cp
echo "Copying to PVC..."
kubectl cp /tmp/restore.db $NAMESPACE/$POD_NAME:$DB_PATH_IN_POD -c $CONTAINER

# 5. Fix permissions (owner only, like live DB)
kubectl exec -n $NAMESPACE $POD_NAME -c $CONTAINER -- chmod 600 $DB_PATH_IN_POD

# 6. Remove WAL/SHM files for clean start
kubectl exec -n $NAMESPACE $POD_NAME -c $CONTAINER -- rm -f ${DB_PATH_IN_POD}-wal ${DB_PATH_IN_POD}-shm

# 7. Scale up writers
echo "Scaling up writers..."
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=3
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=1
kubectl scale deployment ishastra-worker -n $NAMESPACE --replicas=2 2>/dev/null || true

# 8. Wait for rollout
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=300s
kubectl rollout status deployment/ishastra-scheduler -n $NAMESPACE --timeout=300s

echo "=== Database Restore Complete ==="
```

### Scenario 2: Database Restore (EmptyDir / No PVC - Recreate Pod)

```bash
#!/bin/bash
# For deployments using emptyDir - requires pod recreation

set -euo pipefail

BACKUP_FILE="${1:-ishastra-20240115-020000.db}"
NAMESPACE="ishastra"

# 1. Scale down
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=0
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=0

# 2. Download backup
aws s3 cp "s3://ishastra-backups/db/daily/$(date -u +%Y/%m/%d)/${BACKUP_FILE}" /tmp/restore.db

# 3. Create new PVC with backup data
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ishastra-db-restored
  namespace: $NAMESPACE
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
EOF

# 4. Create helper pod to populate PVC
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: db-restore-helper
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  volumes:
  - name: db-data
    persistentVolumeClaim:
      claimName: ishastra-db-restored
  containers:
  - name: restore
    image: alpine:3.20
    command: ["sleep", "3600"]
    volumeMounts:
    - name: db-data
      mountPath: /data
EOF

# 5. Copy backup to PVC
kubectl wait --for=condition=Ready pod/db-restore-helper -n $NAMESPACE --timeout=60s
kubectl cp /tmp/restore.db $NAMESPACE/db-restore-helper:/data/ishastra.db
kubectl exec -n $NAMESPACE db-restore-helper -- chmod 600 /data/ishastra.db

# 6. Update deployment to use new PVC
kubectl patch deployment ishastra-api -n $NAMESPACE -p '{"spec":{"template":{"spec":{"volumes":[{"name":"ishastra-db","persistentVolumeClaim":{"claimName":"ishastra-db-restored"}}]}}}}'

# 7. Clean up helper
kubectl delete pod db-restore-helper -n $NAMESPACE

# 8. Scale up
kubectl scale deployment ishastra-api -n $NAMESPACE --replicas=3
kubectl scale deployment ishastra-scheduler -n $NAMESPACE --replicas=1
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=300s
```

### Scenario 3: Configuration Restore

```bash
#!/bin/bash
# Restore scope configuration and rules

set -euo pipefail

CONFIG_BACKUP="${1:-ishastra-config-20240115-020000.yaml}"
RULES_BACKUP="${2:-ishastra-rules-20240115-020000.yaml}"
NAMESPACE="ishastra"

echo "=== Restoring Configuration ==="

# 1. Download backups
aws s3 cp "s3://ishastra-backups/config/$(date -u +%Y/%m/%d)/${CONFIG_BACKUP}" /tmp/restore-config.yaml
aws s3 cp "s3://ishastra-backups/config/$(date -u +%Y/%m/%d)/${RULES_BACKUP}" /tmp/restore-rules.yaml 2>/dev/null || true

# 2. Validate YAML
kubectl apply --dry-run=client -f /tmp/restore-config.yaml >/dev/null || { echo "Invalid config YAML"; exit 1; }
[[ -f /tmp/restore-rules.yaml ]] && kubectl apply --dry-run=client -f /tmp/restore-rules.yaml >/dev/null || true

# 3. Apply (creates or updates ConfigMaps)
kubectl apply -f /tmp/restore-config.yaml
[[ -f /tmp/restore-rules.yaml ]] && kubectl apply -f /tmp/restore-rules.yaml

# 4. Restart pods to pick up new config
kubectl rollout restart deployment/ishastra-api deployment/ishastra-scheduler -n $NAMESPACE
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=180s
kubectl rollout status deployment/ishastra-scheduler -n $NAMESPACE --timeout=180s

echo "=== Configuration Restore Complete ==="
```

### Scenario 4: Secrets Restore (Vault)

```bash
#!/bin/bash
# Restore secrets from encrypted backup to Vault

set -euo pipefail

SECRETS_BACKUP="${1:-ishastra-secrets-20240115-020000.json.age}"
ENCRYPTION_KEY="${ISHASTRA_BACKUP_ENCRYPTION_KEY}"
VAULT_ADDR="${VAULT_ADDR}"

echo "=== Restoring Secrets to Vault ==="

# 1. Download and decrypt
aws s3 cp "s3://ishastra-backups/secrets/$(date -u +%Y/%m/%d)/${SECRETS_BACKUP}" /tmp/secrets.json.age
age -d -i "$ENCRYPTION_KEY" -o /tmp/secrets.json /tmp/secrets.json.age

# 2. Validate JSON structure
jq -e '.data' /tmp/secrets.json >/dev/null || { echo "Invalid secrets format"; exit 1; }

# 3. Write to Vault (creates new version)
vault kv put secret/ishastra @/tmp/secrets.json

# 4. Trigger ExternalSecret sync (if using ESO)
kubectl annotate externalsecret ishastra-secrets -n ishastra force-sync=$(date +%s) --overwrite

# 5. Restart pods to pick up new secrets
kubectl rollout restart deployment/ishastra-api deployment/ishastra-scheduler -n ishastra
kubectl rollout status deployment/ishastra-api -n ishastra --timeout=180s

# 6. Cleanup
rm -f /tmp/secrets.json /tmp/secrets.json.age

echo "=== Secrets Restore Complete ==="
```

### Scenario 5: Secrets Restore (Kubernetes SealedSecrets)

```bash
#!/bin/bash
# Restore secrets from encrypted backup to Kubernetes secrets

set -euo pipefail

SECRETS_BACKUP="${1:-ishastra-secrets-k8s-20240115-020000.yaml.age}"
ENCRYPTION_KEY="${ISHASTRA_BACKUP_ENCRYPTION_KEY}"
NAMESPACE="ishastra"

echo "=== Restoring Secrets to Kubernetes ==="

# 1. Download and decrypt
aws s3 cp "s3://ishastra-backups/secrets/$(date -u +%Y/%m/%d)/${SECRETS_BACKUP}" /tmp/secrets.yaml.age
age -d -i "$ENCRYPTION_KEY" -o /tmp/secrets.yaml /tmp/secrets.yaml.age

# 2. Apply secrets (SealedSecrets controller will unseal)
kubectl apply -f /tmp/secrets.yaml

# 3. Also restore Redis/PostgreSQL secrets if present
for secret in ishastra-redis-secret ishastra-postgresql-secret ishastra-grafana-secret; do
    BACKUP_FILE="${secret}-$(date -u +%Y%m%d-%H%M%S).yaml.age"
    aws s3 cp "s3://ishastra-backups/secrets/$(date -u +%Y/%m/%d)/${BACKUP_FILE}" "/tmp/${BACKUP_FILE}" 2>/dev/null || continue
    age -d -i "$ENCRYPTION_KEY" -o "/tmp/${secret}.yaml" "/tmp/${BACKUP_FILE}"
    kubectl apply -f "/tmp/${secret}.yaml"
    rm -f "/tmp/${secret}.yaml" "/tmp/${BACKUP_FILE}"
done

# 4. Restart pods
kubectl rollout restart deployment/ishastra-api deployment/ishastra-scheduler -n $NAMESPACE
kubectl rollout status deployment/ishastra-api -n $NAMESPACE --timeout=180s

# 5. Cleanup
rm -f /tmp/secrets.yaml /tmp/secrets.yaml.age

echo "=== Kubernetes Secrets Restore Complete ==="
```

### Scenario 6: Full Stack Restore (Disaster Recovery)

```bash
#!/bin/bash
# Full restore: Database + Config + Secrets + Redis
# Use disaster-recovery.md for cluster-level restore

set -euo pipefail

RESTORE_TIMESTAMP="${1:-20240115-020000}"  # Format: YYYYMMDD-HHMMSS
NAMESPACE="ishastra"

echo "=== Full Stack Restore: $RESTORE_TIMESTAMP ==="

# 1. Database
./restore-database.sh "ishastra-${RESTORE_TIMESTAMP}.db"

# 2. Config
./restore-config.sh "ishastra-config-${RESTORE_TIMESTAMP}.yaml" "ishastra-rules-${RESTORE_TIMESTAMP}.yaml"

# 3. Secrets (Vault)
./restore-secrets-vault.sh "ishastra-secrets-${RESTORE_TIMESTAMP}.json.age"

# 4. Redis (if needed - rate limiter state recoverable)
# ./restore-redis.sh "redis-dump-${RESTORE_TIMESTAMP}.rdb"

# 5. Verify full stack
./verify-full-restore.sh

echo "=== Full Stack Restore Complete ==="
```

---

## Verification

### Post-Restore Verification Checklist

```bash
#!/bin/bash
# verify-full-restore.sh

set -euo pipefail

API_URL="http://ishastra.example.com"
ADMIN_KEY="${ISHASTRA_API_KEY}"

echo "=== Post-Restore Verification ==="

# 1. Health endpoint
curl -sf "$API_URL/api/health" | jq -e '.status == "healthy"' || { echo "FAIL: Health check"; exit 1; }

# 2. Ready endpoint
curl -sf "$API_URL/api/ready" | jq -e '.ready == true' || { echo "FAIL: Ready check"; exit 1; }

# 3. Audit chain verification
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/audit/verify" | jq -e '.ok == true' || { echo "FAIL: Audit chain"; exit 1; }

# 4. Database connectivity & counts
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/admin/stats" | jq -e '.jobs > 0 and .findings >= 0' || { echo "FAIL: DB stats"; exit 1; }

# 5. Scope/policy loaded
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/policies" | jq -e 'length > 0' || { echo "FAIL: No policies"; exit 1; }

# 6. Admin API key works
curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/tenants" | jq -e 'length >= 0' || { echo "FAIL: Admin key"; exit 1; }

# 7. Functional test - submit assessment
JOB_ID=$(curl -sf -X POST "$API_URL/api/assess" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web", "wait": true}' | jq -r '.job_id')

# Poll for completion
for i in {1..30}; do
    STATE=$(curl -sf -H "Authorization: Bearer $ADMIN_KEY" "$API_URL/api/jobs/$JOB_ID" | jq -r '.state')
    [[ "$STATE" == "completed" ]] && break
    [[ "$STATE" == "failed" ]] && { echo "FAIL: Test job failed"; exit 1; }
    sleep 2
done
[[ "$STATE" == "completed" ]] || { echo "FAIL: Test job timeout"; exit 1; }

echo "=== All Verification Checks PASSED ==="
```

### Manual Verification Commands

```bash
# Check database directly
kubectl exec -n ishastra ishastra-api-0 -- sqlite3 /var/lib/ishastra/ishastra.db "
PRAGMA integrity_check;
SELECT COUNT(*) FROM jobs;
SELECT COUNT(*) FROM findings;
SELECT * FROM settings;
"

# Check audit chain
kubectl exec -n ishastra ishastra-api-0 -- /usr/local/bin/python -c "
from ishastra.audit import AuditChain
from ishastra.config import Settings
s = Settings.from_env()
chain = AuditChain(persistent=True, hmac_key=s.audit_hmac_key)
import asyncio
ok, reason = asyncio.run(chain.verify_async())
print(f'OK: {ok}, Reason: {reason}')
"

# Check config loaded
kubectl exec -n ishastra ishastra-api-0 -- cat /etc/ishastra/scope.json | head -5

# Check that required keys exist without displaying secret values
for key in ISHASTRA_API_KEY ISHASTRA_AUDIT_HMAC_KEY ISHASTRA_ENCRYPTION_KEY; do
  kubectl get secret ishastra-secrets -n ishastra -o "jsonpath={.data.$key}" | grep -q .
done
```

---

## Rollback

### If Restore Fails Mid-Process

| Stage | Rollback Action |
|-------|-----------------|
| Database downloaded, not copied | Delete `/tmp/restore.db`, no action needed |
| Database copied, writers not scaled up | Scale up writers: `kubectl scale deployment ishastra-api -n ishastra --replicas=3` |
| Config applied, pods not restarted | Rollback ConfigMap: `kubectl rollout undo configmap/ishastra-config -n ishastra` |
| Secrets restored, pods not restarted | Restart pods with old secrets (Vault keeps version history) |
| Full stack restore partial | Restore each component from **previous** backup timestamp |

### Emergency Rollback to Previous State

```bash
# If current restore introduced issues, restore from backup BEFORE the restore
PREVIOUS_BACKUP="ishastra-20240114-020000.db"  # Day before restore
./restore-database.sh "$PREVIOUS_BACKUP"
./restore-config.sh "ishastra-config-20240114-020000.yaml"
./restore-secrets-vault.sh "ishastra-secrets-20240114-020000.json.age"
```

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Platform On-Call | `platform-oncall@example.com` | Primary |
| Platform Lead | `platform-lead@example.com` | Secondary |
| Database Admin | `dba@example.com` | Data corruption issues |
| Security Team | `security@example.com` | Secrets restore issues |
| Cloud Provider Support | AWS/GCP/Azure Enterprise Support | Backup storage issues |

---

## Related Runbooks

- [backup.md](./backup.md) - Automated backup procedures
- [disaster-recovery.md](./disaster-recovery.md) - Full DR scenarios
- [failover.md](./failover.md) - Warm standby promotion (faster than restore)
- [secret-rotation.md](./secret-rotation.md) - Secret rotation procedures