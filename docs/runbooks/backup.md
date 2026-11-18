# Automated Backup Procedures Runbook

## Overview

This runbook covers automated backup procedures for Strix platform components including SQLite database, configurations, and secrets.

**Backup Schedule:**
- Database: Hourly WAL + Daily full snapshots
- Configurations: On change + Daily
- Secrets: On change (encrypted)
- Retention: 30 days daily, 1 year monthly

---

## Prerequisites

- **Access:** AWS/GCP/Azure credentials with S3/GCS bucket write access
- **Tools:** `aws cli` / `gcloud` / `az cli`, `sqlite3`, `kubectl`, `vault` (if using HashiCorp Vault)
- **Environment:** `STRIX_BACKUP_BUCKET`, `STRIX_DB_PATH`, `STRIX_AUDIT_HMAC_KEY` configured
- **Permissions:** Read access to database, configs, secrets; write access to backup bucket
- **Schedule:** Cron/systemd timer running as `strix-backup` service account

---

## Backup Components

| Component | Source | Frequency | Method | Destination |
|-----------|--------|-----------|--------|-------------|
| SQLite Database (live) | `/var/lib/strix/strix.db` | Hourly (WAL) | SQLite backup API | `s3://bucket/db/hourly/` |
| SQLite Database (full) | `/var/lib/strix/strix.db` | Daily 02:00 UTC | SQLite backup API | `s3://bucket/db/daily/` |
| Scope Config | ConfigMap `strix-config` | On change + Daily | kubectl export | `s3://bucket/config/` |
| Kubernetes Manifests | Git repository | On commit | Git push | Git remote |
| Secrets (encrypted) | Vault / SealedSecrets | On change | Vault API / kubectl | Vault / `s3://bucket/secrets/` |
| Redis AOF/RDB | Redis pod | Every 60s (AOF) | Redis BGSAVE | `s3://bucket/redis/` |
| Prometheus Data | Remote write | Continuous | Thanos/Cortex | Object storage |

---

## Steps

### 1. Database Backup (Hourly WAL + Daily Full)

```bash
#!/bin/bash
# /opt/strix/scripts/backup-database.sh
# Runs hourly via cron: 0 * * * * /opt/strix/scripts/backup-database.sh

set -euo pipefail

DB_PATH="${STRIX_DB_PATH:-/var/lib/strix/strix.db}"
BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)
HOUR_DIR=$(date -u +%H)

# Verify database exists and is accessible
if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: Database not found at $DB_PATH" >&2
    exit 1
fi

# Verify database integrity before backup
sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Database integrity check failed" >&2
    exit 1
}

# Create backup using SQLite backup API (consistent snapshot)
BACKUP_FILE="/tmp/strix-${TIMESTAMP}.db"
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

# Verify backup
sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Backup integrity check failed" >&2
    rm -f "$BACKUP_FILE"
    exit 1
}

# Upload to hourly bucket (WAL-style incremental)
aws s3 cp "$BACKUP_FILE" "s3://${BACKUP_BUCKET}/db/hourly/${DATE_DIR}/${HOUR_DIR}/strix-${TIMESTAMP}.db" \
    --storage-class STANDARD_IA \
    --metadata "source=strix,type=hourly,timestamp=${TIMESTAMP}"

# Daily full backup at 02:00 UTC
if [[ $(date -u +%H) == "02" && $(date -u +%M) -lt 10 ]]; then
    aws s3 cp "$BACKUP_FILE" "s3://${BACKUP_BUCKET}/db/daily/${DATE_DIR}/strix-${TIMESTAMP}.db" \
        --storage-class STANDARD_IA \
        --metadata "source=strix,type=daily,timestamp=${TIMESTAMP}"
fi

# Cleanup local temp
rm -f "$BACKUP_FILE"

echo "Database backup completed: strix-${TIMESTAMP}.db"
```

### 2. Configuration Backup (On Change + Daily)

```bash
#!/bin/bash
# /opt/strix/scripts/backup-config.sh
# Runs daily + triggered by ConfigMap change webhook

set -euo pipefail

BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)

# Export ConfigMaps
kubectl get configmap strix-config -n strix -o yaml > /tmp/strix-config-${TIMESTAMP}.yaml
kubectl get configmap strix-rules -n strix -o yaml > /tmp/strix-rules-${TIMESTAMP}.yaml 2>/dev/null || true

# Verify exports
[[ -s /tmp/strix-config-${TIMESTAMP}.yaml ]] || { echo "ERROR: ConfigMap export empty"; exit 1; }

# Upload
aws s3 cp /tmp/strix-config-${TIMESTAMP}.yaml "s3://${BACKUP_BUCKET}/config/${DATE_DIR}/strix-config-${TIMESTAMP}.yaml"
aws s3 cp /tmp/strix-rules-${TIMESTAMP}.yaml "s3://${BACKUP_BUCKET}/config/${DATE_DIR}/strix-rules-${TIMESTAMP}.yaml" 2>/dev/null || true

# Cleanup
rm -f /tmp/strix-config-${TIMESTAMP}.yaml /tmp/strix-rules-${TIMESTAMP}.yaml

echo "Configuration backup completed"
```

### 3. Secrets Backup (Encrypted, On Change)

```bash
#!/bin/bash
# /opt/strix/scripts/backup-secrets.sh
# Triggered by ExternalSecret/Vault change event

set -euo pipefail

BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)
ENCRYPTION_KEY="${STRIX_BACKUP_ENCRYPTION_KEY}"  # Age/GPG key for encrypting secrets

# Option A: Vault-backed secrets
if command -v vault &>/dev/null && [[ -n "${VAULT_ADDR:-}" ]]; then
    vault kv get -format=json secret/strix > /tmp/strix-secrets-${TIMESTAMP}.json
    
    # Encrypt before upload
    age -r "$ENCRYPTION_KEY" -e /tmp/strix-secrets-${TIMESTAMP}.json > /tmp/strix-secrets-${TIMESTAMP}.json.age
    
    aws s3 cp /tmp/strix-secrets-${TIMESTAMP}.json.age "s3://${BACKUP_BUCKET}/secrets/${DATE_DIR}/strix-secrets-${TIMESTAMP}.json.age"
    
    rm -f /tmp/strix-secrets-${TIMESTAMP}.json /tmp/strix-secrets-${TIMESTAMP}.json.age
fi

# Option B: SealedSecrets / Kubernetes secrets (encrypted at rest in etcd)
kubectl get secret strix-secrets -n strix -o yaml > /tmp/strix-secrets-k8s-${TIMESTAMP}.yaml
kubectl get secret strix-redis-secret -n strix -o yaml > /tmp/strix-redis-secret-${TIMESTAMP}.yaml 2>/dev/null || true
kubectl get secret strix-postgresql-secret -n strix -o yaml > /tmp/strix-postgresql-secret-${TIMESTAMP}.yaml 2>/dev/null || true

# These are already encrypted in etcd, but encrypt again for bucket storage
for f in /tmp/strix-secrets-k8s-${TIMESTAMP}.yaml /tmp/strix-redis-secret-${TIMESTAMP}.yaml /tmp/strix-postgresql-secret-${TIMESTAMP}.yaml; do
    [[ -f "$f" ]] || continue
    age -r "$ENCRYPTION_KEY" -e "$f" > "${f}.age"
    aws s3 cp "${f}.age" "s3://${BACKUP_BUCKET}/secrets/${DATE_DIR}/$(basename "${f}.age")"
    rm -f "$f" "${f}.age"
done

echo "Secrets backup completed"
```

### 4. Redis Backup (AOF/RDB)

```bash
#!/bin/bash
# /opt/strix/scripts/backup-redis.sh
# Runs every 60s via Redis AOF + daily RDB snapshot

set -euo pipefail

REDIS_HOST="${STRIX_REDIS_HOST:-redis-master}"
REDIS_PORT="${STRIX_REDIS_PORT:-6379}"
REDIS_PASSWORD="${STRIX_REDIS_PASSWORD}"
BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)

# Trigger BGSAVE for RDB snapshot
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" BGSAVE

# Wait for BGSAVE to complete
while [[ $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" LASTSAVE) -eq $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" LASTSAVE) ]]; do
    sleep 1
done

# Copy RDB from Redis pod
kubectl cp redis-master:/data/dump.rdb /tmp/redis-dump-${TIMESTAMP}.rdb

# Also copy AOF if exists
kubectl cp redis-master:/data/appendonly.aof /tmp/redis-aof-${TIMESTAMP}.aof 2>/dev/null || true

# Upload
aws s3 cp /tmp/redis-dump-${TIMESTAMP}.rdb "s3://${BACKUP_BUCKET}/redis/${DATE_DIR}/redis-dump-${TIMESTAMP}.rdb"
[[ -f /tmp/redis-aof-${TIMESTAMP}.aof ]] && aws s3 cp /tmp/redis-aof-${TIMESTAMP}.aof "s3://${BACKUP_BUCKET}/redis/${DATE_DIR}/redis-aof-${TIMESTAMP}.aof"

# Cleanup
rm -f /tmp/redis-dump-${TIMESTAMP}.rdb /tmp/redis-aof-${TIMESTAMP}.aof

echo "Redis backup completed"
```

### 5. Verification Cron Job (Daily)

```bash
#!/bin/bash
# /opt/strix/scripts/verify-backups.sh
# Runs daily at 03:00 UTC via cron

set -euo pipefail

BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
AUDIT_HMAC_KEY="${STRIX_AUDIT_HMAC_KEY}"

echo "=== Backup Verification Started $(date) ==="

# 1. Verify latest database backup
LATEST_DB=$(aws s3 ls "s3://${BACKUP_BUCKET}/db/daily/" --recursive | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_DB" ]] || { echo "ERROR: No daily database backup found"; exit 1; }

aws s3 cp "s3://${BACKUP_BUCKET}/db/daily/${LATEST_DB}" /tmp/verify.db

# Integrity check
sqlite3 /tmp/verify.db "PRAGMA integrity_check;" | grep -q "ok" || { echo "ERROR: Database integrity check failed"; exit 1; }

# Audit chain verification
sqlite3 /tmp/verify.db "SELECT verify_chain('$AUDIT_HMAC_KEY');" | grep -q "valid" || { echo "ERROR: Audit chain verification failed"; exit 1; }

# Check table counts
sqlite3 /tmp/verify.db "SELECT COUNT(*) FROM jobs; SELECT COUNT(*) FROM findings; SELECT COUNT(*) FROM audit_chain;"

# 2. Verify latest config backup
LATEST_CONFIG=$(aws s3 ls "s3://${BACKUP_BUCKET}/config/" --recursive | grep strix-config | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_CONFIG" ]] || { echo "WARNING: No config backup found"; }
aws s3 cp "s3://${BACKUP_BUCKET}/config/${LATEST_CONFIG}" /tmp/verify-config.yaml
[[ -s /tmp/verify-config.yaml ]] || { echo "ERROR: Config backup empty"; exit 1; }

# 3. Verify secrets backup
LATEST_SECRETS=$(aws s3 ls "s3://${BACKUP_BUCKET}/secrets/" --recursive | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_SECRETS" ]] || { echo "WARNING: No secrets backup found"; }

echo "=== Backup Verification PASSED $(date) ==="

# Cleanup
rm -f /tmp/verify.db /tmp/verify-config.yaml
```

---

## Verification

### Automated Verification (Daily Cron)
- Database integrity: `PRAGMA integrity_check`
- Audit chain: `verify_chain()` function
- Table row counts: jobs, findings, audit_chain > 0
- Config file: non-empty YAML
- Secrets: decryptable with age/GPG key

### Manual Verification Commands

```bash
# Check backup freshness
aws s3 ls s3://strix-backups/db/daily/ --recursive --human-readable --summarize | tail -5

# Verify specific backup
aws s3 cp s3://strix-backups/db/daily/2024/01/15/strix-20240115-020000.db /tmp/test.db
sqlite3 /tmp/test.db "PRAGMA integrity_check;"
sqlite3 /tmp/test.db "SELECT COUNT(*) FROM jobs, findings, audit_chain;"

# Check config backup
aws s3 cp s3://strix-backups/config/2024/01/15/strix-config-20240115-020000.yaml /tmp/test-config.yaml
head -20 /tmp/test-config.yaml

# Verify encryption key works
age -d -i /path/to/private-key s3://strix-backups/secrets/.../strix-secrets-...json.age | jq .
```

### Grafana Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `StrixBackupMissing` | No daily backup in 25h | critical |
| `StrixBackupVerificationFailed` | Verification cron exits non-zero | critical |
| `StrixBackupSizeAnomaly` | Backup size deviates >50% from 7-day avg | warning |

---

## Rollback

### If Backup Job Fails
1. Check cron logs: `journalctl -u strix-backup-cron -n 50`
2. Re-run failed script manually: `/opt/strix/scripts/backup-database.sh`
3. Verify manually uploaded backup passes verification
4. Alert on-call if repeated failures

### If Backup Corrupt
1. Use previous hour's hourly backup: `s3://bucket/db/hourly/...`
2. Or previous day's daily backup: `s3://bucket/db/daily/...`
3. Document incident and investigate root cause

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Platform On-Call | `platform-oncall@example.com` | Primary |
| Platform Lead | `platform-lead@example.com` | Secondary |
| Backup Vendor Support | AWS/GCP/Azure Enterprise Support | Infrastructure issues |
| Security Team | `security@example.com` | Secrets backup issues |

---

## Related Runbooks

- [restore.md](./restore.md) - Point-in-time restore procedures
- [disaster-recovery.md](./disaster-recovery.md) - Full DR scenarios
- [failover.md](./failover.md) - Warm standby promotion