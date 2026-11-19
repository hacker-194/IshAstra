# Strix Platform Support Runbook

**Version:** 3.5.0  
**Last Updated:** 2026-11-16  
**Classification:** Internal — Operational Procedures

---

## Table of Contents

1. [Triage Procedures](#1-triage-procedures)
2. [Escalation Paths & Severity Definitions](#2-escalation-paths--severity-definitions)
3. [Backup/Restore Procedures](#3-backuprestore-procedures)
4. [Key Rotation Procedures](#4-key-rotation-procedures)
5. [Common Operational Tasks](#5-common-operational-tasks)
6. [Incident Response Playbooks](#6-incident-response-playbooks)
7. [Monitoring & Alerting Runbooks](#7-monitoring--alerting-runbooks)
8. [Disaster Recovery Procedures](#8-disaster-recovery-procedures)
9. [Appendices](#9-appendices)

---

## 1. Triage Procedures

### 1.1 Incoming Issue Channels

| Channel | SLA to Acknowledge | Handler |
|---------|-------------------|---------|
| PagerDuty (SEV-1/2) | 5 minutes | On-call engineer |
| GitHub Issues | 4 hours | Platform team |
| Slack #strix-support | 1 hour | On-call engineer |
| Email security@ | 15 minutes | Security team |
| Customer Portal | 2 hours | Support engineer |

### 1.2 Initial Triage Checklist (First 10 Minutes)

```bash
# 1. Capture essential context
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
echo "Incident ID: $INCIDENT_ID"
echo "Reported by: $REPORTER"
echo "Channel: $CHANNEL"
echo "Timestamp: $(date -u --iso-8601=seconds)"

# 2. Quick system health check
curl -sf https://strix.example.com/api/health | jq .
curl -sf https://strix.example.com/api/ready | jq .

# 3. Check active alerts
curl -sf https://alertmanager.example.com/api/v2/alerts | jq '.[] | select(.status.state=="active") | {alertname, severity, startsAt}'

# 4. Determine severity (see Section 2)
# 5. Assign Incident Commander (IC) and Scribe
# 6. Create incident channel: #incident-$INCIDENT_ID
# 7. Post initial status update
```

### 1.3 Triage Decision Matrix

| Symptom | Likely Severity | Immediate Action |
|---------|-----------------|------------------|
| API returns 500/503 | SEV-1 | Page on-call, check logs |
| Audit chain verification fails | SEV-1 | **STOP WRITERS** immediately |
| Scope violations in logs | SEV-1/2 | Check tenant keys, revoke if needed |
| Jobs stuck in "running" | SEV-2 | Check worker status, cancel stuck jobs |
| High auth failure rate | SEV-2 | Check for credential stuffing |
| Single tenant reports issue | SEV-3 | Check tenant-specific config |
| UI cosmetic issue | SEV-4 | Create GitHub issue |

### 1.4 Information to Capture

- **What**: Exact error messages, HTTP status codes, timestamps
- **Who**: Tenant ID, API key prefix (first 8 chars), source IPs
- **When**: Start time, duration, frequency
- **Where**: Component (API, worker, scheduler, monitor, database)
- **Impact**: Number of affected tenants, jobs, findings

---

## 2. Escalation Paths & Severity Definitions

### 2.1 Severity Levels (P0-P3)

| Level | Name | Definition | Response Time | Resolution Target | Escalation |
|-------|------|------------|---------------|-------------------|------------|
| **P0** | SEV-1 Critical | Platform down, data loss, auth bypass, audit chain corruption, active security breach | 15 min | 1 hour | Page on-call + manager + security lead |
| **P1** | SEV-2 Major | Degraded functionality, scan failures, worker deadlock, Redis down, rate limiter unavailable | 30 min | 4 hours | Page on-call |
| **P2** | SEV-3 Minor | Non-critical bugs, single-tenant issues, webhook delivery failures, config drift | 4 hours | 24 hours | Ticket + next business day |
| **P3** | SEV-4 Low | Cosmetic, documentation, feature requests, non-urgent improvements | Next sprint | Next release | Backlog |

### 2.2 Escalation Contacts

| Role | Contact | Availability |
|------|---------|--------------|
| Platform On-Call | `platform-oncall@example.com` / PagerDuty | 24/7 |
| Platform Lead | `platform-lead@example.com` | Business hours + on-call backup |
| Security Lead | `security-lead@example.com` | 24/7 for security incidents |
| VP Engineering | `vp-eng@example.com` | SEV-1 only |
| CISO | `ciso@example.com` | Security SEV-1 only |
| Database Admin | `dba@example.com` | Business hours |
| Cloud Provider Support | AWS/GCP/Azure Enterprise | Infrastructure issues |

### 2.3 Escalation Timeline

```
T+0min      : Incident detected, IC assigned, channel created
T+15min     : P0 - Manager notified; P1 - On-call paged
T+30min     : P0 - Security lead engaged if data/auth involved
T+1hr       : P0 - VP Eng notified; P1 - Platform lead engaged
T+2hr       : P0 - CISO notified if security incident
T+4hr       : P0/P1 - Status update to stakeholders
T+24hr      : P2 - First response required
T+72hr      : All - RCA draft for P0/P1
```

### 2.4 War Room Protocol (P0 Only)

1. Create dedicated Slack channel: `#incident-YYYYMMDD-XXX`
2. Start video bridge (Google Meet/Zoom) — link in channel topic
3. Assign roles:
   - **IC**: Decision authority, coordinates response
   - **Scribe**: Documents timeline, actions, decisions
   - **Communications**: Drafts customer/status updates
   - **Technical Leads**: One per affected component
4. Update every 15 minutes in channel
5. Customer notification within 4 hours if data exposed

---

## 3. Backup/Restore Procedures

### 3.1 Backup Overview

| Component | Frequency | Retention | Method | Location |
|-----------|-----------|-----------|--------|----------|
| SQLite Database | Hourly (WAL) + Daily 02:00 UTC | 30d daily, 1yr monthly | SQLite backup API | S3 `strix-backups/db/` |
| Scope Config | On change + Daily | 90 days | kubectl export | S3 `strix-backups/config/` |
| K8s Manifests | On commit | Permanent | Git | Git repository |
| Secrets (encrypted) | On change | 90 days | Vault API / kubectl | Vault / S3 `strix-backups/secrets/` |
| Redis AOF/RDB | Every 60s (AOF) + Daily | 7 days | Redis BGSAVE | S3 `strix-backups/redis/` |
| Prometheus Data | Continuous | 15 days | Thanos remote write | Object storage |

### 3.2 SQLite Backup & Verification

#### Automated Backup Script (`/opt/strix/scripts/backup-database.sh`)

```bash
#!/bin/bash
# Runs hourly via cron: 0 * * * * /opt/strix/scripts/backup-database.sh

set -euo pipefail

DB_PATH="${STRIX_DB_PATH:-/var/lib/strix/strix.db}"
BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)
HOUR_DIR=$(date -u +%H)

# Verify database exists and is accessible
[[ -f "$DB_PATH" ]] || { echo "ERROR: Database not found at $DB_PATH" >&2; exit 1; }

# Verify database integrity before backup
sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Database integrity check failed" >&2; exit 1; }

# Create backup using SQLite backup API (consistent snapshot)
BACKUP_FILE="/tmp/strix-${TIMESTAMP}.db"
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

# Verify backup
sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok" || {
    echo "ERROR: Backup integrity check failed" >&2; rm -f "$BACKUP_FILE"; exit 1; }

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

rm -f "$BACKUP_FILE"
echo "Database backup completed: strix-${TIMESTAMP}.db"
```

#### Automated Verification Script (`/opt/strix/scripts/verify-backups.sh`)

```bash
#!/bin/bash
# Runs daily at 03:00 UTC via cron

set -euo pipefail

BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"

echo "=== Backup Verification Started $(date) ==="

# 1. Verify latest database backup
LATEST_DB=$(aws s3 ls "s3://${BACKUP_BUCKET}/db/daily/" --recursive | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_DB" ]] || { echo "ERROR: No daily database backup found"; exit 1; }

aws s3 cp "s3://${BACKUP_BUCKET}/db/daily/${LATEST_DB}" /tmp/verify.db

# Verify integrity and audit chain using the key from the protected environment
python scripts/operational_check.py --db /tmp/verify.db --out /tmp/verify-copy.db

# Check table counts
sqlite3 /tmp/verify.db "
SELECT 'jobs' as table, COUNT(*) FROM jobs
UNION ALL SELECT 'findings', COUNT(*) FROM findings
UNION ALL SELECT 'audit_chain', COUNT(*) FROM audit_chain
UNION ALL SELECT 'audit_log', COUNT(*) FROM audit_log;
"

# 2. Verify latest config backup
LATEST_CONFIG=$(aws s3 ls "s3://${BACKUP_BUCKET}/config/" --recursive | grep strix-config | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_CONFIG" ]] || { echo "WARNING: No config backup found"; }
aws s3 cp "s3://${BACKUP_BUCKET}/config/${LATEST_CONFIG}" /tmp/verify-config.yaml
[[ -s /tmp/verify-config.yaml ]] || { echo "ERROR: Config backup empty"; exit 1; }

# 3. Verify secrets backup
LATEST_SECRETS=$(aws s3 ls "s3://${BACKUP_BUCKET}/secrets/" --recursive | sort | tail -n 1 | awk '{print $4}')
[[ -n "$LATEST_SECRETS" ]] || { echo "WARNING: No secrets backup found"; }

echo "=== Backup Verification PASSED $(date) ==="

rm -f /tmp/verify.db /tmp/verify-config.yaml
```

### 3.3 PostgreSQL Backup (When Using PostgreSQL Backend)

```bash
#!/bin/bash
# /opt/strix/scripts/backup-postgresql.sh
# Runs daily at 02:00 UTC

set -euo pipefail

PG_DSN="${STRIX_DATABASE_URL}"
BACKUP_BUCKET="${STRIX_BACKUP_BUCKET}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DATE_DIR=$(date -u +%Y/%m/%d)

# Dump with consistent snapshot
pg_dump "$PG_DSN" \
    --format=custom \
    --compress=6 \
    --no-owner \
    --no-privileges \
    --file="/tmp/strix-pg-${TIMESTAMP}.dump"

# Verify dump
pg_restore --list "/tmp/strix-pg-${TIMESTAMP}.dump" >/dev/null || {
    echo "ERROR: PostgreSQL dump verification failed"; exit 1; }

# Upload
aws s3 cp "/tmp/strix-pg-${TIMESTAMP}.dump" "s3://${BACKUP_BUCKET}/db/daily/${DATE_DIR}/strix-pg-${TIMESTAMP}.dump" \
    --storage-class STANDARD_IA

rm -f "/tmp/strix-pg-${TIMESTAMP}.dump"
echo "PostgreSQL backup completed: strix-pg-${TIMESTAMP}.dump"
```

### 3.4 Audit Chain Verification

**Critical**: The audit chain MUST be verified after every restore.

```bash
# Verify integrity and audit chain on the backup. Set STRIX_AUDIT_HMAC_KEY in
# the protected operator environment; the value is read from the environment,
# not interpolated into a SQL command.
python scripts/operational_check.py --db /tmp/backup.db --out /tmp/backup-verified.db
```

**Verification via API:**
```bash
curl -sf -H "Authorization: Bearer $ADMIN_KEY" \
  https://strix.example.com/api/audit/verify | jq .
```

### 3.5 Restore Procedures

#### Scenario A: Database Restore (PVC-based Deployment)

```bash
#!/bin/bash
# Restore database to Kubernetes PVC

set -euo pipefail

BACKUP_FILE="${1:-strix-20240115-020000.db}"
NAMESPACE="strix"
PVC_NAME="strix-db-pvc"
POD_NAME="strix-api-0"
CONTAINER="strix-api"
DB_PATH_IN_POD="/var/lib/strix/strix.db"

echo "=== Starting Database Restore ==="
echo "Backup: $BACKUP_FILE"

# 1. Scale down ALL writers
echo "Scaling down writers..."
kubectl scale deployment strix-api -n $NAMESPACE --replicas=0
kubectl scale deployment strix-scheduler -n $NAMESPACE --replicas=0
kubectl scale deployment strix-worker -n $NAMESPACE --replicas=0 2>/dev/null || true

# Wait for pods to terminate
kubectl wait --for=delete pod -l app.kubernetes.io/name=strix,component=api -n $NAMESPACE --timeout=60s

# 2. Download backup
echo "Downloading backup..."
aws s3 cp "s3://strix-backups/db/daily/$(date -u +%Y/%m/%d)/${BACKUP_FILE}" /tmp/restore.db

# 3. Verify once more
python scripts/operational_check.py --db /tmp/restore.db --out /tmp/restore-verified.db

# 4. Copy to PVC via kubectl cp
echo "Copying to PVC..."
kubectl cp /tmp/restore.db $NAMESPACE/$POD_NAME:$DB_PATH_IN_POD -c $CONTAINER

# 5. Fix permissions and remove WAL/SHM
kubectl exec -n $NAMESPACE $POD_NAME -c $CONTAINER -- chmod 600 $DB_PATH_IN_POD
kubectl exec -n $NAMESPACE $POD_NAME -c $CONTAINER -- rm -f ${DB_PATH_IN_POD}-wal ${DB_PATH_IN_POD}-shm

# 6. Scale up writers
echo "Scaling up writers..."
kubectl scale deployment strix-api -n $NAMESPACE --replicas=3
kubectl scale deployment strix-scheduler -n $NAMESPACE --replicas=1
kubectl scale deployment strix-worker -n $NAMESPACE --replicas=2 2>/dev/null || true

# 7. Wait for rollout
kubectl rollout status deployment/strix-api -n $NAMESPACE --timeout=300s
kubectl rollout status deployment/strix-scheduler -n $NAMESPACE --timeout=300s

echo "=== Database Restore Complete ==="
```

#### Scenario B: Configuration Restore

```bash
#!/bin/bash
# Restore scope configuration and rules

set -euo pipefail

CONFIG_BACKUP="${1:-strix-config-20240115-020000.yaml}"
RULES_BACKUP="${2:-strix-rules-20240115-020000.yaml}"
NAMESPACE="strix"

echo "=== Restoring Configuration ==="

# 1. Download backups
aws s3 cp "s3://strix-backups/config/$(date -u +%Y/%m/%d)/${CONFIG_BACKUP}" /tmp/restore-config.yaml
aws s3 cp "s3://strix-backups/config/$(date -u +%Y/%m/%d)/${RULES_BACKUP}" /tmp/restore-rules.yaml 2>/dev/null || true

# 2. Validate YAML
kubectl apply --dry-run=client -f /tmp/restore-config.yaml >/dev/null || { echo "Invalid config YAML"; exit 1; }
[[ -f /tmp/restore-rules.yaml ]] && kubectl apply --dry-run=client -f /tmp/restore-rules.yaml >/dev/null || true

# 3. Apply ConfigMaps
kubectl apply -f /tmp/restore-config.yaml
[[ -f /tmp/restore-rules.yaml ]] && kubectl apply -f /tmp/restore-rules.yaml

# 4. Restart pods to pick up new config
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n $NAMESPACE
kubectl rollout status deployment/strix-api -n $NAMESPACE --timeout=180s
kubectl rollout status deployment/strix-scheduler -n $NAMESPACE --timeout=180s

echo "=== Configuration Restore Complete ==="
```

#### Scenario C: Secrets Restore (Vault)

```bash
#!/bin/bash
# Restore secrets from encrypted backup to Vault

set -euo pipefail

SECRETS_BACKUP="${1:-strix-secrets-20240115-020000.json.age}"
ENCRYPTION_KEY="${STRIX_BACKUP_ENCRYPTION_KEY}"
VAULT_ADDR="${VAULT_ADDR}"

echo "=== Restoring Secrets to Vault ==="

# 1. Download and decrypt
aws s3 cp "s3://strix-backups/secrets/$(date -u +%Y/%m/%d)/${SECRETS_BACKUP}" /tmp/secrets.json.age
age -d -i "$ENCRYPTION_KEY" -o /tmp/secrets.json /tmp/secrets.json.age

# 2. Validate JSON structure
jq -e '.data' /tmp/secrets.json >/dev/null || { echo "Invalid secrets format"; exit 1; }

# 3. Write to Vault (creates new version)
vault kv put secret/strix @/tmp/secrets.json

# 4. Trigger ExternalSecret sync (if using ESO)
kubectl annotate externalsecret strix-secrets -n strix force-sync=$(date +%s) --overwrite

# 5. Restart pods to pick up new secrets
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix
kubectl rollout status deployment/strix-api -n strix --timeout=180s

# 6. Cleanup
rm -f /tmp/secrets.json /tmp/secrets.json.age

echo "=== Secrets Restore Complete ==="
```

### 3.6 Post-Restore Verification Checklist

```bash
#!/bin/bash
# verify-full-restore.sh

set -euo pipefail

API_URL="https://strix.example.com"
ADMIN_KEY="${STRIX_API_KEY}"

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

---

## 4. Key Rotation Procedures

The previous command-based rotation examples in this section were unsafe and
did not match the supported APIs. Use the maintained
[secret and signing-key runbook](runbooks/secret-rotation.md) instead.

The project automates only scope-signing JWKS rotation. It does not provide
generic rotation for application, database, Redis, tenant, or audit secrets.
In particular, changing `STRIX_ENCRYPTION_KEY` without a data re-encryption
migration makes existing encrypted fields unreadable. No fixed 90-day rotation
period is prescribed by the project; the operator must set a policy that
accounts for each key's actual lifecycle and recovery behavior.

---

## 5. Common Operational Tasks

### 5.1 Tenant Creation

```bash
# Via API (admin key required)
curl -X POST https://strix.example.com/api/tenants \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "tier": "enterprise",
    "admin": false,
    "scope": "write"
  }'

# Response includes the API key (shown ONCE - save it!)
# {"tenant_id": "acme-corp", "api_key": "<metric_name>...", "tier": "enterprise"}
```

#### With Custom Scope (Managed Mode)

```bash
# Create engagement policy first
curl -X POST https://strix.example.com/api/policies \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "name": "Acme Corp Production",
    "scope": {
      "include": ["app.acme.com", "api.acme.com"],
      "exclude": ["staging.acme.com", "dev.acme.com"],
      "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
      "allowed_ports": [443, 8443],
      "allow_broad_networks": false
    },
    "effective_at": "2024-01-15T00:00:00Z",
    "expires_at": "2025-01-15T00:00:00Z"
  }'

# Then create tenant (policy will be bound automatically in managed mode)
curl -X POST https://strix.example.com/api/tenants \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "tier": "enterprise",
    "admin": false,
    "scope": "write"
  }'
```

### 5.2 Tenant Management

```bash
# List all tenants
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/tenants | jq .

# Get tenant details
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/tenants/acme-corp | jq .

# Update tenant tier
curl -X PATCH https://strix.example.com/api/tenants/acme-corp \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tier": "pro"}'

# Deactivate tenant (revokes key)
curl -X POST https://strix.example.com/api/tenants/acme-corp/deactivate \
  -H "Authorization: Bearer $ADMIN_KEY"

# Reactivate tenant (issues new key)
curl -X POST https://strix.example.com/api/tenants/acme-corp/activate \
  -H "Authorization: Bearer $ADMIN_KEY"

# Rotate tenant key
curl -X POST https://strix.example.com/api/keys/rotate/acme-corp \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### 5.3 Policy Management (Managed Mode)

```bash
# List all policies
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/policies | jq .

# Get specific policy
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/policies/pol_abc123 | jq .

# Create new policy
curl -X POST https://strix.example.com/api/policies \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "name": "Q1 2024 Engagement",
    "scope": {
      "include": ["app.acme.com", "api.acme.com"],
      "exclude": ["staging.acme.com"],
      "authorized_networks": ["10.0.0.0/8"],
      "allowed_ports": [443],
      "allow_broad_networks": false
    },
    "effective_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-04-01T00:00:00Z"
  }'

# Update policy (creates new version)
curl -X PATCH https://strix.example.com/api/policies/pol_abc123 \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": {
      "include": ["app.acme.com", "api.acme.com", "new-service.acme.com"]
    }
  }'

# Revoke policy (cancels queued/running jobs)
curl -X POST https://strix.example.com/api/policies/pol_abc123/revoke \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### 5.4 Scope Updates (Global Mode)

```bash
# View current scope
kubectl exec -n strix strix-api-0 -- cat /etc/strix/scope.json | jq .

# Validate scope syntax before applying
kubectl exec -n strix strix-api-0 -- /usr/local/bin/python -c "
from strix.scope import Scope
import json
with open('/etc/strix/scope.json') as f:
    scope = Scope(**json.load(f))
print('Scope valid:', scope)
print('Include:', scope.include)
print('Exclude:', scope.exclude)
print('Networks:', scope.authorized_networks)
"

# Update scope ConfigMap
kubectl edit configmap strix-config -n strix

# Or apply new scope file
kubectl create configmap strix-config-new --from-file=scope.json=/path/to/new/scope.json -n strix --dry-run=client -o yaml | kubectl apply -f -
kubectl patch configmap strix-config -n strix -p "$(kubectl get configmap strix-config-new -n strix -o json | jq -r '.data')"

# Restart pods to pick up new scope
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix
kubectl rollout status deployment/strix-api -n strix --timeout=180s
```

### 5.5 Monitoring Target Management

```bash
# List monitored targets
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/monitor/targets | jq .

# Add target to monitoring
curl -X POST https://strix.example.com/api/monitor/targets \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://app.example.com", "profile": "web-deep"}'

# Remove target from monitoring
curl -X DELETE https://strix.example.com/api/monitor/targets/https%3A%2F%2Fapp.example.com \
  -H "Authorization: Bearer $ADMIN_KEY"

# Trigger immediate assessment
curl -X POST https://strix.example.com/api/monitor/targets/https%3A%2F%2Fapp.example.com/assess \
  -H "Authorization: Bearer $ADMIN_KEY"

# Check monitor status
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/monitor/status | jq .
```

### 5.6 Webhook Sink Management

```bash
# List webhook sinks
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/monitor/webhooks | jq .

# Add webhook sink
curl -X POST https://strix.example.com/api/monitor/webhooks \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "slack-alerts",
    "url": "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>",
    "secret": "webhook-signing-secret"
  }'

# Test webhook delivery
curl -X POST https://strix.example.com/api/monitor/webhooks/slack-alerts/test \
  -H "Authorization: Bearer $ADMIN_KEY"

# Delete webhook sink
curl -X DELETE https://strix.example.com/api/monitor/webhooks/slack-alerts \
  -H "Authorization: Bearer $ADMIN_KEY"
```

---

## 6. Incident Response Playbooks

### 6.1 Playbook: Scope Gate Bypass / Unauthorized Scan Attempt

**Severity**: SEV-1 (confirmed bypass) / SEV-2 (repeated violations)

#### Detection
- Logs: `ScopeGate: Target https://evil.com rejected`
- HTTP 403 from `/api/assess` with "Target not within authorized scope"
- Audit log entries with `action: "scope_violation"`
- Alert: `StrixAuthFailureBurst` or repeated violations from same key

#### Immediate Containment (First 5 Minutes)

```bash
# 1. Identify source API key and tenant
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=500 | grep -i "scope violation"

# 2. Check audit log for violations
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT actor, target, timestamp, user_agent FROM audit_log
WHERE action = 'scope_violation'
ORDER BY timestamp DESC LIMIT 20;
"

# 3. REVOKE COMPROMISED KEY IMMEDIATELY
curl -X POST https://strix.example.com/api/keys/revoke/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key_prefix": "sk_live_abc123"}'

# Or via database directly
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
UPDATE api_keys SET revoked = 1 WHERE prefix = 'sk_live_abc123';
"

# 4. Block malicious source IPs
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-attacker-$(date +%s)
  namespace: strix
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: strix
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 203.0.113.0/24  # ATTACKER IP
EOF
```

#### Investigation (First 30 Minutes)

```bash
# 1. Check if any violations resulted in completed scans
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT j.id, j.target, j.state, j.tenant_id, j.created_at FROM jobs j
JOIN audit_log a ON j.tenant_id = a.actor
WHERE a.action = 'scope_violation'
AND j.state = 'completed'
AND j.created_at > a.timestamp;
"

# 2. Determine root cause
# - Overly broad scope configuration?
# - Credential leak?
# - Scope validation bug?
# - Tenant misconfiguration?
```

#### Root Cause Resolution

**Cause 1: Overly Broad Scope**
```bash
# Audit scope for wildcard issues
kubectl exec -n strix strix-api-0 -- /usr/local/bin/python -c "
from strix.scope import Scope
import json
with open('/etc/strix/scope.json') as f:
    scope = Scope(**json.load(f))

for pattern in scope.include:
    if pattern.count('*') > 1 or pattern == '*':
        print(f'WARNING: Overly broad pattern: {pattern}')

for net in scope.authorized_networks:
    if net in ['0.0.0.0/0', '::/0']:
        print(f'WARNING: Open network: {net}')
"
```

**Cause 2: Credential Leak**
```bash
# 1. Rotate all keys for affected tenant
curl -X POST https://strix.example.com/api/keys/rotate/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY"

# 2. Force re-authentication
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
DELETE FROM sessions WHERE tenant_id = 'acme-corp';
"
```

**Cause 3: Scope Validation Bug**
```bash
# Check Strix version for known scope bugs
kubectl exec -n strix strix-api-0 -- /usr/local/bin/strix --version

# Test edge cases
kubectl exec -n strix strix-api-0 -- /usr/local/bin/python -m pytest tests/test_scope.py -v
```

#### Recovery Verification

```bash
# 1. Verify scope gate blocks unauthorized
curl -X POST https://strix.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -d '{"target": "https://evil.com", "profile": "web"}'
# Expect 403

# 2. Verify authorized targets still work
curl -X POST https://strix.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -d '{"target": "https://app.example.com", "profile": "web"}'
# Expect 202

# 3. Monitor for further violations
# PromQL: sum(rate(strix_scope_gate_decisions_total{decision="blocked"}[5m]))  # expect 0
```

---

### 6.2 Playbook: Tenant Data Leak / Findings Exposure

**Severity**: SEV-1

#### Detection
- Tenant reports unauthorized access to findings
- Unusual findings export activity in audit log
- Webhook deliveries to unknown endpoints
- Alert: `StrixCriticalFindingsNew` from unexpected tenant

#### Immediate Containment (First 15 Minutes)

```bash
# 1. REVOKE COMPROMISED CREDENTIALS
# Identify affected tenant from audit log
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT * FROM audit_log
WHERE timestamp > datetime('now', '-24 hours')
AND (action = 'findings_export' OR action = 'key_rotation')
ORDER BY timestamp DESC;
"

# Revoke tenant's API keys
curl -X POST https://strix.example.com/api/keys/revoke/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"key_prefix": "sk_live_compromised"}'

# 2. Stop the service if active exfiltration
kubectl scale deployment strix-api -n strix --replicas=0

# 3. Preserve database for forensics
kubectl cp strix/strix-api-0:/var/lib/strix/strix.db /forensics/strix.db.$(date +%s)
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --since=72h > /forensics/api-logs.$(date +%s).txt
```

#### Impact Assessment

```bash
# 1. Check what findings were accessed
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT f.*, j.target, j.tenant_id FROM findings f
JOIN jobs j ON f.job_id = j.id
WHERE j.tenant_id = '<suspect_tenant>'
AND f.created_at > datetime('now', '-24 hours');
"

# 2. Check webhook deliveries
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT * FROM webhook_deliveries
WHERE created_at > datetime('now', '-24 hours')
AND status = 'delivered';
"

# 3. Check for bulk API access patterns
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT actor, COUNT(*) as calls, MIN(timestamp), MAX(timestamp)
FROM audit_log
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY actor
HAVING calls > 100
ORDER BY calls DESC;
"
```

#### Eradication & Recovery

```bash
# 1. Rotate ALL secrets for affected tenant
# See secret-rotation.md emergency procedure

# 2. Invalidate unauthorized findings (if any created via bypass)
# Mark findings from unauthorized scans as invalid
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
UPDATE findings SET status = 'invalid' WHERE job_id IN (
  SELECT id FROM jobs WHERE tenant_id = '<suspect_tenant>' AND state = 'completed'
  AND created_at > '<compromise_start_time>'
);
"

# 3. Restore service with new credentials
kubectl scale deployment strix-api -n strix --replicas=3
kubectl rollout status deployment/strix-api -n strix --timeout=300s

# 4. Notify affected parties
# See security-incident.md for notification templates
```

---

### 6.3 Playbook: Audit Chain Corruption

**Severity**: SEV-1

#### Detection
- Startup failure: `Audit chain verification failed at startup`
- `/api/audit/verify` returns `{"valid": false, "reason": "..."}`
- Logs show `Audit chain tampered` or `Hash mismatch at sequence N`

#### Immediate Response

```bash
# 1. STOP ALL WRITERS IMMEDIATELY
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0
kubectl scale deployment strix-worker -n strix --replicas=0 2>/dev/null || true

# 2. Preserve database for forensics
kubectl cp strix/strix-api-0:/var/lib/strix/strix.db /forensics/strix.db.forensic.$(date +%s)

# 3. Check audit chain manually
sqlite3 /var/lib/strix/strix.db "SELECT * FROM audit_chain ORDER BY seq DESC LIMIT 10;"

# 4. Check key presence without printing its value
kubectl get secret strix-secrets -n strix \
  -o 'jsonpath={.data.STRIX_AUDIT_HMAC_KEY}' | grep -q . \
  && echo "Audit key is present"
# Compare the secret version in the secret manager's audit log
```

#### Diagnosis

| Failure Mode | Cause | Recovery |
|--------------|-------|----------|
| Sequence gap | Missing entries | Restore from backup |
| Hash mismatch | Data tampering OR key rotation without re-hash | Check key history; restore from backup |
| Previous hash mismatch | Chain broken | Restore from backup |
| Genesis hash wrong | Database replaced | Restore from backup |

#### Recovery Options

**Option A: Key Rotated Without Re-hash**
```bash
# There is no supported in-place rehash operation. Preserve the database and
# restore the previously valid key from the secret manager if it was changed
# accidentally. Otherwise stop writers and escalate for a reviewed recovery.
```

**Option B: Database Tampered - Restore from Backup**
```bash
# Follow database restore procedure (Section 3.5)
# Use latest VERIFIED backup
LATEST_VERIFIED=$(aws s3 ls s3://strix-backups/db/verified/ --recursive | sort | tail -n 1 | awk '{print $4}')
./restore-database.sh "$LATEST_VERIFIED"
```

**Option C: Unknown Cause - Full Forensic Investigation**
```bash
# Do NOT restart writers until root cause identified
# Engage security team immediately
# Preserve all logs and database snapshots
```

#### Post-Recovery
- Do not replace `STRIX_AUDIT_HMAC_KEY` without an approved chain migration;
  see [secret and signing-key rotation](runbooks/secret-rotation.md)
- Review database access controls
- Update runbook with lessons learned

---

### 6.4 Playbook: Worker Deadlock / Jobs Stuck

**Severity**: SEV-2

#### Detection
- Jobs stuck in `running` state > timeout (default 120s)
- `/api/monitor/status` shows `running: true` but no job progress
- Queue depth growing
- Worker logs show no activity

#### Immediate Actions

```bash
# 1. Check worker status
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/monitor/status | jq .

# 2. Check worker logs
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=200 | grep -i worker

# 3. Identify stuck jobs
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT id, target, state, actor, created_at, started_at FROM jobs
WHERE state = 'running' AND started_at < datetime('now', '-5 minutes');
"

# 4. Force cancel stuck jobs
for job_id in $(kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "
SELECT id FROM jobs WHERE state = 'running' AND started_at < datetime('now', '-5 minutes');
"); do
  curl -X POST https://strix.example.com/api/assess/$job_id/cancel \
    -H "Authorization: Bearer $ADMIN_KEY"
done

# 5. Restart API pods (workers run in-process)
kubectl rollout restart deployment/strix-api -n strix
kubectl rollout status deployment/strix-api -n strix --timeout=300s
```

#### Root Cause Investigation

```bash
# 1. Check for OOM kills
dmesg | grep -i kill

# 2. Check disk space
df -h

# 3. Check database locks
sqlite3 /var/lib/strix/strix.db "PRAGMA busy_timeout;"

# 4. Check Redis connectivity (rate limiting)
redis-cli -h $REDIS_HOST ping

# 5. Check for adapter deadlocks (nmap, nuclei hanging)
ps aux | grep -E "nmap|nuclei"

# 6. Check worker memory limit
kubectl exec -n strix strix-api-0 -- cat /proc/self/cgroup | grep memory
```

#### Resolution

| Cause | Fix |
|-------|-----|
| OOM kill | Increase `STRIX_WORKER_MEMORY_MB` or reduce concurrent workers |
| Disk full | Clean up old jobs/findings, increase PVC size |
| Database locked | Restart API, check for long-running transactions |
| Redis down | Restart Redis, check persistence config |
| Adapter hang | Reduce job timeout, check external tool versions |
| Deadlock in locks.py | Review lock ordering, restart pods |

---

### 6.5 Playbook: Redis Unavailable

**Severity**: SEV-2 (if `STRIX_REDIS_REQUIRED=1` or workers > 1)

#### Detection
- Rate limiting fails open/closed
- Scheduler fails to start
- Logs: `Redis required but unreachable`
- Alert: `StrixRedisDown`

#### Immediate Actions

```bash
# 1. Check Redis status
redis-cli -h $REDIS_HOST -p $REDIS_PORT ping

# 2. Check Redis logs
kubectl logs -n strix -l app.kubernetes.io/name=redis --tail=100

# 3. If STRIX_REDIS_REQUIRED=false, Strix falls back to in-memory
# Verify fallback mode:
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=100 | grep "RateLimitMiddleware"

# 4. Restart Redis
kubectl rollout restart statefulset/redis-master -n strix
```

#### Recovery
- Verify Redis persistence (AOF/RDB)
- Check memory: `redis-cli INFO memory`
- If data loss: rate limiter state reset (acceptable - no data loss)

---

### 6.6 Playbook: Database Corruption / Locked

**Severity**: SEV-1

#### Detection
- `sqlite3.OperationalError: database is locked`
- `sqlite3.DatabaseError: database disk image is malformed`
- All write operations fail
- Alert: `StrixDatabaseError`

#### Immediate Actions

```bash
# 1. Stop service
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0

# 2. Check database integrity
sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# 3. If locked, check for stale locks
ls -la /var/lib/strix/strix.db*
# Remove -shm/-wal if no other process using
rm -f /var/lib/strix/strix.db-wal /var/lib/strix/strix.db-shm

# 4. Restore from backup if corrupted
cp /backups/strix.db.latest /var/lib/strix/strix.db
chmod 600 /var/lib/strix/strix.db
```

#### Recovery
- Restore from latest verified backup
- Verify audit chain after restore
- Re-queue any lost jobs

---

## 7. Monitoring & Alerting Runbooks

### 7.1 Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/api/health` | Liveness probe | `{"status": "healthy"}` |
| `/api/ready` | Readiness probe | `{"ready": true}` |
| `/api/metrics` | Prometheus metrics (admin) | Prometheus format |
| `/api/metrics/otel` | OpenTelemetry metrics | OTLP format |
| `/api/audit/verify` | Audit chain verification | `{"ok": true, "length": N}` |
| `/api/monitor/status` | Monitor/scheduler status | `{"running": true, ...}` |

### 7.2 Critical Alerts & Runbook Links

| Alert | Severity | Runbook | Auto-Resolve |
|-------|----------|---------|--------------|
| `StrixAuditChainVerificationFailed` | Critical | Section 6.3 | No |
| `StrixScopeGateBypass` | Critical | Section 6.1 | No |
| `StrixDatabaseCorruption` | Critical | Section 6.6 | No |
| `StrixWorkerDeadlock` | Major | Section 6.4 | Yes (after restart) |
| `StrixRedisDown` | Major | Section 6.5 | Yes |
| `StrixAuthFailureBurst` | Critical | Section 6.1 | No |
| `StrixBackupMissing` | Critical | Section 3 | No |
| `StrixBackupVerificationFailed` | Critical | Section 3 | No |
| `StrixHighJobLatency` | Warning | runbooks/job-latency.md | Yes |
| `StrixQueueBacklog` | Warning | runbooks/queue-backlog.md | Yes |
| `StrixCertificateExpiry` | Warning | runbooks/certificate-expiry.md | No |

### 7.3 Key Metrics Interpretation

`src/strix/metrics.py` exports the HTTP, scope-gate, rate-limit, job, queue,
adapter, database, auth, webhook, findings, audit and build series. Scope denials
are `strix_scope_gate_decisions_total{decision="blocked"}`, labelled by `reason`.
Every `strix_*` query in this runbook returns data. Not exported: compliance
scoring (`strix_compliance_*`) and the `strix_assessment_*` Kubernetes gauges.

#### API Health Metrics

```promql
# Request rate
rate(strix_http_requests_total[5m])

# Error rate by status
rate(strix_http_requests_total{status=~"5.."}[5m]) / rate(strix_http_requests_total[5m])

# Latency p99
histogram_quantile(0.99, rate(strix_http_request_duration_seconds_bucket[5m]))

# In-flight requests
strix_http_requests_in_progress
```

#### Scope Gate Metrics

`strix_scope_gate_decisions_total{decision,reason,tenant}` is exported by
`src/strix/metrics.py`. `decision` is `allowed` or `blocked`; `reason` is the
denial code (`out_of_scope`, `invalid_target`, `resolution_failed`,
`policy_unavailable`, `revoked`, `expired`) or `allowed`; `tenant` is the
engagement policy's tenant or `global`.

```promql
# Gate decisions by outcome
rate(strix_scope_gate_decisions_total{decision="allowed"}[5m])
rate(strix_scope_gate_decisions_total{decision="blocked"}[5m])

# Which denials dominate, and for which tenant
sum by (reason) (rate(strix_scope_gate_decisions_total{decision="blocked"}[5m]))
sum by (tenant) (rate(strix_scope_gate_decisions_total{decision="blocked"}[5m]))
```

#### Rate Limiting Metrics

```promql
# Rate limit checks by outcome
rate(strix_rate_limit_hits_total[5m]) by (route_class, tier, allowed)

# Exceeded limits
rate(strix_rate_limit_exceeded_total[5m]) by (route_class, tier, identity_type)
```

#### Reports and Build

```promql
# Reports generated in the last hour
increase(strix_reports_total[1h])

# Version actually running
strix_build_info
```

#### Job, Adapter and Database Metrics

`strix_jobs_total` counts every state a job enters; `strix_job_state_transitions_total`
is the same event labelled `from`/`to`; `strix_jobs_active` is the number of
running jobs. `strix_job_duration_seconds` is labelled `profile` and `tenant`.

```promql
# Jobs entering each state
rate(strix_jobs_total[5m]) by (state)

# Which transitions dominate (queued -> failed is the one to watch)
rate(strix_job_state_transitions_total[5m]) by (from, to)

# Job duration p95 by profile
histogram_quantile(0.95, rate(strix_job_duration_seconds_bucket[5m])) by (profile, le)

# Queue and worker occupancy (inprocess mode only)
strix_queue_depth
strix_worker_busy / strix_workers_total

# Adapter error rate and slow runs
rate(strix_adapter_errors_total[5m]) by (adapter, error_type)
rate(strix_adapter_timeout_total[5m]) by (adapter)
histogram_quantile(0.95, rate(strix_adapter_duration_seconds_bucket[5m])) by (adapter, le)

# Connection pool headroom and acquire latency
strix_db_pool_size - strix_db_pool_available
histogram_quantile(0.95, rate(strix_db_pool_acquire_seconds_bucket[5m])) by (dialect, le)
```

### 7.4 Grafana Dashboard References

| Dashboard | URL | Key Panels |
|-----------|-----|------------|
| Strix Overview | `https://grafana.example.com/d/strix/overview` | Request rate, error rate, latency, active jobs |
| Security | `https://grafana.example.com/d/strix-security/security-overview` | Scope violations, auth failures, audit chain |
| Workers | `https://grafana.example.com/d/strix-workers/worker-status` | Queue depth, worker utilization, job duration |
| Database | `https://grafana.example.com/d/strix-database/db-health` | Connections, query latency, backup status |
| Rate Limiting | `https://grafana.example.com/d/strix-ratelimit/rate-limiting` | Checks, exceeded, Redis availability |
| Backup/DR | `https://grafana.example.com/d/strix-dr/dr-readiness` | Backup freshness, verification status, RTO/RPO |

### 7.5 Log Analysis Queries (Loki)

```logql
# Scope violations
{job="strix-api"} |= "scope violation"

# Audit chain failures
{job="strix-api"} |= "audit chain" |~ "failed|tampered|mismatch"

# Worker crashes
{job="strix-api"} |= "worker" |~ "crashed|dead|OOM"

# Database errors
{job="strix-api"} |= "database" |~ "error|locked|corrupt"

# Authentication failures
{job="strix-api"} |= "auth" |~ "fail|invalid|revoked"
```

---

## 8. Disaster Recovery Procedures

### 8.1 DR Strategy Summary

| Scenario | RTO | RPO | Strategy |
|----------|-----|-----|----------|
| Single pod failure | < 2 min | 0 | Kubernetes self-heals |
| Database corruption | 30 min | 1 hour | Restore from backup |
| Namespace deleted | 1 hour | 1 hour | Restore from Git + backup |
| Cluster lost | 2-4 hours | 1 hour | New cluster + restore |
| Region lost | 4 hours | 1 hour | Failover to DR region |

### 8.2 Regional Failover Procedure

#### Pre-requisites
- DR cluster provisioned in alternate region
- ArgoCD applications pointing to Git repo
- Backup bucket replicated to DR region
- DNS failover configured (Route53/Cloudflare/Cloud DNS)

#### Failover Steps

```bash
# 1. Provision DR cluster (if not already running)
cd infrastructure/terraform/dr-region
terraform apply -auto-approve

# 2. Install prerequisites
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

# 3. Deploy Strix via ArgoCD
kubectl apply -k deploy/argocd/overlays/dr-region

# 4. Restore data
# Database (from DR region backup bucket)
./restore-database.sh "strix-20240115-020000.db"

# Config
./restore-config.sh "strix-config-20240115-020000.yaml"

# Secrets (from Vault - cross-region replication)
kubectl apply -f deploy/argocd/secrets/external-secrets/

# 5. Update DNS
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXX --change-batch file://dns-failover.json

# 6. Verify DNS propagation
dig strix.example.com

# 7. Verify full functionality
curl -sf https://strix.example.com/api/health
curl -sf https://strix.example.com/api/ready
curl -sf -H "Authorization: Bearer $ADMIN_KEY" https://strix.example.com/api/audit/verify | jq .
```

### 8.3 Ransomware / Encryption Attack Response

```bash
# 1. ISOLATE immediately
kubectl cordon <affected-nodes>
kubectl drain <affected-nodes> --ignore-daemonsets --delete-emptydir-data

# Block all egress from Strix namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: strix
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF

# 2. Assess scope
kubectl get pv -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,CLAIM:.spec.claimRef.name

# Verify backup integrity (offline backups)
# Check air-gapped backups not encrypted

# 3. Recover from CLEAN backups (pre-dating attack)
# Use backup from before earliest detected encryption
# Rebuild cluster from scratch (don't trust compromised nodes)
cd infrastructure/terraform/dr-region
terraform destroy -auto-approve
terraform apply -auto-approve

# 4. Forensic preservation
aws ec2 create-snapshot --volume-id vol-xxxx --description "Forensic snapshot $(date)"

kubectl logs -n strix -l app.kubernetes.io/name=strix --all-containers --tail=-1 > /forensics/strix-logs-$(date +%s).txt
```

### 8.4 DR Testing Checklist (Quarterly)

- [ ] Restore database from backup to staging
- [ ] Verify audit chain integrity after restore
- [ ] Deploy to DR region from scratch
- [ ] Test DNS failover
- [ ] Run full smoke test suite
- [ ] Verify monitoring/alerting in DR
- [ ] Document actual RTO/RPO achieved
- [ ] Update runbook with findings

```bash
# Automated DR test script
#!/bin/bash
# dr-test.sh - Run quarterly

set -euo pipefail

echo "=== DR Test Started $(date) ==="

# 1. Deploy to DR namespace
kubectl create namespace strix-dr-test
helm install strix-dr ./deploy/helm/strix -n strix-dr-test -f deploy/helm/strix/values-dr.yaml

# 2. Restore data
./restore-database.sh "$(aws s3 ls s3://strix-backups/db/daily/ --recursive | sort | tail -1 | awk '{print $4}')"

# 3. Run smoke tests
kubectl exec -n strix-dr-test strix-dr-api-0 -- /usr/local/bin/pytest tests/smoke/ -v

# 4. Verify monitoring
curl -sf http://prometheus.monitoring.svc.cluster.local:9090/-/healthy
curl -sf http://grafana.monitoring.svc.cluster.local:3000/api/health

# 5. Cleanup
helm uninstall strix-dr -n strix-dr-test
kubectl delete namespace strix-dr-test

echo "=== DR Test Complete $(date) ==="
```

---

## 9. Appendices

### 9.1 Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STRIX_ENV` | Yes | development | Environment: development/test/staging/production |
| `STRIX_API_KEY` | Prod only | - | Bootstrap admin key (≥16 chars) |
| `STRIX_AUDIT_HMAC_KEY` | Prod only | - | HMAC key for audit chain |
| `STRIX_ENCRYPTION_KEY` | Prod only | - | Base64-encoded 32-byte AES-GCM field-encryption key |
| `STRIX_WEBHOOK_SECRET` | No | - | Webhook HMAC signing key |
| `STRIX_SCOPE_MODE` | No | auto | auto/global/managed |
| `STRIX_SCOPE_FILE` | Global mode | scope.json | Path to scope file |
| `STRIX_DB` | SQLite | strix.db | SQLite database path |
| `STRIX_DATABASE_URL` | PostgreSQL | - | PostgreSQL DSN |
| `STRIX_WORKERS` | No | 1 | Number of worker processes |
| `STRIX_QUEUE_MAX` | No | 32 | Max queue depth |
| `STRIX_REDIS_URL` | No | redis://localhost:6379/0 | Redis connection URL |
| `STRIX_REDIS_REQUIRED` | No | false | Fail if Redis unavailable |
| `STRIX_RATE_LIMIT_DISABLED` | No | false | Disable rate limiting |
| `STRIX_RETENTION_DAYS` | No | 0 | Retention policy (0=disabled) |
| `STRIX_AUDIT_MAX_ENTRIES` | No | 10000 | Max in-memory audit entries |
| `STRIX_LOG_FORMAT` | No | text | text/json |
| `STRIX_LOG_LEVEL` | No | INFO | Log level |
| `STRIX_TRUSTED_PROXIES` | Behind proxy | - | Comma-separated CIDR list |
| `STRIX_CORS_ORIGINS` | No | - | Comma-separated allowed origins |
| `STRIX_WORKER_MEMORY_MB` | No | 1024 | Worker memory limit |
| `STRIX_DISABLE_DOCS` | Prod | true | Disable API docs |
| `STRIX_DEBUG` | No | false | Debug mode |

### 9.2 Key File Locations

| File | Location | Purpose |
|------|----------|---------|
| SQLite Database | `/var/lib/strix/strix.db` | Primary data store |
| Scope Config | `/etc/strix/scope.json` | Global scope (global mode) |
| Audit HMAC Key | `strix-secrets` K8s secret | Audit chain signing |
| API Keys | `strix-secrets` K8s secret | Admin/bootstrap keys |
| Webhook Secrets | `strix-secrets` K8s secret | Webhook signing |
| Encryption Key | `strix-secrets` K8s secret | Secrets at rest encryption |
| Redis Password | `strix-redis-secret` K8s secret | Redis auth |
| PostgreSQL Password | `strix-postgresql-secret` K8s secret | PostgreSQL auth |

### 9.3 Common Commands Quick Reference

```bash
# Scale deployments
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1
kubectl scale deployment strix-worker -n strix --replicas=2

# View logs
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=100 -f
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=scheduler --tail=100 -f

# Exec into pod
kubectl exec -n strix strix-api-0 -it -- /bin/bash

# Database queries
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "SELECT COUNT(*) FROM jobs;"
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# Audit chain verification
curl -sf -H "Authorization: Bearer $ADMIN_KEY" \
  https://strix.example.com/api/audit/verify | jq .

# Restart pods
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix
kubectl rollout status deployment/strix-api -n strix --timeout=300s

# View ConfigMap
kubectl get configmap strix-config -n strix -o yaml

# View secrets (names only)
kubectl get secret strix-secrets -n strix -o jsonpath='{.data}' | jq 'keys[]'
```

### 9.4 Contact Information

| Team | Contact | Escalation |
|------|---------|------------|
| Platform On-Call | `platform-oncall@example.com` | Primary |
| Platform Lead | `platform-lead@example.com` | Secondary |
| Security Team | `security@example.com` | Security incidents |
| Database Admin | `dba@example.com` | Data corruption |
| Cloud Provider | AWS/GCP/Azure Enterprise | Infrastructure |
| Legal | `legal@example.com` | Compliance/regulatory |
| CISO | `ciso@example.com` | Security SEV-1 |

### 9.5 Runbook Maintenance

- **Review frequency**: Quarterly
- **Update triggers**: After each SEV-1/SEV-2, after DR test, after key rotation
- **Version control**: All runbooks in `/docs/runbooks/` tracked in Git
- **Test procedures**: Annual tabletop exercise, quarterly DR test
- **Owner**: Platform Team Lead

### 9.6 Related Documentation

- [Backup Procedures](./runbooks/backup.md)
- [Restore Procedures](./runbooks/restore.md)
- [Disaster Recovery](./runbooks/disaster-recovery.md)
- [Secret Rotation](./runbooks/secret-rotation.md)
- [Incident Response](./runbooks/incident-response.md)
- [Security Incident](./runbooks/security-incident.md)
- [Scope Gate Failures](./runbooks/scope-gate-failures.md)
- [Failover Procedures](./runbooks/failover.md)
- [Observability Stack](./runbooks/observability-stack.md)
- [Production Readiness](production-readiness.md)
- [Architecture](../ARCHITECTURE.md)
- [Deployment Guide](../DEPLOYMENT.md)
- [Security Audit Prep](security-audit-prep.md)

---

**End of Support Runbook**

*This document must be reviewed and updated after every SEV-1 incident, quarterly DR test, and major release. Last exercised: 2026-11-16 (quarterly DR test).*