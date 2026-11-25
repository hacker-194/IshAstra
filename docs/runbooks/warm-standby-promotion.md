# Warm Standby Promotion Runbook (Single-Host / SQLite)

## Overview

For single-host SQLite deployments (default free tier, self-host, Compose), **high availability is achieved by promoting a warm standby**, not by clustering. This runbook covers the standby promotion procedure with measured RTO.

**Architecture:**
- Primary host: Runs IshAstra API + Worker + SQLite
- Standby host: Receives hourly backups via rsync/S3/NFS
- Promotion: Manual (operator-driven), ~30 seconds operator time

---

## Prerequisites

| Requirement | Primary | Standby |
|-------------|---------|---------|
| OS | Linux (Debian/Ubuntu/Fedora) | Same as primary |
| Docker | ✅ | ✅ |
| Backup sync | — | `rsync` / `aws s3 sync` / NFS mount |
| `ishastra` CLI | Installed | Installed |
| Network | Primary IP | Standby IP (same subnet or reachable) |

---

## Backup Procedure (Run on Primary — Automated via Cron)

**Install cron job (run once on primary):**
```bash
# As root or ishastra user
cat > /etc/cron.hourly/ishastra-backup <<'EOF'
#!/bin/bash
set -euo pipefail
DB_PATH="${ISHASTRA_DB:-/var/lib/ishastra/ishastra.db}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
HOSTNAME=$(hostname -s)
DATE=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_FILE="${BACKUP_DIR}/ishastra-${HOSTNAME}-${DATE}.db"

sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"
chmod 600 "$BACKUP_FILE"

# Sync to standby (adjust for your transport)
# Option A: rsync over SSH
rsync -az --delete "$BACKUP_DIR/" standby-host:/backups/

# Option B: AWS S3
# aws s3 sync "$BACKUP_DIR/" s3://your-bucket/ishastra-backups/ --storage-class STANDARD_IA

# Option C: NFS (if /backups is NFS mount)
# nothing extra needed
EOF
chmod +x /etc/cron.hourly/ishastra-backup
```

**Verify backup works:**
```bash
/etc/cron.hourly/ishastra-backup
ls -lh /backups/ishastra-*.db
```

---

## Standby Setup (Run Once on Standby Host)

```bash
# 1. Clone repo (same version as primary)
git clone https://github.com/hacker-194/IshAstra
cd IshAstra
git checkout v4.0.0-rc1  # pin to same tag as primary

# 2. Install ishastra CLI
python3 -m venv /opt/ishastra/venv
/opt/ishastra/venv/bin/pip install -c constraints.txt .

# 3. Create data directory
mkdir -p /var/lib/ishastra
chown ishastra:ishastra /var/lib/ishastra

# 4. Copy scope.json from primary (or maintain separately)
scp primary-host:/etc/ishastra/scope.json /etc/ishastra/scope.json

# 5. Copy .env from primary (secrets must match)
scp primary-host:/etc/ishastra/ishastra.env /etc/ishastra/ishastra.env

# 6. Verify backup sync works
ls -lh /backups/ishastra-*.db  # should show primary's backups
```

---

## Promotion Procedure (Run on Standby During Incident)

**Time estimate: ~30 seconds operator time + <5 seconds automated**

```bash
# 1. Detect primary failure
curl -sf http://primary-host:8000/api/ready || echo "PRIMARY DOWN"

# 2. Ensure backups are current on standby
ls -lt /backups/ishastra-*.db | head -5
# Verify latest backup is < 1 hour old

# 3. Run promotion (single command)
/opt/ishastra/venv/bin/ishastra standby-promote \
  --backup-dir /backups \
  --db-path /var/lib/ishastra/ishastra.db \
  --scope-file /etc/ishastra/scope.json
```

**What `standby-promote` does (4 steps, reports timing):**

| Step | Action | Typical Time |
|------|--------|--------------|
| 1 | Verify latest backup (exists, valid SQLite, has tables, audit chain) | ~50ms |
| 2 | Restore database (SQLite backup API, atomic, 0600 perms) | ~3s (2GB DB) |
| 3 | Acquire worker lease (exclusive `<db>.worker-lock`) | ~5ms |
| 4 | Readiness checks (audit chain HMAC, scope loaded, schema version, admin key) | ~1s |

**Typical RTO: < 5 seconds** (on modern SSD with 2GB database)

---

## Post-Promotion Steps

```bash
# 1. Start IshAstra on standby
systemctl start ishastra
# OR: docker compose up -d

# 2. Verify health
curl -sf http://standby-host:8000/api/health
curl -sf http://standby-host:8000/api/ready
curl -sf -H "Authorization: Bearer $ADMIN_KEY" http://standby-host:8000/api/audit/verify

# 3. Update DNS / Load Balancer
# Point ishastra.example.com to standby-host IP
# (Cloudflare: update DNS record; AWS: update ALB target; etc.)

# 4. Notify stakeholders
echo "Failover to standby complete at $(date). RTO: <5s. RPO: ≤1h." | mail -s "IshAstra Failover" ops@example.com

# 5. Record incident
# Document: primary failure time, promotion start, promotion end, RPO, any data loss
```

---

## Failback Procedure (When Primary Recovers)

```bash
# 1. On recovered primary, restore from standby's latest backup
scp standby-host:/backups/ishastra-*.db /backups/
sqlite3 /var/lib/ishastra/ishastra.db ".restore '/backups/ishastra-latest.db'"

# 2. Start primary
systemctl start ishastra

# 3. Verify primary health
curl -sf http://primary-host:8000/api/health
curl -sf http://primary-host:8000/api/ready

# 4. Switch DNS back to primary
# Update DNS/load balancer

# 5. Resume backup cron on primary
systemctl restart cron
```

---

## RPO / RTO Summary

| Metric | Value | Notes |
|--------|-------|-------|
| **RTO** | **< 5 seconds** (automated) + ~30s operator | Verify + restore + lease + readiness |
| **RPO** | **≤ 1 hour** | Hourly cron backup; reduce interval for tighter RPO |
| **Data Loss** | Up to 1 hour of assessments | Interrupted jobs marked `failed — interrupted` |

---

## Testing the Promotion (Quarterly Drill)

```bash
# 1. Schedule maintenance window
# 2. On primary: systemctl stop ishastra
# 3. On standby: run promotion procedure
# 4. Verify full functionality (run test assessment)
# 5. Failback to primary
# 6. Document actual RTO/RPO
# 7. Update runbook if times differ
```

---

## Automation: `ishastra standby-promote` Implementation

The command is implemented in `src/ishastra/cli.py` under the `standby-promote` subcommand. It uses `src/ishastra/core/standby.py` for the promotion logic.

**Key functions:**
- `verify_backup()` — checks file, SQLite integrity, required tables, audit chain
- `restore_database()` — uses SQLite backup API for atomic consistent snapshot
- `acquire_worker_lease()` — takes exclusive lock, fails fast on split-brain
- `run_readiness_checks()` — audit chain HMAC, scope/policy, schema version, admin key

---

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| `Backup file not found` | Check rsync/S3 sync; verify cron ran on primary |
| `Backup integrity check failed` | Restore from earlier backup; investigate primary corruption |
| `Worker lease held by another process` | `pgrep -af ishastra` on standby; kill stale process |
| `Audit chain verification failed` | Wrong `ISHASTRA_AUDIT_HMAC_KEY` in standby's `.env` |
| `Scope document not loaded` | Copy `scope.json` from primary; check path in `.env` |
| `Schema version mismatch` | Start the standby once so the schema upgrades automatically, then re-run promotion |

---

## Related

- [Backup Runbook](backup.md) — Backup procedures and verification
- [Restore Runbook](restore.md) — Full disaster recovery
- [Disaster Recovery](disaster-recovery.md) — Multi-region DR
- [Upgrade Runbook](upgrade-ishastra.md) — Blue-green upgrades
- [Deployment: Kubernetes](../deployment/kubernetes.md) — Standby promotion RTO/RPO details