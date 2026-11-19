# Database Issues Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/strix/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `StrixDBPoolExhausted` | warning | Pool available < 10% | 5m |
| `StrixDBPoolAcquireSlow` | warning | p95 acquire > 1s | 5m |
| `StrixDiskSpaceCritical` | critical | Disk free < 5% | 5m |
| `StrixDiskSpaceWarning` | warning | Disk free < 15% | 10m |

---

## Symptoms & Impact

**Symptoms:**
- `sqlite3.OperationalError: database is locked`
- Slow API responses (database queries timing out)
- Jobs failing with database errors
- High `strix_db_pool_acquire_seconds` latency
- Disk space alerts firing
- `sqlite3.DatabaseError: database disk image is malformed`

**Impact:**
- **SEV-1** (corruption/lock): All write operations fail, assessments cannot complete
- **SEV-2** (pool exhaustion): New jobs queue but cannot start, high latency
- **SEV-2** (disk space): Service degradation, potential data loss

---

## Diagnosis Commands

### 1. Database Health Checks
```bash
# Check database integrity
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# Check database size
kubectl exec -n strix strix-api-xxx -- ls -lh /var/lib/strix/strix.db*

# Check WAL/SHM files
kubectl exec -n strix strix-api-xxx -- ls -lh /var/lib/strix/

# Check busy timeout
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA busy_timeout;"

# Check journal mode
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA journal_mode;"

# Check page count and freelist
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA page_count; PRAGMA freelist_count;"
```

### 2. Connection Pool Metrics (PromQL)
```promql
# Pool utilization
strix_db_pool_available / strix_db_pool_size

# Pool acquire latency
histogram_quantile(0.95, sum(rate(strix_db_pool_acquire_seconds_bucket[5m])) by (le))

# Active connections
strix_db_pool_size - strix_db_pool_available

# Database size
strix_db_size_bytes / 1024 / 1024 / 1024
```

### 3. Disk Space & I/O
```bash
# Check disk usage
kubectl exec -n strix strix-api-xxx -- df -h /var/lib/strix

# Check PVC usage
kubectl get pvc -n strix strix-data-pvc -o jsonpath='{.status.capacity.storage}'

# Check I/O wait
kubectl exec -n strix strix-api-xxx -- iostat -x 1 3

# Check for large temp files
kubectl exec -n strix strix-api-xxx -- find /tmp -type f -size +100M -ls
```

### 4. Application Logs
```bash
# Check for database errors
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=200 | grep -iE "database|sqlite|lock|pool|connection" | grep -iE "error|fail|timeout|locked"

# Check for slow queries
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=500 | grep -i "slow query"
```

---

## Resolution Procedures

### Immediate Mitigation

#### For Database Locked / Pool Exhausted
```bash
# 1. Check for stuck transactions
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db ".tables"

# 2. Kill stuck connections (restart pods)
kubectl rollout restart deployment/strix-api -n strix
kubectl rollout restart deployment/strix-scheduler -n strix

# 3. Increase pool size temporarily
kubectl set env deployment/strix-api -n strix STRIX_DB_POOL_SIZE=20
kubectl rollout restart deployment/strix-api -n strix

# 4. Increase busy timeout
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA busy_timeout=60000;"
```

#### For Database Corruption
```bash
# 1. STOP all writers immediately
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0
kubectl scale deployment strix-worker -n strix --replicas=0  # if exists

# 2. Verify corruption
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# 3. Restore from backup
# List available backups
ls -lh /backups/strix.db.*

# Restore latest good backup
kubectl cp /backups/strix.db.latest strix/strix-api-xxx:/var/lib/strix/strix.db

# 4. Verify restored database
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "SELECT COUNT(*) FROM jobs;"

# 5. Restart services
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1
```

#### For Disk Space Critical
```bash
# 1. Clean temporary files
kubectl exec -n strix strix-api-xxx -- find /tmp -type f -mtime +1 -delete

# 2. Vacuum database (reclaims space)
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "VACUUM;"

# 3. Prune old data via API
curl -X POST http://strix.example.com/api/admin/prune \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"retention_days": 30}'

# 4. Expand PVC (if supported by storage class)
kubectl patch pvc strix-data-pvc -n strix -p '{"spec":{"resources":{"requests":{"storage":"20Gi"}}}}'

# 5. Clean old Docker images / logs on node
kubectl debug node/<node-name> -it --image=busybox -- chroot /host sh -c "docker image prune -f"
```

### Root Cause Resolution

#### Connection Leaks
```bash
# Check for connection leaks in code
# Look for: unclosed connections, missing context managers

# Add connection tracking
# STRIX_DB_DEBUG=1 to log pool events
kubectl set env deployment/strix-api -n strix STRIX_DB_DEBUG=1
```

#### WAL Mode Issues
```bash
# Ensure WAL mode enabled for better concurrency
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA journal_mode=WAL;"

# Check synchronous mode
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA synchronous=NORMAL;"
```

#### Migration Issues
```bash
# Check schema version
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA user_version;"

# Run pending migrations
kubectl exec -n strix strix-api-xxx -- /usr/local/bin/strix migrate

# Verify migration
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db ".schema"
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Corruption/Locked (SEV-1)** | 15 minutes | On-call → DBA → Platform Lead |
| **Pool Exhausted (SEV-2)** | 30 minutes | On-call → Platform Lead |
| **Disk Space (SEV-2)** | 1 hour | On-call → Infrastructure |

**SLA Targets:**
- Database availability: 99.99%
- Pool acquire p95 < 100ms
- Backup RPO: 1 hour (continuous WAL shipping)
- Recovery RTO: 30 minutes

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- DBA: `dba@example.com`
- Infrastructure: `infrastructure@example.com`

---

## Post-Incident Actions

1. **Backup verification** - test restore from backup
2. **Connection pool tuning** - adjust based on observed load
3. **Retention policy review** - ensure pruning works
4. **Monitoring enhancement** - add more granular DB metrics
5. **PostgreSQL migration planning** - if SQLite limits reached

---

## Grafana Dashboard Links

- **Strix Database**: `https://grafana.example.com/d/strix-database/database-health`
- **Kubernetes PVC**: `https://grafana.example.com/d/k8s-pvc/pvc-usage`

**Key Panels:**
- Database Size (time series)
- Pool Utilization (gauge)
- Pool Acquire Latency p50/p95/p99 (heatmap)
- Disk Usage (gauge)
- SQLite Integrity Check Status (stat)
- WAL File Size (time series)
