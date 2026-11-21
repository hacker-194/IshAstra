# Database Issues Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/ishastra/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `IshastraDBPoolExhausted` | warning | Pool available < 10% | 5m |
| `IshastraDBPoolAcquireSlow` | warning | p95 acquire > 1s | 5m |
| `IshastraDiskSpaceCritical` | critical | Disk free < 5% | 5m |
| `IshastraDiskSpaceWarning` | warning | Disk free < 15% | 10m |

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
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA integrity_check;"

# Check database size
kubectl exec -n ishastra ishastra-api-xxx -- ls -lh /var/lib/ishastra/ishastra.db*

# Check WAL/SHM files
kubectl exec -n ishastra ishastra-api-xxx -- ls -lh /var/lib/ishastra/

# Check busy timeout
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA busy_timeout;"

# Check journal mode
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA journal_mode;"

# Check page count and freelist
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA page_count; PRAGMA freelist_count;"
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
kubectl exec -n ishastra ishastra-api-xxx -- df -h /var/lib/ishastra

# Check PVC usage
kubectl get pvc -n ishastra ishastra-data-pvc -o jsonpath='{.status.capacity.storage}'

# Check I/O wait
kubectl exec -n ishastra ishastra-api-xxx -- iostat -x 1 3

# Check for large temp files
kubectl exec -n ishastra ishastra-api-xxx -- find /tmp -type f -size +100M -ls
```

### 4. Application Logs
```bash
# Check for database errors
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=200 | grep -iE "database|sqlite|lock|pool|connection" | grep -iE "error|fail|timeout|locked"

# Check for slow queries
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=500 | grep -i "slow query"
```

---

## Resolution Procedures

### Immediate Mitigation

#### For Database Locked / Pool Exhausted
```bash
# 1. Check for stuck transactions
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db ".tables"

# 2. Kill stuck connections (restart pods)
kubectl rollout restart deployment/ishastra-api -n ishastra
kubectl rollout restart deployment/ishastra-scheduler -n ishastra

# 3. Increase pool size temporarily
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_DB_POOL_SIZE=20
kubectl rollout restart deployment/ishastra-api -n ishastra

# 4. Increase busy timeout
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA busy_timeout=60000;"
```

#### For Database Corruption
```bash
# 1. STOP all writers immediately
kubectl scale deployment ishastra-api -n ishastra --replicas=0
kubectl scale deployment ishastra-scheduler -n ishastra --replicas=0
kubectl scale deployment ishastra-worker -n ishastra --replicas=0  # if exists

# 2. Verify corruption
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA integrity_check;"

# 3. Restore from backup
# List available backups
ls -lh /backups/ishastra.db.*

# Restore latest good backup
kubectl cp /backups/ishastra.db.latest ishastra/ishastra-api-xxx:/var/lib/ishastra/ishastra.db

# 4. Verify restored database
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA integrity_check;"
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "SELECT COUNT(*) FROM jobs;"

# 5. Restart services
kubectl scale deployment ishastra-api -n ishastra --replicas=3
kubectl scale deployment ishastra-scheduler -n ishastra --replicas=1
```

#### For Disk Space Critical
```bash
# 1. Clean temporary files
kubectl exec -n ishastra ishastra-api-xxx -- find /tmp -type f -mtime +1 -delete

# 2. Vacuum database (reclaims space)
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "VACUUM;"

# 3. Prune old data via API
curl -X POST http://ishastra.example.com/api/admin/prune \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"retention_days": 30}'

# 4. Expand PVC (if supported by storage class)
kubectl patch pvc ishastra-data-pvc -n ishastra -p '{"spec":{"resources":{"requests":{"storage":"20Gi"}}}}'

# 5. Clean old Docker images / logs on node
kubectl debug node/<node-name> -it --image=busybox -- chroot /host sh -c "docker image prune -f"
```

### Root Cause Resolution

#### Connection Leaks
```bash
# Check for connection leaks in code
# Look for: unclosed connections, missing context managers

# Add connection tracking
# ISHASTRA_DB_DEBUG=1 to log pool events
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_DB_DEBUG=1
```

#### WAL Mode Issues
```bash
# Ensure WAL mode enabled for better concurrency
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA journal_mode=WAL;"

# Check synchronous mode
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA synchronous=NORMAL;"
```

#### Migration Issues
```bash
# Check schema version
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA user_version;"

# Run pending migrations
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/ishastra migrate

# Verify migration
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db ".schema"
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

- **Ishastra Database**: `https://grafana.example.com/d/ishastra-database/database-health`
- **Kubernetes PVC**: `https://grafana.example.com/d/k8s-pvc/pvc-usage`

**Key Panels:**
- Database Size (time series)
- Pool Utilization (gauge)
- Pool Acquire Latency p50/p95/p99 (heatmap)
- Disk Usage (gauge)
- SQLite Integrity Check Status (stat)
- WAL File Size (time series)
