# Runbook: High Database Connections

# Runbook: High Database Connections

**Alert**: `IshastraDatabaseConnectionsHigh`
**Severity**: Warning
**Team**: Platform

## Symptoms

- `pg_stat_activity_count / pg_settings_max_connections > 0.8`
- New connections failing with "too many connections"
- API latency increasing
- Worker tasks timing out on DB operations

## Investigation Steps

### 1. Check Connection Count

```bash
# Current connections
kubectl exec -n ishastra-system deploy/ishastra-api -- psql "$DATABASE_URL" -c "SELECT count(*) FROM pg_stat_activity;"

# By state
kubectl exec -n ishastra-system deploy/ishastra-api -- psql "$DATABASE_URL" -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# By application
kubectl exec -n ishastra-system deploy/ishastra-api -- psql "$DATABASE_URL" -c "SELECT application_name, count(*) FROM pg_stat_activity GROUP BY application_name;"
```

### 2. Check Connection Pool

```bash
# PgBouncer stats (if used)
kubectl exec -n ishastra-system deploy/pgbouncer -- pgbouncer -c "SHOW STATS;"

# Pool utilization
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep db_pool
```

### 3. Identify Long-Running Queries

```bash
kubectl exec -n ishastra-system deploy/ishastra-api -- psql "$DATABASE_URL" -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '30 seconds'
AND state != 'idle';
"
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Pool exhausted | All connections active, no idle | Increase pool size in app config |
| Long queries | Queries running > 30s | Add indexes, optimize queries, add timeouts |
| Connection leak | Connections not returned to pool | Fix pool return in code, add `pool_pre_ping` |
| Too many workers | Worker count × pool size > max_connections | Reduce pool size per worker or max workers |
| Idle connections | Many idle connections | Reduce `pool_recycle`, enable `idle_in_transaction_session_timeout` |

## Immediate Mitigation

```bash
# Kill idle connections
kubectl exec -n ishastra-system deploy/ishastra-api -- psql "$DATABASE_URL" -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle' AND now() - state_change > interval '5 minutes';
"

# Increase max_connections (requires restart)
kubectl exec -n ishastra-system deploy/postgres -- psql -c "ALTER SYSTEM SET max_connections = 500;"
kubectl rollout restart deployment/postgres -n ishastra-system
```

## Permanent Fix

```yaml
# In values.yaml
api:
  env:
    DATABASE_POOL_SIZE: "10"       # Per API pod
    DATABASE_MAX_OVERFLOW: "5"
    DATABASE_POOL_RECYCLE: "1800"  # 30 minutes
    DATABASE_POOL_PRE_PING: "true"

worker:
  env:
    DATABASE_POOL_SIZE: "5"        # Per worker
    DATABASE_MAX_OVERFLOW: "2"
    DATABASE_POOL_RECYCLE: "1800"
    DATABASE_POOL_PRE_PING: "true"

# PostgreSQL config
postgresql:
  maxConnections: 500
  sharedBuffers: "256MB"
  effectiveCacheSize: "1GB"
```

## Escalation

1. **15 min**: Platform on-call
2. **1 hour**: Platform lead + DBA (if available)

## Post-Incident

- [ ] Review connection pool configuration
- [ ] Add connection count alert at 70% threshold
- [ ] Document root cause
- [ ] Update capacity planning

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Monitoring](../deployment/monitoring.md)
- [API Down Runbook](api-down.md)