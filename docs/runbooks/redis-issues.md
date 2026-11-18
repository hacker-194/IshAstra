# Redis Issues Runbook

## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `StrixRedisDown` | critical | Redis up == 0 | 1m |
| `KubePodOOMKilled` (Redis pod) | critical | OOMKilled == 1 | 1m |
| `KubeNodeMemoryPressure` | critical | MemoryPressure == 1 | 5m |

---

## Symptoms & Impact

**Symptoms:**
- Rate limiting fails (open or closed depending on `STRIX_REDIS_REQUIRED`)
- Scheduler fails to start (leader election)
- Distributed locks fail (duplicate scheduled scans)
- Celery queue unavailable (if using Celery workers)
- `redis-cli ping` returns error or times out
- High Redis memory usage / eviction

**Impact:**
- **SEV-2** (Redis down, `STRIX_REDIS_REQUIRED=true`): Rate limiting, scheduling, distributed queue all fail
- **SEV-3** (Redis down, `STRIX_REDIS_REQUIRED=false`): Falls back to in-memory, single-instance only
- **SEV-2** (OOM/Memory pressure): Evictions cause rate limit resets, lock loss

---

## Diagnosis Commands

### 1. Redis Health Checks
```bash
# Basic connectivity
kubectl exec -n strix redis-master-0 -- redis-cli ping

# Check Redis info
kubectl exec -n strix redis-master-0 -- redis-cli INFO
kubectl exec -n strix redis-master-0 -- redis-cli INFO memory
kubectl exec -n strix redis-master-0 -- redis-cli INFO replication
kubectl exec -n strix redis-master-0 -- redis-cli INFO persistence

# Check connected clients
kubectl exec -n strix redis-master-0 -- redis-cli CLIENT LIST

# Check slow log
kubectl exec -n strix redis-master-0 -- redis-cli SLOWLOG GET 20
```

### 2. Kubernetes Redis Status
```bash
# Check Redis pod status
kubectl get pods -n strix -l app.kubernetes.io/name=redis

# Check Redis pod logs
kubectl logs -n strix redis-master-0 --tail=100
kubectl logs -n strix redis-replica-0 --tail=100  # if replication

# Check Redis resources
kubectl top pods -n strix -l app.kubernetes.io/name=redis

# Check PVC
kubectl get pvc -n strix -l app.kubernetes.io/name=redis
```

### 3. Application-Level Redis Checks
```bash
# Test from Strix API pod
kubectl exec -n strix strix-api-xxx -- redis-cli -u redis://redis-master:6379/0 ping

# Check rate limiter keys
kubectl exec -n strix redis-master-0 -- redis-cli -n 0 KEYS "ratelimit:*" | head -20
kubectl exec -n strix redis-master-0 -- redis-cli -n 0 DBSIZE

# Check scheduler locks
kubectl exec -n strix redis-master-0 -- redis-cli -n 0 KEYS "scheduler:lock:*"

# Check Celery queue (if used)
kubectl exec -n strix redis-master-0 -- redis-cli -n 1 LLEN celery
kubectl exec -n strix redis-master-0 -- redis-cli -n 1 KEYS "*" | head -20
```

### 4. Redis Metrics (PromQL)
```promql
# Redis up
up{job="redis"}

# Memory usage
redis_memory_used_bytes / redis_memory_max_bytes

# Connected clients
redis_connected_clients

# Commands per second
rate(redis_commands_processed_total[5m])

# Keyspace hits/misses
rate(redis_keyspace_hits_total[5m]) / (rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m]))

# Replication lag (if replica)
redis_replication_lag_seconds
```

---

## Resolution Procedures

### Immediate Mitigation

#### Redis Down - Single Instance
```bash
# 1. Check pod status
kubectl get pods -n strix redis-master-0

# 2. If CrashLoopBackOff, check logs
kubectl logs -n strix redis-master-0 --previous --tail=50

# 3. Restart Redis pod
kubectl delete pod -n strix redis-master-0

# 4. If PVC issue, check storage
kubectl describe pvc -n strix redis-data-redis-master-0

# 5. Verify recovery
kubectl exec -n strix redis-master-0 -- redis-cli ping
```

#### Redis Down - Replication Mode
```bash
# 1. Check master/replica status
kubectl exec -n strix redis-master-0 -- redis-cli INFO replication
kubectl exec -n strix redis-replica-0 -- redis-cli INFO replication

# 2. If master down, promote replica
kubectl exec -n strix redis-replica-0 -- redis-cli REPLICAOF NO ONE

# 3. Update service to point to new master
kubectl patch svc redis-master -n strix -p '{"spec":{"selector":{"statefulset.kubernetes.io/pod-name":"redis-replica-0"}}}'

# 4. Recreate old master as replica
# (Handled by Redis operator/bitnami chart automatically)
```

#### Redis OOM / Memory Pressure
```bash
# 1. Check memory usage
kubectl exec -n strix redis-master-0 -- redis-cli INFO memory

# 2. Check eviction policy
kubectl exec -n strix redis-master-0 -- redis-cli CONFIG GET maxmemory-policy

# 3. Set appropriate eviction policy (allkeys-lru for rate limiting)
kubectl exec -n strix redis-master-0 -- redis-cli CONFIG SET maxmemory-policy allkeys-lru

# 4. Increase memory limit (requires pod restart)
# Edit values.yaml: redis.master.resources.limits.memory: "1Gi"
helm upgrade strix ./deploy/helm/strix -n strix -f values.yaml

# 5. Flush non-critical keys if emergency
# WARNING: This resets rate limits!
kubectl exec -n strix redis-master-0 -- redis-cli -n 0 FLUSHDB
```

#### Redis Persistence Issues
```bash
# Check AOF/RDB status
kubectl exec -n strix redis-master-0 -- redis-cli INFO persistence

# Force AOF rewrite
kubectl exec -n strix redis-master-0 -- redis-cli BGREWRITEAOF

# Check last save
kubectl exec -n strix redis-master-0 -- redis-cli LASTSAVE

# Trigger manual save
kubectl exec -n strix redis-master-0 -- redis-cli BGSAVE
```

### Root Cause Resolution

#### Network Policy Blocking Redis
```bash
# Check network policy
kubectl get networkpolicy -n strix

# Allow Strix pods to connect to Redis
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: strix-to-redis
  namespace: strix
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: redis
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: strix
    ports:
    - protocol: TCP
      port: 6379
EOF
```

#### Authentication Issues
```bash
# Check Redis password in secret
kubectl get secret strix-redis-secret -n strix -o jsonpath='{.data.redis-password}' | base64 -d

# Verify Strix config matches
kubectl exec -n strix strix-api-xxx -- env | grep STRIX_REDIS

# Test with password
kubectl exec -n strix strix-api-xxx -- redis-cli -a "$REDIS_PASSWORD" ping
```

#### Clock Skew (Rate Limiter Issues)
```bash
# Check time sync on Redis node
kubectl exec -n strix redis-master-0 -- date

# Check time sync on Strix pods
kubectl exec -n strix strix-api-xxx -- date

# Fix: Ensure NTP running on all nodes
# Check chrony/systemd-timesyncd status
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Redis Down (SEV-2)** | 15 minutes | On-call → Infrastructure |
| **OOM/Memory (SEV-2)** | 30 minutes | On-call → Infrastructure |
| **Performance (SEV-3)** | 2 hours | On-call |

**SLA Targets:**
- Redis availability: 99.95%
- p99 latency < 5ms
- Memory usage < 80% of limit
- Replication lag < 1s

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Infrastructure: `infrastructure@example.com`
- DBA: `dba@example.com`

---

## Post-Incident Actions

1. **Memory sizing review** - adjust based on peak usage
2. **Persistence configuration review** - AOF vs RDB tradeoffs
3. **High availability validation** - test failover
4. **Backup/restore test** - verify RDB/AOF recovery
5. **Monitoring enhancement** - add key expiration metrics

---

## Grafana Dashboard Links

- **Redis Overview**: `https://grafana.example.com/d/redis/redis-overview`
- **Redis Memory**: `https://grafana.example.com/d/redis/redis-memory`

**Key Panels:**
- Redis Memory Usage (gauge + time series)
- Connected Clients (time series)
- Commands/sec (time series)
- Hit Rate (gauge)
- Replication Lag (time series)
- Persistence Status (table)
- Key Count by DB (bar chart)