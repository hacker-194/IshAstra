# Ishastra Chaos Engineering & Disaster Recovery Drill

**Version:** 1.0  
**Last updated:** 2026-11-18  
**Frequency:** Monthly (recommended) or before major releases

---

## Purpose

Validate that Ishastra survives infrastructure failures without data loss, maintains audit chain integrity, and recovers automatically within RTO/RPO targets.

---

## Prerequisites

- Staging cluster deployed and healthy
- `kubectl` access to staging namespace (`ishastra-staging`)
- PostgreSQL and Redis managed instances with failover capability
- Grafana/Prometheus alerting configured
- Current backup verified (see `docs/runbooks/backup.md`)

---

## RTO/RPO Targets

| Scenario | RTO (Recovery Time) | RPO (Recovery Point) |
|----------|---------------------|----------------------|
| API pod failure | < 30s (K8s reschedule) | 0 (stateless) |
| Scheduler pod failure | < 30s | 0 (DB-backed) |
| Worker pod failure | < 60s (job requeue) | 0 (idempotent) |
| PostgreSQL failover | < 2min | < 1s (sync replication) |
| Redis failover | < 30s | < 1s (replica) |
| Full cluster loss | < 15min (re-deploy) | Last backup |

---

## Drill Scenarios

### Scenario 1: API Pod Failure (Chaos Mesh / Litmus / Manual)
**Objective:** Verify K8s reschedules pod, health checks pass, no in-flight requests lost

```bash
# 1. Identify API pod
kubectl get pods -n ishastra-staging -l app.kubernetes.io/component=api

# 2. Delete pod (simulates OOM kill, node failure, etc.)
kubectl delete pod -n ishastra-staging <api-pod-name>

# 3. Verify recovery
kubectl rollout status deployment/ishastra-ishastra-api -n ishastra-staging --timeout=2m

# 4. Smoke test
kubectl run smoke-test --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 \
  -- curl -sf https://staging-api.your-domain.com/api/health

# Expected: Pod rescheduled < 30s, health returns 200, no 5xx spike in Grafana
```

**Pass criteria:** 
- [ ] Pod recreated within 30s
- [ ] `/api/health` returns 200 within 60s of deletion
- [ ] No assessment jobs stuck in "running" state
- [ ] Audit chain verifies after recovery (`python scripts/readiness_check.py`)

---

### Scenario 2: Scheduler Pod Failure
**Objective:** Verify scheduled assessments survive scheduler restart

```bash
# 1. Create a scheduled assessment (cron)
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
from ishastra.core.scheduler import create_scheduler
import asyncio
asyncio.run(create_scheduler().add_job(
  'test-scheduled', '0 * * * *',  # hourly
  target='http://httpbin.org/get',
  profile='web',
  options={}
))
"

# 2. Delete scheduler pod
kubectl delete pod -n ishastra-staging -l app.kubernetes.io/component=scheduler

# 3. Verify recovery
kubectl rollout status deployment/ishastra-ishastra-scheduler -n ishastra-staging --timeout=2m

# 4. Verify schedule persisted
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
from ishastra.core.store import get_scheduler
import asyncio
jobs = asyncio.run(get_scheduler().get_jobs())
print([j.id for j in jobs])
"
```

**Pass criteria:**
- [ ] Scheduler pod recreated < 30s
- [ ] Scheduled jobs visible in DB after restart
- [ ] Next scheduled run executes (check `next_run_time`)

---

### Scenario 3: Worker Pod Failure Mid-Assessment
**Objective:** Verify cooperative cancellation + requeue works

```bash
# 1. Start a long-running assessment
JOB_ID=$(curl -s -X POST https://staging-api.your-domain.com/api/assess \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"http://httpbin.org/delay/10","profile":"web-deep"}' | jq -r .job_id)

# 2. Wait for job to reach "running" state
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
from ishastra.core.store import get_assessment
import asyncio
job = asyncio.run(get_assessment('$JOB_ID'))
print(job.state)
" | grep -q running

# 3. Kill worker pod processing this job
WORKER_POD=$(kubectl get pods -n ishastra-staging -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')
kubectl delete pod -n ishastra-staging $WORKER_POD

# 4. Verify job requeued and completes
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
from ishastra.core.store import get_assessment
import asyncio
import time
for _ in range(30):
  job = asyncio.run(get_assessment('$JOB_ID'))
  if job.state in ['completed', 'failed', 'cancelled']:
    print(f'Terminal state: {job.state}')
    break
  time.sleep(2)
"
```

**Pass criteria:**
- [ ] Job moves from "running" → "cancelled" → "queued" → "running" → "completed"
- [ ] No job stuck in "running" > 5min after worker death
- [ ] Audit chain integrity maintained (`python scripts/readiness_check.py`)

---

### Scenario 4: PostgreSQL Failover (Managed Instance)
**Objective:** Verify app survives DB failover with < 1s data loss

**Prerequisite:** PostgreSQL with synchronous replication (RDS Multi-AZ, Cloud SQL HA, Patroni, etc.)

```bash
# 1. Verify current primary
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
import os, asyncpg
conn = asyncpg.connect(os.environ['ISHASTRA_DATABASE_URL'])
print(await conn.fetchval('SELECT pg_is_in_recovery()'))
await conn.close()
"

# 2. Trigger failover (cloud console / CLI / reboot primary)
# AWS RDS: aws rds reboot-db-instance --db-instance-identifier ishastra-staging --force-failover
# GCP Cloud SQL: gcloud sql instances failover ishastra-staging
# Azure: az postgres flexible-server failover --name ishastra-staging

# 3. Verify app recovers (may see brief 500s during failover)
for i in {1..30}; do
  if curl -sf https://staging-api.your-domain.com/api/health >/dev/null; then
    echo "Recovered after ${i} attempts"
    break
  fi
  sleep 2
done

# 4. Verify data integrity
python scripts/readiness_check.py
```

**Pass criteria:**
- [ ] API health returns 200 within 2min of failover initiation
- [ ] No assessment jobs lost (check `state` distribution)
- [ ] Audit chain verifies (`audit chain: ok`)
- [ ] Zero data loss (RPO < 1s with sync replication)

---

### Scenario 5: Redis Failover
**Objective:** Verify rate limiting and caching survive Redis failover

```bash
# 1. Verify Redis connectivity
kubectl exec -n ishastra-staging deploy/ishastra-ishastra-api -- \
  python -c "
import os, redis
r = redis.from_url(os.environ['ISHASTRA_REDIS_URL'])
print(r.ping())
"

# 2. Trigger failover (cloud console / CLI)
# AWS ElastiCache: AWS console → failover
# GCP Memorystore: gcloud redis instances failover ishastra-staging
# Azure: az redis force-reboot --name ishastra-staging --reboot-type PrimaryNode

# 3. Verify rate limiting still works
for i in {1..15}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $API_KEY" \
    https://staging-api.your-domain.com/api/health
done
# Should see 10x 200, then 429 (rate limit)

# 4. Verify recovery
sleep 10
curl -sf https://staging-api.your-domain.com/api/health
```

**Pass criteria:**
- [ ] Rate limiting resumes within 30s
- [ ] No permanent 500 errors
- [ ] Assessment queue continues processing

---

### Scenario 6: Full Cluster Loss (Disaster Recovery)
**Objective:** Verify complete redeployment from backup

```bash
# 1. Take current backup
python scripts/operational_check.py --db ishastra.db --out /tmp/dr-backup.db

# 2. Simulate cluster loss: delete namespace
kubectl delete namespace ishastra-staging --wait=false

# 3. Wait for namespace deletion
kubectl wait --for=delete namespace/ishastra-staging --timeout=5m

# 4. Recreate namespace and prerequisites
kubectl create namespace ishastra-staging
# Re-apply secrets (ExternalSecrets/SealedSecrets)
# Re-apply PostgreSQL/Redis secrets manually if needed

# 5. Deploy from Helm (uses same tag)
helm upgrade --install ishastra-staging ./deploy/helm/ishastra \
  -n ishastra-staging \
  -f ./deploy/helm/ishastra/values-staging.yaml \
  --set-string "global.image.repository=ghcr.io/your-org/ishastra" \
  --set-string "global.image.tag=sha-<LAST_GREEN_SHA>" \
  --wait --timeout 10m

# 6. Restore database from backup
# (Assumes PostgreSQL backup/restore process documented in runbooks/restore.md)

# 7. Verify full functionality
python scripts/readiness_check.py

# 8. Run smoke tests
kubectl run smoke-test --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 \
  -- curl -sf https://staging-api.your-domain.com/api/health
```

**Pass criteria:**
- [ ] Full redeploy + restore < 15min
- [ ] All 23 readiness checks pass
- [ ] Audit chain verifies after restore
- [ ] Assessment history intact

---

## Running the Full Drill Suite

```bash
# Automated runner (creates results JSON)
python scripts/chaos_drill.py --namespace ishastra-staging --output drill-results-$(date +%Y%m%d).json
```

**Expected runtime:** 45-60 minutes for all 6 scenarios

---

## Results Template

| Scenario | Date | Duration | Pass/Fail | Notes |
|----------|------|----------|-----------|-------|
| 1. API Pod Failure | | | | |
| 2. Scheduler Pod Failure | | | | |
| 3. Worker Pod Failure | | | | |
| 4. PostgreSQL Failover | | | | |
| 5. Redis Failover | | | | |
| 6. Full DR | | | | |

---

## Post-Drill Actions

1. **Document failures** in GitHub issue with `chaos-drill` label
2. **Update runbooks** if recovery procedures need adjustment
3. **Tune timeouts/thresholds** in Helm values if RTO not met
4. **Alert on-call** if any scenario fails
5. **Schedule next drill** (monthly)

---

## Related Runbooks

- `docs/runbooks/backup.md` — Backup procedures
- `docs/runbooks/restore.md` — Restore procedures  
- `docs/runbooks/failover.md` — PostgreSQL/Redis failover
- `docs/runbooks/incident-response.md` — General incident response
- `docs/runbooks/disaster-recovery.md` — Full DR procedure

---

*Next review: 2026-12-18*