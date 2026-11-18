# Strix Upgrade Runbook

## Overview

Step-by-step procedure for upgrading Strix platform with zero-downtime where possible.

**Related Alerts:** None directly, but upgrades may trigger transient alerts

---

## Pre-Upgrade Checklist

### 1. Review Release Notes
- [ ] Read `CHANGELOG.md` for breaking changes
- [ ] Check `UPGRADE.md` for version-specific instructions
- [ ] Verify Python version requirement (3.12+ for v3.5.0)
- [ ] Check dependency updates (FastAPI, Pydantic, Starlette, etc.)
- [ ] Review security advisories for dependencies

### 2. Backup (CRITICAL - Do Not Skip)
```bash
# Database backup
kubectl exec -n strix strix-api-0 -- cp /var/lib/strix/strix.db /var/lib/strix/strix.db.pre-upgrade.$(date +%Y%m%d_%H%M%S)

# Verify backup integrity
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db.pre-upgrade.$(date +%Y%m%d_%H%M%S) "PRAGMA integrity_check;"

# Scope document backup
kubectl get configmap strix-config -n strix -o yaml > /backups/strix-config.$(date +%Y%m%d_%H%M%S).yaml

# Config backup
kubectl get secret strix-secrets -n strix -o yaml > /backups/strix-secrets.$(date +%Y%m%d_%H%M%S).yaml

# Helm values backup
helm get values strix -n strix > /backups/helm-values.$(date +%Y%m%d_%H%M%S).yaml
```

### 3. Check Current Health
```bash
# API health
curl -s http://strix.example.com/api/health | jq .

# Readiness
curl -s http://strix.example.com/api/ready | jq .

# Audit chain
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/audit/verify | jq .

# Queue status
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/status | jq .

# Running jobs (should be 0 for clean upgrade)
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  "http://strix.example.com/api/assess?state=running" | jq 'length'
```

### 4. Schedule Maintenance Window
- [ ] Notify stakeholders (if downtime expected)
- [ ] Check for running jobs - wait for completion or cancel
- [ ] Drain queue if possible (pause new job acceptance)
- [ ] Confirm DR region is healthy (for rollback)

---

## Upgrade Procedures

### Method 1: Blue-Green Deployment (Zero Downtime - RECOMMENDED)

**Prerequisites**: Two namespaces or clusters, load balancer with traffic switching

```bash
# 1. Deploy to green namespace
kubectl create namespace strix-green
helm install strix-green ./deploy/helm/strix -n strix-green \
  -f deploy/helm/strix/values-prod.yaml \
  --set global.image.tag=3.5.1

# 2. Run database migrations (if any)
kubectl exec -n strix-green strix-green-api-0 -- /usr/local/bin/strix migrate

# 3. Start green environment
kubectl rollout status deployment/strix-green-api -n strix-green --timeout=300s
kubectl rollout status deployment/strix-green-scheduler -n strix-green --timeout=300s

# 4. Verify green health
curl -s http://strix-green.strix.internal:8000/api/health
curl -s http://strix-green.strix.internal:8000/api/ready
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix-green.strix.internal:8000/api/audit/verify

# 5. Run smoke tests
kubectl exec -n strix-green strix-green-api-0 -- /usr/local/bin/pytest tests/smoke/ -v

# 6. Switch traffic (update ingress/service)
kubectl patch ingress strix -n strix -p '{"spec":{"rules":[{"host":"strix.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"strix-green-api","port":{"number":8000}}}}]}}]}}'

# 7. Monitor for 15 minutes
watch -n 30 'curl -s http://strix.example.com/api/health'

# 8. Decommission blue after confirmation
helm uninstall strix -n strix
kubectl delete namespace strix  # or scale to 0
```

### Method 2: Rolling Upgrade (Brief Downtime ~30-60s)

**Use when**: Single cluster, acceptable brief downtime, no blue-green setup

```bash
# 1. Pause new job acceptance
curl -X POST http://strix.example.com/api/admin/queue/pause \
  -H "Authorization: Bearer $ADMIN_KEY"

# 2. Wait for running jobs to complete (max STRIX_JOB_TIMEOUT)
# Monitor queue drain
watch -n 10 'curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://strix.example.com/api/monitor/status | jq .queue_depth'

# 3. Scale down to single replica (minimize connections)
kubectl scale deployment strix-api -n strix --replicas=1

# 4. Upgrade Helm release
helm upgrade strix ./deploy/helm/strix -n strix \
  -f deploy/helm/strix/values-prod.yaml \
  --set global.image.tag=3.5.1 \
  --wait --timeout=10m

# 5. Run migrations (if any)
kubectl exec -n strix strix-api-0 -- /usr/local/bin/strix migrate

# 6. Verify health
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready

# 7. Resume queue
curl -X POST http://strix.example.com/api/admin/queue/resume \
  -H "Authorization: Bearer $ADMIN_KEY"

# 8. Scale back up
kubectl scale deployment strix-api -n strix --replicas=3
```

### Method 3: In-Place Upgrade (Development/Staging Only)

```bash
# 1. Update image tag in deployment
kubectl set image deployment/strix-api -n strix \
  strix-api=ghcr.io/your-org/strix:3.5.1

kubectl set image deployment/strix-scheduler -n strix \
  strix-scheduler=ghcr.io/your-org/strix:3.5.1

# 2. Wait for rollout
kubectl rollout status deployment/strix-api -n strix --timeout=300s
kubectl rollout status deployment/strix-scheduler -n strix --timeout=300s

# 3. Run migrations
kubectl exec -n strix strix-api-0 -- /usr/local/bin/strix migrate

# 4. Verify
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready
```

---

## Database Migrations

### Automatic Migrations
Strix uses SQLite with automatic schema evolution via `store.py`. Most upgrades are backward-compatible.

### Manual Migration Steps (If Required)

```bash
# Check current schema version
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "PRAGMA user_version;"

# Run migration script (if provided in release)
kubectl exec -n strix strix-api-0 -- /usr/local/bin/python scripts/migrate_v3_5.py

# Verify
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db "PRAGMA user_version;"
kubectl exec -n strix strix-api-0 -- sqlite3 /var/lib/strix/strix.db ".schema"
```

### Migration Safety
- **Always backup first** (see pre-upgrade checklist)
- **Test on staging with production data copy**
- **Migrations are additive** (no column drops)
- **Audit chain preserved** (HMAC key unchanged)

---

## Configuration Changes

### Breaking Config Changes (Check Release Notes)

| Version | Change | Action Required |
|---------|--------|-----------------|
| 3.4 → 3.5 | Python 3.12+ required | Update base image |
| 3.4 → 3.5 | `starlette>=1.3.1` (CVE fix) | Dependency update |
| 3.4 → 3.5 | `defusedxml` for nuclei | New dependency |
| 3.4 → 3.5 | `STRIX_DISABLE_DOCS` default `false` | Set explicitly if needed |
| 3.4 → 3.5 | OpenTelemetry auto-enabled | Set `OTEL_EXPORTER_OTLP_ENDPOINT` |
| 3.4 → 3.5 | Scheduler: `STRIX_SCHEDULER_ENABLED=true` | Enable if using scheduler |
| 3.4 → 3.5 | Retention: `STRIX_RETENTION_DAYS=90` | Configure retention |
| 3.4 → 3.5 | Webhooks: `STRIX_WEBHOOK_SECRET` required | Set secret |

### Config Validation
```bash
# Test config loads
kubectl exec -n strix strix-api-0 -- /usr/local/bin/python -c "
from strix.config import Settings
s = Settings()
print('Config OK:', s.scope_file, s.db_path)
"
```

---

## Post-Upgrade Verification

### 1. Health Checks
```bash
# All endpoints
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/monitor/status
```

### 2. Functional Tests
```bash
# CLI test
kubectl exec -n strix strix-api-0 -- /usr/local/bin/strix assess --target https://example.com --profile web --wait

# API test
curl -X POST http://strix.example.com/api/assess \
  -H "Authorization: Bearer $TEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web", "wait": true}'

# Scope gate test (should fail)
curl -X POST http://strix.example.com/api/assess \
  -H "Authorization: Bearer $TEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://evil.com", "profile": "web"}'
# Expect 403
```

### 3. Integration Tests
```bash
# Run test suite
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/ -v --tb=short -x

# Key test categories
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/test_scope.py -v
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/test_jobs.py -v
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/test_adapters.py -v
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/test_api.py -v
```

### 4. Monitoring Verification
- [ ] Prometheus metrics scraping: `curl http://strix.example.com/api/metrics`
- [ ] Logs shipping to aggregator
- [ ] Alerts firing correctly (test webhook)
- [ ] Grafana dashboards showing data
- [ ] No new alerts firing from upgrade

---

## Rollback Procedure

### If Upgrade Fails

```bash
# 1. Stop new version
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0

# 2. Restore database from pre-upgrade backup
kubectl exec -n strix strix-api-0 -- cp /var/lib/strix/strix.db.pre-upgrade.* /var/lib/strix/strix.db

# 3. Restore config
kubectl apply -f /backups/strix-config.latest.yaml
kubectl apply -f /backups/strix-secrets.latest.yaml

# 4. Rollback Helm release
helm rollback strix -n strix

# Or reinstall previous version
helm upgrade strix ./deploy/helm/strix -n strix \
  -f /backups/helm-values.latest.yaml \
  --set global.image.tag=3.5.0

# 5. Start old version
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1

# 6. Verify
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify
```

### Rollback Decision Matrix

| Issue | Rollback? |
|-------|-----------|
| Health check fails | Yes |
| Audit chain invalid | Yes (investigate first) |
| Jobs failing new errors | Yes |
| Minor UI bug | No (hotfix) |
| Performance regression | Evaluate |
| Breaking API change | Yes (if not planned) |

---

## Version-Specific Notes

### Upgrading to v3.5.0

**New Requirements:**
- Python 3.12+ (was 3.11)
- `starlette>=1.3.1` (CVE fix)
- `defusedxml` for nuclei XML parsing

**Config Changes:**
- `STRIX_DISABLE_DOCS` now defaults to `false` (was `true`)
- OpenTelemetry auto-enabled when `OTEL_EXPORTER_OTLP_ENDPOINT` set

**New Features Requiring Config:**
- Scheduler: `STRIX_SCHEDULER_ENABLED=true`
- Retention: `STRIX_RETENTION_DAYS=90`
- Webhooks: `STRIX_WEBHOOK_SECRET` required for signatures

---

## Upgrade Checklist Summary

| Phase | Task | Done |
|-------|------|------|
| Pre | Review release notes | ☐ |
| Pre | Backup database | ☐ |
| Pre | Backup scope.json | ☐ |
| Pre | Backup config/secrets | ☐ |
| Pre | Backup Helm values | ☐ |
| Pre | Verify current health | ☐ |
| Pre | Schedule window | ☐ |
| Upgrade | Deploy new version | ☐ |
| Upgrade | Run migrations | ☐ |
| Upgrade | Start service | ☐ |
| Post | Verify health endpoints | ☐ |
| Post | Run functional tests | ☐ |
| Post | Run integration tests | ☐ |
| Post | Verify monitoring | ☐ |
| Post | Smoke test assessment | ☐ |
| Post | Confirm with stakeholders | ☐ |
| Doc | Update version in CMDB | ☐ |
| Doc | Record any issues | ☐ |

---

## Escalation & SLA

| Scenario | Response Time | Escalation |
|----------|---------------|------------|
| Upgrade fails health checks | Immediate rollback | On-call → Platform Lead |
| Migration fails | 30 minutes | On-call → DBA → Platform Lead |
| Post-upgrade issues | 1 hour | On-call → Platform Lead |
| Rollback fails | SEV-1 | On-call → VP Eng |

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Platform Lead: `platform-lead@example.com`
- DBA: `dba@example.com`
- Infrastructure: `infrastructure@example.com`

---

## Grafana Dashboard Links

- **Upgrade Tracking**: `https://grafana.example.com/d/strix-upgrade/upgrade-tracking`
- **Health Overview**: `https://grafana.example.com/d/strix-health/health-overview`

**Key Panels:**
- Deployment Version (stat)
- Health Check Status (table)
- Error Rate Post-Upgrade (time series)
- Job Success Rate (gauge)
- Audit Chain Status (stat)
- Migration Status (table)