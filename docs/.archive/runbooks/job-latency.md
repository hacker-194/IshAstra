# Job Latency Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/ishastra/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `IshastraJobLatencyHigh` | warning | p95 job duration > 300s (5 min) | 5m |
| `IshastraJobLatencyCritical` | critical | p99 job duration > 1800s (30 min) | 2m |

---

## Symptoms & Impact

**Symptoms:**
- Jobs taking significantly longer than expected to complete
- High p95/p99 job duration metrics
- Workers appear busy but throughput is low
- Timeout errors in job logs (`ISHASTRA_JOB_TIMEOUT` exceeded)
- Adapter duration metrics elevated for specific tools

**Impact:**
- **SEV-2**: Assessments exceed SLA turnaround times
- Queue backlog builds up (cascading to queue alerts)
- Resource waste (workers occupied on slow jobs)
- Tenant dissatisfaction with slow results

---

## Diagnosis Commands

### 1. Job Duration Metrics (PromQL)
```promql
# Overall job duration percentiles
histogram_quantile(0.50, sum(rate(strix_job_duration_seconds_bucket[5m])) by (le))
histogram_quantile(0.95, sum(rate(strix_job_duration_seconds_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(strix_job_duration_seconds_bucket[5m])) by (le))

# By tenant
histogram_quantile(0.95, sum(rate(strix_job_duration_seconds_bucket[5m])) by (le, tenant))

# By profile
histogram_quantile(0.95, sum(rate(strix_job_duration_seconds_bucket{profile="web-deep"}[5m])) by (le))

# Job completion rate
sum(rate(strix_jobs_total{state="completed"}[5m])) / sum(rate(strix_jobs_total{state=~"completed|failed"}[5m]))
```

### 2. Adapter-Level Latency
```promql
# Adapter duration by adapter
histogram_quantile(0.95, sum(rate(strix_adapter_duration_seconds_bucket[5m])) by (le, adapter))

# Adapter error rate
sum(rate(strix_adapter_errors_total[5m])) by (adapter) / sum(rate(strix_adapter_duration_seconds_count[5m])) by (adapter)

# Specific adapter timeouts
rate(strix_adapter_timeout_total[5m]) by (adapter)
```

### 3. Kubernetes & Application Logs
```bash
# Check for timeout errors in API logs
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=200 | grep -iE "timeout|duration|slow"

# Check worker logs for adapter timing
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=worker --tail=200 | grep -iE "nmap|nuclei|zap|crawler|duration"

# Check specific slow job logs
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=500 | grep <JOB_ID>

# Resource usage during slow jobs
kubectl top pods -n ishastra -l app.kubernetes.io/name=ishastra --containers
```

### 4. External Tool Performance
```bash
# Test nmap directly
kubectl exec -n ishastra ishastra-api-xxx -- nmap -sS -T4 --max-retries 1 --host-timeout 30s scanme.nmap.org

# Test nuclei
kubectl exec -n ishastra ishastra-api-xxx -- nuclei -target scanme.nmap.org -silent -timeout 30

# Test zap
kubectl exec -n ishastra ishastra-api-xxx -- zap-api-scan.py -t https://scanme.nmap.org -f openapi -r zap-report.html

# Check tool versions
kubectl exec -n ishastra ishastra-api-xxx -- nmap --version
kubectl exec -n ishastra ishastra-api-xxx -- nuclei -version
kubectl exec -n ishastra ishastra-api-xxx -- zap.sh -version
```

---

## Resolution Procedures

### Immediate Mitigation (SEV-2: < 1 hour)

#### Option 1: Increase Job Timeout
```bash
# Temporary increase (requires restart)
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_JOB_TIMEOUT=900
kubectl set env deployment/ishastra-worker -n ishastra ISHASTRA_JOB_TIMEOUT=900
kubectl rollout restart deployment/ishastra-api deployment/ishastra-worker -n ishastra

# Verify
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://ishastra.example.com/api/monitor/status | jq .config.job_timeout
```

#### Option 2: Reduce Profile Scope
```bash
# Switch tenants from web-deep to web profile temporarily
# This requires tenant config update or API parameter override

# Or disable expensive adapters temporarily
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_DISABLE_ADAPTERS="nuclei,zap"
kubectl rollout restart deployment/ishastra-api -n ishastra
```

#### Option 3: Cancel Extremely Slow Jobs
```bash
# Find jobs running > 30 min
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  "http://ishastra.example.com/api/assess?state=running" | \
  jq '.[] | select(.started_at < (now - 1800)) | {id, target, profile, started_at}'

# Cancel them
for job_id in $(...); do
  curl -X POST "http://ishastra.example.com/api/assess/$job_id/cancel" \
    -H "Authorization: Bearer $ADMIN_KEY"
done
```

### Root Cause Resolution

#### Cause 1: Slow External Tools (nmap, nuclei, zap)
```bash
# Check tool performance baselines
# nmap SYN scan: ~10-30s for single host
# nuclei: ~5-30s depending on templates
# zap: ~30-120s for API scan

# Fix: Optimize tool arguments
# nmap: -T4 --max-retries 1 --host-timeout 30s
# nuclei: -timeout 30 -rate-limit 100
# zap: -max_scan_duration_in_mins 5

# Update adapter configs in code or via ConfigMap
kubectl edit configmap ishastra-config -n ishastra
```

#### Cause 2: Resource Contention (CPU/Memory)
```bash
# Check pod resource usage
kubectl top pods -n ishastra -l app.kubernetes.io/name=ishastra

# Check for CPU throttling
kubectl describe pod ishastra-api-xxx -n ishastra | grep -A5 Limits

# Fix: Increase CPU limits
# values.yaml: api.resources.limits.cpu: "4000m"
helm upgrade ishastra ./deploy/helm/ishastra -n ishastra -f values.yaml
```

#### Cause 3: Network Latency to Targets
```bash
# Test connectivity from pod
kubectl exec -n ishastra ishastra-api-xxx -- curl -w "@curl-format.txt" -o /dev/null -s https://target.example.com

# Check DNS resolution time
kubectl exec -n ishastra ishastra-api-xxx -- dig target.example.com

# Fix: Use node-local DNS, optimize network policies
# Check network policy egress rules
kubectl get networkpolicy -n ishastra
```

#### Cause 4: Database Lock Contention
```bash
# Check SQLite busy timeout
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA busy_timeout;"

# Increase busy timeout
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA busy_timeout=30000;"

# Enable WAL mode
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "PRAGMA journal_mode=WAL;"
```

### Recovery Verification
```bash
# Monitor job duration percentiles returning to normal
# PromQL: histogram_quantile(0.95, sum(rate(strix_job_duration_seconds_bucket[5m])) by (le))

# Verify no jobs hitting timeout
# PromQL: rate(strix_jobs_total{state="timeout"}[5m]) == 0

# Check adapter durations normalizing
# PromQL: histogram_quantile(0.95, sum(rate(strix_adapter_duration_seconds_bucket[5m])) by (le, adapter))
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Warning** (High) | 2 hours | On-call engineer |
| **Critical** | 30 minutes | On-call → Platform Lead |

**SLA Targets:**
- Web profile p95 < 60s
- Web-deep profile p95 < 300s
- API-deep profile p95 < 600s
- Job timeout rate < 1%

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Security Tools Team: `sectools@example.com`
- Infrastructure: `infrastructure@example.com`

---

## Post-Incident Actions

1. **Profile benchmark** - re-establish baseline durations
2. **Tool version audit** - check for regressions in nmap/nuclei/zap
3. **Resource sizing review** - adjust CPU/memory based on observed usage
4. **Timeout configuration review** - ensure timeouts match SLA requirements
5. **Add synthetic monitoring** - periodic test scans to detect regressions

---

## Grafana Dashboard Links

- **Ishastra Job Performance**: `https://grafana.example.com/d/ishastra-jobs/job-performance`
- **Adapter Latency Breakdown**: `https://grafana.example.com/d/ishastra-adapters/adapter-latency`
- **Resource Utilization**: `https://grafana.example.com/d/ishastra-resources/resource-utilization`

**Key Panels:**
- Job Duration p50/p95/p99 by Profile (heatmap)
- Adapter Duration by Adapter (time series)
- Job Timeout Rate (stat)
- CPU/Memory per Pod (time series)
- Network Latency to Targets (time series)
