# Adapter Errors Runbook

> **Metric note (verified 2026-11-17):** every `strix_*` series this page queries
> is defined in `src/ishastra/metrics.py` and has a data source.
> `strix_queue_depth` and `strix_worker_*` publish in `inprocess` queue mode only.


## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `IshastraAdapterSuccessRateLow` | warning | Success rate < 95% | 5m |
| `IshastraAdapterSuccessRateCritical` | critical | Success rate < 90% | 2m |

---

## Symptoms & Impact

**Symptoms:**
- High `strix_adapter_errors_total` rate for specific adapter
- Findings missing or incomplete for affected adapter
- Job logs show repeated adapter failures
- Adapter duration metrics may show timeouts or very short durations (fast failures)

**Impact:**
- **SEV-2**: Incomplete assessment coverage (missing vulnerability classes)
- False negatives in security findings
- Tenant reports of "scan completed but no results"
- Compliance gaps if required adapters fail

---

## Diagnosis Commands

### 1. Adapter Metrics (PromQL)
```promql
# Adapter success rate by adapter
1 - (sum(rate(strix_adapter_errors_total[5m])) by (adapter) / sum(rate(strix_adapter_duration_seconds_count[5m])) by (adapter))

# Error count by adapter and error type
sum(rate(strix_adapter_errors_total[5m])) by (adapter, error_type)

# Adapter duration percentiles
histogram_quantile(0.95, sum(rate(strix_adapter_duration_seconds_bucket[5m])) by (le, adapter))

# Timeout rate
rate(strix_adapter_timeout_total[5m]) by (adapter)
```

### 2. Application Logs
```bash
# Check API logs for adapter errors
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=200 | grep -iE "adapter|nmap|nuclei|zap|crawler" | grep -iE "error|fail|timeout|exception"

# Check worker logs (if using Kubernetes Jobs)
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=worker --tail=200 | grep -iE "adapter|nmap|nuclei|zap|crawler" | grep -iE "error|fail|timeout|exception"

# Filter by specific adapter
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=500 | grep "nuclei" | grep -i error
```

### 3. Test Adapters Directly
```bash
# Test nmap adapter
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -c "
from ishastra.adapters.nmap import NmapAdapter
a = NmapAdapter()
result = a.run('scanme.nmap.org', {'ports': 'top-100'})
print(result)
"

# Test nuclei adapter
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -c "
from ishastra.adapters.nuclei import NucleiAdapter
a = NucleiAdapter()
result = a.run('https://scanme.nmap.org', {})
print(result)
"

# Test zap adapter
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -c "
from ishastra.adapters.zap import ZapAdapter
a = ZapAdapter()
result = a.run('https://scanme.nmap.org', {})
print(result)
"
```

### 4. Tool Availability & Versions
```bash
# Check if tools are installed and working
kubectl exec -n ishastra ishastra-api-xxx -- which nmap nuclei zap.sh python3

# Check versions
kubectl exec -n ishastra ishastra-api-xxx -- nmap --version
kubectl exec -n ishastra ishastra-api-xxx -- nuclei -version
kubectl exec -n ishastra ishastra-api-xxx -- zap.sh -version 2>&1 | head -5

# Check tool paths in config
kubectl exec -n ishastra ishastra-api-xxx -- cat /etc/ishastra/adapters.yaml 2>/dev/null || echo "Config not found"
```

### 5. Resource & Dependency Checks
```bash
# Check disk space (tools need temp space)
kubectl exec -n ishastra ishastra-api-xxx -- df -h /tmp

# Check memory (zap especially memory hungry)
kubectl exec -n ishastra ishastra-api-xxx -- free -h

# Check network connectivity for nuclei templates
kubectl exec -n ishastra ishastra-api-xxx -- curl -s -o /dev/null -w "%{http_code}" https://github.com/projectdiscovery/nuclei-templates

# Check for missing dependencies
kubectl exec -n ishastra ishastra-api-xxx -- pip list | grep -iE "nmap|nuclei|zap|defusedxml"
```

---

## Resolution Procedures

### Immediate Mitigation (SEV-2: < 1 hour)

#### Option 1: Disable Failing Adapter Temporarily
```bash
# Disable specific adapter via env var
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_DISABLE_ADAPTERS="nuclei"
kubectl set env deployment/ishastra-worker -n ishastra ISHASTRA_DISABLE_ADAPTERS="nuclei"
kubectl rollout restart deployment/ishastra-api deployment/ishastra-worker -n ishastra

# Verify disabled
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
  http://ishastra.example.com/api/monitor/status | jq .enabled_adapters
```

#### Option 2: Restart Pods to Clear Transient State
```bash
# Rolling restart to clear any stuck processes
kubectl rollout restart deployment/ishastra-api -n ishastra
kubectl rollout restart deployment/ishastra-worker -n ishastra  # if exists
```

#### Option 3: Increase Adapter Timeouts
```bash
# Increase adapter-specific timeouts
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_ADAPTER_TIMEOUT_NUCLEI=300
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_ADAPTER_TIMEOUT_ZAP=600
kubectl rollout restart deployment/ishastra-api -n ishastra
```

### Root Cause Resolution

#### Cause 1: Tool Not Installed / Version Mismatch
```bash
# Reinstall tools in container (requires image rebuild)
# Dockerfile: RUN apt-get update && apt-get install -y nmap
#            RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#            RUN pip install zaproxy

# Or update tool versions in base image
# Rebuild and redeploy
docker build -t ghcr.io/your-org/ishastra:3.5.1 .
helm upgrade ishastra ./deploy/helm/ishastra -n ishastra --set global.image.tag=3.5.1
```

#### Cause 2: Nuclei Template Issues
```bash
# Check template installation in the running image
kubectl exec -n ishastra deploy/ishastra-api -- nuclei -tl | head

# The weekly nuclei-template-refresh workflow publishes an image with refreshed
# templates. Review the build, then roll out its immutable digest in production.
helm upgrade ishastra ./deploy/helm/ishastra -n ishastra \
  --set global.image.repository=ghcr.io/OWNER/REPOSITORY \
  --set global.image.tag=nuclei-templates-latest
```

The rolling tag is for controlled refreshes, not a production pin. Resolve and
deploy the published image digest after reviewing the workflow run; do not
delete templates from a live container or install them as root.

#### Cause 3: ZAP Memory/Startup Issues
```bash
# Check ZAP heap size
kubectl exec -n ishastra ishastra-api-xxx -- ps aux | grep zap

# Increase ZAP memory
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_ZAP_HEAP_SIZE=2g
kubectl rollout restart deployment/ishastra-api -n ishastra

# Check ZAP daemon mode
kubectl exec -n ishastra ishastra-api-xxx -- zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
```

#### Cause 4: Network/Dependency Failures
```bash
# Check egress connectivity
kubectl exec -n ishastra ishastra-api-xxx -- curl -v https://api.github.com/repos/projectdiscovery/nuclei-templates

# Fix network policy if blocking
kubectl edit networkpolicy ishastra-api-egress -n ishastra

# Check DNS
kubectl exec -n ishastra ishastra-api-xxx -- nslookup github.com
```

#### Cause 5: Permission/Filesystem Issues
```bash
# Check temp directory permissions
kubectl exec -n ishastra ishastra-api-xxx -- ls -la /tmp

# Check read-only root filesystem
kubectl exec -n ishastra ishastra-api-xxx -- touch /test_write 2>&1

# Fix: Ensure emptyDir volume mounted at /tmp
# Check pod spec: volumes.ishastra-tmp.mountPath: /tmp
```

### Recovery Verification
```bash
# Monitor adapter success rate recovery
# PromQL: 1 - (sum(rate(strix_adapter_errors_total[5m])) by (adapter) / sum(rate(strix_adapter_duration_seconds_count[5m])) by (adapter)) > 0.95

# Verify findings being generated
# PromQL: rate(strix_findings_total{adapter="nuclei"}[5m]) > 0

# Re-enable adapter if disabled
kubectl set env deployment/ishastra-api -n ishastra ISHASTRA_DISABLE_ADAPTERS=""
kubectl rollout restart deployment/ishastra-api -n ishastra
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Warning** (Low) | 4 hours | On-call engineer |
| **Critical** | 1 hour | On-call → Security Tools Lead |

**SLA Targets:**
- Adapter success rate > 99% for core adapters (nmap, crawler)
- Adapter success rate > 95% for extended adapters (nuclei, zap)
- Tool update frequency: weekly for nuclei templates

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Security Tools Team: `sectools@example.com`
- DevOps: `devops@example.com`

---

## Post-Incident Actions

1. **Tool version pinning** - lock versions in Dockerfile
2. **Template update automation** - scheduled nuclei template updates
3. **Adapter health checks** - add startup probes for each adapter
4. **Chaos testing** - simulate tool failures in staging
5. **Documentation update** - record adapter-specific failure modes

---

## Grafana Dashboard Links

- **Ishastra Adapter Health**: `https://grafana.example.com/d/ishastra-adapters/adapter-health`
- **Adapter Latency**: `https://grafana.example.com/d/ishastra-adapters/adapter-latency`

**Key Panels:**
- Adapter Success Rate by Adapter (time series)
- Adapter Error Count by Type (bar chart)
- Adapter Duration p50/p95/p99 (heatmap)
- Findings per Adapter (time series)
- Tool Version Info (table)
