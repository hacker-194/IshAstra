# Observability Stack Runbook

## Alert Triggers

| Alert | Severity | Component | Duration |
|-------|----------|-----------|----------|
| `IshAstraPrometheusDown` | critical | Prometheus | 1m |
| `IshAstraAlertmanagerDown` | critical | Alertmanager | 1m |
| `IshAstraGrafanaDown` | warning | Grafana | 1m |
| `IshAstraLokiDown` | warning | Loki | 1m |
| `IshAstraTempoDown` | warning | Tempo | 1m |
| `IshAstraOTelCollectorDown` | warning | OTel Collector | 1m |

---

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   IshAstra     │────▶│ OTel Collector │────▶│  Tempo      │
│   (API)     │     │  (Agent)      │     │  (Traces)   │
└─────────────┘     └─────────────┘     └─────────────┘
       │                    │                    │
       ▼                    ▼                    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Prometheus  │     │    Loki     │     │  Grafana    │
│ (Metrics)   │     │   (Logs)    │     │ (Dashboards)│
└─────────────┘     └─────────────┘     └─────────────┘
       │                    │
       ▼                    ▼
┌─────────────────────────────────────────┐
│           Alertmanager                  │
└─────────────────────────────────────────┘
```

---

## Diagnosis Commands

### 1. Prometheus Issues

```bash
# Check Prometheus pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=prometheus

# Check Prometheus logs
kubectl logs -n monitoring -l app.kubernetes.io/name=prometheus --tail=100

# Check Prometheus config
kubectl get configmap prometheus-config -n monitoring -o yaml

# Check targets
kubectl exec -n monitoring prometheus-0 -- wget -qO- http://localhost:9090/api/v1/targets | jq .

# Check rules
kubectl exec -n monitoring prometheus-0 -- wget -qO- http://localhost:9090/api/v1/rules | jq .

# Check TSDB status
kubectl exec -n monitoring prometheus-0 -- wget -qO- http://localhost:9090/api/v1/status/tsdb | jq .

# Query metrics directly
kubectl exec -n monitoring prometheus-0 -- wget -qO- 'http://localhost:9090/api/v1/query?query=up' | jq .
```

### 2. Alertmanager Issues

```bash
# Check Alertmanager pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=alertmanager

# Check Alertmanager logs
kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager --tail=100

# Check Alertmanager config
kubectl get secret alertmanager-config -n monitoring -o yaml

# Check alerts
kubectl exec -n monitoring alertmanager-0 -- wget -qO- http://localhost:9093/api/v2/alerts | jq .

# Check silences
kubectl exec -n monitoring alertmanager-0 -- wget -qO- http://localhost:9093/api/v2/silences | jq .

# Check notification status
kubectl exec -n monitoring alertmanager-0 -- wget -qO- http://localhost:9093/api/v2/status | jq .
```

### 3. Grafana Issues

```bash
# Check Grafana pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana

# Check Grafana logs
kubectl logs -n monitoring -l app.kubernetes.io/name=grafana --tail=100

# Check Grafana health
kubectl exec -n monitoring grafana-0 -- wget -qO- http://localhost:3000/api/health | jq .

# Check datasources
kubectl exec -n monitoring grafana-0 -- wget -qO- - --header="Authorization: Bearer $GRAFANA_API_KEY" http://localhost:3000/api/datasources | jq .

# Check dashboards
kubectl exec -n monitoring grafana-0 -- wget -qO- - --header="Authorization: Bearer $GRAFANA_API_KEY" http://localhost:3000/api/search | jq .
```

### 4. Loki Issues

```bash
# Check Loki pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=loki

# Check Loki logs
kubectl logs -n monitoring -l app.kubernetes.io/name=loki --tail=100

# Check Loki config
kubectl get configmap loki-config -n monitoring -o yaml

# Check Loki readiness
kubectl exec -n monitoring loki-0 -- wget -qO- http://localhost:3100/ready | jq .

# Query logs
kubectl exec -n monitoring loki-0 -- wget -qO- 'http://localhost:3100/loki/api/v1/query?query={job=~"ishastra.*"}' | jq .

# Check retention
kubectl exec -n monitoring loki-0 -- wget -qO- http://localhost:3100/loki/api/v1/series?match%5B%5D=%7Bjob%3D%22strix%22%7D | jq .
```

### 5. Tempo Issues

```bash
# Check Tempo pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=tempo

# Check Tempo logs
kubectl logs -n monitoring -l app.kubernetes.io/name=tempo --tail=100

# Check Tempo readiness
kubectl exec -n monitoring tempo-0 -- wget -qO- http://localhost:3200/ready | jq .

# Check traces
kubectl exec -n monitoring tempo-0 -- wget -qO- 'http://localhost:3200/api/search?q=service.name%3Dstrix' | jq .
```

### 6. OTel Collector Issues

```bash
# Check OTel Collector pods
kubectl get pods -n monitoring -l app.kubernetes.io/name=otel-collector

# Check OTel Collector logs
kubectl logs -n monitoring -l app.kubernetes.io/name=otel-collector --tail=100

# Check OTel Collector config
kubectl get configmap otel-collector-config -n monitoring -o yaml

# Check OTel Collector metrics
kubectl exec -n monitoring otel-collector-0 -- wget -qO- http://localhost:8888/metrics | grep -E "otelcol|receiver|exporter"

# Check traces received
kubectl exec -n monitoring otel-collector-0 -- wget -qO- http://localhost:8888/metrics | grep "otelcol_receiver_accepted_spans"
```

---

## Resolution Procedures

### Prometheus Down / Issues

#### 1. Prometheus Pod CrashLooping
```bash
# Check previous container logs
kubectl logs -n monitoring prometheus-0 --previous --tail=100

# Common causes:
# - Config syntax error
# - Out of memory (TSDB too large)
# - Disk full
# - Rule evaluation errors

# Fix: Increase resources
kubectl patch statefulset prometheus -n monitoring -p '{"spec":{"template":{"spec":{"containers":[{"name":"prometheus","resources":{"limits":{"memory":"8Gi"}}}]}}}}'

# Fix: Clean up old data (if retention misconfigured)
kubectl exec -n monitoring prometheus-0 -- find /prometheus -type f -mtime +15 -delete
```

#### 2. Prometheus Target Down (IshAstra)
```bash
# Check if IshAstra metrics endpoint accessible
kubectl exec -n monitoring prometheus-0 -- wget -qO- http://ishastra-api.ishastra.svc.cluster.local:8000/api/metrics

# Check ServiceMonitor
kubectl get servicemonitor -n monitoring ishastra-api -o yaml

# Check network policy
kubectl get networkpolicy -n ishastra

# Fix: Ensure ServiceMonitor selector matches
kubectl patch servicemonitor ishastra-api -n monitoring -p '{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"ishastra"}}}}'
```

#### 3. Prometheus Rule Errors
```bash
# Check rule evaluation errors
kubectl exec -n monitoring prometheus-0 -- wget -qO- http://localhost:9090/api/v1/rules | jq '.data.groups[].rules[] | select(.health!="ok")'

# Reload config after fix
kubectl exec -n monitoring prometheus-0 -- wget -qO- --post-data="" http://localhost:9090/-/reload
```

### Alertmanager Down / Issues

#### 1. Alertmanager Not Sending Notifications
```bash
# Check that the config key exists without printing its potentially sensitive contents
kubectl describe secret alertmanager-config -n monitoring

# Test webhook receiver
kubectl exec -n monitoring alertmanager-0 -- wget -qO- --post-data='[{"labels":{"alertname":"TestAlert"},"annotations":{"summary":"Test"}}]' --header="Content-Type: application/json" http://localhost:9093/api/v2/alerts

# Check inhibition rules
kubectl exec -n monitoring alertmanager-0 -- wget -qO- http://localhost:9093/api/v2/status | jq .config.inhibit_rules
```

### Grafana Down / Issues

#### 1. Grafana Pod Not Starting
```bash
# Check logs
kubectl logs -n monitoring grafana-0 --tail=100

# Common causes:
# - Database migration needed
# - Plugin installation failure
# - Config syntax error

# Fix: Enable database migration
kubectl set env deployment/grafana -n monitoring GF_DATABASE_AUTO_MIGRATE=true

# Fix: Reset admin password
kubectl exec -n monitoring grafana-0 -- grafana-cli admin reset-admin-password newpassword
```

#### 2. Dashboards Not Loading
```bash
# Check dashboard provisioning
kubectl get configmap -n monitoring -l grafana_dashboard=1

# Reload dashboards
kubectl exec -n monitoring grafana-0 -- wget -qO- --post-data="" --header="Authorization: Bearer $GRAFANA_API_KEY" http://localhost:3000/api/admin/provisioning/dashboards/reload
```

### Loki Down / Issues

#### 1. Loki Ingestion Failing
```bash
# Check Loki write path
kubectl logs -n monitoring -l app.kubernetes.io/name=loki --tail=100 | grep -i error

# Check promtail (log shipper)
kubectl get pods -n monitoring -l app.kubernetes.io/name=promtail
kubectl logs -n monitoring -l app.kubernetes.io/name=promtail --tail=100

# Check Loki storage
kubectl exec -n monitoring loki-0 -- df -h /loki
```

#### 2. Query Timeout / Slow
```bash
# Check index size
kubectl exec -n monitoring loki-0 -- du -sh /loki/index

# Check chunk storage
kubectl exec -n monitoring loki-0 -- du -sh /loki/chunks

# Optimize: Reduce retention, increase shard size
# Edit loki-config.yaml limits_config
```

### Tempo Down / Issues

#### 1. Traces Not Appearing
```bash
# Check OTel Collector → Tempo connection
kubectl logs -n monitoring -l app.kubernetes.io/name=otel-collector --tail=100 | grep -i tempo

# Check Tempo ingest
kubectl exec -n monitoring tempo-0 -- wget -qO- http://localhost:3200/metrics | grep tempo_distributor_spans_received_total

# Check trace storage
kubectl exec -n monitoring tempo-0 -- du -sh /tempo
```

### OTel Collector Down / Issues

#### 1. Collector Not Receiving Traces
```bash
# Check IshAstra OTel config
kubectl exec -n ishastra ishastra-api-0 -- env | grep OTEL

# Check collector receiver config
kubectl get configmap otel-collector-config -n monitoring -o yaml | grep -A20 "receivers:"

# Test trace export from IshAstra
kubectl exec -n ishastra ishastra-api-0 -- /usr/local/bin/python -c "
from opentelemetry import trace
tracer = trace.get_tracer(__name__)
with tracer.start_as_current_span('test') as span:
    span.set_attribute('test', 'value')
"
```

#### 2. Collector Memory Issues
```bash
# Check memory usage
kubectl top pods -n monitoring -l app.kubernetes.io/name=otel-collector

# Increase batch processor settings
# Edit otel-collector-config.yaml:
# processors:
#   batch:
#     timeout: 10s
#     send_batch_max_size: 1024
```

---

## Common Maintenance Tasks

### Reload Prometheus Config
```bash
kubectl exec -n monitoring prometheus-0 -- wget -qO- --post-data="" http://localhost:9090/-/reload
```

### Reload Alertmanager Config
```bash
kubectl exec -n monitoring alertmanager-0 -- wget -qO- --post-data="" http://localhost:9093/-/reload
```

### Backup Grafana Dashboards
```bash
kubectl exec -n monitoring grafana-0 -- wget -qO- --header="Authorization: Bearer $GRAFANA_API_KEY" http://localhost:3000/api/search | jq -r '.[] | .uid' | while read uid; do
  kubectl exec -n monitoring grafana-0 -- wget -qO- --header="Authorization: Bearer $GRAFANA_API_KEY" "http://localhost:3000/api/dashboards/uid/$uid" > "/backups/grafana-$uid.json"
done
```

### Clean Up Old Metrics/Logs/Traces
```bash
# Prometheus: Configure retention in values.yaml (default 15d)
# Loki: Configure retention in loki-config.yaml (default 30d)
# Tempo: Configure retention in tempo-config.yaml (default 7d)

# Manual cleanup if needed
kubectl exec -n monitoring prometheus-0 -- find /prometheus -type f -mtime +15 -delete
kubectl exec -n monitoring loki-0 -- find /loki -type f -mtime +30 -delete
kubectl exec -n monitoring tempo-0 -- find /tempo -type f -mtime +7 -delete
```

---

## Escalation & SLA

| Component | Severity | Response Time | Escalation |
|-----------|----------|---------------|------------|
| Prometheus | Critical | 15 min | On-call → Platform Lead |
| Alertmanager | Critical | 15 min | On-call → Platform Lead |
| Grafana | Warning | 2 hours | On-call |
| Loki | Warning | 4 hours | On-call |
| Tempo | Warning | 4 hours | On-call |
| OTel Collector | Warning | 2 hours | On-call |

**SLA Targets:**
- Metrics collection: 99.9%
- Alert delivery: < 1 minute
- Log ingestion: 99.5%
- Trace ingestion: 99.5%
- Dashboard availability: 99.9%

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Observability Team: `observability@example.com`
- Infrastructure: `infrastructure@example.com`

---

## Post-Incident Actions

1. **Root Cause Analysis** within 48 hours
2. **Capacity Review** - adjust resource limits
3. **Configuration Audit** - verify all configs in Git
4. **Runbook Update** - document new failure modes
5. **Chaos Testing** - simulate component failures in staging

---

## Grafana Dashboard Links

- **Observability Stack Health**: `https://grafana.example.com/d/observability/stack-health`
- **Prometheus**: `https://grafana.example.com/d/prometheus/prometheus-overview`
- **Loki**: `https://grafana.example.com/d/loki/loki-overview`
- **Tempo**: `https://grafana.example.com/d/tempo/tempo-overview`

**Key Panels:**
- Component Up/Down Status (stat table)
- Ingestion Rate (metrics/logs/traces) (time series)
- Query Latency (time series)
- Resource Usage (CPU/Memory/Disk) (time series)
- Alert Delivery Latency (histogram)
- Retention Compliance (gauge)