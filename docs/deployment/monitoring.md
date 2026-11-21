# Monitoring & Observability

# Monitoring & Observability

Complete monitoring stack for Ishastra deployments.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Monitoring Stack                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │  Ishastra Pods  │───▶│  Prometheus  │───▶│  Alertmanager│───▶│  PagerDuty│  │
│  │  /metrics    │    │  (scrape)    │    │  (route)     │    │  / Slack │  │
│  └──────────────┘    └──────┬───────┘    └──────────────┘    └──────────┘  │
│                             │                                               │
│                    ┌────────▼────────┐    ┌──────────────┐                 │
│                    │   Grafana       │    │   Loki       │                 │
│                    │   (dashboards)  │    │   (logs)     │                 │
│                    └─────────────────┘    └──────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prometheus Configuration

### ServiceMonitor (Auto-created by Helm)

```yaml
# monitoring/prometheus/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ishastra-api
  namespace: ishastra-system
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: ishastra-api
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
    - ishastra-system
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ishastra-worker
  namespace: ishastra-system
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: ishastra-worker
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
  namespaceSelector:
    matchNames:
    - ishastra-system
```

### PrometheusRule (Alerts)

```yaml
# monitoring/prometheus/prometheusrule.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ishastra-alerts
  namespace: ishastra-system
  labels:
    release: prometheus
spec:
  groups:
  - name: ishastra.rules
    rules:
    # API Availability
    - alert: IshastraAPIDown
      expr: up{job="ishastra-api",namespace="ishastra-system"} == 0
      for: 2m
      labels:
        severity: critical
        team: platform
      annotations:
        summary: "Ishastra API is down"
        description: "API pod {{ $labels.pod }} has been down for 2 minutes"
        runbook_url: "https://docs.ishastra.dev/runbooks/api-down"

    - alert: IshastraAPIHighLatency
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="ishastra-api"}[5m])) > 2
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High API latency (p95 > 2s)"
        description: "p95 latency is {{ $value }}s"

    # Scope Gate
    - alert: IshastraScopeGateDenialsHigh
      expr: rate(scope_gate_denials_total{namespace="ishastra-system"}[5m]) > 10
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High Scope Gate denial rate"
        description: "{{ $value }} denials/sec - possible misconfigured scope"

    - alert: IshastraScopeGateResolutionFailures
      expr: rate(scope_gate_resolution_failures_total[5m]) > 5
      for: 2m
      labels:
        severity: critical
      annotations:
        summary: "DNS resolution failures in Scope Gate"
        description: "{{ $value }} failures/sec - check DNS config"

    # Assessment Queue
    - alert: IshastraQueueDepthHigh
      expr: strix_queue_depth > 1000
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "Assessment queue backing up"
        description: "Queue depth: {{ $value }} - consider scaling workers"

    - alert: IshastraQueueProcessingSlow
      expr: rate(strix_assessment_duration_seconds_sum[5m]) / rate(strix_assessment_duration_seconds_count[5m]) > 600
      for: 15m
      labels:
        severity: warning
      annotations:
        summary: "Assessments taking too long"
        description: "Avg duration: {{ $value }}s"

    # Worker Health
    - alert: IshastraWorkerDown
      expr: up{job="ishastra-worker",namespace="ishastra-system"} == 0
      for: 3m
      labels:
        severity: critical
      annotations:
        summary: "Ishastra Worker down"
        description: "Worker pod {{ $labels.pod }} down for 3 minutes"

    - alert: IshastraWorkerOOMKilled
      expr: increase(container_oom_kills_total{namespace="ishastra-system",container="worker"}[10m]) > 0
      labels:
        severity: critical
      annotations:
        summary: "Worker OOM killed"
        description: "Worker {{ $labels.pod }} was OOM killed - increase memory limit"

    # Scheduler
    - alert: IshastraSchedulerDown
      expr: up{job="ishastra-scheduler",namespace="ishastra-system"} == 0
      for: 2m
      labels:
        severity: critical
      annotations:
        summary: "Ishastra Scheduler down"
        description: "Scheduler pod {{ $labels.pod }} down"

    - alert: IshastraSchedulerLeaderElectionFailures
      expr: rate(strix_scheduler_leader_election_failures_total[5m]) > 0.1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Scheduler not running or stalled"
        description: "Frequent leader changes detected"

    # Database
    - alert: IshastraDatabaseConnectionsHigh
      expr: pg_stat_activity_count / pg_settings_max_connections > 0.8
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Database connections near limit"
        description: "{{ $value | humanizePercentage }} of max connections used"

    - alert: IshastraDatabaseReplicationLag
      expr: pg_replication_lag_seconds > 30
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Database replication lag"
        description: "Replica lag: {{ $value }}s"

    # Redis
    - alert: IshastraRedisMemoryHigh
      expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.85
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Redis memory usage high"
        description: "{{ $value | humanizePercentage }} of max memory used"

    - alert: IshastraRedisDown
      expr: up{job="redis",namespace="ishastra-system"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Redis is down"
        description: "Redis pod {{ $labels.pod }} down"

    # Kubernetes
    - alert: IshastraPodNotReady
      expr: kube_pod_status_ready{namespace="ishastra-system",condition="true"} == 0
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Pod not ready"
        description: "Pod {{ $labels.pod }} not ready for 5 minutes"

    - alert: IshastraHPAReplicasMaxed
      expr: kube_horizontalpodautoscaler_status_desired_replicas{namespace="ishastra-system"} == kube_horizontalpodautoscaler_spec_max_replicas{namespace="ishastra-system"}
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "HPA at max replicas"
        description: "{{ $labels.horizontalpodautoscaler }} at max ({{ $value }}) - check if scaling is working"

    # Certificates
    - alert: IshastraCertExpiringSoon
      expr: certmanager_certificate_expiration_timestamp_seconds - time() < 86400 * 30
      for: 1h
      labels:
        severity: warning
      annotations:
        summary: "TLS certificate expiring in 30 days"
        description: "Certificate {{ $labels.certificate }} expires {{ $value | humanizeDuration }}"
```

## Grafana Dashboards

### Import Dashboards

```bash
# Import from deploy/monitoring/grafana/dashboards/
# Dashboard IDs: 1860, 1861, 1862, 1863
```

### Ishastra Overview Dashboard

```json
{
  "title": "Ishastra Overview",
  "panels": [
    {
      "title": "API Request Rate",
      "type": "graph",
      "targets": [
        {"expr": "rate(http_requests_total{job=\"ishastra-api\"}[5m])", "legendFormat": "{{method}} {{handler}}"}
      ]
    },
    {
      "title": "API Latency (p50, p95, p99)",
      "type": "graph",
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket{job=\"ishastra-api\"}[5m]))", "legendFormat": "p50"},
        {"expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"ishastra-api\"}[5m]))", "legendFormat": "p95"},
        {"expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job=\"ishastra-api\"}[5m]))", "legendFormat": "p99"}
      ]
    },
    {
      "title": "Scope Gate Decisions",
      "type": "graph",
      "targets": [
        {"expr": "rate(scope_gate_decisions_total{decision=\"allow\"}[5m])", "legendFormat": "Allow"},
        {"expr": "rate(scope_gate_decisions_total{decision=\"deny\"}[5m])", "legendFormat": "Deny"},
        {"expr": "rate(scope_gate_decisions_total{decision=\"defer\"}[5m])", "legendFormat": "Defer"}
      ]
    },
    {
      "title": "Assessment Queue Depth",
      "type": "graph",
      "targets": [
        {"expr": "strix_queue_depth", "legendFormat": "Queue Depth"}
      ]
    },
    {
      "title": "Assessment Rate",
      "type": "graph",
      "targets": [
        {"expr": "rate(strix_assessments_started_total[5m])", "legendFormat": "Started"},
        {"expr": "rate(strix_assessments_completed_total[5m])", "legendFormat": "Completed"},
        {"expr": "rate(strix_assessments_failed_total[5m])", "legendFormat": "Failed"}
      ]
    },
    {
      "title": "Worker Pool",
      "type": "graph",
      "targets": [
        {"expr": "kube_pod_info{namespace=\"ishastra-system\",app=\"ishastra-worker\"}", "legendFormat": "Workers"}
      ]
    }
  ]
}
```

### Scope Gate Dashboard

```json
{
  "title": "Ishastra Scope Gate",
  "panels": [
    {
      "title": "Layer 1 Decisions (URL/Host)",
      "type": "piechart",
      "targets": [
        {"expr": "scope_gate_layer1_allow_total", "legendFormat": "Allow"},
        {"expr": "scope_gate_layer1_deny_total", "legendFormat": "Deny"}
      ]
    },
    {
      "title": "Layer 2 Decisions (DNS/IP)",
      "type": "piechart",
      "targets": [
        {"expr": "scope_gate_layer2_allow_total", "legendFormat": "Allow"},
        {"expr": "scope_gate_layer2_deny_total", "legendFormat": "Deny"}
      ]
    },
    {
      "title": "Layer 3 Pinning",
      "type": "graph",
      "targets": [
        {"expr": "rate(scope_gate_pinned_destinations_total[5m])", "legendFormat": "Pinned"}
      ]
    },
    {
      "title": "DNS Cache Hit Rate",
      "type": "gauge",
      "targets": [
        {"expr": "scope_gate_dns_cache_hits / (scope_gate_dns_cache_hits + scope_gate_dns_cache_misses)"}
      ]
    },
    {
      "title": "Break Glass Activations",
      "type": "stat",
      "targets": [
        {"expr": "strix_break_glass_active_total", "legendFormat": "Active"}
      ]
    }
  ]
}
```

## Loki Logging

### Promtail Configuration

```yaml
# monitoring/loki/promtail.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: promtail-config
  namespace: monitoring
data:
  promtail.yaml: |
    server:
      http_listen_port: 9080
      grpc_listen_port: 0
    positions:
      filename: /tmp/positions.yaml
    clients:
      - url: http://loki:3100/loki/api/v1/push
    scrape_configs:
    - job_name: ishastra
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
          - ishastra-system
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: ishastra-(api|worker|scheduler)
      - source_labels: [__meta_kubernetes_pod_name]
        target_label: pod
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
      - source_labels: [__meta_kubernetes_pod_label_app]
        target_label: app
```

### Log Queries

```logql
# All Ishastra logs
{namespace="ishastra-system", app=~"ishastra-.*"}

# API errors
{namespace="ishastra-system", app="ishastra-api"} |= "ERROR"

# Scope Gate denials
{namespace="ishastra-system", app=~"ishastra-.*"} |= "DENIED" | json

# Assessment failures
{namespace="ishastra-system", app="ishastra-worker"} |= "FAILED" | json

# Break Glass events
{namespace="ishastra-system"} |= "break_glass" | json

# Slow requests (>5s)
{namespace="ishastra-system", app="ishastra-api"} | json | duration > 5000000000
```

## Key Metrics Reference

### API Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests by method, handler, status |
| `http_request_duration_seconds` | Histogram | Request latency |
| `http_request_size_bytes` | Histogram | Request body size |
| `http_response_size_bytes` | Histogram | Response body size |

### Scope Gate Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `scope_gate_decisions_total` | Counter | Layer 1/2/3 decisions (allow/deny/defer) |
| `scope_gate_layer1_allow_total` | Counter | Layer 1 allows |
| `scope_gate_layer1_deny_total` | Counter | Layer 1 denials |
| `scope_gate_layer2_allow_total` | Counter | Layer 2 allows |
| `scope_gate_layer2_deny_total` | Counter | Layer 2 denials |
| `scope_gate_pinned_destinations_total` | Counter | Layer 3 pins |
| `scope_gate_denials_total` | Counter | Total denials |
| `scope_gate_resolution_failures_total` | Counter | DNS resolution failures |
| `scope_gate_dns_cache_hits` | Counter | DNS cache hits |
| `scope_gate_dns_cache_misses` | Counter | DNS cache misses |

### Assessment Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `strix_queue_depth` | Gauge | Pending assessments in queue |
| `strix_assessments_started_total` | Counter | Assessments started |
| `strix_assessments_completed_total` | Counter | Assessments completed |
| `strix_assessments_failed_total` | Counter | Assessments failed |
| `strix_assessment_duration_seconds` | Histogram | Assessment duration |
| `strix_findings_total` | Counter | Findings by severity |

### Worker Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `strix_worker_active_tasks` | Gauge | Currently running tasks |
| `strix_worker_task_duration_seconds` | Histogram | Task execution time |
| `strix_worker_errors_total` | Counter | Worker errors by type |

### Scheduler Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `strix_jobs_total` | Counter | Job state transitions |
| `strix_scheduler_leader_election_failures_total` | Counter | Failed elections |
| `strix_scheduler_jobs_triggered_total` | Counter | Cron jobs triggered |

## Alertmanager Configuration

```yaml
# monitoring/alertmanager/config.yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'namespace']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'
  routes:
  - match:
      severity: critical
    receiver: 'critical'
    continue: true
  - match:
      severity: warning
    receiver: 'warning'

receivers:
- name: 'default'
  email_configs:
  - to: 'alerts@ishastra.dev'
    send_resolved: true
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>'
    channel: '#ishastra-alerts'
    send_resolved: true

- name: 'critical'
  pagerduty_configs:
  - service_key: 'PAGERDUTY_KEY'
    severity: critical
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>'
    channel: '#ishastra-critical'
    send_resolved: true

- name: 'warning'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>'
    channel: '#ishastra-warnings'
    send_resolved: true

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'namespace']
```

## Health Checks

### Kubernetes Probes

```yaml
# In deployment templates
livenessProbe:
  httpGet:
    path: /health/live
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3

startupProbe:
  httpGet:
    path: /health/startup
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 30
```

### Health Endpoints

```bash
# Liveness - process is alive
curl https://api.ishastra.dev/health/live
# {"status": "alive"}

# Readiness - ready to serve traffic
curl https://api.ishastra.dev/health/ready
# {"status": "ready", "checks": {"database": "ok", "redis": "ok", "scope_gate": "ok"}}

# Startup - initial initialization complete
curl https://api.ishastra.dev/health/startup
# {"status": "started"}

# Detailed - all dependency checks
curl https://api.ishastra.dev/health/detailed
```

## Runbook Links

| Alert | Runbook |
|-------|---------|
| IshastraAPIDown | [API Down](../runbooks/api-down.md) |
| IshastraScopeGateDenialsHigh | [Scope Gate Denials](../runbooks/scope-gate-denials.md) |
| IshastraQueueDepthHigh | [Queue Backlog](../runbooks/queue-backlog.md) |
| IshastraWorkerOOMKilled | [Worker OOM](../runbooks/worker-oom.md) |
| IshastraDatabaseConnectionsHigh | [DB Connections](../runbooks/db-connections.md) |
| IshastraCertExpiringSoon | [Cert Expiry](../runbooks/certificate-expiry.md) |

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Free Tier Deployment](../deployment/free-tier.md)