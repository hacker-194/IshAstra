# Ishastra Observability Stack

This directory contains the complete observability configuration for Ishastra, including:

## Components

### Prometheus (`prometheus.yml`)
- Scrapes `/api/metrics` from Ishastra API (requires admin key)
- Scrapes node-exporter for host-level metrics (disk, CPU, memory)
- Loads alerting rules from `alerting.yml`
- Sends alerts to Alertmanager

### Alertmanager (`alertmanager.yml`)
- Routes alerts by severity and component
- Supports email, Slack, and PagerDuty notifications
- Critical alerts go to separate channels with PagerDuty integration
- Security alerts (auth, audit) route to security team

### Alerting Rules (`alerting.yml`)
Key alert categories:
- **Queue Backlog**: Jobs queued but not processed
- **Job Latency**: p95/p99 job duration thresholds
- **Adapter Success Rates**: Per-adapter error rates
- **Authentication Failures**: Brute-force detection
- **Audit Chain**: Tampering detection
- **HTTP Error Rates**: 5xx/4xx per endpoint
- **Rate Limiting**: Exceeded rate limits
- **Database Pool**: Exhaustion and slow acquires
- **Disk Pressure**: Host disk space (via node-exporter)
- **Webhook Failures**: Delivery failures
- **Service Health**: Component uptime

### Grafana Dashboards (`grafana/dashboards/`)
- **Ishastra Overview** (`ishastra-overview.json`): High-level service health, latency, success rates
- **Job Latency** (`ishastra-job-latency.json`): HTTP request and job duration percentiles
- **Adapter Success Rates** (`ishastra-adapter-success-rates.json`): Per-adapter error rates and invocations
- **Queue Depth** (`ishastra-queue-depth.json`): Active jobs, backlog, throughput by tenant
- **Tenant Throughput** (`ishastra-tenant-throughput.json`): Request rates, findings, reports by tenant
- **Error Rates** (`ishastra-error-rates.json`): HTTP, adapter, auth, webhook error rates

### OpenTelemetry (`otel.py`)
- Distributed tracing with OTLP export
- Metrics export to Prometheus and OTLP
- Automatic instrumentation for FastAPI, HTTPX, Redis, SQLAlchemy
- Custom trace context propagation
- Enabled via `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable

## Deployment

```bash
# Create secrets directory with admin API key
mkdir -p secrets
printf '%s' "$ISHASTRA_API_KEY" > secrets/strix_api_key && chmod 600 secrets/strix_api_key

# Set Grafana password in .env.production
echo "GRAFANA_PASSWORD=your-secure-password" >> .env.production

# Optional: Configure Alertmanager notifications
echo "SMTP_PASSWORD=your-smtp-password" >> .env.production
echo "SLACK_WEBHOOK_URL=https://hooks.slack.com/..." >> .env.production
echo "SLACK_WEBHOOK_URL_CRITICAL=https://hooks.slack.com/..." >> .env.production
echo "SLACK_WEBHOOK_URL_SECURITY=https://hooks.slack.com/..." >> .env.production
echo "PAGERDUTY_SERVICE_KEY=your-pagerduty-key" >> .env.production

# Start monitoring stack with production
docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## Access

- **Prometheus**: http://localhost:9090 (SSH tunnel)
- **Alertmanager**: http://localhost:9093 (SSH tunnel)
- **Grafana**: http://localhost:3000 (admin / $GRAFANA_PASSWORD)
- **Ishastra Metrics**: http://localhost:8000/api/metrics (requires admin key)

## Exported Metrics

Every series below is defined in `src/ishastra/metrics.py`:

| Metric | Type | Labels |
|---|---|---|
| `strix_http_requests_total` | counter | `method`, `endpoint`, `status` |
| `strix_http_request_duration_seconds` | histogram | `method`, `endpoint` |
| `strix_http_requests_in_progress` | gauge | `method`, `endpoint` |
| `ishastra_scope_gate_decisions_total` | counter | `decision`, `reason`, `tenant` |
| `ishastra_scope_gate_decision_duration_seconds` | histogram | `decision` |
| `strix_rate_limit_hits_total` | counter | `route_class`, `tier`, `allowed` |
| `strix_rate_limit_exceeded_total` | counter | `route_class`, `tier`, `identity_type` |
| `strix_jobs_total` | counter | `state`, `tenant` |
| `strix_jobs_active` | gauge | `tenant` |
| `strix_job_duration_seconds` | histogram | `profile`, `tenant` |
| `strix_job_state_transitions_total` | counter | `from`, `to` |
| `strix_queue_depth` | gauge | `mode` |
| `strix_workers_total` | gauge | `mode` |
| `strix_worker_busy` | gauge | `mode` |
| `strix_adapter_duration_seconds` | histogram | `adapter`, `tenant` |
| `strix_adapter_errors_total` | counter | `adapter`, `error_type`, `tenant` |
| `strix_adapter_timeout_total` | counter | `adapter`, `tenant` |
| `strix_db_pool_size` | gauge | `dialect` |
| `strix_db_pool_available` | gauge | `dialect` |
| `strix_db_pool_acquire_seconds` | histogram | `dialect` |
| `strix_db_size_bytes` | gauge | `dialect` |
| `strix_job_queue_duration_seconds` | histogram | `profile` |
| `strix_auth_success_total` | counter | `tenant`, `tier` |
| `strix_auth_failures_total` | counter | `tenant`, `reason` |
| `strix_webhook_deliveries_total` | counter | `tenant`, `status` |
| `strix_webhook_failures_total` | counter | `tenant`, `error_type` |
| `strix_findings_total` | counter | `tenant`, `severity`, `adapter` |
| `strix_audit_events_total` | counter | `tenant`, `event_type` |
| `strix_audit_chain_length` | gauge | — |
| `strix_audit_chain_verified` | gauge | — |
| `strix_reports_total` | counter | `kind` |
| `strix_build_info` | gauge | `version` |

`mode` is the queue backend; the in-process worker publishes `inprocess`, and the
Celery and Kubernetes queue modes do not emit queue/worker gauges yet. **Not exported**: compliance scoring (`strix_compliance_*`) and the
`strix_assessment_*` Kubernetes job gauges. Panels built on those have no data
source; the compliance alert was removed rather than left firing on nothing.

## Custom-metric autoscaling

The Helm chart's API and worker HPAs use the recording metrics
`ishastra_scope_gate_decision_latency_seconds_p95` and
`strix_assessment_queue_pending`. Prometheus rules for both are included in the
chart. HPA custom metrics require the Prometheus Adapter (or another provider
that exposes `external.metrics.k8s.io`); example values for the
`prometheus-community/prometheus-adapter` chart are in
`prometheus-adapter-values.yaml`. Set its Prometheus URL to your in-cluster
Prometheus service, install it before enabling custom-metric HPAs, and verify
the metrics API with:

```bash
kubectl get --raw /apis/external.metrics.k8s.io/v1beta1/namespaces/ishastra/strix_assessment_queue_pending
```

## Enabling OpenTelemetry

Set the OTLP endpoint to enable distributed tracing:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
export OTEL_SERVICE_NAME=ishastra
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production,cluster=ishastra-prod
```

Install optional dependencies:
```bash
pip install -e ".[otel]"
```

## Alert Runbooks

Each alert includes a `runbook_url` annotation pointing to documentation. Create runbooks at:
- `docs/runbooks/queue-backlog.md`
- `docs/runbooks/job-latency.md`
- `docs/runbooks/adapter-errors.md`
- `docs/runbooks/auth-failures.md`
- `docs/runbooks/audit-chain.md`
- `docs/runbooks/http-errors.md`
- `docs/runbooks/rate-limiting.md`
- `docs/runbooks/db-pool.md`
- `docs/runbooks/disk-pressure.md`
- `docs/runbooks/webhook-failures.md`
- `docs/runbooks/findings-volume.md`
- `docs/runbooks/service-down.md`
- `docs/runbooks/prometheus-down.md`
- `docs/runbooks/redis-down.md`

## Adding New Dashboards

1. Create dashboard JSON in `grafana/dashboards/`
2. Ensure `uid` matches the filename pattern: `ishastra-<name>`
3. Add link to `ishastra-overview.json` for navigation
4. Restart Grafana or wait for provisioning reload (30s default)