# Ishastra Helm Chart

Production-grade Kubernetes deployment for Ishastra - Authorized Security Assessment Platform.

## Chart Structure

```
ishastra/
├── Chart.yaml              # Chart metadata and dependencies
├── values.yaml             # Default values (production-ready)
├── values-dev.yaml         # Development environment
├── values-staging.yaml     # Staging environment
├── values-prod.yaml        # Production environment
├── templates/
│   ├── _helpers.tpl        # Template helpers
│   ├── deployment-api.yaml # Ishastra API deployment
│   ├── deployment-scheduler.yaml # Scheduler deployment
│   ├── deployment-worker.yaml    # worker deployment (one writer per database)
│   ├── service-api.yaml        # API service
│   ├── service-scheduler.yaml  # Scheduler service
│   ├── service-headless.yaml   # Redis headless service
│   ├── ingress.yaml            # Ingress with TLS and rate limiting
│   ├── configmap.yaml          # App config + scope.json
│   ├── secrets.yaml            # Secrets (External Secrets ready)
│   ├── pvc.yaml                # SQLite WAL persistence
│   ├── serviceaccount.yaml     # ServiceAccount
│   ├── rbac.yaml               # RBAC (ClusterRole, Role)
│   ├── networkpolicy.yaml      # Network policies
│   ├── pdb.yaml                # Pod Disruption Budgets
│   ├── hpa.yaml                # Horizontal Pod Autoscalers
│   ├── servicemonitor.yaml     # Prometheus ServiceMonitors
│   └── psp.yaml                # PodSecurityPolicy (deprecated) / PodSecurity labels
└── charts/                     # Subcharts (dependencies)
```

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- cert-manager (for TLS)
- external-dns (optional, for DNS automation)
- External Secrets Operator / Vault Agent (for secret management)
- Prometheus Operator (for monitoring)

## Quick Start

### Development

```bash
helm install ishastra ./deploy/helm/ishastra \
  -f ./deploy/helm/ishastra/values-dev.yaml \
  --namespace ishastra-dev --create-namespace
```

### Staging

```bash
helm install ishastra ./deploy/helm/ishastra \
  -f ./deploy/helm/ishastra/values-staging.yaml \
  --namespace ishastra-staging --create-namespace
```

### Production

```bash
helm install ishastra ./deploy/helm/ishastra \
  -f ./deploy/helm/ishastra/values-prod.yaml \
  --namespace ishastra-prod --create-namespace
```

## Configuration

### Required Secrets

Before deploying to staging/production, create the following secrets:

```bash
# Ishastra API secrets
kubectl create secret generic ishastra-secrets \
  --from-literal=ISHASTRA_API_KEY="$(openssl rand -base64 32)" \
  --from-literal=ISHASTRA_AUDIT_HMAC_KEY="$(openssl rand -base64 32)" \
  --from-literal=ISHASTRA_WEBHOOK_SECRET="$(openssl rand -base64 32)" \
  --from-literal=ISHASTRA_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  -n ishastra-prod

# Redis password
kubectl create secret generic ishastra-redis-secret \
  --from-literal=redis-password="$(openssl rand -base64 32)" \
  -n ishastra-prod

# PostgreSQL password (if enabled)
kubectl create secret generic ishastra-postgresql-secret \
  --from-literal=postgresql-password="$(openssl rand -base64 32)" \
  -n ishastra-prod

# Grafana admin
kubectl create secret generic ishastra-grafana-secret \
  --from-literal=admin-user="admin" \
  --from-literal=admin-password="$(openssl rand -base64 32)" \
  -n ishastra-prod
```

### External Secrets Operator

For production, use External Secrets Operator with Vault:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ishastra-secrets
  namespace: ishastra-prod
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: ishastra-secrets
    creationPolicy: Owner
  data:
    - secretKey: ISHASTRA_API_KEY
      remoteRef:
        key: secret/data/ishastra/production
        property: ISHASTRA_API_KEY
    - secretKey: ISHASTRA_AUDIT_HMAC_KEY
      remoteRef:
        key: secret/data/ishastra/production
        property: ISHASTRA_AUDIT_HMAC_KEY
    # ... other secrets
```

### Scope Configuration

The `scope.json` is managed via ConfigMap. For production, replace with a signed scope document:

```bash
kubectl create configmap ishastra-config \
  --from-file=scope.json=/path/to/signed/scope.json \
  -n ishastra-prod --dry-run=client -o yaml | kubectl apply -f -
```

## Components

| Component | Description | Replicas (Prod) |
|-----------|-------------|-----------------|
| **ishastra-api** | FastAPI + Uvicorn workers | 3 (HPA: 3-20) |
| **ishastra-scheduler** | APScheduler for recurring assessments | 2 (HPA: 2-5) |
| **ishastra-worker** | Assessment worker; one writer per database (see production guide) | 1 |
| **redis** | Rate-limit counters (jobs are in-process) | 1 |
| **postgresql** | Multi-tenant database (optional) | 1 primary |
| **prometheus** | Metrics collection | 1 |
| **grafana** | Dashboards and visualization | 1 |

## Security Features

- **Non-root containers** (UID 10001)
- **Read-only root filesystem**
- **Dropped all capabilities**
- **Seccomp profile: RuntimeDefault**
- **Pod Security Standards: restricted**
- **Network Policies** (ingress/egress)
- **Pod Disruption Budgets**
- **RBAC with least privilege**
- **TLS via cert-manager**
- **Rate limiting at Ingress**

## Monitoring

The chart includes ServiceMonitors for Prometheus scraping:

- `/api/metrics` on API, Scheduler, and Worker pods
- Redis and PostgreSQL metrics (via bitnami charts)

Default dashboards available in Grafana:
- Ishastra Overview
- API Latency & Errors
- Assessment Queue Depth
- Resource Utilization

## Upgrading

```bash
helm upgrade ishastra ./deploy/helm/ishastra \
  -f ./deploy/helm/ishastra/values-prod.yaml \
  -n ishastra-prod
```

## Uninstalling

```bash
helm uninstall ishastra -n ishastra-prod
# Note: PVCs and secrets are preserved by default
```

## Values Reference

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.image.repository` | Image repository | `ghcr.io/hacker-194/ishastra` |
| `global.image.tag` | Image tag | `3.5.0` |
| `global.podSecurityStandard` | Pod Security Standard | `restricted` |

### API

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.enabled` | Enable API deployment | `true` |
| `api.replicaCount` | Number of replicas (one writer per database) | `1` |
| `api.resources` | CPU/Memory limits/requests | See values.yaml |
| `api.hpa.enabled` | Enable HPA | `false` (one writer per database) |
| `api.ingress.enabled` | Enable Ingress | `true` |
| `api.ingress.className` | Ingress class | `nginx` |

### Queue

| Parameter | Description | Default |
|-----------|-------------|---------|
| `queue.mode` | `inprocess`, `redis-streams` or `k8s-jobs` | `inprocess` |
| `queue.stream` | Redis stream key (redis-streams only) | `ishastra:assessments` |
| `queue.group` | Consumer group (redis-streams only) | `ishastra-workers` |
| `queue.visibilitySeconds` | Idle time before a pending entry is reclaimed | `7200` |

`api.replicaCount > 1` requires `queue.mode: redis-streams` with Redis enabled:
login flow state, rate limits and the API key registry are then shared, and the
scheduler and monitor loops are owned by the scheduler Deployment. Key
revocation reaches every replica within 5 seconds. `inprocess` is memory-only and holds an
exclusive per-database worker lease, so it also refuses
`worker.replicaCount > 1` and any worker HPA. Set `queue.mode: redis-streams`
to run several worker replicas against one stream: queued assessments survive a
pod restart, and the database stays single-writer (`claim_job` still guarantees
one execution).

### Redis

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.enabled` | Enable Redis | `true` |
| `redis.architecture` | standalone/replication | `replication` (prod) |
| `redis.auth.enabled` | Enable auth | `true` |

### PostgreSQL

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.enabled` | Enable PostgreSQL | `false` |
| `postgresql.auth.database` | Database name | `ishastra` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.prometheus.enabled` | Enable Prometheus | `false` |
| `monitoring.grafana.enabled` | Enable Grafana | `false` |

## License

MIT