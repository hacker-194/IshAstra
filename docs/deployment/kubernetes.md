# Kubernetes Deployment

# Kubernetes Deployment

Production-grade Kubernetes deployment for Strix.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Strix on Kubernetes                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Ingress (NGINX / Cloudflare)                      │  │
│  │              TLS │ Rate Limit │ WAF │ Canary                         │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│  ┌────────────────────────────────▼─────────────────────────────────────┐  │
│  │                      Namespace: strix-system                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │  │
│  │  │   API       │  │  Worker     │  │ Scheduler   │  │  Scope     │  │  │
│  │  │  Deployment │  │  Deployment │  │  Deployment │  │  Gate      │  │  │
│  │  │  (HPA/PDB)  │  │  (HPA/PDB)  │  │  (Leader)   │  │  (Sidecar) │  │  │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────────┘  │  │
│  │         │                │                │                            │  │
│  │         └────────────────┼────────────────┘                            │  │
│  │                          ▼                                             │  │
│  │  ┌────────────────────────────────────────────────────────────────┐   │  │
│  │  │              ConfigMap + Secrets (SealedSecrets)               │   │  │
│  │  └────────────────────────────────────────────────────────────────┘   │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│           ┌───────────────────────┼───────────────────────┐               │
│           ▼                       ▼                       ▼               │
│  ┌───────────────┐        ┌───────────────┐        ┌───────────────┐    │
│  │  PostgreSQL   │        │    Redis      │        │  Object Store │    │
│  │  (Managed)    │        │  (Managed)    │        │    (S3/GCS)   │    │
│  └───────────────┘        └───────────────┘        └───────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Kubernetes 1.28+
- Helm 3.12+
- kubectl configured
- Cert-manager (for TLS)
- Ingress controller (NGINX recommended)

## Quick Start with Helm

```bash
# Add repo (when published)
helm repo add strix https://charts.strix.dev
helm repo update

# Install with production values
helm install strix strix/strix -f values-prod.yaml \
  --namespace strix-system --create-namespace

# Or from local chart
cd deploy/helm/strix
helm install strix . -f values-prod.yaml \
  --namespace strix-system --create-namespace
```

## Helm Chart Structure

```
deploy/helm/strix/
├── Chart.yaml
├── values.yaml              # Defaults
├── values-free.yaml         # Free tier
├── values-prod.yaml         # Production
├── templates/
│   ├── namespace.yaml
│   ├── serviceaccount.yaml
│   ├── rbac.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── deployment-api.yaml
│   ├── deployment-worker.yaml
│   ├── deployment-scheduler.yaml
│   ├── hpa-api.yaml
│   ├── hpa-worker.yaml
│   ├── pdb-api.yaml
│   ├── pdb-worker.yaml
│   ├── networkpolicy.yaml
│   ├── servicemonitor.yaml
│   ├── ingress.yaml
│   └── _helpers.tpl
└── charts/
    ├── postgresql/          # Optional (disable for managed)
    └── redis/               # Optional (disable for managed)
```

## Production Values (values-prod.yaml)

```yaml
# deploy/helm/strix/values-prod.yaml

global:
  imageRegistry: ghcr.io
  imagePullSecrets:
    - ghcr-secret

# API Deployment
api:
  replicaCount: 3
  image:
    repository: strix/api
    tag: "3.5.0"
    pullPolicy: IfNotPresent
  
  resources:
    limits:
      cpu: "2000m"
      memory: "4Gi"
    requests:
      cpu: "500m"
      memory: "1Gi"
  
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 50
    targetCPUUtilization: 70
    targetMemoryUtilization: 80
    behavior:
      scaleUp:
        stabilizationWindowSeconds: 60
        policies:
        - type: Percent
          value: 100
          periodSeconds: 60
      scaleDown:
        stabilizationWindowSeconds: 300
  
  podDisruptionBudget:
    minAvailable: 2
  
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    readOnlyRootFilesystem: true
  
  env:
    - name: LOG_LEVEL
      value: "INFO"
    - name: STRIX_SCOPE_DOC_PATH
      value: "/config/scope.json"
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: strix-secrets
          key: database-url
    - name: REDIS_URL
      valueFrom:
        secretKeyRef:
          name: strix-secrets
          key: redis-url
    - name: STRIX_JWKS_URL
      value: "https://api.strix.dev/.well-known/jwks.json"

# Worker Deployment
worker:
  replicaCount: 5
  image:
    repository: strix/worker
    tag: "3.5.0"
  
  resources:
    limits:
      cpu: "4000m"
      memory: "8Gi"
    requests:
      cpu: "1000m"
      memory: "2Gi"
  
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 100
    targetCPUUtilization: 60
    # Custom metric: queue depth
    metrics:
    - type: External
      external:
        metric:
          name: strix_queue_depth
        target:
          type: AverageValue
          averageValue: "50"
  
  podDisruptionBudget:
    minAvailable: 1
  
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    # NET_RAW needed for nmap SYN scan
    # capabilities:
    #   add: ["NET_RAW"]
    readOnlyRootFilesystem: true

# Scheduler Deployment
scheduler:
  replicaCount: 2
  image:
    repository: strix/scheduler
    tag: "3.5.0"
  
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
    requests:
      cpu: "100m"
      memory: "128Mi"
  
  leaderElection:
    enabled: true
    lockName: strix-scheduler
    leaseDuration: 30s
    renewDeadline: 15s
    retryPeriod: 5s

# Scope Gate Configuration
scopeGate:
  enabled: true
  # Runs as sidecar in API and Worker pods
  config:
    cacheTTL: 300
    maxCacheSize: 10000
    defaultDeny: true
  
  signing:
    keyRotation:
      enabled: true
      interval: "30d"
      gracePeriod: "7d"
  
  breakGlass:
    enabled: true
    # Configured via scope document

# Network Policies
networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress-nginx
      ports:
      - protocol: TCP
        port: 8000
    - from:
      - podSelector:
          matchLabels:
            app: strix-worker
      ports:
      - protocol: TCP
        port: 8000
  egress:
    - to:
      - namespaceSelector:
          matchLabels:
            name: external-dns
      ports:
      - protocol: UDP
        port: 53
    - to:
      - namespaceSelector: {}
      ports:
      - protocol: TCP
        port: 443
      - protocol: TCP
        port: 5432
      - protocol: TCP
        port: 6379

# Ingress
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1s"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
  hosts:
    - host: api.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: strix-tls
      hosts:
        - api.yourdomain.com

# Monitoring
monitoring:
  prometheus:
    enabled: true
    serviceMonitor: true
    prometheusRule: true
  grafana:
    enabled: true
    dashboards: true
    sidecar:
      dashboards:
        enabled: true
      datasources:
        enabled: true

# External Database (Managed)
postgresql:
  enabled: false
externalDatabase:
  host: "your-rds-instance.xyz.us-east-1.rds.amazonaws.com"
  port: 5432
  database: "strix"
  sslMode: "require"
  # Credentials from secret

# External Redis (Managed)
redis:
  enabled: false
externalRedis:
  host: "your-elasticache.xyz.use1.cache.amazonaws.com"
  port: 6379
  tls: true
  # Credentials from secret

# Secrets Management
secrets:
  # SealedSecrets (GitOps)
  sealedSecrets:
    enabled: true
    secretName: strix-secrets
  
  # External Secrets Operator
  externalSecrets:
    enabled: false
    provider: aws  # aws, gcp, azure
    secretStore:
      name: aws-secretsmanager
      provider:
        aws:
          service: SecretsManager
          region: us-east-1
          auth:
            jwt:
              serviceAccountRef:
                name: external-secrets-sa
```

## Free Tier Values (values-free.yaml)

```yaml
# deploy/helm/strix/values-free.yaml

global:
  imageRegistry: ghcr.io

api:
  replicaCount: 1
  resources:
    limits:
      cpu: "1000m"
      memory: "2Gi"
    requests:
      cpu: "100m"
      memory: "256Mi"
  autoscaling:
    enabled: true
    minReplicas: 1
    maxReplicas: 3

worker:
  replicaCount: 1
  resources:
    limits:
      cpu: "2000m"
      memory: "4Gi"
    requests:
      cpu: "250m"
      memory: "512Mi"
  autoscaling:
    enabled: true
    minReplicas: 0
    maxReplicas: 5

scheduler:
  replicaCount: 1

scopeGate:
  enabled: true

postgresql:
  enabled: false
externalDatabase:
  host: "ep-xxx.us-east-1.aws.neon.tech"
  port: 5432
  database: "strix"
  sslMode: "require"

redis:
  enabled: false
externalRedis:
  host: "xxx.upstash.io"
  port: 6379
  tls: true

ingress:
  enabled: true
  className: "cloudflare"
  annotations:
    kubernetes.io/ingress.class: "cloudflare"
  hosts:
    - host: api.yourdomain.com
      paths: ["/"]

monitoring:
  prometheus:
    enabled: true
  grafana:
    enabled: true
```

## Secrets Management

### SealedSecrets (GitOps)

```bash
# Install controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.27.0/controller.yaml

# Get public key
kubeseal --fetch-cert --controller-name=sealed-secrets --controller-namespace=kube-system > pub-cert.pem

# Seal secrets
cat <<EOF | kubeseal --format yaml --cert pub-cert.pem > sealed-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: strix-secrets
  namespace: strix-system
type: Opaque
stringData:
  database-url: "postgresql://user:pass@host:5432/strix"
  redis-url: "redis://:pass@host:6379/0"
  jwt-secret: "super-secret-jwt-key"
  api-key: "strix-api-key-123"
EOF

# Commit to git
git add sealed-secrets.yaml
git commit -m "Add sealed secrets for Strix"
```

### External Secrets Operator

```bash
# Install ESO
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# Create SecretStore
cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secretsmanager
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
            namespace: strix-system
EOF

# Create ExternalSecret
cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: strix-secrets
  namespace: strix-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secretsmanager
  target:
    name: strix-secrets
    creationPolicy: Owner
  data:
    - secretKey: database-url
      remoteRef:
        key: strix/database-url
    - secretKey: redis-url
      remoteRef:
        key: strix/redis-url
    - secretKey: jwt-secret
      remoteRef:
        key: strix/jwt-secret
EOF
```

## Database Setup

### PostgreSQL (Managed Service)

```sql
-- Create database
CREATE DATABASE strix;
CREATE USER strix WITH ENCRYPTED PASSWORD 'strong-password';
GRANT ALL PRIVILEGES ON DATABASE strix TO strix;

-- Enable extensions
\c strix
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
```

### Run Migrations

```bash
# As Kubernetes Job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: strix-migrate-$(date +%s)
  namespace: strix-system
spec:
  template:
    spec:
      containers:
      - name: migrate
        image: ghcr.io/strix/strix:3.5.0
        command: ["alembic", "upgrade", "head"]
        envFrom:
        - secretRef:
            name: strix-secrets
      restartPolicy: OnFailure
  backoffLimit: 3
EOF

# Check status
kubectl logs -n strix-system job/strix-migrate-xxx
```

## Ingress Configuration

### NGINX Ingress

```yaml
# annotations for production
annotations:
  cert-manager.io/cluster-issuer: "letsencrypt-prod"
  nginx.ingress.kubernetes.io/rate-limit: "100"
  nginx.ingress.kubernetes.io/rate-limit-window: "1s"
  nginx.ingress.kubernetes.io/proxy-body-size: "10m"
  nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
  nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
  nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
```

### Cloudflare Tunnel (Zero Public IP)

```yaml
# For free tier / Cloudflare Tunnel
ingress:
  className: "cloudflare"
  annotations:
    kubernetes.io/ingress.class: "cloudflare"
    ingress.kubernetes.io/force-ssl-redirect: "true"
```

## Monitoring

### Prometheus ServiceMonitor

```yaml
# Auto-created with monitoring.prometheus.serviceMonitor: true
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: strix-api
  namespace: strix-system
spec:
  selector:
    matchLabels:
      app: strix-api
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Grafana Dashboards

Import from `deploy/monitoring/grafana/dashboards/`:
- `strix-overview.json` - Cluster overview
- `strix-scope-gate.json` - Authorization metrics
- `strix-assessments.json` - Assessment pipeline
- `strix-infrastructure.json` - K8s resources

### Key Alerts

```yaml
# PrometheusRule (auto-created with monitoring.prometheus.prometheusRule: true)
groups:
- name: strix
  rules:
  - alert: StrixAPIDown
    expr: up{job="strix-api"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Strix API is down"

  - alert: StrixScopeGateDenialsHigh
    expr: rate(scope_gate_denials_total[5m]) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High Scope Gate denial rate"

  - alert: StrixQueueDepthHigh
    expr: strix_queue_depth > 1000
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Assessment queue backing up"

  - alert: StrixWorkerOOMKilled
    expr: increase(container_oom_kills_total{container="worker"}[10m]) > 0
    labels:
      severity: critical
    annotations:
      summary: "Worker OOM killed"
```

## Scaling

### Horizontal Pod Autoscaler

```bash
# Check HPA status
kubectl get hpa -n strix-system

# Custom metrics for worker scaling
# Requires Prometheus Adapter for custom metrics
```

### Cluster Autoscaler

```yaml
# Ensure cluster autoscaler is configured for worker node groups
# Worker nodes need:
# - Labels: workload=strix-worker
# - Taints: strix-worker=true:NoSchedule (optional)
```

## Backup & Disaster Recovery

### Database Backup (Managed)

```bash
# AWS RDS: Automated backups + PITR (configure in AWS console)
# GCP Cloud SQL: Automated backups + PITR
# Azure Database: Automated backups + PITR

# Manual backup
kubectl exec -n strix-system deploy/strix-api -- pg_dump -h $DB_HOST -U strix strix | gzip > backup-$(date +%F).sql.gz
```

### Restore Procedure

```bash
# 1. Restore database
gunzip -c backup-2024-01-15.sql.gz | psql -h $DB_HOST -U strix strix

# 2. Verify Scope Gate
kubectl exec -n strix-system deploy/strix-api -- python -c "
from strix.core.scope import ScopeGate
gate = ScopeGate.from_file('/config/scope.json')
print('Scope Gate:', 'OK' if gate.validate_config() else 'FAIL')
"

# 3. Smoke test
curl https://api.yourdomain.com/health
```

## Rollback

```bash
# Helm rollback
helm rollback strix -n strix-system

# Specific revision
helm rollback strix 3 -n strix-system

# Verify
kubectl rollout status deploy/strix-api -n strix-system
kubectl rollout status deploy/strix-worker -n strix-system
```

## Security Hardening Checklist

- [ ] Network policies restrict inter-pod traffic
- [ ] Pod Security Standards: restricted profile
- [ ] All containers run as non-root (UID 1000)
- [ ] Read-only root filesystem
- [ ] No privileged containers
- [ ] Capabilities dropped (ALL)
- [ ] Seccomp profile: RuntimeDefault
- [ ] Secrets in SealedSecrets/External Secrets (not ConfigMaps)
- [ ] TLS 1.2+ everywhere (ingress, DB, Redis, inter-service)
- [ ] API rate limiting enabled
- [ ] Audit logging to SIEM
- [ ] Image scanning in CI (Trivy)
- [ ] SLSA Level 3 provenance for images
- [ ] Admission policies (Kyverno/OPA) for pod validation

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Pods Pending | No resources / node selector | Check node capacity, labels, taints |
| CrashLoopBackOff | Config error / Scope Gate fail | Check logs, validate scope.json |
| Ingress 502 | Service not ready / wrong port | Check service selector, port |
| HPA not scaling | Metrics not available | Check Prometheus Adapter, metrics |
| NetworkPolicy blocking | Missing egress rules | Add DNS, DB, Redis egress |

### Debug Commands

```bash
# Check pod logs
kubectl logs -n strix-system -l app=strix-api --tail=100
kubectl logs -n strix-system -l app=strix-worker --tail=100

# Check events
kubectl get events -n strix-system --sort-by='.lastTimestamp'

# Check Scope Gate config
kubectl exec -n strix-system deploy/strix-api -- cat /config/scope.json

# Test Scope Gate
kubectl exec -n strix-system deploy/strix-api -- python -c "
from strix.core.scope import ScopeGate
gate = ScopeGate.from_file('/config/scope.json')
import asyncio
async def test():
    try:
        dest = await gate.validate_outbound('https://api.example.com')
        print('ALLOWED:', dest.ip)
    except Exception as e:
        print('DENIED:', e)
asyncio.run(test())
"

# Check network policies
kubectl get networkpolicy -n strix-system -o yaml

# Check HPA metrics
kubectl get hpa -n strix-system -o yaml
```

## Related

- [Helm Deployment](../deployment/helm.md)
- [Free Tier Deployment](../deployment/free-tier.md)
- [Docker Compose](../deployment/docker-compose.md)
- [Monitoring](../deployment/monitoring.md)
- [Production Deployment](../quickstart/production.md)