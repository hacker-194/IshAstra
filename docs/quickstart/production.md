# Production Deployment

# Production Deployment Guide

Enterprise-grade deployment on EKS, GKE, AKS, or self-managed Kubernetes.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Production Cluster                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Cloud Load Balancer (ALB/NGINX)                   │  │
│  │                    TLS Termination + WAF                             │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│  ┌────────────────────────────────▼─────────────────────────────────────┐  │
│  │                      Ingress Controller (NGINX)                       │  │
│  │              Rate Limiting │ Auth │ Canary Routes                     │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│           ┌───────────────────────┼───────────────────────┐               │
│           ▼                       ▼                       ▼               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐      │
│  │  API Pods (3+)  │    │  Worker Pods    │    │ Scheduler Pods  │      │
│  │  HPA: 3-50      │    │  HPA: 2-100     │    │  2 Replicas     │      │
│  │  PDB: min 2     │    │  PDB: min 1     │    │  Leader Election│      │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘      │
│           │                      │                      │               │
│           └──────────────────────┼──────────────────────┘               │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Scope Gate (Sidecar/Init)                      │  │
│  │  Default-Deny │ DNS Rebinding Protection │ Pinned Destinations  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                  │                                      │
│           ┌──────────────────────┼──────────────────────┐               │
│           ▼                      ▼                      ▼               │
│  ┌───────────────┐      ┌───────────────┐      ┌───────────────┐      │
│  │   PostgreSQL  │      │     Redis     │      │  Object Store │      │
│  │  (Managed,    │      │  (Managed,    │      │    (S3/GCS/   │      │
│  │   HA, PITR)   │      │   Cluster)    │      │   Azure Blob) │      │
│  └───────────────┘      └───────────────┘      └───────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Helm Deployment

### Prerequisites

- Kubernetes 1.28+
- Helm 3.12+
- kubectl configured for target cluster
- Cert-manager installed (for TLS)

### Install

```bash
# Add repo (when published)
helm repo add strix https://charts.strix.dev
helm repo update

# Or install from local chart
cd deploy/helm/strix

# Production values
helm install strix . -f values-prod.yaml \
  --namespace strix-system --create-namespace

# Verify
kubectl get pods -n strix-system -w
```

### values-prod.yaml Key Settings

```yaml
# High Availability
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 50
  targetCPUUtilization: 70

# Pod Disruption Budget
podDisruptionBudget:
  minAvailable: 2

# Security
podSecurityContext:
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

# Resources
resources:
  limits:
    cpu: "2000m"
    memory: "4Gi"
  requests:
    cpu: "500m"
    memory: "1Gi"

# Database (External Managed)
postgresql:
  enabled: false
externalDatabase:
  host: "your-rds-instance.xyz.us-east-1.rds.amazonaws.com"
  port: 5432
  database: "strix"
  sslMode: "require"

# Redis (External Managed)
redis:
  enabled: false
externalRedis:
  host: "your-elasticache.xyz.use1.cache.amazonaws.com"
  port: 6379
  tls: true

# Monitoring
monitoring:
  prometheus:
    enabled: true
    serviceMonitor: true
  grafana:
    enabled: true
    dashboards: true

# TLS
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
  hosts:
    - host: api.yourdomain.com
      paths: ["/"]
  tls:
    - secretName: strix-tls
      hosts: [api.yourdomain.com]
```

## Secrets Management

### SealedSecrets (GitOps)

```bash
# Install controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.27.0/controller.yaml

# Seal a secret
kubeseal --format yaml < secrets.yaml > sealed-secrets.yaml

# Commit sealed-secrets.yaml to git
git add sealed-secrets.yaml
git commit -m "Add sealed API keys"
```

### External Secrets Operator (AWS/GCP/Azure)

```yaml
# values-prod.yaml addition
externalSecrets:
  enabled: true
  provider: aws  # or gcp, azure
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

## Database Setup

### PostgreSQL (Managed)

```sql
-- Create database and user
CREATE DATABASE strix;
CREATE USER strix WITH ENCRYPTED PASSWORD 'strong-password';
GRANT ALL PRIVILEGES ON DATABASE strix TO strix;

-- Enable extensions
\c strix
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

### Run Migrations

```bash
# As Kubernetes Job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: strix-migrate
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
```

## Monitoring & Alerting

### Key Metrics to Alert On

| Metric | Warning | Critical |
|--------|---------|----------|
| `scope_gate_check_duration_seconds` | > 100ms | > 500ms |
| `scope_gate_denials_total` | > 10/min | > 100/min |
| `api_request_duration_seconds` | > 1s | > 5s |
| `worker_queue_depth` | > 100 | > 1000 |
| `db_connections_active` | > 80% | > 95% |

### Grafana Dashboards

Import from `deploy/monitoring/grafana/dashboards/`:
- Strix Overview
- Scope Gate Performance
- Assessment Pipeline
- Infrastructure Health

## Backup & Disaster Recovery

### Database Backup

```bash
# Automated (managed service)
# AWS RDS: Automated backups + PITR
# GCP Cloud SQL: Automated backups + PITR
# Azure Database: Automated backups + PITR

# Manual
pg_dump -h $DB_HOST -U strix strix | gzip > strix-$(date +%F).sql.gz
```

### Restore Procedure

```bash
# 1. Restore database
gunzip -c strix-2024-01-15.sql.gz | psql -h $DB_HOST -U strix strix

# 2. Verify Scope Gate
kubectl exec -n strix-system deploy/strix-api -- python -c "
from strix.core.scope import ScopeGate
gate = ScopeGate()
print('Scope Gate:', 'OK' if gate.validate_config() else 'FAIL')
"

# 3. Smoke test
curl https://api.yourdomain.com/health
```

## Rollback

```bash
# Helm rollback
helm rollback strix -n strix-system

# Or specific revision
helm rollback strix 3 -n strix-system

# Verify
kubectl rollout status deploy/strix-api -n strix-system
```

## Security Hardening Checklist

- [ ] Network policies restrict inter-pod traffic
- [ ] Pod Security Standards: restricted profile
- [ ] All containers run as non-root
- [ ] Read-only root filesystem
- [ ] No privileged containers
- [ ] Secrets in SealedSecrets/External Secrets (not ConfigMaps)
- [ ] TLS 1.2+ everywhere (ingress, DB, Redis, inter-service)
- [ ] API rate limiting enabled
- [ ] Audit logging to SIEM
- [ ] Image scanning in CI (Trivy/Griffeye)
- [ ] SLSA Level 3 provenance for images

## Capacity Planning

| Component | Baseline | Scale Trigger | Max |
|-----------|----------|---------------|-----|
| API Pods | 3 | CPU > 70% | 50 |
| Workers | 5 | Queue > 50 | 100 |
| PostgreSQL | db.r6g.xlarge | Connections > 80% | db.r6g.4xlarge |
| Redis | cache.r6g.xlarge | Memory > 70% | cache.r6g.4xlarge |

## Compliance

- **SOC 2 Type II**: Audit logs, access controls, encryption
- **ISO 27001**: Asset management, incident response, crypto
- **NIST 800-53**: AC-3, AC-6, AU-2, SC-7, SC-8, SI-4
- **PCI DSS**: Network segmentation, encryption, logging

See [Compliance Mapping](../compliance/overview.md).