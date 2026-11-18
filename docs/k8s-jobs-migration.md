# Migration Path: In-Process/Celery → K8s Jobs

> **Metric note (verified 2026-11-17):** the `strix_assessment_*` Kubernetes job
> gauges named below are **not** exported. The job, adapter and database
> families (`strix_jobs_*`, `strix_adapter_*`, `strix_db_pool_*`) are exported
> by `src/strix/metrics.py` but are published by the in-process worker, not the
> Kubernetes task runner.


## Overview

This document describes the migration from the current queue modes to K8s Jobs mode.

| Mode | Status | Use Case |
|------|--------|----------|
| `inprocess` | Default, stable | Single-node, development, low throughput |
| `celery` | Experimental, opt-in | Distributed, horizontal scaling, Redis dependency |
| `k8s-jobs` | **New** | Production, isolation, cost optimization, multi-tenancy |

---

## Phase 1: Infrastructure Prerequisites (Week 1-2)

### 1.1 Kubernetes Cluster Requirements
- Kubernetes 1.27+
- CSI driver for persistent volumes (PostgreSQL)
- Ingress controller (nginx)
- cert-manager for TLS
- External Secrets Operator or Vault Agent for secrets
- Cluster Autoscaler for spot instance scaling

### 1.2 Runtime Classes (Cluster Admin)
```bash
# gVisor (recommended for scanner isolation)
kubectl apply -f - <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
scheduling:
  podOverhead:
    podFixed:
      memory: "120Mi"
      cpu: "300m"
EOF

# Kata Containers (alternative, stronger isolation)
kubectl apply -f - <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
scheduling:
  podOverhead:
    podFixed:
      memory: "200Mi"
      cpu: "500m"
EOF
```

### 1.3 Priority Classes (Cluster Admin)
```bash
kubectl apply -f - <<EOF
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: strix-spot-priority
value: 1000000
globalDefault: false
description: "Priority for Strix assessment jobs on spot instances"
---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: strix-low-priority
value: 0
globalDefault: false
description: "Low priority for preemptible assessment jobs"
EOF
```

### 1.4 Namespace and RBAC
```bash
kubectl create namespace strix-assessments
# Apply RBAC from Helm chart (includes batch/jobs, networking.k8s.io/networkpolicies)
```

---

## Phase 2: Database Migration (Week 2)

### 2.1 PostgreSQL Required
K8s Jobs mode **requires PostgreSQL** (no SQLite). Each Job pod writes directly to the database.

```yaml
# values-k8s-jobs.yaml
postgresql:
  enabled: true
  auth:
    enabled: true
    existingSecret: strix-postgresql-secret
    database: strix
    username: strix
```

### 2.2 Run Migrations
```bash
# Run schema migrations on PostgreSQL
helm upgrade --install strix ./deploy/helm/strix \
  -f values.yaml \
  -f values-k8s-jobs.yaml \
  -f values-prod.yaml \
  --set postgresql.enabled=true
```

### 2.3 Verify Database Connectivity
```bash
kubectl exec -it deployment/strix-api -- python -c "
from strix.core import store
import asyncio
asyncio.run(store.get_database())
print('DB connected:', store.current_path())
"
```

---

## Phase 3: ConfigMap and Secrets (Week 2-3)

### 3.1 Scope ConfigMap
```yaml
# Deploy per-tenant or global scope
apiVersion: v1
kind: ConfigMap
metadata:
  name: strix-scope
  namespace: strix-assessments
data:
  scope.json: |
    {
      "program": "Bug Bounty Program",
      "authorized_by": "security@example.com",
      "authorization_ref": "BB-2024-001",
      "include": ["*.example.com"],
      "exclude": ["test.example.com", "dev.example.com"],
      "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
      "allowed_ports": [80, 443, 8443, 9443],
      "allow_broad_networks": false
    }
```

### 3.2 Database Secret
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: strix-secrets
  namespace: strix-assessments
type: Opaque
stringData:
  database-url: "postgresql://strix:password@postgresql:5432/strix"
  STRIX_ENCRYPTION_KEY: "base64-encoded-32-byte-key"
  STRIX_AUDIT_HMAC_KEY: "base64-encoded-32-byte-key"
  STRIX_WEBHOOK_SECRET: "base64-encoded-32-byte-key"
  STRIX_API_KEY: "admin-api-key-16-chars-min"
```

### 3.3 External Secrets (Production)
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: strix-secrets
  namespace: strix-assessments
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: strix-secrets
    creationPolicy: Owner
  data:
    - secretKey: database-url
      remoteRef:
        key: secret/data/strix
        property: database-url
    - secretKey: STRIX_ENCRYPTION_KEY
      remoteRef:
        key: secret/data/strix
        property: encryption-key
    # ... other secrets
```

---

## Phase 4: Deploy K8s Jobs Mode (Week 3)

### 4.1 Helm Upgrade
```bash
helm upgrade --install strix ./deploy/helm/strix \
  -f values.yaml \
  -f values-prod.yaml \
  -f values-k8s-jobs.yaml \
  --namespace strix \
  --create-namespace
```

### 4.2 Verify Deployment
```bash
# Check API deployment
kubectl get pods -n strix -l app.kubernetes.io/component=api

# Check K8s Jobs RBAC
kubectl auth can-i create jobs --as=system:serviceaccount:strix:strix -n strix-assessments
kubectl auth can-i create networkpolicies --as=system:serviceaccount:strix:strix -n strix-assessments

# Test assessment submission
curl -X POST https://strix.example.com/api/assess \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web"}'
```

---

## Phase 5: Traffic Migration (Week 3-4)

### 5.1 Canary Deployment
```yaml
# values-canary.yaml
api:
  replicaCount: 3
  env:
    STRIX_QUEUE_MODE: "k8s-jobs"
    # Keep 1 replica on inprocess for rollback
```

```bash
# Deploy canary with k8s-jobs
helm upgrade --install strix-canary ./deploy/helm/strix \
  -f values.yaml \
  -f values-prod.yaml \
  -f values-k8s-jobs.yaml \
  -f values-canary.yaml \
  --namespace strix

# Route 10% traffic to canary via Ingress
```

### 5.2 Monitor Metrics
```promql
# Job success rate
rate(strix_assessment_jobs_completed_total[5m]) / rate(strix_assessment_jobs_submitted_total[5m])

# Job duration histogram
histogram_quantile(0.95, rate(strix_assessment_job_duration_seconds_bucket[5m]))

# Queue depth (pending Jobs)
kube_job_status_active{job=~"strix-assess-.*"}

# Spot instance utilization
sum(kube_pod_info{namespace="strix-assessments", priority_class_name="strix-spot-priority"}) by (node)
```

### 5.3 Full Cutover
```bash
# After validation, switch all traffic
helm upgrade strix ./deploy/helm/strix \
  -f values.yaml \
  -f values-prod.yaml \
  -f values-k8s-jobs.yaml \
  --namespace strix

# Scale down Celery workers (if running)
kubectl scale deployment strix-worker --replicas=0 -n strix
```

---

## Phase 6: Decommission Old Modes (Week 4)

### 6.1 Remove Celery Dependencies
```bash
# Remove Redis if no longer needed
helm uninstall redis -n strix

# Remove Celery worker deployment
kubectl delete deployment strix-worker -n strix
```

### 6.2 Clean Up Code (Optional)
- Remove `CeleryAssessmentQueue` from `src/strix/core/queue.py`
- Remove Celery task definitions
- Remove `STRIX_CELERY_*` environment variables
- Update documentation

---

## Rollback Plan

| Scenario | Action |
|----------|--------|
| K8s Jobs failing | `STRIX_QUEUE_MODE=inprocess` on API, scale up API replicas |
| Database overload | Reduce `backoffLimit`, increase `activeDeadlineSeconds` |
| Spot instance exhaustion | Remove `priorityClassName`, use on-demand nodes |
| NetworkPolicy too restrictive | Set `networkPolicyEnabled: false` temporarily |

```bash
# Emergency rollback to in-process
helm upgrade strix ./deploy/helm/strix \
  -f values.yaml \
  -f values-prod.yaml \
  --set api.env.STRIX_QUEUE_MODE=inprocess \
  --set worker.enabled=true \
  --namespace strix
```

---

## Configuration Reference

### Environment Variables (API)

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIX_QUEUE_MODE` | `inprocess` | `inprocess`, `celery`, `k8s-jobs` |
| `STRIX_K8S_NAMESPACE` | `strix-assessments` | Namespace for Jobs |
| `STRIX_K8S_IMAGE` | `global.image` | Assessment container image |
| `STRIX_K8S_RUNTIME_CLASS` | `gvisor` | `gvisor`, `kata`, or empty |
| `STRIX_K8S_PRIORITY_CLASS` | `strix-spot-priority` | Priority class name |
| `STRIX_K8S_TTL` | `3600` | Job TTL after finish (seconds) |
| `STRIX_K8S_BACKOFF_LIMIT` | `2` | Job retry count |
| `STRIX_K8S_ACTIVE_DEADLINE` | `7200` | Max job runtime (seconds) |
| `STRIX_K8S_CPU_LIMIT` | `2000m` | Container CPU limit |
| `STRIX_K8S_MEMORY_LIMIT` | `2Gi` | Container memory limit |
| `STRIX_K8S_DB_SECRET` | `strix-secrets` | Secret with DATABASE_URL |
| `STRIX_K8S_SCOPE_CM` | `strix-scope` | ConfigMap with scope.json |

### Job Pod Environment Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `STRIX_JOB_ID` | API | Unique job identifier |
| `STRIX_TENANT_ID` | API | Tenant ID |
| `STRIX_TARGET` | API | Assessment target |
| `STRIX_PROFILE` | API | Scan profile |
| `STRIX_TIMEOUT_SECONDS` | API | Per-assessment timeout |
| `STRIX_SCOPE_JSON` | ConfigMap | Scope snapshot (JSON) |
| `STRIX_DATABASE_URL` | Secret | PostgreSQL connection |
| `STRIX_AUTH_CONFIG` | Secret (optional) | Encrypted auth config |

---

## Troubleshooting

### Job Stuck in Pending
```bash
# Check node capacity
kubectl describe nodes | grep -A 5 "Allocated resources"

# Check spot instance availability
kubectl get nodes -l node.kubernetes.io/instance-type=spot

# Check priority class
kubectl get priorityclass strix-spot-priority
```

### Job Fails Immediately
```bash
# Check Job logs
kubectl logs job/strix-assess-<job-id> -n strix-assessments

# Check events
kubectl get events -n strix-assessments --sort-by='.lastTimestamp' | grep strix-assess

# Common issues:
# - ImagePullBackOff: check imagePullSecrets
# - CreateContainerConfigError: check ConfigMap/Secret names
# - Permission denied: check RBAC for batch/jobs
```

### NetworkPolicy Blocking Egress
```bash
# Test connectivity from Job pod
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -n strix-assessments -- \
  nc -zv example.com 443

# Check NetworkPolicy
kubectl get networkpolicy -n strix-assessments -l strix.job-id=<job-id>
kubectl describe networkpolicy strix-assess-<job-id>-netpol -n strix-assessments
```

### Database Connection Issues
```bash
# Test from API pod
kubectl exec -it deployment/strix-api -n strix -- \
  python -c "import asyncpg; import asyncio; asyncio.run(asyncpg.connect('$DATABASE_URL'))"
```

---

## Cost Optimization Checklist

- [ ] Spot instance node pool configured with cluster-autoscaler
- [ ] PriorityClass `strix-spot-priority` applied to Jobs
- [ ] `ttlSecondsAfterFinished: 3600` for automatic cleanup
- [ ] `backoffLimit: 2` to limit retry costs
- [ ] HPA on API based on queue depth (custom metrics)
- [ ] Resource requests/limits tuned for assessment workloads
- [ ] PodDisruptionBudget for graceful spot termination
- [ ] NetworkPolicy prevents unnecessary egress charges

---

## Security Checklist

- [ ] RuntimeClass `gvisor` or `kata` configured
- [ ] PodSecurityContext: non-root, read-only fs, dropped capabilities
- [ ] NetworkPolicy: egress restricted to scope targets + DNS + DB
- [ ] ServiceAccount with minimal RBAC (batch/jobs, networkpolicies)
- [ ] Secrets via External Secrets Operator (not hardcoded)
- [ ] Database: TLS, dedicated user, least privilege
- [ ] Audit chain integrity verified in Job runner
- [ ] Scope snapshot bound at Job creation (immutable)
