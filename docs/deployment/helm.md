# Helm Deployment

# Helm Deployment

Deploy Ishastra using the official Helm chart.

> **Scaling warning:** Ishastra is single-writer. Run one API/worker process per
> database and leave `hpa.enabled` / `autoscaling.enabled` off. Values files
> that raise `replicaCount` or enable autoscaling describe an unsupported
> topology; see [Production deployment](../quickstart/production.md).

## Chart Overview

```
ishastra/
├── Chart.yaml                 # Chart metadata
├── values.yaml                # Default values
├── values-prod.yaml           # Production overrides
├── values-free.yaml           # Free tier overrides
├── charts/                    # Sub-charts
│   ├── postgresql/            # Optional PostgreSQL
│   └── redis/                 # Optional Redis
└── templates/                 # K8s manifests
    ├── namespace.yaml
    ├── serviceaccount.yaml
    ├── rbac.yaml
    ├── configmap.yaml
    ├── secret.yaml
    ├── deployment-api.yaml
    ├── deployment-worker.yaml
    ├── deployment-scheduler.yaml
    ├── hpa-api.yaml
    ├── hpa-worker.yaml
    ├── pdb-api.yaml
    ├── pdb-worker.yaml
    ├── networkpolicy.yaml
    ├── servicemonitor.yaml
    ├── ingress.yaml
    └── _helpers.tpl
```

## Installation

### From OCI Registry (Recommended)

```bash
# Add OCI registry
helm registry login ghcr.io

# Pull chart
helm pull oci://ghcr.io/ishastra/charts/ishastra --version 3.5.0 --untar

# Install
cd ishastra
helm install ishastra . -f values-prod.yaml -n ishastra-system --create-namespace
```

### From Local Source

```bash
cd deploy/helm/ishastra
helm install ishastra . -f values-prod.yaml -n ishastra-system --create-namespace
```

### With Custom Values

```bash
helm install ishastra . \
  -f values-prod.yaml \
  -f values-custom.yaml \
  -n ishastra-system --create-namespace
```

## Configuration Reference

### Global Settings

```yaml
global:
  imageRegistry: ghcr.io
  imagePullSecrets:
    - ghcr-secret
  labels:
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: ishastra
```

### API Deployment

```yaml
api:
  replicaCount: 3
  image:
    repository: ishastra/api
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
  
  podDisruptionBudget:
    enabled: true
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
    - name: ISHASTRA_SCOPE_DOC_PATH
      value: "/config/scope.json"
```

### Worker Deployment

```yaml
worker:
  replicaCount: 5
  image:
    repository: ishastra/worker
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
    metrics:
    - type: External
      external:
        metric:
          name: ishastra_queue_depth
        target:
          type: AverageValue
          averageValue: "50"
  
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
```

### Scheduler Deployment

```yaml
scheduler:
  replicaCount: 2
  image:
    repository: ishastra/scheduler
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
    lockName: ishastra-scheduler
    leaseDuration: 30s
    renewDeadline: 15s
    retryPeriod: 5s
```

### Assessment Queue

`queue.mode` selects how assessments are queued. It is the one value that
decides whether worker replicas may scale.

| Mode | Durable | Worker replicas | Use |
|------|---------|-----------------|-----|
| `inprocess` (default) | No | Exactly 1 | Pilot, single host |
| `redis-streams` | Yes | 1..N | Production; queued jobs survive a restart |
| `k8s-jobs` | Depends on the cluster | 1 | Experimental; one Job per assessment |

```yaml
queue:
  mode: redis-streams
  stream: ishastra:assessments
  group: ishastra-workers
  visibilitySeconds: 7200
```

The chart fails to render rather than start a second writer or a second
scheduler. `api.replicaCount > 1` is rejected unless `queue.mode: redis-streams`
is set with Redis enabled, because login state, rate limits and the API key
registry are then shared through Redis (revocation propagates within 5
seconds); in `inprocess` mode `worker.replicaCount > 1` and any worker HPA are
rejected too. In `redis-streams` mode the worker Deployment
consumes one Redis Stream through a consumer group; `claim_job` still
guarantees one execution per assessment, so this scales workers, not database
writers.

Cron execution belongs to the scheduler Deployment: the chart sets
`ISHASTRA_SCHEDULER_ENABLED=false` on the API and worker pods, so each scheduled
job runs once instead of once per pod.

### Scope Gate

```yaml
scopeGate:
  enabled: true
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
```

### Network Policies

```yaml
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
            app: ishastra-worker
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
```

### Ingress

```yaml
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
    - secretName: ishastra-tls
      hosts:
        - api.yourdomain.com
```

### Monitoring

```yaml
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
```

### External Database

```yaml
postgresql:
  enabled: false
externalDatabase:
  host: "your-rds.xyz.us-east-1.rds.amazonaws.com"
  port: 5432
  database: "ishastra"
  sslMode: "require"
```

### External Redis

```yaml
redis:
  enabled: false
externalRedis:
  host: "your-elasticache.xyz.use1.cache.amazonaws.com"
  port: 6379
  tls: true
```

### Database Connections

Each Ishastra process keeps its own asyncpg pool, so the pool size has to fit the
whole fleet:

| Env var | Default | Meaning |
|---------|---------|---------|
| `ISHASTRA_PG_POOL_MIN` | `1` | Idle connections kept per process |
| `ISHASTRA_PG_POOL_MAX` | `5` | Peak connections per process (clamped to 50) |

`ISHASTRA_PG_POOL_MAX × replicas` must stay under PostgreSQL's `max_connections`.
At the production maximum of 30 workers the default of 5 would ask for 150
connections — set it lower on the workers, or put PgBouncer in front:

```yaml
worker:
  env:
    ISHASTRA_PG_POOL_MAX: "2"
```

### Database Backups

`backup.enabled` runs `ishastra backup` on a schedule. Every artifact is verified
before the job exits, and artifacts past the retention window are pruned.

| Value | Default | Description |
|-------|---------|-------------|
| `backup.enabled` | `false` | Render the backup CronJob |
| `backup.schedule` | `0 * * * *` | Cron schedule |
| `backup.directory` | `/var/lib/ishastra/backups` | Where artifacts go; point it at an RWX/NFS claim to keep backups off the primary host |
| `backup.retentionDays` | `14` | Delete artifacts older than this |
| `backup.timeoutSeconds` | `900` | Job deadline |
| `backup.claimName` | `pvc.strixData.name` | Existing claim holding the database |

```bash
# Verify an artifact (SQLite snapshot or pg_dump archive)
kubectl exec deploy/ishastra-api -- ishastra backup --verify /var/lib/ishastra/backups/ishastra-<ts>.db
# Restore and promote, see DEPLOYMENT.md §9
ishastra standby-promote --backup-dir /var/lib/ishastra/backups --db-path "$ISHASTRA_DATABASE_URL"
```

## Secrets Management

### SealedSecrets

```yaml
secrets:
  sealedSecrets:
    enabled: true
    secretName: ishastra-secrets
```

```bash
# Seal secrets
cat secret.yaml | kubeseal --format yaml --cert pub-cert.pem > sealed-secrets.yaml
```

### External Secrets Operator

```yaml
secrets:
  externalSecrets:
    enabled: true
    provider: aws
    secretStore:
      name: aws-secretsmanager
      provider:
        aws:
          service: SecretsManager
          region: us-east-1
```

## Upgrading

```bash
# Upgrade with new values
helm upgrade ishastra . -f values-prod.yaml -n ishastra-system

# Upgrade chart version
helm upgrade ishastra oci://ghcr.io/ishastra/charts/ishastra --version 3.5.1 -f values-prod.yaml -n ishastra-system

# Check history
helm history ishastra -n ishastra-system
```

## Rollback

```bash
# Rollback to previous
helm rollback ishastra -n ishastra-system

# Rollback to specific revision
helm rollback ishastra 3 -n ishastra-system
```

## Uninstalling

```bash
# Delete release
helm uninstall ishastra -n ishastra-system

# Delete namespace (optional)
kubectl delete namespace ishastra-system

# Delete PVCs (if not using external DB)
kubectl delete pvc -n ishastra-system -l app=postgresql
kubectl delete pvc -n ishastra-system -l app=redis
```

## Troubleshooting

### Check Chart Status

```bash
# List releases
helm list -n ishastra-system

# Get manifest
helm get manifest ishastra -n ishastra-system

# Get values
helm get values ishastra -n ishastra-system
```

### Debug Templates

```bash
# Render templates without installing
helm template ishastra . -f values-prod.yaml -n ishastra-system

# With debug
helm template ishastra . -f values-prod.yaml -n ishastra-system --debug
```

### Common Issues

| Issue | Fix |
|-------|-----|
| ImagePullBackOff | Check `imagePullSecrets`, registry access |
| Pending pods | Check resources, node selectors, PVCs |
| ConfigMap not updating | Restart pods: `kubectl rollout restart deploy/ishastra-api` |
| Ingress not working | Check className, annotations, TLS secret |

## Custom Values Example

```yaml
# values-custom.yaml
global:
  imageRegistry: "my-registry.io"

api:
  replicaCount: 5
  resources:
    limits:
      memory: "8Gi"
  env:
    - name: CUSTOM_VAR
      value: "production"

worker:
  replicaCount: 10
  autoscaling:
    maxReplicas: 200

ingress:
  hosts:
    - host: api.prod.company.com
      paths: ["/"]

monitoring:
  grafana:
    enabled: true
```

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Free Tier Deployment](../deployment/free-tier.md)
- [Docker Compose](../deployment/docker-compose.md)
- [Production Quickstart](../quickstart/production.md)