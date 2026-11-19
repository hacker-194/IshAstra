# Helm Deployment

# Helm Deployment

Deploy Strix using the official Helm chart with production-ready defaults.

## Chart Overview

```
strix/
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
helm pull oci://ghcr.io/strix/charts/strix --version 3.5.0 --untar

# Install
cd strix
helm install strix . -f values-prod.yaml -n strix-system --create-namespace
```

### From Local Source

```bash
cd deploy/helm/strix
helm install strix . -f values-prod.yaml -n strix-system --create-namespace
```

### With Custom Values

```bash
helm install strix . \
  -f values-prod.yaml \
  -f values-custom.yaml \
  -n strix-system --create-namespace
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
    meta.helm.sh/release-name: strix
```

### API Deployment

```yaml
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
    - name: STRIX_SCOPE_DOC_PATH
      value: "/config/scope.json"
```

### Worker Deployment

```yaml
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
    metrics:
    - type: External
      external:
        metric:
          name: strix_queue_depth
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
```

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
    - secretName: strix-tls
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
  database: "strix"
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

## Secrets Management

### SealedSecrets

```yaml
secrets:
  sealedSecrets:
    enabled: true
    secretName: strix-secrets
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
helm upgrade strix . -f values-prod.yaml -n strix-system

# Upgrade chart version
helm upgrade strix oci://ghcr.io/strix/charts/strix --version 3.5.1 -f values-prod.yaml -n strix-system

# Check history
helm history strix -n strix-system
```

## Rollback

```bash
# Rollback to previous
helm rollback strix -n strix-system

# Rollback to specific revision
helm rollback strix 3 -n strix-system
```

## Uninstalling

```bash
# Delete release
helm uninstall strix -n strix-system

# Delete namespace (optional)
kubectl delete namespace strix-system

# Delete PVCs (if not using external DB)
kubectl delete pvc -n strix-system -l app=postgresql
kubectl delete pvc -n strix-system -l app=redis
```

## Troubleshooting

### Check Chart Status

```bash
# List releases
helm list -n strix-system

# Get manifest
helm get manifest strix -n strix-system

# Get values
helm get values strix -n strix-system
```

### Debug Templates

```bash
# Render templates without installing
helm template strix . -f values-prod.yaml -n strix-system

# With debug
helm template strix . -f values-prod.yaml -n strix-system --debug
```

### Common Issues

| Issue | Fix |
|-------|-----|
| ImagePullBackOff | Check `imagePullSecrets`, registry access |
| Pending pods | Check resources, node selectors, PVCs |
| ConfigMap not updating | Restart pods: `kubectl rollout restart deploy/strix-api` |
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