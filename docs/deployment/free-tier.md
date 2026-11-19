# Free Tier Deployment

# Free Tier Deployment

Run Strix for $0/month using Oracle Cloud Free Tier, Neon, Upstash, Cloudflare, and GHCR.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Free Tier Architecture ($0/month)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                 │
│  │   Cloudflare │────▶│  Oracle ARM  │◀───▶│    Neon      │                 │
│  │   (DNS, TLS, │     │  (4 Ampere,  │     │  (PostgreSQL,│                 │
│  │   WAF, CDN)  │     │   24GB RAM)  │     │   512MB)     │                 │
│  └──────────────┘     └──────┬───────┘     └──────────────┘                 │
│                             │                                               │
│                    ┌────────▼────────┐     ┌──────────────┐                 │
│                    │   k0s Cluster   │◀───▶│   Upstash    │                 │
│                    │  (k3s/k0s)      │     │  (Redis,     │                 │
│                    │  Strix Pods     │     │   256MB)     │                 │
│                    └─────────────────┘     └──────────────┘                 │
│                                                                              │
│  Container Images: GHCR (1GB free)                                           │
│  Monitoring: Cloudflare Analytics + Prometheus (self-hosted)                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Resource Limits (Free Tier)

| Resource | Limit | Strix Usage |
|----------|-------|-------------|
| Oracle ARM | 4 OCPU, 24GB RAM | API (1C/2G), Worker (2C/4G), Scheduler (0.5C/0.5G) |
| Neon PostgreSQL | 512MB storage | ~100MB for assessments |
| Upstash Redis | 256MB storage | Queue + cache |
| Cloudflare | Unlimited requests | DNS, TLS, WAF, CDN |
| GHCR | 1GB storage | ~500MB for 3 images |
| Oracle Boot Volume | 200GB | OS + containers |

## Prerequisites

- Oracle Cloud account (Always Free tier)
- Cloudflare account (free)
- Neon account (free tier)
- Upstash account (free tier)
- GitHub account (for GHCR)
- Domain name (or use Cloudflare Pages subdomain)

## Step 1: Oracle Cloud Setup

### Create VM Instance

```bash
# Via Oracle Cloud Console:
# 1. Create VM instance: "VM.Standard.A1.Flex" (ARM)
# 2. Shape: 4 OCPU, 24GB RAM
# 3. Image: Ubuntu 22.04 Minimal
# 4. SSH keys: Add your public key
# 5. Network: Create VCN with public subnet
# 6. Security lists: Allow 22, 80, 443, 6443 (k0s)
```

### Initialize Server

```bash
ssh ubuntu@<oracle-ip>

# Update and install basics
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-plugin git curl jq

# Add user to docker group
sudo usermod -aG docker ubuntu
newgrp docker

# Verify
docker run hello-world
```

### Install k0s (Lightweight Kubernetes)

```bash
# Download and install k0s
curl -sSLf https://get.k0s.sh | sudo sh

# Create config
sudo mkdir -p /etc/k0s
cat <<EOF | sudo tee /etc/k0s/k0s.yaml
apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
metadata:
  name: strix-free
spec:
  api:
    address: 0.0.0.0
    port: 6443
    extraArgs:
      enable-admission-plugins: "NodeRestriction,PodSecurityPolicy"
  controllerManager:
    extraArgs:
      bind-address: "0.0.0.0"
  scheduler:
    extraArgs:
      bind-address: "0.0.0.0"
  network:
    provider: kube-router
    calico: {}
  storage:
    type: local
    localPath:
      path: /var/lib/k0s/local-path-provisioner
  telemetry:
    enabled: false
EOF

# Start k0s
sudo k0s install controller --single --config /etc/k0s/k0s.yaml
sudo k0s start

# Get kubeconfig
sudo k0s kubeconfig admin > ~/kubeconfig
export KUBECONFIG=~/kubeconfig

# Verify
kubectl get nodes
```

## Step 2: Cloudflare Setup

### DNS Configuration

```
Type    Name    Content                  Proxy
A       @       <oracle-ip>              Proxied
A       api     <oracle-ip>              Proxied
CNAME   www     yourdomain.com           Proxied
```

### SSL/TLS Settings

- SSL/TLS encryption mode: **Full (strict)**
- Always Use HTTPS: **On**
- Automatic HTTPS Rewrites: **On**

### Workers (Optional - for auth)

```javascript
// Cloudflare Worker for API key validation
export default {
  async fetch(request, env) {
    const apiKey = request.headers.get("Authorization")?.replace("Bearer ", "");
    if (!apiKey || !await validateKey(apiKey, env)) {
      return new Response("Unauthorized", { status: 401 });
    }
    return fetch(request);
  }
}
```

## Step 3: Neon Database

### Create Project

1. Go to console.neon.tech
2. Create project: `strix-free`
3. Region: US East (closest to Oracle)
4. Copy connection string

```
postgresql://user:pass@ep-xxx.us-east-1.aws.neon.tech/strix?sslmode=require
```

### Run Migrations

```bash
# From local machine
export DATABASE_URL="postgresql://user:pass@ep-xxx.us-east-1.aws.neon.tech/strix?sslmode=require"
docker run --rm -e DATABASE_URL ghcr.io/strix/strix:3.5.0 alembic upgrade head
```

## Step 4: Upstash Redis

### Create Database

1. Go to console.upstash.com
2. Create database: `strix-free`
3. Region: US East
4. Type: Regional (free)
5. Copy REST URL and token

```
UPSTASH_REDIS_REST_URL=https://xxx.upstash.io
UPSTASH_REDIS_REST_TOKEN=xxx
```

### Convert to Redis URL

```bash
# Upstash REST to Redis URL format
redis://:TOKEN@HOST:6379/0
# Example:
redis://:abc123@us1-xxx.upstash.io:6379/0
```

## Step 5: GHCR Images

### Build and Push

```bash
# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Build images
docker build -t ghcr.io/your-org/strix-api:3.5.0 -f Dockerfile.api .
docker build -t ghcr.io/your-org/strix-worker:3.5.0 -f Dockerfile.worker .
docker build -t ghcr.io/your-org/strix-scheduler:3.5.0 -f Dockerfile.scheduler .

# Push
docker push ghcr.io/your-org/strix-api:3.5.0
docker push ghcr.io/your-org/strix-worker:3.5.0
docker push ghcr.io/your-org/strix-scheduler:3.5.0
```

### Create Image Pull Secret

```bash
# On Oracle VM
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=YOUR_GITHUB_TOKEN \
  --namespace=strix-system
```

## Step 6: Deploy Strix

### Create Namespace

```bash
kubectl create namespace strix-system
```

### Create ConfigMap (Scope Document)

```bash
# Create scope.json first (see Scope Gate docs)
kubectl create configmap strix-scope \
  --from-file=scope.json=/path/to/scope.json \
  -n strix-system
```

### Create Secrets

```bash
kubectl create secret generic strix-secrets \
  --from-literal=database-url="postgresql://user:pass@ep-xxx.us-east-1.aws.neon.tech/strix?sslmode=require" \
  --from-literal=redis-url="redis://:token@us1-xxx.upstash.io:6379/0" \
  --from-literal=jwt-secret="$(openssl rand -base64 32)" \
  --from-literal=api-key="strix-$(openssl rand -hex 16)" \
  -n strix-system
```

### Deploy with Helm (Free Tier Values)

```bash
# Get Helm chart
git clone https://github.com/strix/strix.git
cd strix/deploy/helm/strix

# Install with free tier values
helm install strix . -f values-free.yaml -n strix-system
```

### values-free.yaml

```yaml
# deploy/helm/strix/values-free.yaml

global:
  imageRegistry: ghcr.io
  imagePullSecrets:
    - ghcr-secret

api:
  replicaCount: 1
  image:
    repository: your-org/strix-api
    tag: "3.5.0"
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
  image:
    repository: your-org/strix-worker
    tag: "3.5.0"
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
  image:
    repository: your-org/strix-scheduler
    tag: "3.5.0"
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
    requests:
      cpu: "50m"
      memory: "128Mi"

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
  host: "us1-xxx.upstash.io"
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
    serviceMonitor: true
  grafana:
    enabled: false  # Disable to save resources
```

## Step 7: Verify Deployment

```bash
# Check pods
kubectl get pods -n strix-system -w

# Check logs
kubectl logs -n strix-system -l app=strix-api
kubectl logs -n strix-system -l app=strix-worker

# Test API
curl https://api.yourdomain.com/health

# Test assessment
curl -X POST https://api.yourdomain.com/api/v1/assessments \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_id": "default",
    "targets": ["https://httpbin.org"],
    "adapters": ["http_probe"]
  }'
```

## Cost Breakdown

| Service | Monthly Cost | Notes |
|---------|--------------|-------|
| Oracle ARM VM | $0 | Always Free: 4 OCPU, 24GB |
| Neon PostgreSQL | $0 | Free: 512MB storage |
| Upstash Redis | $0 | Free: 256MB storage |
| Cloudflare | $0 | Free: DNS, TLS, WAF, CDN |
| GHCR | $0 | Free: 1GB storage |
| **Total** | **$0** | |

## Scaling Limits

| Component | Free Tier Max | Upgrade Path |
|-----------|---------------|--------------|
| API replicas | 3 | Increase Oracle OCPU or add nodes |
| Worker replicas | 5 | Add Oracle VM, use spot instances |
| Concurrent assessments | ~10 | Horizontal worker scaling |
| Assessment queue | 1000 | Redis upgrade (paid Upstash) |
| Database size | 512MB | Neon paid plan ($19/mo for 10GB) |
| Redis storage | 256MB | Upstash paid plan |

## Troubleshooting

### Common Issues

| Issue | Fix |
|-------|-----|
| Pods OOMKilled | Reduce memory limits, increase swap |
| ImagePullBackOff | Check GHCR secret, rate limits |
| Neon connection timeout | Check security groups, SSL mode |
| Upstash connection refused | Verify TLS, correct host/port |
| Ingress 502 | Check Cloudflare proxy, k0s port |

### Resource Monitoring

```bash
# Node resources
kubectl top nodes

# Pod resources
kubectl top pods -n strix-system

# Check events
kubectl get events -n strix-system --sort-by='.lastTimestamp'
```

### Oracle ARM Specific

```bash
# Enable swap (critical for 24GB RAM)
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Check ARM compatibility
docker run --rm --platform linux/arm64 ghcr.io/your-org/strix-api:3.5.0 --version
```

## Upgrade Path

### To Production

1. **Database**: Neon Pro ($19/mo) → 10GB, read replicas, PITR
2. **Redis**: Upstash Pro → 1GB, multi-AZ, persistence
3. **Compute**: Oracle paid VMs or AWS/GCP/Azure managed K8s
4. **Monitoring**: Grafana Cloud or self-hosted stack
5. **Security**: Add WAF rules, SIEM integration

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Quick Start: Free Tier](../quickstart/free-tier.md)
- [Production Deployment](../quickstart/production.md)