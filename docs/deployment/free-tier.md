# Free Tier Deployment

Run **Ishastra** for **$0/month** using Oracle Cloud Free Tier + **Coolify** (self-hosted PaaS).

> **Always Free limits, checked November 2026.** The Arm allowance is **2 OCPU / 12 GB
> of memory in total** (1,500 OCPU-hours + 9,000 GB-hours per month). Oracle halved it
> from 4 OCPU / 24 GB in June 2026 and terminates instances above the new allowance, so
> size every A1 instance together, not each one. Also included: two AMD Micro VMs
> (1/8 OCPU, 1 GB each), 200 GB block storage, 10 TB egress. A debit/credit card is
> required at sign-up for identity verification — temporary holds only, nothing is
> charged inside the allowance. Resources must be created in your **home region**, and
> Oracle may reclaim an instance that stays under 20% CPU, network and (A1 only) memory
> over a 7-day window, so a scanner left idle can be reclaimed: keep it doing real work
> and keep off-box backups. Confirm your tenancy's numbers in the console before sizing.

> **Why Coolify?** It manages PostgreSQL, Redis, TLS certs, deployments, and rollbacks — no k0s/Helm complexity. Single ARM instance runs everything.

> **Scaling warning:** Free tier is single-writer (1 API, 1 worker replica). Do not enable HPA. See [Production deployment](../quickstart/production.md).

## Architecture (Coolify — Recommended)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Oracle Cloud Free Tier ($0/month)                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    ARM Instance (2 OCPU, 12GB RAM)                   │    │
│  │  ┌─────────────────────────────────────────────────────────────┐   │    │
│  │  │                      Coolify (Port 8000)                     │   │    │
│  │  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────┐  │   │    │
│  │  │  │PostgreSQL│  │  Redis   │  │   Ishastra │  │  Cloud-  │  │   │    │
│  │  │  │(managed) │  │(managed) │  │  API/Worker│  │  flared  │  │   │    │
│  │  │  └──────────┘  └──────────┘  └────────────┘  └──────────┘  │   │    │
│  │  └─────────────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  AMD Instance (1/8 OCPU, 6GB) — Optional: CI runner, monitoring             │
│                                                                              │
│  Your Domain → Cloudflare (DNS, TLS, WAF) → Oracle ARM:80/443               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Resource Limits (Free Tier)

| Resource | Limit | Ishastra Usage |
|----------|-------|----------------|
| Oracle ARM | 2 OCPU, 12GB RAM total | Coolify + Postgres + Redis + API (1C/2G) + Worker (1C/2G) |
| Oracle AMD | 1/8 OCPU, 6GB RAM | Optional: CI, monitoring |
| Oracle Boot Volume | 200GB | OS + containers + DB data |
| Cloudflare | Unlimited | DNS, TLS, WAF, CDN, Tunnel |
| GHCR | 1GB storage | ~500MB for 5 multi-arch images |

## Resource Limits (Free Tier)

| Resource | Limit | Ishastra Usage |
|----------|-------|-------------|
| Oracle ARM | 2 OCPU, 12GB RAM total | API (1C/2G), Worker (1C/3G), Scheduler (0.25C/0.5G) |
| Neon PostgreSQL | 512MB storage | ~100MB for assessments |
| Upstash Redis | 256MB storage | Queue + cache |
| Cloudflare | Unlimited requests | DNS, TLS, WAF, CDN |
| GHCR | 1GB storage | ~500MB for 3 images |
| Oracle Boot Volume | 200GB | OS + containers |

## Prerequisites

- Oracle Cloud account (Always Free tier)
- Cloudflare account (free)
- GitHub account (for GHCR)
- Domain name (or use Cloudflare Pages subdomain)

## Step 1: Oracle Cloud Setup

### Create VM Instances

**ARM Instance (Main — runs everything):**
```bash
# Via Oracle Cloud Console:
# 1. Create VM instance: "VM.Standard.A1.Flex" (ARM)
# 2. Shape: 1 OCPU, 6GB RAM (x2 instances = the 2 OCPU/12GB Always Free total)
# 3. Image: Ubuntu 22.04 Minimal
# 4. SSH keys: Add your public key
# 5. Network: Create VCN with public subnet
# 6. Security lists: Allow 22, 80, 443
```

**AMD Instance (Optional — CI runner):**
```bash
# 1. Create VM instance: "VM.Standard.E2.1.Micro" (AMD)
# 2. Shape: 1/8 OCPU, 6GB RAM
# 3. Same VCN, same SSH key
```

### Initialize ARM Server

```bash
ssh ubuntu@<ARM_PUBLIC_IP>

# Update and install basics
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-plugin git curl jq

# Add user to docker group
sudo usermod -aG docker ubuntu
newgrp docker

# Enable swap (the free 12GB instance is shared)
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Verify
docker run hello-world
```

### Install Coolify

```bash
# Coolify install (takes 5-10 min)
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash

# Follow prompts:
# - Choose "Docker" as installation type
# - Set Coolify URL (e.g., coolify.yourdomain.com) — or use IP:8000 initially
# - Generate encryption key (SAVE IT!)
# - Create admin user
```

After install, Coolify runs on port 8000. Access via `http://<ARM_IP>:8000`.

## Step 2: Cloudflare Setup

### DNS Configuration

```
Type    Name    Content                  Proxy
A       @       <ARM_PUBLIC_IP>          Proxied
A       api     <ARM_PUBLIC_IP>          Proxied
A       coolify <ARM_PUBLIC_IP>          Proxied
CNAME   www     yourdomain.com           Proxied
```

### SSL/TLS Settings

- SSL/TLS encryption mode: **Full (strict)**
- Always Use HTTPS: **On**
- Automatic HTTPS Rewrites: **On**

## Step 3: GitHub Container Registry (GHCR)

### Create GHCR Token

1. GitHub → Settings → Developer settings → Personal access tokens → Fine-grained
2. Name: `ishastra-ci`
3. Resource owner: your user/org
4. Repository access: Select your Ishastra fork
5. Permissions: `Packages` → Read/Write, `Contents` → Read
6. Generate token → Copy!

### Login Docker (Local Machine)

```bash
echo <GHCR_TOKEN> | docker login ghcr.io -u <YOUR_GITHUB_USER> --password-stdin
```

## Step 4: Build & Push Images

```bash
# Clone repo
git clone https://github.com/<YOUR_USER>/ishastra.git
cd ishastra

# Build and push all 5 images from single Dockerfile (multi-arch)
make build-and-push REGISTRY=ghcr.io/<YOUR_USER> TAG=v3.5.0
```

This pushes:
- `ghcr.io/<USER>/ishastra:v3.5.0` (base)
- `ghcr.io/<USER>/ishastra-operator:v3.5.0`
- `ghcr.io/<USER>/ishastra-api:v3.5.0`
- `ghcr.io/<USER>/ishastra-worker:v3.5.0`
- `ghcr.io/<USER>/ishastra-scheduler:v3.5.0`

### Verify Images

```bash
docker pull ghcr.io/<USER>/ishastra-api:v3.5.0
docker run --rm ghcr.io/<USER>/ishastra-api:v3.5.0 ishastra --version
```

## Step 5: Deploy via Coolify

### 5.1 Configure Coolify

1. Open `http://<ARM_IP>:8000` (or your Coolify domain)
2. **Servers** → Add your ARM instance as "Local" (auto-detected)
3. **Projects** → Create "ishastra"
4. **Databases** → Add PostgreSQL + Redis (Coolify manages these)
   - PostgreSQL: Name `ishastra-db`, Version 16
   - Redis: Name `ishastra-redis`, Version 7

### 5.2 Create Application

1. **Applications** → New → **Docker Compose**
2. Repository: Your GitHub fork (public or private with deploy key)
3. Build pack: **Docker Compose**
4. Compose file: `docker-compose.yml`
5. Enable "Pull on deploy"

### 5.3 Environment Variables

Click "Add" for each:

| Variable | Value | Description |
|----------|-------|-------------|
| `ISHASTRA_DATABASE_URL` | `postgresql://postgres:<PASS>@ishastra-db:5432/ishastra` | From Coolify Postgres |
| `ISHASTRA_REDIS_URL` | `redis://ishastra-redis:6379/0` | From Coolify Redis |
| `ISHASTRA_SCOPE_FILE` | `/etc/ishastra/scope.json` | Mounted config |
| `ISHASTRA_ENCRYPTION_KEY` | `<32-byte-base64>` | `openssl rand -base64 32` |
| `ISHASTRA_AUDIT_HMAC_KEY` | `<32-byte-base64>` | `openssl rand -base64 32` |
| `ISHASTRA_WORKERS` | `2` | Concurrency |
| `ISHASTRA_LOG_FORMAT` | `json` | Structured logs |
| `ISHASTRA_LOG_LEVEL` | `INFO` | |

### 5.4 Scope Configuration

1. Create `scope.json` locally:
```json
{
  "program": "My Security Program",
  "authorized_by": "John Doe",
  "authorization_ref": "CONTRACT-2024-001",
  "include": ["*.yourdomain.com", "api.yourdomain.com"],
  "exclude": ["admin.yourdomain.com"],
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "allowed_ports": [80, 443, 8080],
  "allow_broad_networks": false
}
```

2. **Optional — Sign scope** (recommended):
```bash
ishastra scope-keygen --kid key-1 --key scope-key.pem --jwks scope-jwks.json
ishastra scope-sign --scope scope.json --key scope-key.pem --kid key-1 --expires-in 30d
# Publish JWKS to public URL, set ISHASTRA_SCOPE_JWKS_URL
```

3. Coolify → Application → Volumes → New Volume → Config Map
   - Name: `ishastra-scope`
   - Key: `scope.json` → Value: (paste signed scope.json)
   - Mount Path: `/etc/ishastra/scope.json`

### 5.5 Ports & Health

- **Ports**: Expose 8000 (HTTP)
- **Health Check**: `/api/health`
- **Deploy!**

### 5.6 Configure Domain

1. Coolify → Application → Domains
2. Add `ishastra.yourdomain.com` (or `api.yourdomain.com`)
3. Enable **Force HTTPS** (Let's Encrypt auto)
4. Save → Coolify provisions cert

## Step 7: First Assessment

```bash
# Open UI
https://ishastra.yourdomain.com

# 1. Settings → API Keys → New → Name: admin-key → Copy key
# 2. Dashboard → Assessments → New Assessment
#    Target: https://api.yourdomain.com (or any authorized target)
#    Profile: web-deep
#    Run!
# 3. Watch findings populate in real-time
```

## Cost Breakdown

| Service | Monthly Cost | Notes |
|---------|--------------|-------|
| Oracle ARM VM | $0 | Always Free: 2 OCPU, 12GB total (changed June 2026) |
| Oracle AMD VM | $0 | Always Free: 1/8 OCPU, 6GB (optional CI) |
| Cloudflare | $0 | Free: DNS, TLS, WAF, CDN, Tunnel |
| GHCR | $0 | Free: 1GB storage |
| **Total** | **$0** | |

## Scaling Limits (Coolify Free Tier)

| Component | Free Tier Max | Upgrade Path |
|-----------|---------------|--------------|
| API replicas | 1 | Add RAM/CPU to ARM; paid Oracle or managed K8s |
| Worker replicas | 1 | Vertical scale; add second ARM instance |
| Concurrent assessments | ~5 | Horizontal worker scaling |
| Assessment queue | 5000 | Coolify Redis persistence; paid Upstash |
| Database size | ~10GB | Coolify Postgres on 200GB boot volume |
| Redis storage | ~5GB | Same |

## Troubleshooting

### Common Issues

| Issue | Fix |
|-------|-----|
| Deploy fails | Check Coolify logs; verify `docker-compose.yml` syntax |
| Database connection refused | Verify `ISHASTRA_DATABASE_URL` matches Coolify Postgres creds |
| Redis connection refused | Verify `ISHASTRA_REDIS_URL` uses `ishastra-redis:6379` |
| Scope gate blocks scans | Check scope.json includes target; verify JWKS URL if signed |
| Certificates not issuing | Ensure domain A record points to ARM IP; port 80 open |
| Container OOMKilled | Reduce memory limits in Coolify; increase swap |

### Resource Monitoring

```bash
# On ARM instance
docker stats

# Coolify dashboard → Server → Resources
# Coolify → Application → Logs

# Check swap
free -h
```

### Oracle ARM Specific

```bash
# Enable swap (the free 12GB instance is shared) — run once
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Check ARM compatibility
docker run --rm --platform linux/arm64 ghcr.io/<USER>/ishastra-api:v3.5.0 --version
```

## Upgrade Path

### To Production

1. **Database**: Coolify Postgres → Managed PostgreSQL (Neon Pro $19/mo, AWS RDS, CloudSQL) for PITR, read replicas
2. **Redis**: Coolify Redis → Managed Redis (Upstash Pro, AWS ElastiCache) for multi-AZ, persistence
3. **Compute**: Single ARM → Oracle paid VMs or AWS/GCP/Azure managed K8s (EKS/GKE/AKS)
4. **Orchestration**: Coolify → Helm + ArgoCD on K8s for GitOps
5. **Monitoring**: Coolify built-in → Grafana Cloud / Prometheus + Grafana stack
6. **Security**: Cloudflare WAF rules, SIEM integration, SLSA provenance on releases

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Quick Start: Free Tier](../quickstart/free-tier.md)
- [Production Deployment](../quickstart/production.md)