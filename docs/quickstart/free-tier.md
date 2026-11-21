# Free Tier Deployment — $0/month Production

Deploy **Ishastra** to Oracle Cloud Always Free + **Coolify** (self-hosted PaaS) with zero monthly cost.

> Sizes below use the **2 OCPU / 12 GB** Always Free Arm allowance (halved from
> 4 OCPU / 24 GB in June 2026). Sign-up, reclamation and home-region rules are in
> [Free tier deployment](../deployment/free-tier.md).

## Architecture (Coolify)

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
│  AMD Instance (1/8 OCPU, 6GB) — Optional: CI runner                         │
│                                                                              │
│  Your Domain → Cloudflare (DNS, TLS, WAF) → Oracle ARM:80/443               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **Oracle Cloud Account** — [Sign up](https://cloud.oracle.com/free) for Always Free tier
2. **Cloudflare Account** — [Free plan](https://dash.cloudflare.com/sign-up) for DNS, TLS, WAF, Tunnel
3. **GitHub Account** — For GHCR (container registry) and Actions
4. **Domain name** — Or use Cloudflare Pages subdomain

## Step-by-Step Deployment

### 1. Reserve Oracle Resources

**ARM Instance (Main):**
- Shape: `VM.Standard.A1.Flex` → 2 OCPU, 12 GB RAM (the whole Always Free Arm allowance)
- Image: Ubuntu 22.04 Minimal
- Security lists: Allow 22, 80, 443

**AMD Instance (Optional CI):**
- Shape: `VM.Standard.E2.1.Micro` → 1/8 OCPU, 6 GB RAM

### 2. Initialize ARM Server

```bash
ssh ubuntu@<ARM_IP>

sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-plugin git curl jq
sudo usermod -aG docker ubuntu
newgrp docker

# Enable swap (critical)
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 3. Install Coolify

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
# Follow prompts: Docker type, URL, encryption key, admin user
```

Access Coolify at `http://<ARM_IP>:8000`

### 4. Configure Coolify

1. **Servers** → Add ARM as "Local"
2. **Projects** → Create "ishastra"
3. **Databases** → Add PostgreSQL 16 (`ishastra-db`) + Redis 7 (`ishastra-redis`)

### 5. Build & Push Images (Local Machine)

```bash
git clone https://github.com/<YOUR_USER>/ishastra.git
cd ishastra

echo <GHCR_TOKEN> | docker login ghcr.io -u <YOUR_USER> --password-stdin

make build-and-push REGISTRY=ghcr.io/<YOUR_USER> TAG=v3.5.0
```

### 6. Deploy via Coolify

1. **Applications** → New → **Docker Compose**
2. Repository: Your GitHub fork
3. Build pack: Docker Compose → File: `docker-compose.yml`
4. Enable "Pull on deploy"

**Environment Variables:**
| Variable | Value |
|----------|-------|
| `ISHASTRA_DATABASE_URL` | `postgresql://postgres:<PASS>@ishastra-db:5432/ishastra` |
| `ISHASTRA_REDIS_URL` | `redis://ishastra-redis:6379/0` |
| `ISHASTRA_SCOPE_FILE` | `/etc/ishastra/scope.json` |
| `ISHASTRA_ENCRYPTION_KEY` | `openssl rand -base64 32` |
| `ISHASTRA_AUDIT_HMAC_KEY` | `openssl rand -base64 32` |
| `ISHASTRA_WORKERS` | `2` |
| `ISHASTRA_LOG_FORMAT` | `json` |
| `ISHASTRA_LOG_LEVEL` | `INFO` |

**Volumes:** Add Config Map `ishastra-scope` → `scope.json` → Mount `/etc/ishastra/scope.json`

**Ports:** 8000 (HTTP) | **Health:** `/api/health` | **Deploy!**

### 7. Configure Domain

Coolify → Application → Domains → Add `ishastra.yourdomain.com` → Force HTTPS → Save

## Post-Deployment

```bash
# Verify API
curl https://ishastra.yourdomain.com/api/health

# Open UI
open https://ishastra.yourdomain.com

# Create API key: Settings → API Keys → New
# Run first assessment: Dashboard → Assessments → New
```

## Cost Breakdown

| Service | Free Tier Limit | Ishastra Usage |
|---------|----------------|----------------|
| Oracle ARM Compute | 2 OCPU, 12 GB | Coolify + DB + API + Worker |
| Oracle AMD Compute | 1/8 OCPU, 6 GB | Optional CI runner |
| Oracle Block Vol | 200 GB | OS + containers + DB data |
| Cloudflare | Unlimited | DNS, TLS, WAF, CDN, Tunnel |
| GHCR | 500 MB | 5 multi-arch images |
| GitHub Actions | 2000 min/mo | CI/CD |

**Total: $0/month**

## Troubleshooting

### Oracle ARM "Out of Capacity"
Try different availability domain; check back later.

### Coolify Deploy Fails
```bash
# Check logs in Coolify dashboard → Application → Logs
# Verify docker-compose.yml syntax locally:
docker compose config
```

### Database Connection Refused
- Verify `ISHASTRA_DATABASE_URL` matches Coolify Postgres credentials
- Check Coolify → Databases → Postgres → Connection info

### Scope Gate Blocks Scans
- Ensure `scope.json` includes target domain
- If signed: verify JWKS URL is public and `ISHASTRA_SCOPE_JWKS_URL` set

### Certificates Not Issuing
- Domain A record → ARM public IP
- Port 80 open on Oracle security list
- Cloudflare proxy ON (orange cloud)

## Scaling Beyond Free Tier

When you outgrow free limits:
1. **Vertical**: Increase ARM OCPU/RAM (Oracle paid)
2. **Horizontal**: Add second ARM instance → Coolify multi-server
3. **Managed DB**: Migrate to Neon Pro / AWS RDS / CloudSQL for PITR, replicas
4. **Managed Redis**: Upstash Pro / ElastiCache for multi-AZ
5. **Orchestration**: Coolify → Helm + ArgoCD on managed K8s (EKS/GKE/AKS)
6. **Observability**: Grafana Cloud / self-hosted Prometheus stack

See [Kubernetes Deployment](../deployment/kubernetes.md) or [Helm Deployment](../deployment/helm.md).