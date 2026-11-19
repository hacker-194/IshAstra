# Free Tier Deployment

# Free Tier Deployment — $0/month Production

Deploy Strix to Oracle Cloud Always Free + Neon + Upstash + Cloudflare with zero monthly cost.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Oracle Cloud Always Free                    │
│  ┌──────────────────┐         ┌──────────────────┐             │
│  │   ARM Instance 1 │         │   ARM Instance 2 │             │
│  │   (4 OCPU/24GB)  │◀──────▶│   (4 OCPU/24GB)  │             │
│  │   k0s Control    │         │   k0s Worker     │             │
│  └────────┬─────────┘         └────────┬─────────┘             │
│           │                            │                        │
│           ▼                            ▼                        │
│  ┌──────────────────────────────────────────────────┐          │
│  │              Cloudflare Tunnel                    │          │
│  │         (Zero public IP, DDoS protection)        │          │
│  └────────────────────┬─────────────────────────────┘          │
│                       │                                         │
│           ┌───────────┼───────────┐                             │
│           ▼           ▼           ▼                             │
│    ┌───────────┐ ┌─────────┐ ┌───────────┐                     │
│    │   Neon    │ │ Upstash │ │  GHCR     │                     │
│    │PostgreSQL │ │  Redis  │ │ (Images)  │                     │
│    │ (0.5 GB)  │ │(256 MB) │ │           │                     │
│    └───────────┘ └─────────┘ └───────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **Oracle Cloud Account** — [Sign up](https://cloud.oracle.com/free) for Always Free tier
2. **Cloudflare Account** — [Free plan](https://dash.cloudflare.com/sign-up) for Tunnel + DNS
3. **Neon Account** — [Free tier](https://neon.tech) for PostgreSQL
4. **Upstash Account** — [Free tier](https://upstash.com) for Redis
5. **GitHub Account** — For GHCR (container registry) and Actions

## One-Shot Bootstrap

```bash
git clone https://github.com/strix/strix
cd strix
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```

The script will prompt for:
- Oracle Cloud compartment OCID
- Cloudflare API token and zone
- Neon project connection string
- Upstash Redis URL and token
- Domain name for ingress

## What Gets Deployed

| Component | Configuration |
|-----------|---------------|
| **Kubernetes** | k0s HA (2 control planes, 1+ workers) |
| **Ingress** | Cloudflare Tunnel (no public IPs) |
| **Database** | Neon serverless PostgreSQL |
| **Cache** | Upstash serverless Redis |
| **Secrets** | SealedSecrets (git-safe) |
| **Monitoring** | Prometheus + Grafana |
| **Registry** | GHCR (GitHub Container Registry) |

## Post-Deployment

```bash
# Verify API
curl https://api.yourdomain.com/health

# Access Grafana
open https://grafana.yourdomain.com
# Login: admin / (from SealedSecret)

# Check Scope Gate metrics
curl https://api.yourdomain.com/metrics | grep scope_gate
```

## Cost Breakdown

| Service | Free Tier Limit | Strix Usage |
|---------|----------------|-------------|
| Oracle Compute | 2x ARM 4 OCPU/24GB | k0s cluster |
| Oracle Block Vol | 200 GB | k0s etcd + PV |
| Oracle LB | 1 | Cloudflare Tunnel |
| Neon PostgreSQL | 0.5 GB | Assessment data |
| Upstash Redis | 256 MB | Job queue + cache |
| Cloudflare | Unlimited | Tunnel + DNS + DDoS |
| GHCR | 500 MB | Container images |
| GitHub Actions | 2000 min/mo | CI/CD |

**Total: $0/month**

## Troubleshooting

### Oracle Instance Creation Fails
```bash
# Check quota
oci limits value list --service-name compute --compartment-id $COMPARTMENT_OCID
```

### Cloudflare Tunnel Not Connecting
```bash
# Check tunnel status
cloudflared tunnel list
cloudflared tunnel info $TUNNEL_ID
```

### Neon Connection Fails
```bash
# Test connection
psql "$NEON_DSN" -c "SELECT version();"
```

## Scaling Beyond Free Tier

When you outgrow free limits:
1. Upgrade Neon/Upstash to paid plans
2. Add Oracle worker nodes
3. Switch to `values-prod.yaml` Helm config
4. Scale vertically (one writer per database; autoscaling is not supported)

See [Kubernetes Deployment](../deployment/kubernetes.md) or [Helm Deployment](../deployment/helm.md).