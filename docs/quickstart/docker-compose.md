# Docker Compose Quickstart

Run the full Ishastra stack locally in under 5 minutes.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- 4 GB RAM available for containers
- Ports 5432, 6379, 8000, 8080, 3000, 9090 free on localhost

## One-Command Start

```bash
git clone https://github.com/hacker-194/IshAstra
cd ishastra

# Copy environment template and set passwords
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD, GRAFANA_PASSWORD

docker compose up -d
```

## Services

| Service | URL | Purpose |
|---------|-----|---------|
| **Ishastra API** | http://localhost:8000 | Main API (scope-gate) |
| **Egress Gateway** | http://localhost:8080 | Worker CONNECT proxy |
| **Worker Manager** | (internal) | Spawns disposable scan workers |
| **PostgreSQL** | localhost:5432 | Primary database |
| **Redis** | localhost:6379 | Queue / cache / rate limiting |
| **Prometheus** | http://localhost:9090 | Metrics collection |
| **Grafana** | http://localhost:3000 | Dashboards (admin / $GRAFANA_PASSWORD) |
| **Jaeger** | http://localhost:16686 | Distributed tracing |
| **nginx** | http://localhost / https://localhost | TLS termination (optional) |
| **Keycloak** | http://localhost:8180 | SSO (profile: `sso`) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Host                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  ishastra-   │  │  ishastra-   │  │   ishastra-worker-   │  │
│  │  network     │  │  worker-net  │  │   net (INTERNAL)     │  │
│  │  172.28.0.0  │  │  172.29.0.0  │  │                      │  │
│  │              │  │              │  │  ┌────────────────┐  │  │
│  │ ┌──────────┐ │  │ ┌──────────┐ │  │  │ Worker         │  │  │
│  │ │ Postgres │ │  │ │ Egress   │ │  │  │ Containers     │  │  │
│  │ │  :5432   │ │  │ │ Gateway  │ │  │  │ (ephemeral)    │  │  │
│  │ └──────────┘ │  │ │ :8080    │ │  │  └────────────────┘  │  │
│  │ ┌──────────┐ │  │ └──────────┘ │  │       ▲              │  │
│  │ │  Redis   │ │  │ ┌──────────┐ │  │       │              │  │
│  │ │  :6379   │ │  │ │ Worker   │ │  │       │ Capability   │  │
│  │ └──────────┘ │  │ │ Manager  │ │  │       │ Token +      │  │
│  │ ┌──────────┐ │  │ └──────────┘ │  │       │ Egress Proxy │  │
│  │ │Scope-Gate│◄─┼──┤              │  │       │              │  │
│  │ │  :8000   │ │  │              │  │       │              │  │
│  │ └──────────┘ │  │              │  │       │              │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         ▲                ▲                                        │
│         │                │                                        │
│    ┌────┴────┐    ┌─────┴─────┐                                  │
│    │ Prometheus│  │ Grafana   │                                  │
│    │  :9090   │  │  :3000    │                                  │
│    └─────────┘  └───────────┘                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Network Isolation

The `ishastra-worker-net` (172.29.0.0/16) is an **internal** Docker network:

- No outbound internet access
- Workers can **only** reach the egress gateway at `172.29.0.2:8080`
- Host-level nftables rules (optional) enforce this at the kernel level

### Enable Host Firewall (Linux only, requires root)

```bash
# Run the firewall init container (applies nftables rules)
docker compose --profile firewall up egress-firewall
```

This creates an `inet ishaistra_egress` table with a `worker_egress` chain on the `forward` hook that:
1. Accepts established/related traffic
2. Allows `172.29.0.0/16` → `172.29.0.2:8080` (egress gateway)
3. Drops cloud metadata IPs (169.254.169.254, 169.254.170.2, 100.100.100.200)
4. Drops all other traffic from `172.29.0.0/16`

> **Note:** The egress gateway (CONNECT proxy) is the **primary** control. It validates capability tokens on every request. The nftables rules are defense-in-depth.

## First Scan in < 5 Minutes

```bash
# 1. Start the stack
docker compose up -d

# 2. Wait for health checks (30-60s)
docker compose ps
# All services should show "healthy" or "running"

# 3. Get API key from logs
docker compose logs scope-gate | grep "API key"

# 4. Run a test assessment
export ISHASTRA_API_KEY=<key-from-logs>
curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://httpbin.org",
    "profile": "quick",
    "scope": {"include": ["httpbin.org"], "allowed_ports": [443]}
  }'

# 5. Poll for results
curl http://localhost:8000/api/v1/assessments/<job_id> \
  -H "Authorization: Bearer $ISHASTRA_API_KEY"
```

**Expected timeline:**
- `docker compose up -d` → ~30s (images cached) to ~3min (first pull)
- Health checks pass → ~30s
- First assessment (quick profile) → ~60-120s
- **Total: < 5 minutes**

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `POSTGRES_PASSWORD` | — | **Yes** | PostgreSQL password |
| `GRAFANA_PASSWORD` | — | **Yes** | Grafana admin password |
| `ISHASTRA_OIDC_ISSUER` | — | No | OIDC issuer URL |
| `ISHASTRA_OIDC_CLIENT_ID` | — | No | OIDC client ID |
| `ISHASTRA_OIDC_CLIENT_SECRET` | — | No | OIDC client secret |
| `ISHASTRA_OIDC_REDIRECT_URI` | — | No | OIDC redirect URI |
| `KEYCLOAK_ADMIN_PASSWORD` | — | Profile `sso` | Keycloak admin password |

See `.env.example` for all options.

## Development Mode

Mount source for hot reload:

```bash
# Already configured in docker-compose.yml for scope-gate:
# volumes:
#   - ./src:/app/src:ro

# Make changes to src/ishastra/... and the API reloads automatically
```

## Common Operations

```bash
# View logs
docker compose logs -f scope-gate
docker compose logs -f worker-manager
docker compose logs -f egress-gateway

# Restart a service
docker compose restart scope-gate

# Run one-off commands
docker compose exec scope-gate ishastra --help
docker compose exec postgres psql -U ishastra -d ishastra

# Stop and remove volumes (full reset)
docker compose down -v

# Scale workers (via worker-manager config)
# Edit ISHASTRA_WORKERS in .env and restart worker-manager
```

## Troubleshooting

### Port Conflicts
```bash
# Check what's using ports
lsof -i :5432 -i :6379 -i :8000 -i :8080 -i :3000 -i :9090

# Change ports in docker-compose.yml (host side only)
# ports:
#   - "15432:5432"  # Postgres on 15432
```

### Database Connection Issues
```bash
# Check PostgreSQL logs
docker compose logs postgres

# Verify connectivity from scope-gate
docker compose exec scope-gate pg_isready -h postgres -U ishastra
```

### Worker Network Issues
```bash
# Verify worker-net exists and is internal
docker network inspect ishastra-worker-net

# Test egress gateway from worker-net namespace
docker run --rm --network ishastra-worker-net alpine:3.20 \
  wget -qO- http://egress-gateway:8080/health
```

### Firewall Not Applying
```bash
# Must run on Linux host with root
# Check nftables rules
sudo nft list table inet ishaistra_egress

# Manual apply (for debugging)
sudo nft -f deploy/firewall/ishastra_egress.nft
```

### First Scan Slow / Timeout
- Increase `ISHASTRA_WORKER_TIMEOUT` (default 300s)
- Check worker-manager logs: `docker compose logs worker-manager`
- Ensure Docker daemon has resources (CPU/memory limits in compose)

## Production Considerations

This compose file is for **local development and quickstart only**. For production:

1. **Use managed PostgreSQL** (RDS, CloudSQL, Neon) — not the compose container
2. **Use managed Redis** (ElastiCache, Upstash) — not the compose container
3. **Run on Kubernetes** — see `k8s/` and `docs/deployment/kubernetes.md`
4. **Enable TLS** — nginx + cert-manager or Cloudflare Tunnel
5. **Set resource limits** — adjust `deploy.resources` for your node sizes
6. **Configure backups** — PostgreSQL PITR, Redis AOF/RDB
7. **Rotate secrets** — use Vault or SealedSecrets, not `.env`

## Profiles

```bash
# With SSO (Keycloak)
docker compose --profile sso up -d

# With host firewall (Linux root required)
docker compose --profile firewall up -d

# Both
docker compose --profile sso --profile firewall up -d
```

## File Structure

```
.
├── docker-compose.yml              # This file
├── Dockerfile                      # Multi-stage build (builder + runtime)
├── deploy/
│   ├── firewall/
│   │   └── ishaistra_egress.nft    # nftables rules for worker-net
│   ├── monitoring/
│   │   ├── prometheus.yml
│   │   └── grafana/
│   ├── nginx/
│   │   └── nginx.conf
│   └── keycloak/
│       └── realm-export.json
├── examples/
│   ├── scopes/                     # Scope documents (mounted to scope-gate)
│   ├── jwks/                       # JWKS for scope verification
│   └── keys/                       # Capability signing keys
└── src/ishastra/                   # Source code (mounted for dev)
```

## Next Steps

- [Local Development](local-dev.md) — Development workflow, debugging, tests
- [Free Tier Deployment](free-tier.md) — $0/month on Oracle Cloud + Coolify
- [Production Deployment](production.md) — Kubernetes, Helm, managed services
- [Architecture Overview](../architecture/overview.md) — System design docs