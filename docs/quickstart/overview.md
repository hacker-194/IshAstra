# Quick Start Overview

# Quick Start Overview

Get Strix running in under 5 minutes.

## Prerequisites

- Python 3.12+
- Docker (for local development)
- Git

## Installation Options

### Option 1: Free Tier Cloud (Recommended for Production)

Deploy to Oracle Cloud Always Free + Neon + Upstash + Cloudflare in one command:

```bash
git clone https://github.com/strix/strix
cd strix
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```

**What you get:**
- HA k0s Kubernetes cluster on 2x Oracle ARM instances (4 OCPU, 24GB RAM each)
- Neon serverless PostgreSQL (0.5 GB free tier)
- Upstash serverless Redis (256 MB free tier)
- Cloudflare Tunnel ingress (zero public IP, automatic DDoS protection)
- SealedSecrets for git-safe secret management
- Prometheus + Grafana monitoring stack
- Full Strix API at `https://api.yourdomain.com`

See [Free Tier Deployment](free-tier.md) for details.

### Option 2: Local Development (Docker Compose)

```bash
git clone https://github.com/strix/strix
cd strix
docker-compose up -d
```

**Services started:**
- Strix API: http://localhost:8000
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### Option 3: Local Kubernetes (Kind)

```bash
./scripts/bootstrap-kind.sh
```

Creates a local Kind cluster with all Strix components.

## Verify Installation

```bash
# Health check
curl http://localhost:8000/health

# Should return:
# {"status":"healthy","version":"3.5.0","scope_gate":"active"}
```

## First Assessment

```bash
# Create a scope document
cat > my-scope.json <<'EOF'
{
  "version": "2",
  "metadata": {"name": "My Assessment", "owner": "team@example.com"},
  "authorized_networks": ["10.0.0.0/8", "192.168.0.0/16"],
  "include_hosts": ["api.example.com", "app.example.com"],
  "exclude_hosts": ["admin.example.com"],
  "allowed_ports": [80, 443, 8080, 8443]
}
EOF

# Submit assessment
curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $STRIX_API_KEY" \
  -d '{"scope_path": "my-scope.json", "targets": ["https://api.example.com"]}'
```

## Next Steps

- [Free Tier Deployment](free-tier.md) — Production deployment guide
- [Local Development](local-dev.md) — Development workflow
- [Production Deployment](production.md) — Enterprise deployment
- [Scope Gate Concepts](../scope-gate/concepts.md) — Understand authorization
- [API Reference](../api/authentication.md) — Full API documentation