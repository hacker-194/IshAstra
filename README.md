# Strix — Authorization-First Security Assessment Platform

[![License](https://img.shields.io/github/license/strix/strix)](LICENSE)
[![CI](https://github.com/strix/strix/actions/workflows/ci.yml/badge.svg)](https://github.com/strix/strix/actions)
[![Coverage](https://img.shields.io/codecov/c/github/strix/strix)](https://codecov.io/gh/strix/strix)
[![Slack](https://img.shields.io/badge/Slack-Join-blue)](https://slack.strix.dev)
[![Python](https://img.shields.io/badge/python-3.12+-blue)](https://python.org)
[![Kubernetes](https://img.shields.io/badge/k8s-1.28+-blue)](https://kubernetes.io)

> **The only security scanner that enforces authorization BEFORE every connection.**

## Why Strix?

| Feature | Strix | Nuclei | Trivy | OWASP ZAP | OpenVAS |
|---------|-------|--------|-------|-----------|---------|
| **Default-deny authorization** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Multi-tenant isolation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Cryptographic audit chain** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SARIF + compliance reports** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Runs Nuclei/nmap/SQLMap** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Policy-as-code (CIDR+ASN+Geo)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **DNS rebinding protection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Free-tier deployable** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **TLA+ formally verified** | ✅ | ❌ | ❌ | ❌ | ❌ |

## Quick Start (Free Tier — $0/month)

```bash
# One-shot bootstrap on Oracle Cloud Always Free
git clone https://github.com/strix/strix
cd strix
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```

**What you get:**
- HA k0s cluster on Oracle Always Free (2x ARM 4OCPU/24GB)
- Neon PostgreSQL (serverless, 0.5GB free)
- Upstash Redis (serverless, 256MB free)
- Cloudflare Tunnel ingress (zero public IP, DDoS protection)
- SealedSecrets for git-safe secret management
- Prometheus + Grafana monitoring
- Full Strix ScopeGate API at `https://api.yourdomain.com`

## Local Development (Docker Compose)

```bash
docker-compose up -d
# API at http://localhost:8000
# Grafana at http://localhost:3000 (admin/admin)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Strix Platform                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   REST API   │    │   Job Queue  │    │   Assessment Worker  │  │
│  │  (FastAPI)   │───▶│  (In-Memory) │───▶│  (Threaded Pool)     │  │
│  └──────────────┘    └──────────────┘    └──────────┬───────────┘  │
│       │                                             │              │
│       │                    ┌────────────────────────┼────────┐     │
│       ▼                    ▼                        ▼        ▼     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Scope Gate (Authorization)                  │  │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────────┐   │  │
│  │  │ Layer 1 │ │ Layer 2 │ │  Layer 3 │ │    Observer      │   │  │
│  │  │ URL/Host│ │  DNS/IP │ │ Pinned   │ │ (Strix Proof)    │   │  │
│  │  │  Gate   │ │ Policy  │ │ Dest.    │ │                  │   │  │
│  │  └─────────┘ └─────────┘ └──────────┘ └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│       │                    │                        │        │      │
│       ▼                    ▼                        ▼        ▼      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     Adapter Framework                          │  │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────────┐   │  │
│  │  │  HTTP   │ │ Crawler │ │ Dynamic  │ │    External      │   │  │
│  │  │ Probe   │ │         │ │ Validate │ │  (nmap, nuclei)  │   │  │
│  │  └─────────┘ └─────────┘ └──────────┘ └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│       │                    │                        │        │      │
│       ▼                    ▼                        ▼        ▼      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Findings Engine                             │  │
│  │  Normalize ▶ Dedupe ▶ Redact ▶ Persist (SQLite) ▶ Export     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Innovations

### 1. Scope Gate — Default-Deny Authorization (`src/strix/core/scope.py`)
- **Layer 1 (URL/Host)**: Validates structure, host against include/exclude, port against allowed_ports — no DNS
- **Layer 2 (DNS/IP)**: Resolves hostname, validates every IP against authorized_networks, denies special-use addresses (loopback, link-local, private, multicast) unless explicitly authorized
- **Layer 3 (Pinned Destination)**: Returns single `Destination` (scheme, host, port, IP) — prevents DNS rebinding
- **ContextVar isolation**: Per-task scope binding for multi-tenant safety
- **TLA+ verified**: 6 invariants, 21.4M states model-checked

### 2. Break-Glass Dual Approval (`src/strix/core/scope_breakglass.py`)
- Emergency authorization with dual approval workflow
- Time-bounded, audited, metrics-instrumented

### 3. Strix Proof — Cryptographic Audit Chain
- Every gate decision receipted: `grant → gate → proof → verify`
- Tamper-evident, offline verifiable, compliance-ready

### 4. Adapter Framework — Real Tools, Normalized Output
- HTTP Probe, Crawler, Dynamic Validation
- External: nmap, Nuclei, SQLMap, Nikto
- All adapters re-check Scope Gate internally

## Documentation

- [Quick Start](docs/quickstart/overview.md)
- [Architecture](ARCHITECTURE.md)
- [Scope Gate Deep Dive](docs/scope-gate/concepts.md)
- [Adapter Development](docs/adapters/custom.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Free-Tier Deployment](docs/deployment/free-tier.md)
- [API Reference](docs/api/authentication.md)
- [Compliance Mapping](docs/compliance/overview.md)

## Deployment Options

| Environment | Command | Cost |
|-------------|---------|------|
| **Free Tier (Oracle)** | `./scripts/bootstrap-free.sh` | $0/month |
| **Production (EKS/GKE/AKS)** | `helm install -f values-prod.yaml` | Cloud costs |
| **Local Dev** | `docker-compose up -d` | Free |
| **Kind/Minikube** | `./scripts/bootstrap-kind.sh` | Free |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style (ruff, mypy)
- Testing requirements
- PR process

## Security

- [Security Policy](SECURITY.md) — vulnerability disclosure
- [Security Review](docs/security-review.md)
- [TLA+ Verification](docs/tla/)

## License

Apache-2.0 — see [LICENSE](LICENSE)

## Community

- **Slack**: [slack.strix.dev](https://slack.strix.dev)
- **Discord**: [discord.gg/strix](https://discord.gg/strix)
- **Issues**: [GitHub Issues](https://github.com/strix/strix/issues)
- **Discussions**: [GitHub Discussions](https://github.com/strix/strix/discussions)

---

**Built with ❤️ for the open source security community.**  
*Authorization-first. Audit-ready. Free forever.*