# Strix Documentation

# Strix

**Authorization-First Security Assessment Platform**

Strix is a security assessment platform built on a **default-deny authorization engine** (Scope Gate) that prevents unauthorized outbound connections during security testing.

## Core Features

### Scope Gate (Default-Deny Authorization)
- **Layer 1**: URL/Host/Port validation against allowlists
- **Layer 2**: DNS resolution + IP CIDR policy enforcement
- **Layer 3**: Destination pinning (IPv6-first, deterministic selection)
- **Formally verified**: 6 TLA+ invariants, 21.4M states model-checked

### Adapter Framework
- **Built-in**: HTTP Probe, Crawler, Dynamic Validation
- **External**: Nmap, Nuclei, SQLMap, Nikto (wrapped with Scope Gate)
- **Custom**: SDK for building your own adapters

### Strix Proof (Cryptographic Audit Chain)
- **Grant** → **Gate** → **Proof** → **Verify**
- Ed25519 signatures with JWKS rotation
- Tamper-evident assessment receipts

### Multi-Tenancy
- ContextVar-based isolation
- Row-Level Security (PostgreSQL)
- Partner/Organization/Tier hierarchy

## Quick Links

| Section | Description |
|---------|-------------|
| [Quick Start Overview](quickstart/overview.md) | Get running in 5 minutes |
| [Free Tier Deployment](quickstart/free-tier.md) | $0/month on Oracle Cloud |
| [Local Development](quickstart/local-dev.md) | Docker Compose setup |
| [Production Deployment](quickstart/production.md) | Kubernetes/Helm |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Strix Platform                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐  │
│  │   API       │  │  Worker     │  │  Scheduler             │  │
│  │  (FastAPI)  │  │  (Celery)   │  │  (APScheduler)         │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬────────────┘  │
│         │                │                     │               │
│         └────────────────┼─────────────────────┘               │
│                          ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Scope Gate                            │   │
│  │  Layer 1: URL/Host  │  Layer 2: DNS/IP  │  Layer 3: Pin │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                     │
│         ┌────────────────┼────────────────┐                   │
│         ▼                ▼                ▼                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ PostgreSQL  │  │   Redis     │  │  Object     │           │
│  │ (RLS, pgv)  │  │  (Queue)    │  │  Store (S3) │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Documentation Structure

- **Quick Start** - Installation and first assessment
- **Architecture** - System design and component details
- **Scope Gate** - Authorization engine deep dive
- **Adapters** - Built-in, external, and custom adapters
- **Deployment** - Kubernetes, Helm, Docker Compose, Free Tier
- **API Reference** - REST API endpoints
- **Compliance** - NIST, ISO 27001, SOC 2, PCI DSS mappings
- **Contributing** - Development, testing, release process

## Get Started

```bash
# Quick start with Docker Compose
git clone https://github.com/strix/strix.git
cd strix
cp .env.example .env
docker compose up -d
docker compose exec api alembic upgrade head
curl http://localhost:8000/health
```

## Community

- **GitHub**: [github.com/strix/strix](https://github.com/strix/strix)
- **Discord**: [discord.gg/strix](https://discord.gg/strix)
- **Slack**: [slack.strix.dev](https://slack.strix.dev)
- **Twitter**: [@strix_security](https://twitter.com/strix_security)

## License

Apache-2.0 — See [LICENSE](license.md)

---

*Built with security-first principles. Every outbound connection is authorized, pinned, and audited.*