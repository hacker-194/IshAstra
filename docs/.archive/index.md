# Strix Documentation
# Process: MkDocs builds this as the documentation homepage
# Effect: Entry point for all documentation navigation
# No secrets written in plain text
# User instruction: "update all"

# Strix — Authorization-First Security Assessment Platform

> **The only security scanner that enforces authorization BEFORE every connection.**

Strix is an open-source security assessment platform built on a revolutionary principle: **default-deny authorization for every outbound connection**. Unlike traditional scanners that connect first and ask questions later, Strix's Scope Gate validates every destination against explicit policy before a single packet leaves your infrastructure.

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

## Quick Start

### Free Tier — $0/month
```bash
git clone https://github.com/strix/strix
cd strix
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```
**What you get:** HA k0s cluster on Oracle Always Free, Neon PostgreSQL, Upstash Redis, Cloudflare Tunnel, SealedSecrets, Prometheus + Grafana.

### Local Development
```bash
docker-compose up -d
# API at http://localhost:8000
# Grafana at http://localhost:3000 (admin/admin)
```

## Core Architecture

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

## Key Innovations

### 1. Scope Gate — Default-Deny Authorization
- **Layer 1 (URL/Host)**: Validates structure, host against include/exclude, port against allowed_ports — no DNS
- **Layer 2 (DNS/IP)**: Resolves hostname, validates every IP against authorized_networks, denies special-use addresses
- **Layer 3 (Pinned Destination)**: Returns single `Destination` (scheme, host, port, IP) — prevents DNS rebinding
- **ContextVar isolation**: Per-task scope binding for multi-tenant safety
- **TLA+ verified**: 6 invariants, 21.4M states model-checked

### 2. Break-Glass Dual Approval
Emergency authorization with dual approval workflow — time-bounded, audited, metrics-instrumented.

### 3. Strix Proof — Cryptographic Audit Chain
Every gate decision receipted: `grant → gate → proof → verify` — tamper-evident, offline verifiable, compliance-ready.

### 4. Adapter Framework — Real Tools, Normalized Output
HTTP Probe, Crawler, Dynamic Validation, External (nmap, Nuclei, SQLMap, Nikto) — all re-check Scope Gate internally.

## Documentation Structure

| Section | Description |
|---------|-------------|
| [Quick Start](quickstart/overview.md) | Get running in minutes |
| [Architecture](architecture/overview.md) | System design and data flows |
| [Scope Gate](scope-gate/concepts.md) | Deep dive on authorization engine |
| [Adapters](adapters/built-in.md) | Built-in and external tool integrations |
| [Deployment](deployment/kubernetes.md) | K8s, Helm, Docker Compose, Free Tier |
| [API Reference](api/authentication.md) | REST API with examples |
| [Compliance](compliance/overview.md) | NIST, ISO, SOC2, PCI mappings |
| [Contributing](contributing/development.md) | Development setup and guidelines |

## Community & Support

- **Slack**: [slack.strix.dev](https://slack.strix.dev)
- **Discord**: [discord.gg/strix](https://discord.gg/strix)
- **GitHub Issues**: [Bug reports & features](https://github.com/strix/strix/issues)
- **Discussions**: [Q&A and ideas](https://github.com/strix/strix/discussions)

## License

Apache-2.0 — see [LICENSE](../LICENSE)

---

*Authorization-first. Audit-ready. Free forever.*