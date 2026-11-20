# Strix — Authorization-First Security Assessment Platform

[![License](https://img.shields.io/github/license/ishastra/ishastra)](LICENSE)
[![CI](https://github.com/ishastra/ishastra/actions/workflows/ci.yml/badge.svg)](https://github.com/ishastra/ishastra/actions)
[![Python](https://img.shields.io/badge/python-3.12+-blue)](https://python.org)
[![Kubernetes](https://img.shields.io/badge/k8s-1.28+-blue)](https://kubernetes.io)

> **The only security scanner that enforces authorization BEFORE every connection.**

> **Project status:** pilot-grade for a single-tenant, single-host deployment.
> The authorization core is TLA+-verified and CI-enforced; the platform has no
> HA or multi-node story yet. Read
> [Production deployment](docs/quickstart/production.md) before promising
> uptime, and [SECURITY.md](SECURITY.md) for the honest security posture.

## Why Strix?

| Feature | Strix | Nuclei | Trivy | OWASP ZAP | OpenVAS |
|---------|-------|--------|-------|-----------|---------|
| **Default-deny authorization** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **API-key tenant isolation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Cryptographic audit chain** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SARIF + compliance reports** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Runs Nuclei/nmap/SQLMap** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Policy-as-code (CIDR+ASN+Geo)** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **DNS rebinding protection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Free-tier deployable** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **TLA+ formally verified** | ✅ | ❌ | ❌ | ❌ | ❌ |

## Try It In One Command

```bash
pip install ishastra
ishastra demo
```

The demo writes its own Ed25519-signed scope (localhost only), generates an
admin key, uses SQLite, and prints the URL plus the key you paste into the top
bar. Nothing outside `.ishastra-demo/` is touched.

In CI, the bundled action runs a scoped assessment and uploads SARIF:

```yaml
- uses: ishastra/ishastra@v1
  with:
    target: https://staging.example.com
    scope-file: scope.json          # signed; the gate refuses anything else
    profile: web-deep
    fail-on-findings: "true"
```

Third-party adapters plug in without forking the project. Publish one under the
`ishastra.adapters` entry-point group and it becomes available to profiles:

```toml
[project.entry-points."ishastra.adapters"]
my-probe = "my_package.adapters:MyProbe"
```

A plugin can add an adapter id but cannot replace a built-in one.

## Signed Evidence Bundles

`ishastra bundle` packages a job's result, its findings as SARIF, the rendered HTML report, the audit-chain entries and the exact scope document into a zip whose manifest is Ed25519-signed and whose members are SHA-256 pinned. Verification is offline, and any member that was edited, added or removed after signing is rejected.

```bash
ishastra bundle --job <job-id> --scope scope.json --key scope-signing-key.pem --kid <kid> -o evidence.zip
ishastra bundle --verify evidence.zip --jwks jwks.json
```

## Quick Start (Free Tier — $0/month)

```bash
# One-shot bootstrap on Oracle Cloud Always Free
git clone https://github.com/ishastra/ishastra
cd ishastra
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```

**What you get:**
- 2-node k0s cluster on Oracle Always Free (2x ARM 4OCPU/24GB); add a third node for control-plane quorum
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

### 1. Scope Gate — Default-Deny Authorization (`src/ishastra/core/scope.py`)
- **Layer 1 (URL/Host)**: Validates structure, host against include/exclude, port against allowed_ports — no DNS
- **Layer 2 (DNS/IP)**: Resolves hostname, validates every IP against authorized_networks, denies special-use addresses (loopback, link-local, private, multicast) unless explicitly authorized
- **Layer 3 (Pinned Destination)**: Returns single `Destination` (scheme, host, port, IP) — prevents DNS rebinding
- **ContextVar isolation**: Per-task scope binding for multi-tenant safety
- **TLA+ verified**: 6 invariants, 21.4M states model-checked

### 2. Break-Glass Dual Approval (`src/ishastra/core/scope_breakglass.py`)
- Emergency authorization with dual approval workflow
- Time-bounded, audited, metrics-instrumented

### 3. Strix Proof — Cryptographic Audit Chain
- Every gate decision receipted: `grant → gate → proof → verify`
- Tamper-evident, offline verifiable, compliance-ready

### 4. Adapter Framework — Real Tools, Normalized Output
- HTTP Probe, Crawler, Dynamic Validation
- External: nmap, Nuclei, SQLMap, Nikto
- All adapters re-check Scope Gate internally

## Job Notifications

Set `ISHASTRA_NOTIFY_WEBHOOK_URL` to POST a JSON summary (job, target, state, verdict, severity counts) whenever a job finishes. The same body carries Slack `text` and `blocks`, so a Slack incoming webhook renders it as a formatted card while other receivers read the structured fields. Destinations must be public https URLs; set `ISHASTRA_WEBHOOK_SECRET` to add an `X-Strix-Signature: sha256=…` HMAC header, so the receiver can verify the payload.

## Documentation

- [Quick Start](docs/quickstart/overview.md)
- [Architecture](ARCHITECTURE.md)
- [Scope Gate Deep Dive](docs/scope-gate/concepts.md)
- [Adapter Development](docs/adapters/custom.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Production Deployment & Readiness](docs/quickstart/production.md)
- [Free-Tier Deployment](docs/deployment/free-tier.md)
- [API Reference](docs/api/authentication.md)
- [Compliance Mapping](docs/compliance/overview.md)

## Deployment Options

| Environment | Command | Cost |
|-------------|---------|------|
| **Free Tier (Oracle)** | `./scripts/bootstrap-free.sh` | $0/month |
| **Single-host production** | systemd or Compose, one writer | Low |
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

- **Questions and ideas**: [GitHub Discussions](https://github.com/ishastra/ishastra/discussions)
- **Issues**: [GitHub Issues](https://github.com/ishastra/ishastra/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ishastra/ishastra/discussions)

---

**Built with ❤️ for the open source security community.**  
*Authorization-first. Audit-ready. Free forever.*