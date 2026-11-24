# Changelog

# Changelog

All notable changes to Ishastra are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Project adheres to [Semantic Versioning](https://semver.org/).

## [4.0.0-rc1] - 2025-11-24

### Added
- **Capability Tokens**: Ed25519-signed JWTs with TTL ≤900s for worker→gateway auth
- **Egress Gateway**: CONNECT proxy with nftables deny-by-default firewall
- **Worker Manager**: Disposable containers with hardened Docker flags (no-new-privs, seccomp, drop caps)
- **Evidence Signing Service**: RFC 9530 manifests with per-artifact Ed25519 + SHA-256
- **Out-of-Process Plugin Framework**: JSON-over-stdio protocol with plugin template
- **Template Allowlist**: Nuclei/Nmap NSE glob-pattern allowlist for safe custom templates
- **Rate Limiting**: Per-engagement RPS from Rules of Engagement (JobRateLimiter)
- **High-Risk Authorization**: Explicit `high_risk_allowed` in RoE, `high_risk` in job config
- **Import/Export Pipeline**: SARIF, Nuclei, ZAP import; SARIF/HTML/PDF/CSV/JSON/DefectDojo export
- **GitHub Action**: `ishastra/assess@v1` for CI/CD pipeline integration
- **SBOM Generation**: SPDX JSON with cyclonedx-python, cosign signing, SLSA provenance
- **Multi-Arch Images**: linux/amd64 + linux/arm64 with Docker manifest
- **Optional Local AI Advisor**: Ollama-powered finding triage (privacy-first, no cloud)
- **Demo Lab Seeding**: `scripts/seed_demo_lab.py` for instant evaluation

### Changed
- **Scope Gate Enforcement**: Mandatory at every boundary (dispatch, adapter, worker)
- **Redaction**: Credentials stripped from evidence, SARIF, logs, webhooks
- **Queue Modes**: Added `k8s-jobs` alongside `in-process`, `redis-streams`, `sqlite`
- **Organizations v2**: Org/Team/Membership hierarchy with RBAC roles
- **Pricing Tiers**: FREE/STARTER/PRO/ENTERPRISE with feature flags
- **Dispatch Reliability**: Synchronous SIGTERM handling, `os._exit(0)` cleanup
- **CLI**: Added `worker gateway` subcommand for standalone gateway
- **Deployment**: SQLite default, PostgreSQL experimental, hardened compose

### Deprecated
- In-process plugin execution (use out-of-process framework)
- Legacy Strix naming (fully removed)

### Removed
- AI Analyst provider abstraction (was never production-ready)
- 25 empty v4.0 skeleton modules
- `strix-*` metric/cookie/key prefixes (all `ishastra-*`)

### Fixed
- **Critical**: Crashed scanners (pip-audit, safety) no longer report false clean passes
- CI security gates hardened: removed `|| true` and `continue-on-error: true`
- Git history cleaned: removed 5 Co-Authored-By: Claude Fable 5 trailers
- Process-kill test flakiness: dispatcher now exits cleanly on SIGTERM
- Vulnerable dependencies updated: mitmproxy 12.1.3→12.3.1, kubernetes 30.1.0
- Template allowlist glob patterns with fnmatch

### Security
- Capability token revocation with in-memory + Redis-backed RevocationList
- Egress firewall deny-by-default with nftables script rendering
- Worker containers: read-only rootfs, tmpfs /tmp, no NET_RAW/NET_ADMIN
- Evidence signing: per-artifact signatures + manifest verification
- Supply chain: SBOM, cosign, SLSA provenance, reproducible builds

---

## [Unreleased]

### Added
- Custom Adapter SDK with TypeScript/Python bindings
- Webhook event filtering by severity
- Assessment progress streaming via SSE
- Bulk finding status updates

### Changed
- DNS resolver timeout default: 5s → 10s
- API key rotation: 90 days → configurable (default 90)

### Deprecated
- `callback_url` HTTP support (use HTTPS)
- `dns_servers` without `dns_resolver: custom`

### Removed
- Legacy adapter v1 interface (use v2)

### Fixed
- Webhook retry exponential backoff calculation
- Scope Gate Layer 3 IPv6 pinning edge case
- Finding deduplication race condition

### Security
- Updated all base images to latest security patches
- Added CSP headers to API responses

---

## [3.5.0] - 2024-01-15

### Added
- **Ishastra Proof**: Cryptographic audit chain (Grant → Gate → Proof → Verify)
- **TLA+ Formal Verification**: 6 invariants model-checked over 21.4M states
- **Break-Glass Dual Approval**: Emergency access with MFA and audit trail
- **Free Tier Deployment**: Oracle Cloud ARM + Neon PostgreSQL + Upstash Redis
- **Scope Gate Layer 3**: Destination pinning (IPv6-first, deterministic)
- **Adapter Framework**: Built-in, External, and Custom SDK
- **Policy-as-Code**: CIDR + ASN + Geo authorization
- **Multi-Tenancy**: ContextVar isolation + PostgreSQL RLS
- **Compliance Mappings**: NIST 800-53, ISO 27001, SOC 2, PCI DSS 4.0.1

### Changed
- Architecture: Microservices (API, Worker, Scheduler) with Celery
- Database: PostgreSQL 16 with pgvector, Redis 7 for queue
- Deployment: k0s Kubernetes, Helm, SealedSecrets/External Secrets
- Monitoring: Prometheus, Grafana, OpenTelemetry
- Documentation: Complete MkDocs site with Material theme

### Security
- Ed25519 signatures with JWKS rotation
- TLS 1.3 everywhere, mTLS for internal services
- Distroless containers, non-root, read-only filesystem
- Supply chain: SBOM, cosign signatures, reproducible builds

---

## [3.4.0] - 2023-10-01

### Added
- Nuclei adapter integration
- SQLMap adapter integration
- Nikto adapter integration
- Dynamic validation adapter (auth bypass, IDOR, XSS, SQLi)
- Assessment retry with target/adapter filtering
- SARIF export for findings
- Webhook dead letter queue

### Changed
- Scope Gate: Added Layer 2 DNS resolution with pinned resolvers
- API: Async FastAPI with Pydantic v2
- Workers: Celery with Redis backend
- Auth: JWT token exchange, scoped API keys

### Fixed
- Scope Gate CIDR overlap detection
- Adapter timeout handling
- Database connection pooling

---

## [3.3.0] - 2023-07-15

### Added
- HTTP Probe adapter (security headers, cookies, methods, tech detection)
- Crawler adapter (forms, JS endpoints, sensitive paths)
- Nmap adapter (port scanning, service detection)
- Assessment progress streaming
- Finding categories and severity taxonomy

### Changed
- Scope document versioning and activation workflow
- Break-glass: Added max duration and MFA requirement
- Database: Added Row-Level Security policies

### Fixed
- DNS resolution caching
- Webhook signature verification

---

## [3.2.0] - 2023-04-01

### Added
- Scope Gate: 3-layer validation (URL/Host, DNS/IP, Pinned Destination)
- Default-deny authorization engine
- Assessment scheduling with APScheduler
- API key management (create, rotate, revoke)
- Health checks and readiness probes

### Changed
- Migration from monolith to modular architecture
- Configuration: Environment-based with validation

### Fixed
- Memory leak in long-running assessments
- Race condition in scope activation

---

## [3.1.0] - 2023-01-15

### Added
- Initial Scope Gate implementation (Layer 1 only)
- Basic assessment API
- PostgreSQL storage with SQLAlchemy
- Docker Compose for local development

### Changed
- Project restructure: src/ishastra, src/ishastra-rust

### Fixed
- Initial release stabilization

---

## [3.0.0] - 2022-10-01

### Added
- Initial public release
- Core assessment engine
- Basic adapter framework

---

## Migration Guides

### 3.4 → 3.5

**Breaking Changes:**
- Scope Gate now requires all 3 layers (was Layer 1 only)
- API keys now require explicit scopes
- Adapter interface changed to v2

**Migration Steps:**
```bash
# 1. Update scope documents with Layer 2/3 config
ishastra scope migrate --add-layer2 --add-layer3

# 2. Rotate API keys with scopes
ishastra auth rotate-key --add-scopes assessments:read,assessments:write

# 3. Update adapter configurations
ishastra adapter migrate --to-v2

# 4. Run database migrations
alembic upgrade head
```

### 3.3 → 3.4

**Breaking Changes:**
- Assessment status `partial` added (some targets failed)
- Finding status `accepted_risk` added

**Migration Steps:**
```bash
# Run migrations
alembic upgrade head

# Update finding statuses if needed
ishastra finding migrate-status
```

### 3.2 → 3.3

**Breaking Changes:**
- Scope document structure changed (break_glass object)
- Adapter registry moved to `ishastra.adapters.registry`

**Migration Steps:**
```bash
# Migrate scope documents
ishastra scope migrate --add-break-glass

# Update imports
# from ishastra.adapters import HTTPProbeAdapter  # old
from ishastra.adapters.http_probe import HTTPProbeAdapter  # new
```

---

## Release Notes Template

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- Feature description

### Changed
- Change description

### Deprecated
- Deprecation notice

### Removed
- Removal notice

### Fixed
- Bug fix description

### Security
- Security improvement
```

---

## Links

- [GitHub Releases](https://github.com/hacker-194/IshAstra/releases)
- [Release Process](contributing/releasing.md)
- [Migration Guides](#migration-guides)