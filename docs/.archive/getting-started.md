# Getting Started with Ishastra

**Ishastra** is an authorized security assessment platform that enforces **default-deny authorization** before every outbound connection. It runs real security tools against authorized targets, normalizes findings into a common model, and exports results as SARIF or evidence reports.

---

## Prerequisites

- **Python 3.12+**
- **Linux** (primary platform; macOS/Windows WSL supported)
- **Authorization document** — a scope.json defining what you are authorized to test

> ⚠️ **Critical**: Ishastra will **refuse all scans** without a valid authorization document. This is by design — the default-deny model means nothing is assessed without explicit authorization.

---

## Quick Start (5 Minutes)

### 1. Install Ishastra

```bash
# Clone the repository
git clone <repository-url>
cd ishastra-v3.5.0-hardened

# Create virtual environment and install
python -m venv .venv
source .venv/bin/activate
pip install -c constraints.txt -e ".[dev]"
```

### 2. Configure Authorization (Required)

```bash
# Copy the example scope document
cp scope.example.json scope.json

# Edit scope.json with YOUR authorized targets
# Required fields: program, authorized_by, authorization_ref, include (non-empty list)
vim scope.json
```

**Minimal valid scope.json:**
```json
{
  "program": "My Security Program",
  "authorized_by": "Security Team Lead",
  "authorization_ref": "AUTH-2024-001",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443],
  "allow_broad_networks": false
}
```

### 3. Generate API Key

```bash
# For local testing, generate a key
export ISHASTRA_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# In production, set this in your environment or .env file
```

### 4. Start the Server

```bash
# Development mode
ishastra serve --host 0.0.0.0 --port 8000

# Production (with reverse proxy for TLS)
ishastra serve --host 0.0.0.0 --port 8000 --workers 1
```

### 5. Verify It Works

```bash
# Health check (no auth required)
curl http://localhost:8000/api/health

# Interactive API docs (no auth required)
open http://localhost:8000/docs

# Run an inline assessment (for testing)
ishastra assess --target https://example.com --profile web
```

---

## Core Concepts

### Authorization Model

Ishastra uses a **three-layer scope gate**:

| Layer | Check | Purpose |
|-------|-------|---------|
| **Layer 1** | URL structure, host patterns, port allowlist | Fast syntactic validation — no DNS |
| **Layer 2** | DNS resolution → IP against authorized networks | Prevents scanning unauthorized IPs |
| **Layer 3** | Pinned destination (scheme + host + port + IP) | Prevents DNS rebinding (TOCTOU) |

**Every outbound connection** goes through all three layers. Adapters **must** call `checked_destination()` before any network I/O.

### Profiles

Pre-defined adapter sequences for common assessment types:

| Profile | Adapters | Use Case |
|---------|----------|----------|
| `web` | http, git-exposure | Quick web header + exposure check |
| `web-crawl` | crawl, http, git-exposure | Discovery + assessment |
| `web-deep` | crawl, http, dynamic-validation, git-exposure, nuclei | Broad web app assessment |
| `api` | http, openapi, git-exposure | API discovery + spec validation |
| `api-deep` | crawl, http, openapi, authz, ssrf-oob, dynamic-validation, git-exposure, nuclei | Deep API security assessment |
| `ports` | tcp, nmap | Network port scanning |
| `network` | http, tcp, nmap, git-exposure | Combined network + web |

### Job Lifecycle

```
POST /api/assess → QUEUED → RUNNING → COMPLETED | PARTIAL | FAILED | CANCELLED
```

A job is **"clean" (no findings with complete coverage)** ONLY when **every** selected adapter ran to completion (`RunState.OK`). Partial, failed, or unavailable adapters make the result **inconclusive**, never clean.

---

## Running Your First Assessment

### Option 1: CLI (Inline)

```bash
# Simple assessment
ishastra assess --target https://example.com --profile web

# With options
ishastra assess \
  --target https://api.example.com \
  --profile api-deep \
  --timeout 300 \
  --wait
```

### Option 2: REST API (Async)

```bash
# 1. Queue assessment
curl -X POST http://localhost:8000/api/assess \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web-deep"}'

# Response: { "id": "job_abc123", "state": "queued", "poll_url": "/api/assess/job_abc123" }

# 2. Poll for results
curl -X GET http://localhost:8000/api/assess/job_abc123 \
  -H "Authorization: Bearer $ISHASTRA_API_KEY"

# 3. Get SARIF export
curl -X GET http://localhost:8000/api/assess/job_abc123/sarif \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -o results.sarif

# 4. Get HTML report
curl -X GET http://localhost:8000/api/assess/job_abc123/report.html \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -o report.html
```

---

## Multi-Tenant Mode (Production)

For production deployments serving multiple teams/tenants:

### 1. Enable Managed Mode

```bash
export ISHASTRA_SCOPE_MODE=managed
```

### 2. Create Engagement Policy (Admin)

```bash
curl -X POST http://localhost:8000/api/policies \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "acme-corp",
    "program": "Acme Corp Bug Bounty",
    "authorized_by": "Security Team",
    "authorization_ref": "BB-2024-001",
    "include": ["example.com", "api.example.com"],
    "exclude": ["staging.example.com"],
    "authorized_networks": ["10.0.0.0/8"],
    "allowed_ports": [80, 443, 8080, 8443],
    "allow_broad_networks": false,
    "ttl_seconds": 31536000
  }'
```

### 3. Create Tenant API Key

```bash
curl -X POST http://localhost:8000/api/keys/create \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant": "acme-corp", "tier": "unlimited", "ttl_days": 365}'
```

### 4. Tenant Runs Assessment

```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Authorization: Bearer $TENANT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web-deep", "policy_id": "pol_abc123"}'
```

---

## Configuration Reference

Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ISHASTRA_API_KEY` | (required) | Admin API key for bootstrap |
| `ISHASTRA_SCOPE_FILE` | `scope.json` | Path to scope document |
| `ISHASTRA_SCOPE_MODE` | `auto` | `global`, `managed`, or `auto` |
| `ISHASTRA_DB` | `ishastra.db` | SQLite database path |
| `ISHASTRA_DATABASE_URL` | (optional) | PostgreSQL DSN; experimental single-host API+worker |
| `ISHASTRA_AUDIT_HMAC_KEY` | (warn if missing) | HMAC key for audit chain integrity |
| `ISHASTRA_WEBHOOK_SECRET` | (warn if missing) | Secret for webhook signatures |
| `ISHASTRA_REDIS_URL` | `redis://localhost:6379/0` | Redis for shared rate limiting |
| `ISHASTRA_REDIS_REQUIRED` | `false` | Fail startup if Redis unavailable |
| `ISHASTRA_WORKERS` | `1` | Concurrent assessment jobs in the in-process worker |
| `ISHASTRA_QUEUE_MODE` | `inprocess` | `k8s-jobs` enables the experimental distributed queue |
| `ISHASTRA_DISABLE_DOCS` | `false` | Disable /docs, /redoc, /openapi.json |
| `ISHASTRA_TRUSTED_PROXIES` | (empty) | Trusted proxy IPs for X-Forwarded-* |

---

## Next Steps

- [Architecture Overview](../ARCHITECTURE.md) — Understand the internal design
- [Configuration Reference](configuration.md) — All configuration options
- [Adapter Development Guide](adapter-development.md) — Build custom adapters
- [API Documentation](API_DOCUMENTATION.md) — Complete REST API documentation
- [Compliance Pack Guide](compliance-pack.md) — NRB, NTA, NCSP evidence packs
- [Operations Runbooks](runbooks/) — Incident response, capacity planning, upgrades

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `scope document rejected` | Check JSON syntax, required fields, valid CIDR networks |
| `Target not in scope` | Verify host matches `include` patterns, port in `allowed_ports` |
| `DNS resolution failed` | Check network connectivity, authorized_networks includes resolved IP |
| `Audit chain verification failed` | Database tampered or HMAC key changed — investigate immediately |
| `Webhook not receiving` | Check `ISHASTRA_WEBHOOK_SECRET` matches, monitor running, targets configured |
| `PDF generation fails` | Install system deps: `libpango-1.0-0 libharfbuzz0b libpangocairo-1.0-0` |

---

## Support

- **Documentation**: `/docs` (Swagger UI) or `/redoc` (ReDoc)
- **OpenAPI Spec**: `GET /openapi.json`
- **Issues**: GitHub Issues
- **Security**: security@example.com