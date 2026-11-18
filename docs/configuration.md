# Configuration Reference

Complete reference for all Strix configuration options.

---

## Environment Variables

Runtime settings are read once at startup by `Settings.from_env()`. The bind
address and port are CLI flags (`strix --host 127.0.0.1 --port 8000`), not
environment variables.

### Core Settings

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STRIX_ENV` | `development` | No | `production` fails closed without the required secrets and forces API docs off. |
| `STRIX_API_KEY` | — | **Yes** | Admin API key for bootstrap. Generated keys shown once. Required in production. |
| `STRIX_SCOPE_FILE` | `scope.json` | No | Path to scope authorization document. |
| `STRIX_SCOPE_MODE` | `auto` | No | Scope mode: `global`, `managed`, `auto`. |
| `STRIX_SCOPE_JWKS` | — | No | JWKS file with Ed25519 public keys. When set, a scope document loads only if signed by one of those keys. See [scope signing](#signed-scope-documents). |
| `STRIX_SCOPE_MAX_AGE_SECONDS` | `86400` | No | How old a signed scope document may be. An older document is refused even though its signature verifies. |
| `STRIX_DB` | `strix.db` | No | SQLite database file path. |
| `STRIX_DATABASE_URL` | — | No | PostgreSQL DSN; overrides `STRIX_DB`. Advanced: tested single-host (SIGTERM, load soak, audit chain, Celery integration). |
| `STRIX_WORKERS` | `1` | No | Concurrent assessment jobs in the in-process worker. |
| `STRIX_QUEUE_MAX` | `32` | No | Maximum queued jobs. |
| `STRIX_QUEUE_MODE` | `inprocess` | No | `k8s-jobs` enables the experimental distributed queue (tested single-host: 10 jobs). |
| `STRIX_CELERY_BROKER_URL` | `redis://localhost:6379/1` | No | Celery broker when Celery mode is enabled. |
| `STRIX_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | No | Celery result backend. |

### Security & Authorization

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STRIX_AUDIT_HMAC_KEY` | — | **Recommended** | HMAC-SHA256 key for audit chain integrity. 32+ random bytes, base64. Without this, audit chain is forgeable by anyone with DB write access. |
| `STRIX_WEBHOOK_SECRET` | — | **Recommended** | Secret for webhook HMAC signatures. 32+ random bytes, base64. All webhooks share this secret. |
| `STRIX_ENCRYPTION_KEY` | — | Recommended for webhooks | Base64 32-byte AES-GCM key for webhook secrets at rest. |
| `STRIX_TRUSTED_PROXIES` | — | No | Comma-separated trusted proxy IPs/CIDRs for `X-Forwarded-*` headers. |
| `STRIX_CORS_ORIGINS` | — | No | Comma-separated allowed CORS origins. Wildcard `*` not recommended. |
| `STRIX_DISABLE_DOCS` | `false` | No | `1`/`true` disables `/docs`, `/redoc` and `/openapi.json`. Forced on by `STRIX_ENV=production`. |
| `STRIX_MAX_BODY_BYTES` | `1048576` | No | Hard request-body cap (413 above it). |
| `STRIX_MAX_NESTING_DEPTH` | `10` | No | Maximum JSON container depth. |
| `STRIX_RATE_LIMIT_DISABLED` | — | No | `1` disables rate limiting; local development only. |
| `STRIX_REDIS_REQUIRED` | `false` | No | If `true`, fail startup if Redis is unavailable. |

### Redis

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STRIX_REDIS_URL` | `redis://localhost:6379/0` | No | Redis connection URL for shared rate limiting/cache. |

Tier limits are defined in `core/rate_limit.py`; there are no per-tier rate
environment variables.

### Retention & Cleanup

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STRIX_RETENTION_DAYS` | `0` | No | `0` keeps everything. A positive value prunes finished jobs/findings and plain audit entries; the sealed chain is never pruned. |

### Observability

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | No | Enable OpenTelemetry tracing (e.g., `http://localhost:4318/v1/traces`). |
| `STRIX_LOG_LEVEL` | `INFO` | No | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `STRIX_LOG_FORMAT` | `text` | No | Log format: `json` or `text`. |
| `STRIX_WORKER_MEMORY_MB` | `1024` | No | Worker memory limit in MB; `0` disables it. |

Optional binaries (`nmap`, `nuclei`) are discovered on `PATH`; the adapters
report missing tools as unavailable coverage rather than clean results.

---

## Scope Document Schema (`scope.json`)

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `program` | string | Program name (e.g., "Acme Corp Bug Bounty") |
| `authorized_by` | string | Authorizing entity/role (e.g., "Security Team") |
| `authorization_ref` | string | Reference ID (e.g., "BB-2024-001") |
| `include` | string[] | **Non-empty** list of host patterns. Wildcards: `*.example.com` (subdomains only, never apex) |
| `exclude` | string[] | Host patterns to exclude from `include` |
| `authorized_networks` | string[] | CIDR networks (IPv4/IPv6). No IPv4-mapped IPv6. |
| `allowed_ports` | integer[] | Explicit port allowlist. Production should enumerate. |
| `allow_broad_networks` | boolean | If `false` (default), networks broader than `/8` rejected. |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `auth` | object | Per-tenant authentication configuration for scheduled/monitored assessments. |
| `auth.users` | object[] | Array of auth principals. Each has `id`, optional `cookies`, `headers`, `bearer`. |

### Scope Document Example

```json
{
  "program": "NRB Compliance Assessment",
  "authorized_by": "CISO",
  "authorization_ref": "NRB-DIR-SEC-2024-001",
  "include": [
    "*.examplebank.com",
    "api.examplebank.com",
    "mobile.examplebank.com"
  ],
  "exclude": [
    "test.examplebank.com",
    "dev.examplebank.com",
    "staging.examplebank.com"
  ],
  "authorized_networks": [
    "10.0.0.0/8",
    "172.16.0.0/12"
  ],
  "allowed_ports": [80, 443, 8443, 9443],
  "allow_broad_networks": false,
  "auth": {
    "users": [
      {
        "id": "compliance-scanner",
        "bearer": "eyJhbGciOiJIUzI1NiIs...",
        "cookies": [
          {"name": "sessionid", "value": "abc123"}
        ],
        "headers": {
          "X-Custom-Header": "value"
        }
      }
    ]
  }
}
```

### Validation Rules

1. **Unknown fields rejected** — prevents silent typos
2. `include` must be non-empty
3. Host patterns: `*.domain.tld` covers subdomains only
4. Networks: no IPv4-mapped IPv6 (`::ffff:10.0.0.1`)
5. Networks broader than `/8` require `allow_broad_networks: true`
6. `allowed_ports` must be valid port numbers (1-65535)
7. Atomic load: invalid document **never** replaces active config

---

## Engagement Policy Schema (Managed Mode)

Used in `STRIX_SCOPE_MODE=managed` for multi-tenant authorization.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `policy_id` | string | Generated on create (e.g., `pol_abc123`) |
| `tenant_id` | string | Owning tenant identifier |
| `program` | string | Program name |
| `authorized_by` | string | Authorizing entity |
| `authorization_ref` | string | Authorization reference |
| `version` | integer | Incremented on each update |
| `status` | enum | `active` or `revoked` |
| `include` | string[] | Host patterns (same as scope) |
| `exclude` | string[] | Excluded host patterns |
| `authorized_networks` | string[] | CIDR networks |
| `allowed_ports` | integer[] | Port allowlist |
| `allow_broad_networks` | boolean | Broad network allowance |
| `effective_at` | integer | Unix timestamp when policy becomes effective |
| `expires_at` | integer | Unix timestamp when policy expires |
| `created_by` | string | Creator identifier |
| `created_at` | integer | Creation timestamp |

### Policy Lifecycle

```
CREATE (v1, active) → UPDATE (v2, active) → REVOKE (v2, revoked)
```

- **Revoke** cancels all queued/running jobs for that policy
- **Update** with `ttl_seconds` extends expiration
- Worker re-validates policy at dequeue + execution start

---

## API Key Tiers

| Tier | General requests/min | Assessment submissions/min |
|------|----------------------|----------------------------|
| `free` | 5 | 5 |
| `pro` | 60 | 20 |
| `enterprise` | 300 | 60 |

The tier controls rate limits only. All profiles, scheduling, webhooks,
policies and every other feature are identical and MIT-licensed; they are not
gated by tier. These names are not prices or paid plans.

Each key also has a `scope`: `write` (default) or `read`. A `read` key can use
`GET`, `HEAD` and `OPTIONS`; every other method is refused with `403`. A tenant
can also have multiple member keys with `admin`, `analyst` or `viewer` roles via
`/api/users`; the legacy tenant key remains and is not replaced by user keys.

---

## Database Configuration

### SQLite (Default)

- **Path**: `STRIX_DB` (default: `strix.db`)
- **Permissions**: Owner-only (0600)
- **Mode**: Single-host, single-writer, async via `aiosqlite`
- **Tables**: jobs, findings, assets, finding_events, finding_remediation, api_keys, audit_log, audit_chain, policies, monitor_targets, settings, assessment_schedules, and schema metadata

### PostgreSQL (Advanced: Tested Single-Host, No HA)

```bash
pip install -e ".[postgres]"
export STRIX_DATABASE_URL="postgresql://user:pass@host/db"
```

> **Advanced: tested single-host, no HA.** Validated: schema migrations v1-v20,
> SIGTERM soak test (no stale worker lock, audit chain intact, API verify
> passes), assessment load test (10 jobs, 0 failed), Celery queue integration
> (10 jobs distributed across Celery workers). No HA, multi-node migration or
> supported failover. Use SQLite for a pilot unless you accept and test the
> single-host limitation.

---

## Reverse Proxy Configuration

Strix speaks HTTP. Terminate TLS at the proxy:

```nginx
# Nginx example
server {
    listen 443 ssl http2;
    server_name strix.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Required Strix config:**
```bash
export STRIX_TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12"
```

---

## Systemd Service (Production)

```ini
# /etc/systemd/system/strix.service
[Unit]
Description=Strix Security Assessment Platform
After=network.target

[Service]
Type=simple
User=strix
Group=strix
WorkingDirectory=/opt/strix
EnvironmentFile=/opt/strix/.env.production
ExecStart=/opt/strix/.venv/bin/strix serve --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/strix

[Install]
WantedBy=multi-user.target
```

---

## Docker Compose (Production)

```yaml
# docker-compose.prod.yml
services:
  strix:
    build: .
    ports:
      - "8000:8000"
    environment:
      - STRIX_API_KEY=${STRIX_API_KEY}
      - STRIX_SCOPE_FILE=/etc/strix/scope.json
      - STRIX_SCOPE_MODE=managed
      - STRIX_DB=/data/strix.db
      - STRIX_AUDIT_HMAC_KEY=${STRIX_AUDIT_HMAC_KEY}
      - STRIX_WEBHOOK_SECRET=${STRIX_WEBHOOK_SECRET}
      - STRIX_REDIS_URL=redis://redis:6379/0
      - STRIX_REDIS_REQUIRED=true
      - STRIX_TRUSTED_PROXIES=172.16.0.0/12
      - STRIX_DISABLE_DOCS=true
    volumes:
      - ./scope.json:/etc/strix/scope.json:ro
      - strix-data:/data
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  strix-data:
  redis-data:
```

---

## Generating Secure Keys

```bash
# API key (for STRIX_API_KEY)
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# HMAC key (for STRIX_AUDIT_HMAC_KEY, STRIX_WEBHOOK_SECRET)
python -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())'
```

---

## Configuration Validation

Strix validates configuration at startup:

1. **Production mode** — `STRIX_ENV=production` fails closed without `STRIX_API_KEY` and `STRIX_AUDIT_HMAC_KEY`, and forces API docs off.
2. **Scope document** — loaded via `scope.load()`. Invalid = fatal (serves but refuses all scans).
3. **Audit HMAC key** — required in production; warns if missing in development.
4. **Webhook secret** — warns if missing (signatures unverifiable).
5. **Redis** — fails if `STRIX_REDIS_REQUIRED=1` and unreachable.
6. **Admin key adoption** — fails if `STRIX_API_KEY` invalid format.

---

## Complete .env.production Example

```bash
# Core
STRIX_API_KEY=sk_admin_abc123...
STRIX_SCOPE_FILE=/etc/strix/scope.json
STRIX_SCOPE_MODE=managed
STRIX_DB=/data/strix.db
STRIX_WORKERS=1  # concurrent assessment jobs

# Security
STRIX_AUDIT_HMAC_KEY=base64_encoded_32_bytes
STRIX_WEBHOOK_SECRET=base64_encoded_32_bytes
STRIX_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
STRIX_CORS_ORIGINS=https://strix.example.com
STRIX_DISABLE_DOCS=true

# Redis
STRIX_REDIS_URL=redis://redis:6379/0
STRIX_REDIS_REQUIRED=true

# Retention (0 keeps everything)
STRIX_RETENTION_DAYS=90

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4318/v1/traces
STRIX_LOG_LEVEL=INFO
STRIX_LOG_FORMAT=json
```
## Signed scope documents

`STRIX_SCOPE_JWKS` names a JWKS file (RFC 8037 Ed25519 keys). When it is set, a
scope document loads only if it carries a valid signature from one of those
keys. An unsigned or tampered document is refused and the API serves with no
active scope -- every target denied -- rather than falling back to an unsigned
file.

```bash
strix scope-keygen --kid 2026-11          # writes scope-signing-key.pem (0600) + scope-jwks.json
strix scope-sign --scope scope.json --key scope-signing-key.pem --kid 2026-11
STRIX_SCOPE_JWKS=/etc/strix/scope-jwks.json strix serve
```

Rotation: run `scope-keygen --kid 2026-12` against the same `--jwks` file (it
adds the key instead of replacing the set), sign new documents with the new kid,
then retire the old key by deleting its entry. Documents signed with a retired
key stop loading -- removing the key is the revoke step.

The signature covers every field, including `revoked` and `expires_at`, so
revoking or extending a signed document must re-sign it:

```python
revoke_scope(path, revoked_by="sec-lead", reason="engagement ended",
             private_key="scope-signing-key.pem", kid="2026-12")
```

Signatures prove authorship, not recency: a document saved before a revocation
would verify forever. Every signature therefore carries a signed `issued_at`, and
`STRIX_SCOPE_MAX_AGE_SECONDS` (default 24h) bounds its age -- an older copy is
refused as stale. Re-sign to refresh, which `revoke_scope` and
`extend_scope_expiry` already do when given the key.

Minting a scope should bound its lifetime. `strix scope-sign` stamps
`expires_at` from `--expires-in` (default `24h`, `--no-expiry` to opt out), and
never replaces an `expires_at` the document already sets -- signing cannot
extend a window it did not create.

`STRIX_SCOPE_INTEL_FILE` points at a JSON file read at startup to install
the ASN and GeoIP lookups, e.g.
`{"asn": {"93.184.216.0/24": 15133}, "country": {"93.184.216.0/24": "US"}}`.
Longest prefix wins; a malformed file stops the app from loading the scope, and
an address with no matching prefix is refused.

Optional network policy lives in the same document: `allowed_asns` and
`allowed_countries` (ISO 3166-1 alpha-2). The gate consults lookup functions the
application installs with `strix.core.scope.register_intel(asn=..., country=...)`
and denies with `policy_unavailable` when a policy is set without a usable
source, so a broken or stale BGP/GeoIP table cannot widen access.

Just-in-time authorization is opt-in through `STRIX_SCOPE_JIT_URL`. After the
local scope allows a target, `ScopeGate.validate_outbound_async` posts the
decision input there and treats anything other than HTTP 200 with
`{"result": {"allow": true}}` as a denial.

Keep the private key off every host that only verifies documents.
