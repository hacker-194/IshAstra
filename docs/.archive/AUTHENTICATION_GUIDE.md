# Ishastra API Authentication Guide

## Overview

Ishastra uses **API Key authentication** with tiered access control and a
read/write scope. All authenticated endpoints require a valid API key passed in
the `Authorization` header as a Bearer token.

## Quick Start

### 1. Get Your API Key

If you're an administrator, create a key for a tenant:

```bash
curl -X POST https://ishastra.example.com/api/keys/create \
  -H "Authorization: Bearer sk_admin_..." \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "my-org",
    "tier": "unlimited",
    "scope": "write",
    "ttl_days": 365
  }'
```

**Save the returned `api_key` immediately — it's shown only once.**

### 2. Use the API Key

```bash
curl -H "Authorization: Bearer sk_live_abc123..." \
  https://ishastra.example.com/api/overview
```

---

## Key Tiers & Permissions

| Tier | General requests/min | Assessment submissions/min |
|------|----------------------|----------------------------|
| `standard` | 5 | 5 |
| `elevated` | 60 | 20 |
| `unlimited` | 300 | 60 |

The tier controls rate limits only. Profiles, scheduling, webhooks, policies and
every other feature are identical and MIT-licensed; they are not gated by tier.
These names are not prices or paid plans. The API accepts `standard`, `elevated` and
`unlimited`; `professional` is not a valid value.

## Key Scopes

| Scope | Allowed | Use it for |
|-------|---------|------------|
| `write` (default) | All endpoints the key's tier and admin flag permit | CI, scanners and operators that create or change state |
| `read` | `GET`, `HEAD` and `OPTIONS` only | Dashboards, report readers and least-privilege integrations |

A `read` key is refused with `403` on any other HTTP method, including
`POST /api/probe` and `POST /api/assess`. Scope does not replace the engagement
policy: a read key still only sees targets the tenant is authorized to assess.

A tenant has one legacy tenant key that is replaced on rotation, plus any number
of member keys (`/api/users`) with `admin`, `analyst` or `viewer` roles. Viewers
are read-only; analysts can run assessments; tenant admins manage members and
risk-exception decisions. Per-project and per-endpoint scopes do not exist.

## Tenant Users

Tenant admins can create members and receive each member's key once:

```bash
curl -X POST https://ishastra.example.com/api/users \
  -H "Authorization: Bearer <tenant-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice", "role": "analyst", "ttl_days": 365}'
```

Revoke a member with `POST /api/users/{user_id}/revoke`. Member keys are
separate from the legacy tenant key. Organizations (`/api/v2/orgs`), OIDC/SAML
SSO (`/auth/*`) and SCIM 2.0 (`/scim/v2`) are implemented; per-project scopes
are not.

---

## Authentication Methods

### Bearer Token (Required)

```http
Authorization: Bearer sk_live_abc123def456...
```

### Idempotency Key (Optional)

For safe retries on assessment creation:

```http
Idempotency-Key: assessment-2024-01-15-001
```

- Must be 1-128 characters: `A-Z a-z 0-9 . _ : -`
- Repeat the same key to get the original job instead of creating a duplicate
- Response includes `"deduplicated": true` for repeated requests

---

## Key Management

### Create Key (Admin or Tenant Owner)

```http
POST /api/keys/create
Authorization: Bearer <your-key>
Content-Type: application/json

{
  "tenant": "acme-corp",
  "tier": "unlimited",
  "scope": "read",
  "ttl_days": 365
}
```

**Constraints:**
- `tenant`: alphanumeric + `._-`, 1-64 chars
- `tier`: `standard`, `elevated`, or `unlimited`
- `scope`: `read` or `write` (default: `write`)
- `ttl_days`: 1-3650 (optional, null = no expiry)

**Permissions:**
- Admins can create keys for any tenant
- Tenants can only create keys for themselves
- Cannot create a key with tier higher than your own

---

### Rotate Key

```http
POST /api/keys/rotate/acme-corp?ttl_days=365
Authorization: Bearer <your-key>
```

- Generates new key, invalidates old one immediately
- Preserves absolute expiry unless new `ttl_days` provided
- Returns new key (shown only once)

---

### Check Key Status

```http
GET /api/keys/status
Authorization: Bearer <your-key>
```

**Response:**
```json
{
  "tenant_id": "acme-corp",
  "tier": "unlimited",
  "active": true,
  "admin": false,
  "scope": "write",
  "expires_at": "2025-01-15T10:30:00Z",
  "created_at": "2024-01-15T10:30:00Z",
  "last_used_at": "2024-01-14T15:20:00Z"
}
```

---

### Revoke Key

```http
POST /api/keys/revoke/acme-corp
Authorization: Bearer <your-key>
```

- Immediately invalidates the key
- Cannot be undone; must create a new key

---

## Scope & Authorization

### Managed Mode (Multi-tenant)

Each tenant has an **engagement policy** created by administrators:

```json
{
  "tenant_id": "acme-corp",
  "program": "Acme Corp Bug Bounty",
  "authorized_by": "Security Team",
  "authorization_ref": "BB-2024-001",
  "include": ["example.com", "api.example.com"],
  "exclude": ["staging.example.com"],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443, 8080, 8443],
  "allow_broad_networks": false,
  "effective_at": 1705312800,
  "expires_at": 1736848800
}
```

**Your API key is bound to your tenant's policy.** You can only assess targets within your `include` list, minus `exclude`, on allowed ports/networks.

### Global Mode (Single-tenant)

Single scope document at `ISHASTRA_SCOPE_FILE` applies to all tenants.

---

## Per-Assessment Authentication

For assessing authenticated endpoints, provide auth config in the assessment request:

### Token / API Key Auth

```json
{
  "auth": {
    "type": "token",
    "bearer": "eyJhbGciOiJIUzI1NiIs...",
    "api_key": "sk_live_...",
    "api_key_header": "X-API-Key",
    "custom_headers": {"X-Org-ID": "123"},
    "principal_id": "api-user-1"
  }
}
```

### Session / Cookie Auth

```json
{
  "auth": {
    "type": "session",
    "cookies": {"sessionid": "abc123", "csrftoken": "xyz789"},
    "principal_id": "session-user-1"
  }
}
```

### Form Login Auth

```json
{
  "auth": {
    "type": "form_login",
    "login_url": "https://example.com/login",
    "username": "testuser",
    "password": "secret",
    "username_field": "username",
    "password_field": "password",
    "csrf_field": "csrf_token",
    "extra_fields": {"remember_me": "true"},
    "principal_id": "form-user-1"
  }
}
```

### Multi-Step Auth (Chained)

```json
{
  "auth": {
    "type": "multi_step",
    "steps": [
      {"type": "token", "bearer": "initial-token"},
      {"type": "form_login", "login_url": "https://example.com/2fa", "username": "user", "password": "pass"}
    ],
    "principal_id": "mfa-user-1"
  }
}
```

**Security Notes:**
- Credentials are encrypted at rest using `ISHASTRA_ENCRYPTION_KEY`
- `principal_id` uniquely identifies this auth config (auto-generated if omitted)
- Only the assessment worker can decrypt and use the credentials

---

## Rate Limit Headers

Every response includes:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Max requests in window |
| `X-RateLimit-Remaining` | Requests left |
| `X-RateLimit-Reset` | Unix timestamp when window resets |

**429 Response:**
```json
{
  "detail": "Rate limit exceeded. Try again in 45 seconds."
}
```

---

## Error Responses

### 401 Unauthorized
```json
{"detail": "Invalid or missing API key"}
```

### 403 Forbidden
```json
{"detail": "Target https://evil.com is not within authorized scope"}
{"detail": "Cannot manage API keys for another tenant"}
{"detail": "Insufficient tier for this operation"}
```

### 429 Too Many Requests
```json
{"detail": "Rate limit exceeded. Try again in 45 seconds."}
```

---

## Best Practices

### 1. Store Keys Securely
- Use environment variables: `export ISHASTRA_API_KEY=sk_live_...`
- Never commit keys to version control
- Follow a key-specific rotation policy; changing audit or encryption keys
  without the required migration can invalidate audit verification or make
  stored credentials unreadable. See the [secret rotation runbook](runbooks/secret-rotation.md).

### 2. Use Idempotency Keys
```bash
# Safe to retry on network failures
curl -X POST /api/assess \
  -H "Idempotency-Key: scan-$(date +%s)-${RANDOM}" \
  -d '{"target": "https://example.com"}'
```

### 3. Handle Rate Limits Gracefully
```python
import time
import httpx

def api_call_with_retry(client, method, url, **kwargs):
    for attempt in range(3):
        response = client.request(method, url, **kwargs)
        if response.status_code == 429:
            reset = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - time.time(), 1)
            time.sleep(wait)
            continue
        return response
    raise Exception("Rate limited after retries")
```

### 4. Choose a Rate-Limit Profile
- `free`: Development, testing, low-volume scanning
- `pro`: Regular assessments and CI/CD integration
- `enterprise`: High-volume deployments

All tiers can use every profile, scheduling, webhooks and policy feature. The
tier changes rate limits only.

### 5. Monitor Key Usage
```bash
# Check last_used_at to detect unused keys
curl -H "Authorization: Bearer $ADMIN_KEY" \
  https://ishastra.example.com/api/keys/status
```

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ISHASTRA_API_KEY` | Admin key for bootstrap | Yes (prod) |
| `ISHASTRA_ENCRYPTION_KEY` | Base64 32-byte key for AES-GCM field encryption of stored auth configs and webhook URLs | Required in production |
| `ISHASTRA_SCOPE_FILE` | Path to global scope document | Global mode only |

---

## Local Keycloak (OIDC)

The compose profile imports a development-only Ishastra realm and OIDC client.
Start it with the API:

```bash
ISHASTRA_OIDC_ISSUER=http://keycloak.localhost:8180/realms/ishastra \
ISHASTRA_OIDC_CLIENT_ID=ishastra-local \
ISHASTRA_OIDC_CLIENT_SECRET=ishastra-local-dev-secret \
ISHASTRA_OIDC_REDIRECT_URI=http://localhost:8000/api/auth/oidc/callback \
  docker compose --profile sso up -d keycloak scope-gate
curl -fsS http://localhost:8180/realms/ishastra/.well-known/openid-configuration
```

Open `http://localhost:8000/api/auth/oidc/login`. The test account is
`ishastra-local-user` / `local-only-change-me`; the Keycloak admin password is
`local-only-change-me`. These defaults are for local development only. Do not
reuse them outside a disposable environment. The API exchanges the authorization
code using PKCE and validates the ID token against Keycloak's JWKS.

The realm uses `keycloak.localhost`, which resolves to loopback in browsers and
to the Keycloak container on the Compose network. Override `ISHASTRA_OIDC_*` in the
environment if the API is exposed at another URL. Existing SAML configuration
is independent and is set through the `ISHASTRA_SAML_*` variables below.

---

## Troubleshooting

### "Invalid API Key"
- Key may be revoked, expired, or mistyped
- Check `GET /api/keys/status` with a working admin key

### "Target not in scope"
- Verify target matches `include` patterns in your policy
- Check `exclude` patterns aren't matching
- Ensure ports are in `allowed_ports`

### "Rate limit exceeded"
- Implement exponential backoff
- Consider upgrading tier
- Batch requests where possible

### "Authentication encryption key not configured"
- Set `ISHASTRA_ENCRYPTION_KEY` (32 random bytes, base64 encoded)
- Required for per-assessment auth configs

---

## Migration from Legacy Auth

If upgrading from a version without tiered keys:

1. All existing keys are treated as `enterprise` tier
2. Run `ishastra admin migrate-keys` to assign explicit tiers
3. Update any hardcoded tier assumptions in client code