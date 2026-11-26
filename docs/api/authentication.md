# API Authentication

IshAstra authenticates API requests with **Bearer API keys**. Browser sessions
can use OIDC or SAML when an operator configures an identity provider. There is
no API-key-to-JWT exchange and no public JWKS endpoint for API authentication.

## API keys

Create a key with the CLI (admin only):

```bash
ishastra create-api-key --tenant default
```

Options: `--tier {free,pro,enterprise}`, `--scope {read,write}`, `--admin`,
`--ttl-days N`. `--tier` is a rate-limit profile label kept for compatibility,
not a license tier; every deployment is free and ungated. The key is printed
once; store it in a secret manager.

The same operation over HTTP (admin key required):

```http
POST /api/keys/create
Authorization: Bearer $ADMIN_KEY
Content-Type: application/json
```

```json
{
  "tenant": "default",
  "tier": "standard",
  "scope": "write",
  "scope_type": "tenant",
  "ttl_days": 90
}
```

| Field | Description |
|-------|-------------|
| `tenant` | Tenant identifier (`^[A-Za-z0-9_.-]+$`, max 64) |
| `scope` | `read` for safe methods only, `write` to manage jobs, findings and keys |
| `scope_type` | `tenant` for every project, `project` for one project |
| `project_id` | Required when `scope_type` is `project` |
| `ttl_days` | Lifetime in days, 1–3650; omitted means no expiry |

Use the key as a Bearer token:

```bash
curl -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  https://your-host/api/assess
```

Keys are stored as SHA-256 hashes, never in plaintext. The `ishastra_` prefix is
a legacy wire-format prefix retained for compatibility; it grants no additional
privilege.

### Inspect, rotate and revoke

| Route | Description |
|-------|-------------|
| `GET /api/keys/status` | Caller's key metadata |
| `POST /api/keys/rotate/{tenant_id}` | Rotate a tenant key |
| `POST /api/keys/revoke/{tenant_id}` | Revoke a tenant key |
| `GET /api/keys/projects` | List project-scoped keys |
| `POST /api/keys/projects/{project_id}/rotate` | Rotate a project key |
| `POST /api/keys/projects/{project_id}/revoke` | Revoke a project key |

Revocation takes effect on the next request; there is no long-lived JWT to
expire.

### Key scope

A key is either read-only or write-scoped, and may be an admin key. Read-only
keys can call `GET`/`HEAD`/`OPTIONS`; any write method requires a write-scoped
key. Admin-only routes additionally require the admin flag.

## Browser sessions (OIDC/SAML)

When `ISHASTRA_OIDC_*` or the SAML settings are configured, `/auth/oidc/login`
or `/auth/saml/login` redirects to the identity provider and creates a signed
session cookie. The cookie is `HttpOnly`, `Secure` in production, and
`SameSite=Strict`. State-changing browser requests also require the CSRF token
issued with the session.

Tenant identity is derived from the validated API key or the identity-provider
subject. It is never read from `X-Tenant-ID` or any other caller-supplied
header.

Auth routes: `/auth/status`, `/auth/logout`, `/auth/oidc/{login,callback,logout}`,
`/auth/saml/{login,acs,slo}`.

## Middleware and failures

- `TenantStateMiddleware` validates the key and sets `request.state.tenant_id`.
- `require_auth` rejects read-only keys on write methods.
- `require_admin` gates administrative and metrics endpoints.
- Failed authentication returns `401`; insufficient scope returns `403`;
  rate limiting returns `429` with `Retry-After`.

## What is not implemented

- API-key-to-JWT token exchange, JWT TTLs, and a public API JWKS endpoint.
- Per-resource OAuth scopes such as `assessments:read`; use read/write/admin
  key scopes instead.
- mTLS between application components.

See [`SECURITY.md`](https://github.com/hacker-194/IshAstra/blob/main/SECURITY.md)
for the supported security posture.
