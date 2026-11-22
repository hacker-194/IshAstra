# API Authentication

Ishastra authenticates API requests with **Bearer API keys**. Browser sessions
can use OIDC or SAML when an operator configures an identity provider. There is
no API-key-to-JWT exchange and no public JWKS endpoint for API authentication.

## API keys

Create a key with the CLI (admin only):

```bash
ishastra auth create-key --name "CI/CD Pipeline" --expires 90d
```

Or with an existing admin key:

```bash
curl -X POST https://your-host/api/v1/auth/keys \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Pipeline", "expires_in_days": 90}'
```

The response contains the key once. Store it in a secret manager.

```json
{
  "id": "key_abc123",
  "name": "CI/CD Pipeline",
  "key": "ishastra_abc123...",
  "created_at": "2026-01-15T10:00:00Z",
  "expires_at": "2026-04-15T10:00:00Z"
}
```

Use it as a Bearer token:

```bash
curl -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  https://your-host/api/v1/assessments
```

Keys are stored as SHA-256 hashes, never in plaintext. The `ishastra_` prefix is a
legacy wire-format prefix retained for compatibility; it does not grant any
additional privilege.

### Key scope

A key is either read-only or write-scoped, and may be an admin key. Read-only
keys can call `GET`/`HEAD`/`OPTIONS`; any write method requires a write-scoped
key. Admin-only routes additionally require the admin flag.

### Rotation and revocation

Rotate a key by creating a replacement and revoking the old one. Revocation
takes effect on the next request; there is no long-lived JWT to expire.

```bash
ishastra auth rotate-key --help
ishastra auth revoke-key --help
```

## Browser sessions (OIDC/SAML)

When `ISHASTRA_OIDC_*` or the SAML settings are configured, `/auth/login`
redirects to the identity provider and creates a signed session cookie. The
cookie is `HttpOnly`, `Secure` in production, and `SameSite=Strict`. State-
changing browser requests also require the CSRF token issued with the session.

Tenant identity is derived from the validated API key or the identity-provider
subject. It is never read from `X-Tenant-ID` or any other caller-supplied header.

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

See [`SECURITY.md`](https://github.com/hacker-194/IshAstra/blob/master/SECURITY.md) for the supported security posture.
