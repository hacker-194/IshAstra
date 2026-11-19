# API Authentication

# API Authentication

Authentication and authorization for the Strix REST API.

## Overview

Strix uses **Bearer Token (API Key)** authentication with optional **JWT** for delegated access.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Authentication Flow                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Client                                                                      │
│    │                                                                         │
│    │ 1. POST /api/v1/auth/token (or use pre-issued API Key)                 │
│    ▼                                                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Strix API                                                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐  │   │
│  │  │ API Key     │  │ JWT         │  │ Scope Gate                  │  │   │
│  │  │ Validation  │──▶│ Validation  │──▶│ Authorization (per req)   │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## API Key Authentication

### Obtaining an API Key

```bash
# Via CLI (admin only)
strix auth create-key --name "CI/CD Pipeline" --expires 90d

# Via API (requires existing key)
curl -X POST https://api.strix.dev/api/v1/auth/keys \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Pipeline", "expires_in_days": 90}'
```

**Response:**
```json
{
  "id": "key_abc123",
  "name": "CI/CD Pipeline",
  "prefix": "strix_",
  "key": "strix_abc123def456...",  // Only shown once!
  "created_at": "2024-01-15T10:00:00Z",
  "expires_at": "2024-04-15T10:00:00Z",
  "last_used_at": null
}
```

### Using API Key

```bash
# Header format
Authorization: Bearer strix_abc123def456...

# Example request
curl -H "Authorization: Bearer strix_abc123def456..." \
  https://api.strix.dev/api/v1/assessments
```

### API Key Format

```
strix_{base62_encoded_random_bytes}
```

- Prefix: `strix_` (identifies as Strix key)
- Entropy: 256 bits (32 bytes)
- Encoding: Base62 (URL-safe, no special chars)

### Key Scopes (Planned)

```json
{
  "scopes": [
    "assessments:read",
    "assessments:write",
    "findings:read",
    "scope:read",
    "scope:write",
    "admin:keys"
  ]
}
```

## JWT Authentication (Delegated)

### Token Exchange

```bash
# Exchange API Key for short-lived JWT
curl -X POST https://api.strix.dev/api/v1/auth/token \
  -H "Authorization: Bearer strix_abc123def456..." \
  -H "Content-Type: application/json" \
  -d '{"ttl_seconds": 3600}'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "assessments:read assessments:write"
}
```

### Using JWT

```bash
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

### JWKS Endpoint

```bash
# Public keys for JWT verification
curl https://api.strix.dev/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "strix-2024-01",
      "x": "base64url-encoded-public-key",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

## Middleware Implementation

### API Key Validator

```python
# src/strix/api/middleware/auth.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from strix.core.auth import validate_api_key, validate_jwt

security = HTTPBearer(auto_error=False)

async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Identity:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Try API Key first
    if token.startswith("strix_"):
        identity = await validate_api_key(token)
        if identity:
            return identity
    
    # Try JWT
    identity = await validate_jwt(token)
    if identity:
        return identity
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

### Scope-Based Authorization

```python
# Per-request Scope Gate check
async def authorize_request(
    identity: Identity = Depends(get_current_identity),
    request: Request = None
) -> AuthorizationContext:
    # Extract target from request
    target_url = extract_target(request)
    
    # Validate through Scope Gate
    dest = await scope_gate.validate_outbound(target_url, identity.scope)
    
    return AuthorizationContext(
        identity=identity,
        destination=dest,
        scope=identity.scope
    )
```

## Identity Model

```python
@dataclass
class Identity:
    # API Key auth
    key_id: str | None = None
    key_name: str | None = None
    key_scopes: list[str] = field(default_factory=list)
    
    # JWT auth
    subject: str | None = None  # "user:123" or "service:ci"
    tenant_id: str | None = None
    roles: list[str] = field(default_factory=list)
    
    # Scope Gate
    scope_id: str
    scope: ScopeDocument
    
    # Metadata
    authenticated_at: datetime
    source: Literal["api_key", "jwt"]
```

## Rate Limiting by Identity

```python
# Per-identity rate limits
RATE_LIMITS = {
    "default": {"requests": 100, "window": "1m"},
    "assessments:write": {"requests": 10, "window": "1m"},
    "scope:write": {"requests": 5, "window": "1m"},
    "admin:*": {"requests": 1000, "window": "1m"},
}

# Applied via middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    identity = request.state.identity
    limits = get_limits_for_identity(identity)
    # ... enforce limits
```

## Error Responses

### 401 Unauthorized

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token",
    "details": {}
  }
}
```

### 403 Forbidden

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Insufficient scopes for this operation",
    "details": {
      "required_scopes": ["assessments:write"],
      "granted_scopes": ["assessments:read"]
    }
  }
}
```

### 429 Too Many Requests

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 100,
      "window": "60s",
      "retry_after": 45
    }
  }
}
```

## Security Best Practices

### For Clients

1. **Store keys securely** - Use environment variables, secret managers
2. **Rotate regularly** - 90-day max expiry recommended
3. **Use least privilege** - Create keys with minimal required scopes
4. **Monitor usage** - Check `last_used_at` for unused keys
5. **Revoke immediately** if compromised

### For Server

1. **Hash stored keys** - bcrypt/scrypt, never plaintext
2. **Log auth events** - Success/failure with key prefix (not full key)
3. **Enforce HTTPS** - Reject HTTP in production
4. **Implement key rotation** - Automated expiry and renewal
5. **Audit trail** - All auth decisions logged to SIEM

## Key Management API

### List Keys

```bash
GET /api/v1/auth/keys
```

```json
{
  "keys": [
    {
      "id": "key_abc123",
      "name": "CI/CD Pipeline",
      "prefix": "strix_",
      "created_at": "2024-01-15T10:00:00Z",
      "expires_at": "2024-04-15T10:00:00Z",
      "last_used_at": "2024-01-15T14:30:00Z",
      "scopes": ["assessments:read", "assessments:write"]
    }
  ]
}
```

### Revoke Key

```bash
DELETE /api/v1/auth/keys/{key_id}
```

### Rotate Key

```bash
POST /api/v1/auth/keys/{key_id}/rotate
```

```json
{
  "id": "key_abc123",
  "name": "CI/CD Pipeline",
  "prefix": "strix_",
  "key": "strix_newkey...",  // New key
  "created_at": "2024-04-15T10:00:00Z",
  "expires_at": "2024-07-15T10:00:00Z"
}
```

## Related

- [Assessments API](../api/assessments.md)
- [Findings API](../api/findings.md)
- [Scope Management](../api/scope-management.md)
- [Webhooks](../api/webhooks.md)
- [Security Review](../security-review.md)