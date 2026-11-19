# Scope Management API

# Scope Management API

REST API for managing Scope Gate documents and authorization policies.

## Base URL

```
https://api.strix.dev/api/v1
```

## Scope Document Object

```json
{
  "id": "scope_prod_001",
  "name": "Production Scope",
  "description": "Authorized targets for production assessments",
  "version": 2,
  "metadata": {
    "owner": "security@company.com",
    "created_by": "key_abc123",
    "tags": ["production", "pci-dss"]
  },
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "include_hosts": ["api.example.com", "app.example.com"],
  "exclude_hosts": ["internal.example.com", "admin.example.com"],
  "allowed_ports": [80, 443, 8080, 8443],
  "dns_resolver": "cloudflare",
  "dns_timeout": 5,
  "dns_servers": ["1.1.1.1", "1.0.0.1"],
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@company.com", "cto@company.com"],
    "max_duration": 3600,
    "require_mfa": true,
    "notification_webhook": "https://company.slack.com/webhook"
  },
  "signing": {
    "key_id": "strix-2024-01",
    "algorithm": "Ed25519",
    "jwks_url": "https://api.strix.dev/.well-known/jwks.json"
  },
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z",
  "revoked_at": null,
  "status": "active"
}
```

## Status Values

| Status | Description |
|--------|-------------|
| `draft` | Not yet activated |
| `active` | Currently in use |
| `deprecated` | Superseded by newer version |
| `revoked` | Emergency revocation |

## Create Scope

```bash
POST /scopes
```

### Request

```json
{
  "name": "Production Scope",
  "description": "Authorized targets for production assessments",
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "include_hosts": ["api.example.com", "app.example.com"],
  "exclude_hosts": ["internal.example.com"],
  "allowed_ports": [80, 443, 8080, 8443],
  "dns_resolver": "cloudflare",
  "dns_timeout": 5,
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@company.com", "cto@company.com"],
    "max_duration": 3600,
    "require_mfa": true
  }
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Description |
| `authorized_networks` | string[] | Yes | CIDR allowlist |
| `include_hosts` | string[] | No | Host suffix allowlist |
| `exclude_hosts` | string[] | No | Host suffix blocklist |
| `allowed_ports` | int[] | No | Port allowlist (default: [80, 443]) |
| `dns_resolver` | enum | No | `system`, `cloudflare`, `google`, `quad9`, `custom` |
| `dns_timeout` | int | No | DNS timeout seconds (default: 5) |
| `dns_servers` | string[] | No | Custom DNS servers (when resolver=custom) |
| `break_glass` | object | No | Emergency access config |
| `signing` | object | No | Signing key config (auto-generated) |

### Response (201 Created)

```json
{
  "id": "scope_prod_001",
  "name": "Production Scope",
  "version": 2,
  "status": "draft",
  "created_at": "2024-01-15T10:00:00Z",
  "signing": {
    "key_id": "strix-2024-01",
    "algorithm": "Ed25519",
    "jwks_url": "https://api.strix.dev/.well-known/jwks.json"
  }
}
```

## Get Scope

```bash
GET /scopes/{scope_id}
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | int | Specific version (default: latest) |
| `include_revoked` | bool | Include revoked scopes |

### Response (200 OK)

```json
{
  "id": "scope_prod_001",
  "name": "Production Scope",
  "version": 2,
  "status": "active",
  ...
}
```

## List Scopes

```bash
GET /scopes
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status |
| `tag` | string | - | Filter by tag |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

### Response (200 OK)

```json
{
  "scopes": [
    {"id": "scope_prod_001", "name": "Production", "status": "active", ...},
    {"id": "scope_staging_001", "name": "Staging", "status": "active", ...}
  ],
  "pagination": {"total": 5, "limit": 50, "offset": 0, "has_more": false}
}
```

## Update Scope

```bash
PATCH /scopes/{scope_id}
```

### Request

```json
{
  "description": "Updated description",
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "include_hosts": ["api.example.com", "app.example.com", "new.example.com"]
}
```

### Response (200 OK)

```json
{
  "id": "scope_prod_001",
  "version": 3,
  "updated_at": "2024-01-15T14:30:00Z",
  ...
}
```

## Activate Scope

```bash
POST /scopes/{scope_id}/activate
```

### Response (200 OK)

```json
{
  "id": "scope_prod_001",
  "status": "active",
  "activated_at": "2024-01-15T14:30:00Z",
  "activated_by": "key_abc123"
}
```

## Deprecate Scope

```bash
POST /scopes/{scope_id}/deprecate
```

### Request

```json
{
  "replacement_scope_id": "scope_prod_002"
}
```

### Response (200 OK)

```json
{
  "id": "scope_prod_001",
  "status": "deprecated",
  "deprecated_at": "2024-01-15T14:30:00Z",
  "replacement_scope_id": "scope_prod_002"
}
```

## Revoke Scope (Emergency)

```bash
POST /scopes/{scope_id}/revoke
```

### Request

```json
{
  "reason": "Compromised signing key",
  "immediate": true
}
```

### Response (200 OK)

```json
{
  "id": "scope_prod_001",
  "status": "revoked",
  "revoked_at": "2024-01-15T14:30:00Z",
  "revoked_by": "key_abc123",
  "reason": "Compromised signing key"
}
```

## Validate Scope Configuration

```bash
POST /scopes/{scope_id}/validate
```

### Response (200 OK)

```json
{
  "valid": true,
  "warnings": [],
  "errors": [],
  "checks": {
    "cidr_syntax": "pass",
    "host_syntax": "pass",
    "port_range": "pass",
    "dns_resolver": "pass",
    "break_glass_config": "pass",
    "signing_key": "pass"
  }
}
```

## Test Scope Against Target

```bash
POST /scopes/{scope_id}/test
```

### Request

```json
{
  "url": "https://api.example.com/endpoint"
}
```

### Response (200 OK)

```json
{
  "allowed": true,
  "layers": {
    "layer1": {"decision": "allow", "reason": "Host in include_hosts"},
    "layer2": {"decision": "allow", "reason": "IP in authorized_networks", "resolved_ips": ["10.0.1.50"]},
    "layer3": {"decision": "allow", "pinned_ip": "10.0.1.50", "ttl": 300}
  },
  "destination": {
    "scheme": "https",
    "host": "api.example.com",
    "port": 443,
    "ip": "10.0.1.50",
    "resolved_at": 1705312800,
    "ttl": 300
  }
}
```

## Get Scope Versions

```bash
GET /scopes/{scope_id}/versions
```

### Response (200 OK)

```json
{
  "versions": [
    {"version": 3, "status": "active", "created_at": "2024-01-15T14:30:00Z"},
    {"version": 2, "status": "deprecated", "created_at": "2024-01-10T10:00:00Z"},
    {"version": 1, "status": "deprecated", "created_at": "2024-01-01T10:00:00Z"}
  ]
}
```

## Export Scope Document

```bash
GET /scopes/{scope_id}/export
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | enum | `json` | `json`, `yaml` |
| `version` | int | latest | Specific version |

### Response (200 OK)

```json
{
  "version": 2,
  "metadata": {"name": "Production Scope", "owner": "security@company.com"},
  "authorized_networks": ["10.0.0.0/8"],
  "include_hosts": ["api.example.com"],
  "exclude_hosts": [],
  "allowed_ports": [80, 443],
  "dns_resolver": "cloudflare",
  "dns_timeout": 5,
  "break_glass": {...},
  "signing": {...}
}
```

## Import Scope Document

```bash
POST /scopes/import
```

### Request

```json
{
  "name": "Imported Scope",
  "document": {
    "version": 2,
    "metadata": {"name": "Imported Scope", "owner": "security@company.com"},
    "authorized_networks": ["10.0.0.0/8"],
    ...
  }
}
```

### Response (201 Created)

```json
{
  "id": "scope_imported_001",
  "name": "Imported Scope",
  "version": 2,
  "status": "draft",
  "created_at": "2024-01-15T15:00:00Z"
}
```

## Error Responses

### 400 Bad Request

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid scope configuration",
    "details": {
      "field_errors": {
        "authorized_networks": "Invalid CIDR: 'invalid/cidr'",
        "break_glass.approvers": "At least 2 approvers required when enabled"
      }
    }
  }
}
```

### 404 Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Scope not found",
    "details": {"scope_id": "scope_prod_001"}
  }
}
```

### 409 Conflict

```json
{
  "error": {
    "code": "CONFLICT",
    "message": "Scope has active assessments",
    "details": {
      "active_assessments": ["asm_abc123", "asm_def456"],
      "action": "Cancel assessments or wait for completion"
    }
  }
}
```

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /scopes` | 10/min per key |
| `GET /scopes` | 100/min per key |
| `GET /scopes/{id}` | 200/min per key |
| `PATCH /scopes/{id}` | 20/min per key |
| `POST /scopes/{id}/validate` | 50/min per key |
| `POST /scopes/{id}/test` | 100/min per key |

## Break-Glass Configuration {#break-glass}

The `break_glass` field in scope documents configures emergency access:

```json
{
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@company.com", "cto@company.com"],
    "max_duration": 3600,
    "require_mfa": true,
    "notification_webhook": "https://company.slack.com/webhook"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | bool | Yes | Enable break-glass for this scope |
| `approvers` | string[] | Yes | Minimum 2 email addresses for dual approval |
| `max_duration` | int | Yes | Maximum access duration in seconds (max: 86400) |
| `require_mfa` | bool | No | Require MFA for approvers (default: true) |
| `notification_webhook` | string | No | Webhook URL for break-glass events |

### Break-Glass API Endpoints

```bash
# Request break-glass access
POST /api/v1/scopes/{scope_id}/break-glass/request

# Approve break-glass request (requires 2 approvals)
POST /api/v1/break-glass/{request_id}/approve

# Get break-glass status
GET /api/v1/break-glass/{request_id}
```

## Strix Proof Verification {#proof-verification}

Scope documents are cryptographically signed using Ed25519. The signing configuration:

```json
{
  "signing": {
    "key_id": "strix-2024-01",
    "algorithm": "Ed25519",
    "jwks_url": "https://api.strix.dev/.well-known/jwks.json"
  }
}
```

### Verification Process

1. Fetch JWKS from `jwks_url`
2. Find key matching `key_id`
3. Verify scope document signature
4. Check certificate chain validity

```python
import jwt
import requests

def verify_scope_signature(scope_doc: dict) -> bool:
    signing = scope_doc["signing"]
    jwks = requests.get(signing["jwks_url"]).json()
    
    # Find matching key
    key = next((k for k in jwks["keys"] if k["kid"] == signing["key_id"]), None)
    if not key:
        return False
    
    # Verify using Ed25519 public key
    public_key = jwt.algorithms.ECAlgorithm.from_jwk(key)
    # ... verification logic
    return True
```

## Related

- [Authentication](../api/authentication.md)
- [Assessments API](../api/assessments.md)
- [Scope Gate Concepts](../scope-gate/concepts.md)
- [Scope Gate Configuration](../scope-gate/configuration.md)