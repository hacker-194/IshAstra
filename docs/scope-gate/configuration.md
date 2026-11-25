# NOTE: IshAstra does not implement MFA; enforce it at your identity provider.

# Scope Gate Configuration

# Scope Gate Configuration

Complete reference for configuring the Scope Gate authorization engine.

## Scope Document Schema (v2)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["version", "metadata", "authorized_networks"],
  "properties": {
    "version": {"type": "integer", "const": 2},
    "metadata": {
      "type": "object",
      "required": ["name", "owner"],
      "properties": {
        "name": {"type": "string", "maxLength": 256},
        "owner": {"type": "string", "format": "email"},
        "created": {"type": "string", "format": "date-time"},
        "expires": {"type": "string", "format": "date-time"},
        "description": {"type": "string", "maxLength": 1024}
      }
    },
    "authorized_networks": {
      "type": "array",
      "items": {"type": "string", "pattern": "^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^([0-9a-fA-F:]+)(/[0-9]{1,3})?$"},
      "minItems": 1
    },
    "include_hosts": {
      "type": "array",
      "items": {"type": "string", "maxLength": 255}
    },
    "exclude_hosts": {
      "type": "array",
      "items": {"type": "string", "maxLength": 255}
    },
    "allowed_ports": {
      "type": "array",
      "items": {"type": "integer", "minimum": 1, "maximum": 65535},
      "uniqueItems": true,
      "default": [80, 443, 8080, 8443]
    },
    "dns_resolver": {
      "type": "string",
      "enum": ["system", "cloudflare", "google", "quad9", "custom"],
      "default": "system"
    },
    "dns_timeout": {
      "type": "integer",
      "minimum": 1,
      "maximum": 30,
      "default": 5
    },
    "dns_servers": {
      "type": "array",
      "items": {"type": "string", "format": "ipv4"},
      "maxItems": 3
    },
    "break_glass": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean", "default": false},
        "approvers": {
          "type": "array",
          "items": {"type": "string", "format": "email"},
          "minItems": 2
        },
        "max_duration": {"type": "string", "pattern": "^\\d+[hm]$"},
      }
    },
    "signing": {
      "type": "object",
      "properties": {
        "key_id": {"type": "string"},
        "algorithm": {"type": "string", "const": "Ed25519"}
      }
    }
  }
}
```

## Field Reference

### version
- **Required**: Yes
- **Type**: Integer
- **Value**: Must be `2` (v1 legacy not supported)

### metadata
- **name**: Human-readable scope name (max 256 chars)
- **owner**: Contact email for scope owner
- **created**: ISO 8601 timestamp (auto-generated if omitted)
- **expires**: Optional expiration (scope becomes invalid after)
- **description**: Optional free-text description

### authorized_networks
- **Required**: Yes
- **Type**: Array of CIDR strings
- **Min items**: 1
- **Format**: IPv4 CIDR (`10.0.0.0/8`) or IPv6 CIDR (`2001:db8::/32`)
- **Purpose**: Explicit allowlist for Layer 2 IP validation

```json
"authorized_networks": [
  "10.0.0.0/8",           // RFC 1918 private
  "192.168.0.0/16",       // RFC 1918 private
  "172.16.0.0/12",        // RFC 1918 private
  "2001:db8::/32",        // Documentation (explicitly allowed)
  "169.254.169.254/32"    // AWS metadata (explicitly allowed)
]
```

### include_hosts
- **Optional**
- **Type**: Array of hostname patterns
- **Matching**: Suffix match (`.example.com` matches `api.example.com`)
- **Wildcards**: `*.example.com` supported
- **Precedence**: Evaluated before `exclude_hosts`

```json
"include_hosts": [
  "api.example.com",
  "*.internal.example.com",
  "app.*.example.com"
]
```

### exclude_hosts
- **Optional**
- **Type**: Array of hostname patterns
- **Matching**: Suffix match
- **Precedence**: Overrides `include_hosts`

```json
"exclude_hosts": [
  "admin.example.com",
  "*.staging.example.com",
  "*.dev.example.com"
]
```

### allowed_ports
- **Optional**
- **Default**: `[80, 443, 8080, 8443]`
- **Type**: Array of integers (1-65535)
- **Unique**: Yes

```json
"allowed_ports": [80, 443, 8080, 8443, 3000, 8000]
```

### dns_resolver
- **Optional**
- **Default**: `"system"`
- **Options**:
  - `"system"`: OS resolver (getaddrinfo)
  - `"cloudflare"`: 1.1.1.1 (DoH)
  - `"google"`: 8.8.8.8 (DoH)
  - `"quad9"`: 9.9.9.9 (DoH)
  - `"custom"`: Use `dns_servers`

### dns_timeout
- **Optional**
- **Default**: `5`
- **Range**: 1-30 seconds

### dns_servers
- **Required if**: `dns_resolver: "custom"`
- **Type**: Array of IPv4 addresses
- **Max**: 3 servers

```json
"dns_resolver": "custom",
"dns_servers": ["10.0.0.1", "10.0.0.2"]
```

### break_glass {#break-glass}
- **Optional**
- **enabled**: Enable emergency access
- **approvers**: Minimum 2 email addresses for dual approval
- **max_duration**: Duration string (e.g., `"4h"`, `"30m"`, `"1d"`)

```json
"break_glass": {
  "enabled": true,
  "approvers": ["security-lead@example.com", "cto@example.com", "ciso@example.com"],
  "max_duration": "4h",
}
```

### signing
- **Optional**
- **key_id**: Key identifier for Ed25519 signing
- **algorithm**: Must be `"Ed25519"`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ISHASTRA_SCOPE_DOC_PATH` | `scope.json` | Path to scope document |
| `ISHASTRA_SCOPE_CACHE_TTL` | `300` | DNS cache TTL (seconds) |
| `ISHASTRA_SCOPE_MAX_CACHE_SIZE` | `10000` | Max cached resolutions |
| `ISHASTRA_DNS_RESOLVER` | `system` | Default DNS resolver |
| `ISHASTRA_DNS_TIMEOUT` | `5` | Default DNS timeout |
| `ISHASTRA_BREAK_GLASS_ENABLED` | `false` | Global break-glass enable |
| `ISHASTRA_REVOCATION_URL` | — | Revocation check endpoint |
| `ISHASTRA_JWKS_URL` | — | JWKS endpoint for verification |

## Programmatic Configuration

```python
from ishastra.core.scope import ScopeGate, ScopeDocument
from ishastra.core.scope_signing import JWKSManager

# Create scope document
scope = ScopeDocument(
    version=2,
    metadata=ScopeMetadata(
        name="Production",
        owner="security@example.com",
        expires=datetime(2024, 12, 31)
    ),
    authorized_networks=["10.0.0.0/8", "192.168.0.0/16"],
    include_hosts=["api.example.com"],
    exclude_hosts=["admin.example.com"],
    allowed_ports=[80, 443, 8080, 8443],
    dns_resolver="cloudflare",
    dns_timeout=3,
)

# Configure Scope Gate
gate = ScopeGate(
    scope=scope,
    cache_ttl=300,
    max_cache_size=10000,
    observers=[IshAstraProofObserver(signer, key_id, storage, jwks_manager)],
)

# Or load from file
gate = ScopeGate.from_file("scope.json")
```

## Validation

### Startup Validation

```python
# Validate scope document on startup
scope = ScopeDocument.from_file("scope.json")
errors = scope.validate()

if errors:
    for error in errors:
        print(f"Config error: {error}")
    sys.exit(1)
```

### Schema Validation

```bash
# Validate against JSON Schema
python -m ishastra.core.scope validate scope.json

# Or with jsonschema CLI
jsonschema -i scope.json schemas/scope-v2.json
```

## Examples

### Minimal Scope

```json
{
  "version": 2,
  "metadata": {
    "name": "Internal Scan",
    "owner": "team@example.com"
  },
  "authorized_networks": ["10.0.0.0/8"]
}
```

### Production Scope

```json
{
  "version": 2,
  "metadata": {
    "name": "Production Assessment Q1 2024",
    "owner": "security@example.com",
    "created": "2024-01-15T10:00:00Z",
    "expires": "2024-04-15T10:00:00Z",
    "description": "Quarterly production security assessment"
  },
  "authorized_networks": [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "2001:db8::/32"
  ],
  "include_hosts": [
    "api.example.com",
    "app.example.com",
    "*.internal.example.com"
  ],
  "exclude_hosts": [
    "admin.example.com",
    "*.staging.example.com"
  ],
  "allowed_ports": [80, 443, 8080, 8443],
  "dns_resolver": "cloudflare",
  "dns_timeout": 3,
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@example.com", "cto@example.com"],
    "max_duration": "4h",
  }
}
```

### Multi-Region Scope

```json
{
  "version": 2,
  "metadata": {
    "name": "Multi-Region Assessment",
    "owner": "platform@example.com"
  },
  "authorized_networks": [
    "10.0.0.0/8",          // US-East
    "10.1.0.0/16",         // US-West
    "10.2.0.0/16",         // EU-West
    "10.3.0.0/16",         // AP-Southeast
    "192.168.0.0/16",      // On-prem
    "2001:db8:1::/48",     // IPv6 US
    "2001:db8:2::/48"      // IPv6 EU
  ],
  "include_hosts": [
    "*.example.com"
  ],
  "exclude_hosts": [
    "*.internal.example.com",
    "*.admin.example.com"
  ],
  "allowed_ports": [80, 443, 8080, 8443, 9443],
  "dns_resolver": "system",
  "dns_timeout": 5
}
```

### Break-Glass Only Scope

```json
{
  "version": 2,
  "metadata": {
    "name": "Emergency Incident Response",
    "owner": "incident@example.com",
    "expires": "2024-01-16T10:00:00Z"
  },
  "authorized_networks": ["10.0.0.0/8"],
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@example.com", "cto@example.com", "ciso@example.com"],
    "max_duration": "2h",
  }
}
```

## Migration from v1

v1 scope documents are not supported. Convert:

```python
# v1 format
{
  "scope": {
    "include": ["api.example.com"],
    "exclude": ["admin.example.com"],
    "networks": ["10.0.0.0/8"]
  }
}

# v2 format
{
  "version": 2,
  "metadata": {"name": "Migrated", "owner": "team@example.com"},
  "authorized_networks": ["10.0.0.0/8"],
  "include_hosts": ["api.example.com"],
  "exclude_hosts": ["admin.example.com"],
  "allowed_ports": [80, 443, 8080, 8443]
}
```

## Validation Checklist

Before deploying:

- [ ] `version` is 2
- [ ] `metadata.name` and `metadata.owner` present
- [ ] `authorized_networks` has at least 1 CIDR
- [ ] All CIDRs are valid (IPv4 or IPv6)
- [ ] `include_hosts`/`exclude_hosts` are valid hostnames
- [ ] `allowed_ports` are 1-65535
- [ ] If `dns_resolver: "custom"`, `dns_servers` provided
- [ ] If `break_glass.enabled`, at least 2 approvers
- [ ] Scope validates without errors: `python -m ishastra.core.scope validate scope.json`

## Related

- [Concepts](../scope-gate/concepts.md)
- [Policies](../scope-gate/policies.md)
- [Break Glass](../scope-gate/break-glass.md)
- [API: Scope Management](../api/scope-management.md)
