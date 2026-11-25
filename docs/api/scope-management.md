# Scope Management API

The scope endpoint reports the authorization record the caller is judged
against. Scope is enforced by the Scope Gate on every outbound connection, so
this route is read-only: there is no endpoint that widens authorization at
request time.

## Get the active scope

```http
GET /api/scope
Authorization: Bearer $ISHASTRA_API_KEY
```

### Managed mode

In managed mode each tenant has its own engagement policy, and a tenant never
sees another engagement's hosts, networks or ports.

```json
{
  "configured": true,
  "mode": "managed",
  "tenant_id": "default",
  "policy": {
    "id": "pol_...",
    "include": ["app.example.com"],
    "authorized_networks": ["203.0.113.0/24"],
    "allowed_ports": [443],
    "expires_at": 1798761600
  }
}
```

When no usable policy exists:

```json
{
  "configured": false,
  "mode": "managed",
  "tenant_id": "default",
  "detail": "no usable authorization policy for this tenant"
}
```

### Global mode

In global mode the single-organization scope document (`version: 2`) is
returned:

```json
{
  "configured": true,
  "mode": "global",
  "scope": {
    "version": 2,
    "program": "Example Program",
    "authorized_by": "Security Team",
    "authorization_ref": "ENG-2026-001",
    "include": ["app.example.com"],
    "exclude": [],
    "authorized_networks": ["203.0.113.0/24"],
    "allowed_ports": [443],
    "allow_broad_networks": false,
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
```

The mode is selected by configuration (`ISHASTRA_SCOPE_MODE`), not per request.

## Policies

Engagement policies are managed through the policy routes:

| Route | Description |
|-------|-------------|
| `GET /api/policies` | List policies visible to the caller |
| `GET /api/policies/{policy_id}` | Read one policy |
| `GET /api/policies/{policy_id}/diff/{other_id}` | Diff two policies |
| `POST /api/policies/{policy_id}/revoke` | Revoke a policy |
| `GET /api/policies/lifecycle` | Policy lifecycle state |

Assessments accept an optional `policy_id` to pin a specific policy; otherwise
the tenant's newest valid policy is used.

## Creating scope documents

The CLI produces and signs scope documents:

```bash
ishastra scope-wizard --output scope.json
ishastra scope-keygen
ishastra scope-sign scope.json
```

`scope-wizard` writes a `version: 2` document; `scope-sign` signs it with the
operator key so the gate can verify it offline. See
[Scope Gate concepts](../scope-gate/concepts.md) and
[Break Glass](../scope-gate/break-glass.md).

## Break Glass

Dual-approval expansion is performed offline with the CLI:

```bash
ishastra scope-breakglass --help
```

The command writes a signed scope document with a short expiry. See
[Break-Glass Dual Approval](../scope-gate/break-glass.md).

## Proof Verification

```http
POST /api/proof/verify
```

Verifies a proof pack against the gate and issuer keys. See
[Proof Chain](../architecture/proof-chain.md).

## Related

- [Authentication](authentication.md)
- [Assessments API](assessments.md)
