# Scope Gate Concepts

# Scope Gate Concepts

Core concepts and mental models for IshAstra's authorization engine.

## The Problem: Implicit Trust

Traditional security scanners operate on **implicit trust**:

```
Scanner → Target (No validation)
```

They connect first, ask questions later. This creates:
- **SSRF vulnerabilities**: Scanner becomes attack vector
- **Data exfiltration**: Scanner accesses internal services
- **Compliance gaps**: No audit trail of what was authorized
- **Multi-tenant risk**: One tenant's scan affects another

## The Solution: Explicit Authorization

IshAstra Scope Gate enforces **explicit authorization** — default-deny for every connection:

```
Worker → Scope Gate → Target
       (Validates)   (Only if allowed)
```

Every outbound connection must be **explicitly authorized** by policy before a single packet leaves.

## Three-Layer Defense

### Layer 1: Syntactic Validation (No Network)

Validates URL structure without DNS resolution.

| Check | Purpose |
|-------|---------|
| Scheme | Only `http`/`https` allowed |
| Host format | Valid hostname or IP literal |
| Port range | 1-65535, against allowlist |
| Host allowlist | `include_hosts` / `exclude_hosts` |
| Path/Query | No validation (pass-through) |

**Key insight**: Fast, stateless, zero network I/O. Catches 90% of misconfigurations instantly.

### Layer 2: Semantic Validation (DNS + Policy)

Resolves hostname and validates **every** resolved IP against policy.

| Check | Purpose |
|-------|---------|
| DNS Resolution | A/AAAA records, timeout handling |
| IP Allowlist | Every IP must match `authorized_networks` CIDR |
| Special-Use Detection | Loopback, link-local, private, multicast, documentation |
| Empty Resolution | NXDOMAIN → DENY |

**Key insight**: Validates ALL resolved IPs, not just the first. This is the DNS rebinding protection.

### Layer 3: Pinning (Immutable Destination)

Returns a single `Destination` object that adapters MUST use.

| Property | Purpose |
|----------|---------|
| `ip` | Pinned IP address (validated at Layer 2) |
| `host` | Original hostname (for SNI, Host header) |
| `port` | Validated port |
| `scheme` | http/https |
| `resolved_at` | Timestamp for TTL tracking |
| `ttl` | Remaining cache time |

**Key insight**: Adapters connect to `ip:port` but send `Host: host` header. TLS validates against `host`, not `ip`.

## Default-Deny Philosophy

```
┌─────────────────────────────────────────────────────────────┐
│                    Authorization Model                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Traditional:    ALLOW by default, DENY exceptions          │
│  IshAstra:          DENY by default, ALLOW explicit            │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  authorized_networks = ["10.0.0.0/8"]               │   │
│  │  → 10.0.0.1: ALLOWED                                │   │
│  │  → 192.168.1.1: DENIED (not in list)                │   │
│  │  → 127.0.0.1: DENIED (special-use, not in list)     │   │
│  │  → 8.8.8.8: DENIED (not in list)                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Why default-deny?**
- **Fail-safe**: Misconfiguration = blocked, not exposed
- **Auditability**: Every ALLOW is explicit in policy
- **Compliance**: Matches zero-trust architectures
- **Multi-tenant**: Tenant A cannot scan Tenant B's networks

## Special-Use Address Protection

RFC 5735, 6598, 6890 define special-use addresses that are **denied by default** unless explicitly authorized.

| Category | IPv4 | IPv6 | Risk |
|----------|------|------|------|
| Loopback | 127.0.0.0/8 | ::1/128 | Local service access |
| Link-Local | 169.254.0.0/16 | fe80::/10 | Metadata services (AWS/GCP/Azure) |
| Private | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | fc00::/7 | Internal network access |
| Multicast | 224.0.0.0/4 | ff00::/8 | Network disruption |
| Documentation | 192.0.2.0/24, etc. | 2001:db8::/32 | Test addresses |
| IPv6 Transition | ::ffff:0:0/96, 2002::/16 | — | Tunneling attacks |

**To allow**: Explicitly add to `authorized_networks`:
```json
{
  "authorized_networks": ["10.0.0.0/8", "169.254.169.254/32"]
}
```

## DNS Rebinding Protection

### The Attack

```
Attacker controls example.com DNS:
  T=0:   example.com → 10.0.0.1 (authorized internal IP)
  T=60:  example.com → 169.254.169.254 (AWS metadata)
  T=120: example.com → 127.0.0.1 (local service)

Traditional scanner: Resolves once, caches, connects to changing IPs
```

### IshAstra Defense

```
IshAstra resolves ONCE at Layer 2:
  1. Resolve example.com → [10.0.0.1, 169.254.169.254, 127.0.0.1]
  2. Validate EVERY IP against authorized_networks
  3. 169.254.169.254 → DENY (link-local, not authorized)
  4. 127.0.0.1 → DENY (loopback, not authorized)
  5. RESULT: ENTIRE HOST DENIED

No partial authorization. All IPs must pass.
```

### Pinning at Layer 3

```
Layer 3 returns single Destination:
  Destination(scheme="https", host="example.com", port=443, ip="10.0.0.1")

Adapter MUST:
  1. Connect to 10.0.0.1:443
  2. Send Host: example.com
  3. Verify TLS cert for example.com (not 10.0.0.1)
  4. Re-validate before each new connection
```

## Multi-Tenancy: ContextVar Isolation

### The Problem

```
Worker Process
  ├── Task A (Tenant 1) → Scope: 10.0.0.0/8
  └── Task B (Tenant 2) → Scope: 192.168.0.0/16

If scope stored in global variable → LEAKAGE
```

### The Solution: ContextVar

```python
import contextvars

_current_scope: contextvars.ContextVar[ScopeDocument | None] = \
    contextvars.ContextVar("_current_scope", default=None)

class ScopeContext:
    def __init__(self, scope: ScopeDocument):
        self.scope = scope
        self.token = None

    def __enter__(self):
        self.token = _current_scope.set(self.scope)
        return self

    def __exit__(self, *args):
        _current_scope.reset(self.token)

# Usage - automatic isolation
async def run_task(task: Task):
    with ScopeContext(task.scope):
        # All ScopeGate calls in this task use THIS scope
        for target in task.targets:
            dest = await gate.validate_outbound(target)
            await adapter.run(dest)
```

**Guarantees**:
- Task-local (async-safe)
- Automatic cleanup (even on exception)
- No global state
- Testable with `ScopeContext(test_scope)`

## Observer Pattern: IshAstra Proof

Every gate decision generates a receipt for the audit chain.

```
CheckContext → GateObserver → GateReceipt (signed)
```

### CheckContext

```python
@dataclass
class CheckContext:
    task_id: str           # Unique task identifier
    scope_id: str          # Scope document ID
    url: str               # Original URL
    layer: int             # 1, 2, or 3
    timestamp: float       # Unix timestamp
    metadata: dict         # Custom fields (IPs, destination, etc.)
```

### Built-in Observer

```python
class IshAstraProofObserver:
    def on_check(self, ctx: CheckContext, result: AuthResult):
        receipt = GateReceipt(
            task_id=ctx.task_id,
            scope_id=ctx.scope_id,
            url=ctx.url,
            layer=ctx.layer,
            decision=result.decision,
            reason=result.reason,
            timestamp=ctx.timestamp,
            # ... more fields
        )
        receipt.signature = signer.sign(receipt.to_bytes())
        storage.append(receipt)
```

### Chain Structure

```
Grant Receipt (Scope signed)
    │
    ├── Gate Receipt (Layer 1: ALLOW)
    ├── Gate Receipt (Layer 2: ALLOW - all IPs authorized)
    ├── Gate Receipt (Layer 3: Pinned destination)
    │
    ▼
Proof Receipt (Aggregated + Merkle root)
    │
    ▼
Verify Receipt (Offline verification)
```

## TLA+ Formal Verification

Scope Gate logic formally verified with 6 invariants over 21.4M states.

| Invariant | Guarantees |
|-----------|------------|
| `DefaultDenyInvariant` | No connection without explicit authorization |
| `PinningInvariant` | Layer 3 IP always from Layer 2 authorized set |
| `NoRebindingInvariant` | Same host → same pinned IP within TTL |
| `IsolationInvariant` | Scope A decisions never affect Scope B |
| `RevocationFreshnessInvariant` | Revoked scopes rejected within 24h |
| `BreakGlassInvariant` | Emergency access requires dual approval |

```bash
# Run verification
cd docs/tla
tlc -config JudgeAddresses.cfg JudgeAddresses.tla
```

## Scope Document (Policy as Code)

```json
{
  "version": 2,
  "metadata": {
    "name": "Production Assessment",
    "owner": "security@example.com",
    "created": "2024-01-15T10:00:00Z",
    "expires": "2024-07-15T10:00:00Z"
  },
  "authorized_networks": [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "2001:db8::/32"
  ],
  "include_hosts": [
    "api.example.com",
    "*.internal.example.com"
  ],
  "exclude_hosts": [
    "admin.example.com"
  ],
  "allowed_ports": [80, 443, 8080, 8443],
  "dns_resolver": "system",
  "dns_timeout": 5,
  "break_glass": {
    "enabled": true,
    "approvers": ["security-lead@example.com", "cto@example.com"],
    "max_duration": "4h"
  }
}
```

## Decision Flow

```
                    ┌─────────────────┐
                    │  validate()     │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Layer 1 Check  │
                    │  (URL/Host)     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         ┌─────────┐   ┌─────────┐    ┌─────────┐
         │  DENY   │   │  ALLOW  │    │ DEFER   │
         │ (Final) │   │ (Final)*│    │ (Layer 2)│
         └─────────┘   └─────────┘    └────┬────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  Layer 2 Check  │
                                  │  (DNS/IP)       │
                                  └────────┬────────┘
                                           │
                          ┌────────────────┼────────────────┐
                          ▼                ▼                ▼
                     ┌─────────┐      ┌─────────┐      ┌─────────┐
                     │  DENY   │      │  ALLOW  │      │ DEFER   │
                     │ (Final) │      │ (Final)*│      │ (Layer 3)│
                     └─────────┘      └─────────┘      └────┬────┘
                                                             │
                                                             ▼
                                                    ┌─────────────────┐
                                                    │  Layer 3 Check  │
                                                    │  (Pinning)      │
                                                    └────────┬────────┘
                                                             │
                                                      ┌──────┴──────┐
                                                      ▼             ▼
                                                 ┌─────────┐ ┌─────────┐
                                                 │  DENY   │ │  ALLOW  │
                                                 │ (Final) │ │ + Pinned│
                                                 └─────────┘ └────┬────┘
                                                                  │
                                                                  ▼
                                                         ┌─────────────────┐
                                                         │  Observer       │
                                                         │  (Receipt)      │
                                                         └─────────────────┘

* ALLOW at Layer 1/2 only if no authorized_networks defined
  If authorized_networks defined, must pass Layer 2
```

## Performance Characteristics

| Operation | Latency (p99) | Throughput |
|-----------|---------------|------------|
| Layer 1 only | < 0.1ms | 12,000 ops/s |
| Layer 1+2 (cached) | < 0.5ms | 11,000 ops/s |
| Layer 1+2+3 | < 1ms | 10,000 ops/s |
| DNS Resolution | ~50ms | 20 ops/s |

## Related

- [Configuration](../scope-gate/configuration.md)
- [Policies](../scope-gate/policies.md)
- [Break Glass](../scope-gate/break-glass.md)
- [TLA+ Verification](../scope-gate/tla-verification.md)
- [Architecture: Scope Gate](../architecture/scope-gate.md)