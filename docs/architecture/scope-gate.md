# Scope Gate Architecture

# Scope Gate Architecture

Deep dive into the authorization engine that makes Ishastra unique.

## Overview

The Scope Gate is a **default-deny authorization layer** that validates every outbound connection before it leaves your infrastructure. It sits between your assessment workers and target systems, enforcing policy at three layers.

```text
┌─────────────────────────────────────────────────────────────────┐
│                      Assessment Worker                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Scope Gate (In-Process)                  │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │ │
│  │  │  Layer 1    │──▶│  Layer 2    │──▶│  Layer 3           │  │ │
│  │  │  URL/Host   │   │  DNS/IP     │   │  Pinned Dest.    │  │ │
│  │  │  Gate       │   │  Policy     │   │  (Immutable)     │  │ │
│  │  └─────────────┘   └─────────────┘   └────────────────────┘  │ │
│  │        │                │                     │               │ │
│  │        ▼                ▼                     ▼               │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │              Observer (Ishastra Proof)                      │  │ │
│  │  │  Receipts: grant → gate → proof → verify                │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             ▼
                    ┌─────────────────┐
                    │  Target System  │
                    │ (Only pinned IP)│
                    └─────────────────┘
```

## Layer 1: URL/Host Gate

**File**: `src/ishastra/security/authorization/scope.py` — `_authorize_sync()` lines

### Checks Performed

1. **URL Structure Validation**
   - Valid scheme (http/https)
   - Valid host (not empty, not IP literal unless allowed)
   - Valid port (1-65535)
   - No invalid characters, proper encoding

2. **Host Allowlist/Blocklist**
   - `include_hosts`: Exact match or suffix match (`.example.com` matches `api.example.com`)
   - `exclude_hosts`: Exact match or suffix match (takes precedence)
   - Wildcard support: `*.example.com`

3. **Port Allowlist**
   - `allowed_ports`: List of allowed destination ports
   - Default: `[80, 443, 8080, 8443]` if not specified

4. **Scheme Validation**
   - Only `http` and `https` allowed
   - `https` enforced for sensitive ports

### Decision Logic

```python
def _authorize_sync(url: str, scope: Scope) -> AuthResult:
    # 1. Parse URL
    parsed = parse_url(url)
    if not parsed:
        return DENY("malformed_url")

    # 2. Check host against include/exclude
    if scope.include and not _listed(parsed.host, scope.include):
        return DENY("host_not_in_include_list")

    if scope.exclude and _listed(parsed.host, scope.exclude):
        return DENY("host_in_exclude_list")

    # 3. Check port
    if scope.allowed_ports and parsed.port not in scope.allowed_ports:
        return DENY("port_not_allowed")

    # 4. If no networks defined, allow at Layer 1 (Layer 2 will enforce)
    if not scope.authorized_networks:
        return ALLOW(layer=1)

    # 5. Networks defined → require Layer 2
    return DEFER_TO_LAYER_2
```

### Performance

- **Zero DNS** — purely syntactic validation
- **< 0.1ms** p99 latency
- **Stateless** — no caching needed

---

## Layer 2: DNS/IP Policy

**File**: `src/ishastra/security/authorization/scope.py` — `_authorize()` lines

### Checks Performed

1. **DNS Resolution**
   - Resolves hostname to A/AAAA records
   - Configurable resolver (system, custom, DoH)
   - Timeout: 5s default
   - Caching: TTL-respecting with max 300s

2. **IP Allowlist Validation**
   - **Every resolved IP** must match at least one `authorized_networks` CIDR
   - Supports IPv4 and IPv6
   - CIDR notation: `10.0.0.0/8`, `2001:db8::/32`

3. **Special-Use Address Detection** (RFC 5735, RFC 6598, RFC 6890)
   | Category | IPv4 | IPv6 | Default Action |
   |----------|------|------|----------------|
   | Loopback | 127.0.0.0/8 | ::1/128 | DENY |
   | Link-Local | 169.254.0.0/16 | fe80::/10 | DENY |
   | Private | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | fc00::/7 | DENY |
   | Multicast | 224.0.0.0/4 | ff00::/8 | DENY |
   | Documentation | 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 | 2001:db8::/32 | DENY |
   | IPv6 Transition | ::ffff:0:0/96, 2002::/16 | — | DENY |

   **Override**: Explicitly add to `authorized_networks` to allow.

4. **Empty Resolution Handling**
   - No A/AAAA records → DENY ("resolution_failed")
   - Prevents hanging on NXDOMAIN

### Decision Logic

```python
async def _authorize(url: str, scope: Scope) -> AuthResult:
    # Layer 1 checks first (sync)
    layer1 = _authorize_sync(url, scope)
    if layer1.is_final:
        return layer1

    # Layer 2: DNS Resolution
    parsed = parse_url(url)
    addresses = await resolve_host(parsed.host)

    if not addresses:
        return DENY("resolution_failed")

    # Check EVERY address against authorized_networks
    for addr in addresses:
        if not _ip_in_networks(addr, scope.authorized_networks):
            return DENY(f"ip_not_authorized: {addr}")

        if _is_special_use(addr) and not _explicitly_authorized(addr, scope):
            return DENY(f"special_use_address: {addr}")

    # All IPs authorized → proceed to Layer 3
    return ALLOW(layer=2, addresses=addresses)
```

### DNS Rebinding Protection

The critical insight: **Layer 2 validates ALL resolved IPs**, not just the first one.

```
Attacker controls example.com DNS:
  T=0:  example.com → 10.0.0.1 (authorized)
  T=60: example.com → 169.254.169.254 (AWS metadata - DENIED by special-use)
  T=120: example.com → 127.0.0.1 (loopback - DENIED)

Ishastra resolves ONCE at Layer 2, pins ALL IPs, validates ALL.
If any IP fails → entire host DENIED.
```

### Performance

- **DNS resolution**: ~10-50ms (cached)
- **IP validation**: < 0.01ms per IP
- **Caching**: Respects TTL, max 300s, per-process

---

## Layer 3: Pinned Destination

**File**: `src/ishastra/security/authorization/scope.py` — `ScopeGate.validate_outbound()` lines

### Purpose

Returns a **single, immutable `Destination`** that adapters MUST connect to. This prevents:
- DNS rebinding (IP changes after validation)
- Round-robin DNS load balancing to unauthorized IPs
- CNAME chains to unauthorized destinations

### Destination Object

```python
@dataclass(frozen=True)
class Destination:
    scheme: str        # "https"
    host: str          # "api.example.com"
    port: int          # 443
    ip: str            # "10.0.0.1"  (PINNED - validated at Layer 2)
    resolved_at: float # Unix timestamp
    ttl: int           # Remaining TTL seconds
```

### Selection Algorithm

```python
def _select_destination(addresses: list[str], parsed: ParsedURL) -> Destination:
    # Prefer IPv6 if available and authorized
    ipv6 = [a for a in addresses if ':' in a]
    ipv4 = [a for a in addresses if '.' in a]

    # Deterministic selection: first authorized IPv6, else first IPv4
    selected_ip = ipv6[0] if ipv6 else ipv4[0]

    return Destination(
        scheme=parsed.scheme,
        host=parsed.host,
        port=parsed.port,
        ip=selected_ip,
        resolved_at=time.time(),
        ttl=calculate_ttl(addresses)
    )
```

### Adapter Contract

**Every adapter MUST:**
1. Call `gate.validate_outbound(url, scope)` before connecting
2. Connect ONLY to `destination.ip:destination.port`
3. Set `Host` header to `destination.host`
4. Validate TLS certificate against `destination.host` (not IP)
5. Re-validate for each new connection (connection pooling OK within TTL)

```python
# Correct adapter usage
async def fetch(url: str, scope: Scope) -> Response:
    dest = await gate.validate_outbound(url, scope)

    # Connect to PINNED IP
    conn = await http_client.connect(dest.ip, dest.port)

    # But send Host header for SNI and virtual hosting
    conn.set_header("Host", dest.host)

    # Verify cert matches HOSTNAME, not IP
    conn.verify_certificate(dest.host)

    return await conn.request("GET", url)
```

---

## ContextVar Isolation (Multi-Tenancy)

**File**: `src/ishastra/security/authorization/scope.py` — `ScopeContext` class

### Problem

Workers run multiple assessments concurrently. Scope documents must not leak between tasks.

### Solution: ContextVar-Bound Scope

```python
# ContextVar holds current task's scope
_current_scope: ContextVar[Scope | None] = ContextVar("_current_scope", default=None)

class ScopeContext:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.token = None

    def __enter__(self):
        self.token = _current_scope.set(self.scope)
        return self

    def __exit__(self, *args):
        _current_scope.reset(self.token)

# Usage in worker
async def run_assessment(assessment: Assessment):
    scope = await load_scope(assessment.scope_id)

    with ScopeContext(scope):
        # All ScopeGate calls in this task use THIS scope
        for target in assessment.targets:
            dest = await gate.validate_outbound(target, scope)
            await adapter.run(dest)
```

### Guarantees

- **No cross-task leakage**: ContextVar is task-local (async-safe)
- **Automatic cleanup**: `__exit__` always called (even on exception)
- **Testable**: Can override in tests with `ScopeContext(test_scope)`

---

## Observer Pattern (Ishastra Proof)

**File**: `src/ishastra/security/authorization/scope.py` — `GateObserver` protocol

### Purpose

Every gate decision generates a **cryptographic receipt** for audit chain.

### Observer Interface

```python
@runtime_checkable
class GateObserver(Protocol):
    def on_check(self, ctx: CheckContext, result: AuthResult):
        """Called for every Layer 1/2/3 check"""

    def on_destination(self, ctx: CheckContext, dest: Destination):
        """Called when Layer 3 returns pinned destination"""

    def on_error(self, ctx: CheckContext, error: Exception):
        """Called on resolution/validation errors"""
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
    metadata: dict         # Custom fields
```

### Built-in Observer: IshastraProofObserver

```python
class IshastraProofObserver:
    def __init__(self, signer: Ed25519Signer, storage: ProofStorage):
        self.signer = signer
        self.storage = storage

    def on_check(self, ctx: CheckContext, result: AuthResult):
        receipt = GateReceipt(
            task_id=ctx.task_id,
            scope_id=ctx.scope_id,
            url=ctx.url,
            layer=ctx.layer,
            decision=result.decision,  # ALLOW/DENY/DEFER
            reason=result.reason,
            timestamp=ctx.timestamp,
        )
        receipt.signature = self.signer.sign(receipt.to_bytes())
        self.storage.append(receipt)
```

### Receipt Chain

```
Grant Receipt (Scope Doc signed)
    │
    ▼
Gate Receipt (Each check: Layer 1, 2, 3)
    │
    ▼
Proof Receipt (Aggregated, Merkle root)
    │
    ▼
Verify Receipt (Offline verification)
```

---

## TLA+ Formal Verification

**File**: `docs/tla/JudgeAddresses.tla`

### Model Checked

- **States**: 21.4 million
- **Invariants**: 6 verified
- **Tool**: TLC (TLA+ Model Checker)

### Invariants

| Invariant | Description |
|-----------|-------------|
| `DefaultDenyInvariant` | No connection allowed without explicit authorization |
| `PinningInvariant` | Layer 3 destination IP always from Layer 2 authorized set |
| `NoRebindingInvariant` | Same host always resolves to same pinned IP within TTL |
| `IsolationInvariant` | Scope A decisions never affect Scope B |
| `RevocationFreshnessInvariant` | Revoked scopes rejected within 24h |
| `BreakGlassInvariant` | Emergency access requires dual approval |

### Running Verification

```bash
cd docs/tla
tlc -config JudgeAddresses.cfg JudgeAddresses.tla
# Or use the script
./scripts/verify-tla.sh
```

---

## Configuration Reference

### Scope Document v2

```json
{
  "version": "2",
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
    "admin.example.com",
    "*.staging.example.com"
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

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `version` | Yes | int | Must be 2 |
| `metadata.name` | Yes | string | Human-readable name |
| `metadata.owner` | Yes | string | Contact email |
| `metadata.expires` | No | ISO8601 | Scope expiration |
| `authorized_networks` | Yes | string[] | CIDR allowlist |
| `include_hosts` | No | string[] | Host allowlist (suffix match) |
| `exclude_hosts` | No | string[] | Host blocklist (suffix match) |
| `allowed_ports` | No | int[] | Port allowlist (default: 80,443,8080,8443) |
| `dns_resolver` | No | string | `system`, `cloudflare`, `google`, `custom` |
| `dns_timeout` | No | int | Seconds (default: 5) |
| `break_glass` | No | object | Emergency access config |

---

## Metrics & Observability

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `scope_gate_checks_total` | Counter | `layer`, `decision` | Total checks by layer and decision |
| `scope_gate_check_duration_seconds` | Histogram | `layer` | Check latency |
| `scope_gate_denials_total` | Counter | `reason`, `layer` | Denials by reason |
| `scope_gate_dns_duration_seconds` | Histogram | — | DNS resolution latency |
| `scope_gate_active_scopes` | Gauge | — | Currently bound scopes |

### Grafana Dashboard

Import `deploy/monitoring/grafana/dashboards/scope-gate.json` for:
- Check rate by layer/decision
- Latency percentiles (p50, p95, p99)
- Denial reasons breakdown
- DNS resolution health
- Active scope count

---

## Testing

### Unit Tests

```bash
pytest tests/unit/test_scope.py -v
pytest tests/unit/test_scope_gate.py -v
```

### Key Test Cases

| Test | Purpose |
|------|---------|
| `test_authorize_allowed_network` | CIDR matching works |
| `test_authorize_denied_unauthorized_ip` | Non-allowed IP rejected |
| `test_authorize_denied_loopback` | 127.0.0.1 denied by default |
| `test_authorize_denied_link_local` | 169.254.x.x denied |
| `test_authorize_denied_private` | RFC1918 denied unless authorized |
| `test_authorize_dns_rebinding_protection` | All IPs must be authorized |
| `test_authorize_empty_resolution_denied` | NXDOMAIN → DENY |
| `test_contextvar_isolation` | No cross-task scope leakage |
| `test_pinned_destination_immutable` | Destination cannot be modified |

### Integration Tests

```bash
pytest tests/integration/test_scope_gate_integration.py -v
```

Tests real DNS resolution, network policy enforcement, and adapter integration.

---

## Performance Benchmarks

```text
Scope Gate Check (Layer 1 only):     12,000 ops/s  p99 < 0.1ms
Scope Gate Check (Layer 1+2, cached): 11,000 ops/s  p99 < 0.5ms
Scope Gate Check (Layer 1+2+3):       10,000 ops/s  p99 < 1ms
DNS Resolution (uncached):                    p99 ~ 50ms
```

Run benchmarks:
```bash
pytest tests/benchmarks/test_scope_gate_bench.py --benchmark-only
```

---

## Troubleshooting

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `DENY: host_not_in_include_list` | Host not in include_hosts | Add host or `*.domain.com` |
| `DENY: ip_not_authorized: 1.2.3.4` | Resolved IP not in CIDR | Add CIDR to authorized_networks |
| `DENY: special_use_address: 127.0.0.1` | Loopback/private IP resolved | Add to authorized_networks if intentional |
| `DENY: resolution_failed` | DNS returns no records | Check DNS, target may not exist |
| `ContextVar leak` | Scope not cleaned up | Ensure `ScopeContext` used as context manager |

### Debug Mode

```python
import logging
logging.getLogger("ishastra.security.authorization.scope").setLevel(logging.DEBUG)

# Or via env
ISHASTRA_LOG_LEVEL=DEBUG
```

Shows: Layer decisions, DNS resolution, IP matching, pinned destination selection.

---

## Related

- [Scope Gate Configuration](../scope-gate/configuration.md)
- [Policy-as-Code](../scope-gate/policies.md)
- [Break Glass](../scope-gate/break-glass.md)
- [TLA+ Verification](../scope-gate/tla-verification.md)
- [API: Scope Management](../api/scope-management.md)