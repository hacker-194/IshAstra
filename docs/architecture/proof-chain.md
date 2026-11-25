# IshAstra Proof — Cryptographic Audit Chain

# IshAstra Proof — Cryptographic Audit Chain

Tamper-evident, offline-verifiable audit trail for every Scope Gate decision.

## Overview

IshAstra Proof creates a cryptographic chain linking every authorization decision back to the original signed scope document.

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
│                        IshAstra Proof Chain                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐               │
│  │   GRANT      │     │    GATE      │     │   PROOF      │               │
│  │  (Scope Doc  │────▶│  (Each Check │────▶│  (Aggregate  │               │
│  │   Signed)    │     │   Receipt)   │     │   + Merkle)  │               │
│  └──────────────┘     └──────────────┘     └──────┬───────┘               │
│                                                   │                        │
│                                                   ▼                        │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                     VERIFY (Offline)                              │    │
│  │  1. Verify Grant signature (Ed25519, JWKS)                      │    │
│  │  2. Verify each Gate receipt signature                          │    │
│  │  3. Verify Merkle root matches Proof                            │    │
│  │  4. Verify revocation freshness (< 24h, no future skew)         │    │
│  │  5. All valid → COMPLIANT                                       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Chain Components

### 1. Grant Receipt (Scope Document Signature)

**File**: `src/ishastra/core/scope_signing.py` — `sign_scope_document()`

```python
@dataclass
class GrantReceipt:
    scope_id: str
    document_hash: str          # SHA-256 of canonical scope JSON
    public_key_jwk: dict        # Ed25519 public key (JWK format)
    key_id: str                 # Key identifier for rotation
    signed_at: float            # Unix timestamp
    expires_at: float | None    # Scope expiration
    signature: str              # Ed25519 signature over document_hash

    def verify(self, jwks: JWKS) -> bool:
        key = jwks.get_key(self.key_id)
        if not key:
            return False
        return key.verify(self.document_hash.encode(), self.signature)
```

### 2. Gate Receipt (Per-Check Decision)

**File**: `src/ishastra/security/authorization/scope.py` — `GateObserver.on_check()`

```python
@dataclass
class GateReceipt:
    task_id: str
    scope_id: str
    url: str
    layer: int                  # 1, 2, or 3
    decision: Decision          # ALLOW, DENY, DEFER
    reason: str                 # e.g., "ip_not_authorized", "host_not_in_include"
    timestamp: float
    ip_addresses: list[str] | None  # Resolved IPs (Layer 2/3)
    pinned_destination: Destination | None  # Layer 3 only
    metadata: dict
    signature: str              # Ed25519 over canonical receipt

    def to_canonical_bytes(self) -> bytes:
        # Deterministic serialization for signing
        return json.dumps({
            "task_id": self.task_id,
            "scope_id": self.scope_id,
            "url": self.url,
            "layer": self.layer,
            "decision": self.decision.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "ip_addresses": self.ip_addresses,
            "pinned_destination": self.pinned_destination.to_dict() if self.pinned_destination else None,
            "metadata": self.metadata,
        }, separators=(",", ":"), sort_keys=True).encode()
```

### 3. Proof Receipt (Aggregated Assessment)

**File**: `src/ishastra/core/proof.py` — `ProofAggregator`

```python
@dataclass
class ProofReceipt:
    assessment_id: str
    scope_id: str
    grant_receipt: GrantReceipt
    gate_receipts: list[GateReceipt]
    merkle_root: str            # Merkle root of all gate receipts
    started_at: float
    completed_at: float
    total_checks: int
    allowed_checks: int
    denied_checks: int
    signature: str              # Ed25519 over entire proof (excluding signature)

    def verify(self, jwks: JWKS) -> VerificationResult:
        # 1. Verify grant receipt
        if not self.grant_receipt.verify(jwks):
            return VerificationResult(valid=False, reason="grant_signature_invalid")

        # 2. Verify each gate receipt
        for receipt in self.gate_receipts:
            if not receipt.verify(jwks):
                return VerificationResult.valid=False, reason=f"gate_receipt_invalid: {receipt.task_id}")

        # 3. Verify Merkle root
        computed_root = compute_merkle_root([r.to_canonical_bytes() for r in self.gate_receipts])
        if computed_root != self.merkle_root:
            return VerificationResult.valid=False, reason="merkle_root_mismatch"

        # 4. Verify revocation freshness
        if not self._check_revocation_freshness(jwks):
            return VerificationResult.valid=False, reason="revocation_stale"

        return VerificationResult.valid=True
```

## Cryptographic Primitives

### Ed25519 Signatures

- **Algorithm**: Ed25519 (RFC 8032)
- **Library**: `cryptography.hazmat.primitives.asymmetric.ed25519`
- **Key Size**: 32 bytes private, 32 bytes public
- **Signature**: 64 bytes

### JWKS (JSON Web Key Set)

**File**: `src/ishastra/core/scope_signing.py` — `JWKSManager`

```python
class JWKSManager:
    def __init__(self, keys: dict[str, Ed25519PrivateKey]):
        self.keys = keys
        self._jwks_cache = None

    def get_jwks(self) -> dict:
        """Public JWKS for verification"""
        if self._jwks_cache is None:
            self._jwks_cache = {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": kid,
                        "x": base64url_encode(key.public_key().public_bytes_raw()),
                        "use": "sig",
                        "alg": "EdDSA",
                    }
                    for kid, key in self.keys.items()
                ]
            }
        return self._jwks_cache

    def rotate_key(self, old_kid: str) -> str:
        """Generate new key, mark old for revocation"""
        new_kid = f"key-{int(time.time())}"
        self.keys[new_kid] = Ed25519PrivateKey.generate()
        # Old key kept for verification of past receipts
        return new_kid
```

### Merkle Tree

```python
def compute_merkle_root(leaves: list[bytes]) -> str:
    """Compute Merkle root using SHA-256"""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    level = [hashlib.sha256(leaf).digest() for leaf in leaves]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level

    return level[0].hex()
```

## Observer Implementation

### GateObserver Protocol

**File**: `src/ishastra/security/authorization/scope.py` — `GateObserver`

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

### IshAstraProofObserver

**File**: `src/ishastra/core/proof.py` — `IshAstraProofObserver`

```python
class IshAstraProofObserver:
    def __init__(
        self,
        signer: Ed25519PrivateKey,
        key_id: str,
        storage: ProofStorage,
        jwks_manager: JWKSManager,
    ):
        self.signer = signer
        self.key_id = key_id
        self.storage = storage
        self.jwks_manager = jwks_manager
        self._current_proof: ProofReceipt | None = None

    def on_check(self, ctx: CheckContext, result: AuthResult):
        receipt = GateReceipt(
            task_id=ctx.task_id,
            scope_id=ctx.scope_id,
            url=ctx.url,
            layer=ctx.layer,
            decision=result.decision,
            reason=result.reason,
            timestamp=ctx.timestamp,
            ip_addresses=ctx.metadata.get("ip_addresses"),
            pinned_destination=ctx.metadata.get("pinned_destination"),
            metadata=ctx.metadata,
        )

        # Sign receipt
        canonical = receipt.to_canonical_bytes()
        receipt.signature = self.signer.sign(canonical).hex()

        # Store
        self.storage.append_gate_receipt(ctx.task_id, receipt)

        # Add to current proof aggregation
        if self._current_proof:
            self._current_proof.gate_receipts.append(receipt)

    def on_destination(self, ctx: CheckContext, dest: Destination):
        # Update last gate receipt with pinned destination
        if self._current_proof and self._current_proof.gate_receipts:
            last = self._current_proof.gate_receipts[-1]
            last.pinned_destination = dest
            # Re-sign with updated destination
            last.signature = self.signer.sign(last.to_canonical_bytes()).hex()

    def finalize_proof(self, assessment_id: str, grant_receipt: GrantReceipt) -> ProofReceipt:
        proof = ProofReceipt(
            assessment_id=assessment_id,
            scope_id=grant_receipt.scope_id,
            grant_receipt=grant_receipt,
            gate_receipts=self._current_proof.gate_receipts if self._current_proof else [],
            merkle_root=compute_merkle_root(
                [r.to_canonical_bytes() for r in self._current_proof.gate_receipts]
            ) if self._current_proof else "",
            started_at=self._current_proof.started_at if self._current_proof else time.time(),
            completed_at=time.time(),
            total_checks=len(self._current_proof.gate_receipts) if self._current_proof else 0,
            allowed_checks=sum(1 for r in self._current_proof.gate_receipts if r.decision == Decision.ALLOW),
            denied_checks=sum(1 for r in self._current_proof.gate_receipts if r.decision == Decision.DENY),
        )

        # Sign proof
        proof.signature = self.signer.sign(proof.to_canonical_bytes()).hex()

        # Store
        self.storage.store_proof(proof)

        self._current_proof = None
        return proof
```

## Verification (Offline)

### CLI Verification

```bash
# Verify a proof receipt
ishastra proof verify proof-receipt.json --jwks jwks.json

# Output:
# Grant signature: VALID
# Gate receipts: 47/47 VALID
# Merkle root: MATCH
# Revocation: FRESH (checked 2024-01-15T10:30:00Z)
# RESULT: COMPLIANT
```

### Python Verification

```python
from ishastra.core.proof import verify_proof
from ishastra.core.scope_signing import load_jwks

jwks = load_jwks("https://api.example.com/.well-known/jwks.json")

with open("proof-receipt.json") as f:
    proof = ProofReceipt.model_validate_json(f.read())

result = verify_proof(proof, jwks)

if result.valid:
    print("✅ Proof verified - COMPLIANT")
else:
    print(f"❌ Proof invalid: {result.reason}")
```

### Verification Steps

```python
def verify_proof(proof: ProofReceipt, jwks: JWKS) -> VerificationResult:
    # 1. Grant receipt signature
    if not proof.grant_receipt.verify(jwks):
        return VerificationResult(False, "grant_signature_invalid")

    # 2. Grant not expired
    if proof.grant_receipt.expires_at and proof.grant_receipt.expires_at < time.time():
        return VerificationResult(False, "grant_expired")

    # 3. Each gate receipt signature
    for receipt in proof.gate_receipts:
        if not receipt.verify(jwks):
            return VerificationResult(False, f"gate_receipt_invalid: {receipt.task_id}")

    # 4. Merkle root
    computed = compute_merkle_root([r.to_canonical_bytes() for r in proof.gate_receipts])
    if computed != proof.merkle_root:
        return VerificationResult(False, "merkle_root_mismatch")

    # 5. Revocation freshness (max 24h, no future skew > 5min)
    if not _check_revocation_freshness(proof, jwks):
        return VerificationResult(False, "revocation_stale")

    return VerificationResult(True, "compliant")
```

## Revocation Freshness

### Requirements

- **Max Age**: Revocation status must be checked within 24 hours
- **Future Skew**: Reject signatures with timestamp > 5 minutes in future
- **JWKS Rotation**: Keys rotated, old keys retained for verification

### Implementation

```python
def _check_revocation_freshness(proof: ProofReceipt, jwks: JWKS) -> bool:
    now = time.time()

    # Check grant receipt timestamp
    if abs(proof.grant_receipt.signed_at - now) > 300:  # 5 min skew
        return False

    # Check each gate receipt timestamp
    for receipt in proof.gate_receipts:
        if abs(receipt.timestamp - now) > 300:
            return False

    # Check revocation status (if revocation endpoint configured)
    if revocation_url := os.getenv("ISHASTRA_REVOCATION_URL"):
        revoked = check_revocation(proof.grant_receipt.key_id, revocation_url)
        if revoked:
            # Allow if revoked after proof completion
            revoked_at = get_revocation_time(proof.grant_receipt.key_id)
            if revoked_at and revoked_at < proof.completed_at:
                return False

    # Max age: proof must be verified within 24h of completion
    if now - proof.completed_at > 86400:  # 24 hours
        return False

    return True
```

## Storage

### ProofStorage Interface

```python
class ProofStorage(Protocol):
    async def append_gate_receipt(self, task_id: str, receipt: GateReceipt):
        ...

    async def store_proof(self, proof: ProofReceipt):
        ...

    async def get_proof(self, assessment_id: str) -> ProofReceipt | None:
        ...

    async def get_gate_receipts(self, task_id: str) -> list[GateReceipt]:
        ...
```

### PostgreSQL Implementation

```python
class PostgresProofStorage:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def append_gate_receipt(self, task_id: str, receipt: GateReceipt):
        async with self.pool.acquire() as conn:
            await conn.execute("""INSERT INTO gate_receipts (task_id, scope_id, url, layer, decision, reason,
                                              timestamp, ip_addresses, pinned_destination,
                                              metadata, signature)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)""",
                task_id, receipt.scope_id, receipt.url, receipt.layer,
                receipt.decision.value, receipt.reason, receipt.timestamp,
                receipt.ip_addresses, receipt.pinned_destination,
                receipt.metadata, receipt.signature)

    async def store_proof(self, proof: ProofReceipt):
        async with self.pool.acquire() as conn:
            await conn.execute("""INSERT INTO proof_receipts (assessment_id, scope_id, grant_receipt,
                                           gate_receipts, merkle_root, started_at,
                                           completed_at, total_checks, allowed_checks,
                                           denied_checks, signature)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)""",
                proof.assessment_id, proof.scope_id,
                proof.grant_receipt.model_dump_json(),
                json.dumps([r.model_dump() for r in proof.gate_receipts]),
                proof.merkle_root, proof.started_at, proof.completed_at,
                proof.total_checks, proof.allowed_checks, proof.denied_checks,
                proof.signature)
```

## Compliance Mapping

### NIST 800-53

| Control | IshAstra Proof Coverage |
|---------|---------------------|
| AU-2 (Audit Events) | Every gate decision logged |
| AU-3 (Audit Content) | Full context in receipt |
| AU-6 (Audit Review) | Offline verification |
| AU-7 (Audit Reduction) | Merkle tree aggregation |
| AU-8 (Timestamp) | Unix timestamps on all receipts |
| AU-9 (Protection) | Ed25519 signatures, tamper-evident |
| AU-10 (Non-repudiation) | Cryptographic signatures |
| AU-11 (Retention) | Configurable retention policy |

### ISO 27001

| Control | Coverage |
|---------|----------|
| A.12.4.1 (Event Logging) | All authorization decisions |
| A.12.4.3 (Log Protection) | Cryptographic integrity |
| A.18.1.3 (Record Protection) | Tamper-evident chain |

### SOC 2

| Criteria | Coverage |
|----------|----------|
| CC7.2 (System Monitoring) | Real-time gate monitoring |
| CC7.3 (Incident Detection) | Denial alerts |
| CC8.1 (Change Management) | Scope document versioning |

---

## API Reference

### Get Proof for Assessment

```bash
GET /api/v1/assessments/{assessment_id}/proof
Authorization: Bearer $KEY

Response:
{
  "assessment_id": "assess-123",
  "proof": { ... ProofReceipt JSON ... },
  "verification": {
    "valid": true,
    "checked_at": "2024-01-15T10:30:00Z",
    "jwks_source": "https://api.example.com/.well-known/jwks.json"
  }
}
```

### Get JWKS

```bash
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "key-1705312800",
      "x": "base64url-encoded-public-key",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

### Verify Proof (API)

```bash
POST /api/v1/proof/verify
Authorization: Bearer $KEY
Content-Type: application/json

{
  "proof": { ... },
  "jwks_url": "https://api.example.com/.well-known/jwks.json"
}

Response:
{
  "valid": true,
  "details": {
    "grant_signature": "valid",
    "gate_receipts": 47,
    "gate_receipts_valid": 47,
    "merkle_root": "match",
    "revocation": "fresh"
  }
}
```

## Key Rotation

### Automatic Rotation

```yaml
# values.yaml
scopeGate:
  signing:
    keyRotation:
      enabled: true
      interval: "30d"  # Rotate every 30 days
      gracePeriod: "7d"  # Old keys valid for verification
```

### Manual Rotation

```bash
# Generate new key
ishastra keys rotate

# Output: new key ID, JWKS updated
# Old key retained for verification
```

### Verification with Rotated Keys

```python
# JWKS contains ALL keys (current + retired)
# Verification tries each key until one works
def verify_with_jwks(receipt: SignedReceipt, jwks: JWKS) -> bool:
    for key in jwks.keys:
        if key.kid == receipt.key_id:
            return key.verify(receipt.payload, receipt.signature)
    return False  # Key not found
```

## Performance

| Operation | Latency (p99) | Throughput |
|-----------|---------------|------------|
| Sign receipt | < 0.1ms | 50k/s |
| Verify receipt | < 0.2ms | 25k/s |
| Merkle root (1000 leaves) | < 1ms | 1k/s |
| Full proof verify | < 5ms | 200/s |

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `grant_signature_invalid` | Wrong key, corrupted receipt | Check JWKS, re-download |
| `merkle_root_mismatch` | Missing receipts, tampering | Verify all receipts present |
| `revocation_stale` | Revocation check > 24h old | Re-run verification |
| `key_not_found` | Key rotated, not in JWJS | Update JWKS cache |
| `future_skew` | Clock drift | Sync NTP on all nodes |

---

## Related

- [Scope Gate](../scope-gate/concepts.md)
- [Scope Signing](../scope-gate/configuration.md#signing)
- [API: Proof Verification](../api/scope-management.md#proof-verification)
- [Compliance Mapping](../compliance/overview.md)