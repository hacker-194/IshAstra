"""Capability tokens for worker authorization.

Ed25519-signed JWT tokens (RFC 8037) binding worker to job/scope/policy.
TTL <= 15 minutes. Revocation via database-backed list.

Called by:
- src/ishastra/security/capabilities/issuer.py (CapabilityIssuer.issue_token)
- src/ishastra/security/capabilities/verifier.py (CapabilityVerifier.verify)
- src/ishastra/execution/worker_manager.py (WorkerManager injects token into worker)
- Tests in tests/unit/test_capability_token.py

No existing file serves this purpose - this is the new v4.0 capability token implementation
for Phase 2 Vertical Slice (Security Spine).

Data schemas:
- Reads: Ed25519 private key from config/secrets (base64 URL-safe)
- Writes: CapabilityToken dict to worker environment / database
- Token structure: JWT-like with fields (jti, iat, exp, tenant_id, engagement_id, job_id,
  targets[], pinned_ips[], allowed_ports[], allowed_protocols[], allowed_tools[],
  policy_hash, rules_of_engagement_hash, request_budget, bandwidth_limit_mb, issuer, signature)

User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

CAPABILITY_VERSION = "ishastra-capability/1"

DEFAULT_AUDIENCE = "ishastra-egress-gateway"

MAX_TTL_SECONDS = 15 * 60

PRIVATE_KEY_PREFIX = "ishastra-capability-private:"
PUBLIC_KEY_PREFIX = "ishastra-capability-public:"


def _b64(raw: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    """Decode URL-safe base64 without padding."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def new_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair for capability signing.

    Returns:
        (private_key_b64, public_key_b64) - URL-safe base64 without padding
    """
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64(private), _b64(public)


def public_key(private_key: str) -> str:
    """Derive public key from private key."""
    try:
        key = Ed25519PrivateKey.from_private_bytes(_unb64(private_key))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid Ed25519 private key: {exc}") from None
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def fingerprint(public: str) -> str:
    """Short stable identifier for a key (first 32 hex chars of SHA-256)."""
    try:
        return hashlib.sha256(_unb64(public)).hexdigest()[:32]
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid Ed25519 public key: {exc}") from None


def canonical(value: Any) -> bytes:
    """Canonical JSON for signing: sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(payload: Any, private_key: str) -> str:
    """Sign a payload with Ed25519 private key."""
    key = Ed25519PrivateKey.from_private_bytes(_unb64(private_key))
    return _b64(key.sign(canonical(payload)))


def verify_signature(payload: Any, signature: str, public: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public)).verify(
            _unb64(signature), canonical(payload)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True)
class CapabilityToken:
    """A short-lived capability token authorizing a worker for a specific job."""

    jti: str
    iat: float
    exp: float

    tenant_id: str
    engagement_id: str
    job_id: str

    targets: tuple[str, ...]          # Host patterns (include list)
    pinned_ips: tuple[str, ...]       # Layer 3 pinned destination IPs
    allowed_ports: tuple[int, ...]    # Allowed destination ports
    allowed_protocols: tuple[str, ...]  # e.g., ("tcp", "http", "https")
    allowed_tools: tuple[str, ...]    # Tool names worker may invoke

    policy_hash: str                  # SHA-256 of the engagement policy
    rules_of_engagement_hash: str     # SHA-256 of RoE (testing_hours, rate_limit_rps, etc.)

    request_budget: int               # Max HTTP requests worker may make
    bandwidth_limit_mb: int           # Max MB worker may transfer

    issuer: str                       # Public key fingerprint of issuer
    version: str = CAPABILITY_VERSION  # Token version, pinned by the verifier
    audience: str = DEFAULT_AUDIENCE   # Only the egress gateway may accept it
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.jti:
            raise ValueError("jti is required")
        if self.exp <= self.iat:
            raise ValueError("exp must be after iat")
        if self.exp - self.iat > MAX_TTL_SECONDS:
            raise ValueError(f"TTL exceeds maximum {MAX_TTL_SECONDS}s")
        if not self.tenant_id or not self.engagement_id or not self.job_id:
            raise ValueError("tenant_id, engagement_id, job_id are required")
        if not self.targets:
            raise ValueError("targets cannot be empty")
        if self.request_budget <= 0:
            raise ValueError("request_budget must be positive")
        if not self.policy_hash:
            raise ValueError("policy_hash is required")
        if not self.rules_of_engagement_hash:
            raise ValueError("rules_of_engagement_hash is required")
        if not self.issuer:
            raise ValueError("issuer is required")
        if not self.version:
            raise ValueError("version is required")
        if not self.audience:
            raise ValueError("audience is required")

    def body(self) -> dict[str, Any]:
        """The signed content (everything except signature)."""
        return {
            "version": self.version,
            "audience": self.audience,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "job_id": self.job_id,
            "targets": self.targets,
            "pinned_ips": self.pinned_ips,
            "allowed_ports": self.allowed_ports,
            "allowed_protocols": self.allowed_protocols,
            "allowed_tools": self.allowed_tools,
            "policy_hash": self.policy_hash,
            "rules_of_engagement_hash": self.rules_of_engagement_hash,
            "request_budget": self.request_budget,
            "bandwidth_limit_mb": self.bandwidth_limit_mb,
            "issuer": self.issuer,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict including signature."""
        return {**self.body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityToken:
        """Deserialize from dict."""
        try:
            return cls(
                jti=str(data["jti"]),
                iat=float(data["iat"]),
                exp=float(data["exp"]),
                tenant_id=str(data["tenant_id"]),
                engagement_id=str(data["engagement_id"]),
                job_id=str(data["job_id"]),
                targets=tuple(str(t) for t in data.get("targets", [])),
                pinned_ips=tuple(str(ip) for ip in data.get("pinned_ips", [])),
                allowed_ports=tuple(int(p) for p in data.get("allowed_ports", [])),
                allowed_protocols=tuple(str(p) for p in data.get("allowed_protocols", [])),
                allowed_tools=tuple(str(t) for t in data.get("allowed_tools", [])),
                policy_hash=str(data["policy_hash"]),
                rules_of_engagement_hash=str(data["rules_of_engagement_hash"]),
                request_budget=int(data["request_budget"]),
                bandwidth_limit_mb=int(data["bandwidth_limit_mb"]),
                issuer=str(data["issuer"]),
                version=str(data.get("version", CAPABILITY_VERSION)),
                audience=str(data.get("audience", DEFAULT_AUDIENCE)),
                signature=str(data.get("signature", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed capability token: {exc}") from None

    def sign(self, private_key: str) -> CapabilityToken:
        """Sign the token with the issuer's private key."""
        if self.signature:
            raise ValueError("token already signed")
        body = self.body()
        if self.issuer != fingerprint(public_key(private_key)):
            raise ValueError("issuer fingerprint does not match private key")
        sig = sign(body, private_key)
        return CapabilityToken(**{**body, "signature": sig})

    def verify(self, public_key: str, *, now: float | None = None) -> tuple[bool, str]:
        """Verify the token signature and expiration.

        Args:
            public_key: The issuer's public key (URL-safe base64)
            now: Current timestamp (defaults to time.time())

        Returns:
            (valid, reason) - valid=True means signature OK and not expired
        """
        if not self.signature:
            return False, "token is not signed"
        if not verify_signature(self.body(), self.signature, public_key):
            return False, "signature verification failed"
        moment = time.time() if now is None else now
        if moment < self.iat:
            return False, f"token not yet valid (iat: {self.iat})"
        if moment >= self.exp:
            return False, f"token expired at {self.exp}"
        if self.issuer != fingerprint(public_key):
            return False, f"issuer mismatch: expected {fingerprint(public_key)}, got {self.issuer}"
        return True, ""

    def is_expired(self, now: float | None = None) -> bool:
        """Check if token is expired."""
        moment = time.time() if now is None else now
        return moment >= self.exp

    def remaining_ttl(self, now: float | None = None) -> float:
        """Seconds until expiration (negative if expired)."""
        moment = time.time() if now is None else now
        return self.exp - moment


def create_capability_token(
    *,
    tenant_id: str,
    engagement_id: str,
    job_id: str,
    targets: list[str],
    pinned_ips: list[str],
    allowed_ports: list[int],
    allowed_protocols: list[str],
    allowed_tools: list[str],
    policy_hash: str,
    rules_of_engagement_hash: str,
    request_budget: int,
    bandwidth_limit_mb: int,
    issuer_private_key: str,
    ttl_seconds: int = MAX_TTL_SECONDS,
) -> CapabilityToken:
    """Create and sign a new capability token.

    Args:
        tenant_id: Tenant identifier
        engagement_id: Engagement identifier
        job_id: Job identifier
        targets: Host patterns from scope (include list)
        pinned_ips: Resolved IPs from Layer 3 pinning
        allowed_ports: Allowed destination ports
        allowed_protocols: Allowed protocols (tcp, http, https)
        allowed_tools: Tool names the worker may invoke
        policy_hash: SHA-256 of the engagement policy document
        rules_of_engagement_hash: SHA-256 of RoE document
        request_budget: Max HTTP requests
        bandwidth_limit_mb: Max MB transfer
        issuer_private_key: Ed25519 private key for signing
        ttl_seconds: Token TTL (max 900s)

    Returns:
        Signed CapabilityToken
    """
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"TTL {ttl_seconds}s exceeds maximum {MAX_TTL_SECONDS}s")
    if ttl_seconds <= 0:
        raise ValueError("TTL must be positive")

    now = time.time()
    token = CapabilityToken(
        jti=uuid.uuid4().hex,
        iat=now,
        exp=now + ttl_seconds,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        job_id=job_id,
        targets=tuple(targets),
        pinned_ips=tuple(pinned_ips),
        allowed_ports=tuple(allowed_ports),
        allowed_protocols=tuple(allowed_protocols),
        allowed_tools=tuple(allowed_tools),
        policy_hash=policy_hash,
        rules_of_engagement_hash=rules_of_engagement_hash,
        request_budget=request_budget,
        bandwidth_limit_mb=bandwidth_limit_mb,
        issuer=fingerprint(public_key(issuer_private_key)),
    )
    return token.sign(issuer_private_key)
