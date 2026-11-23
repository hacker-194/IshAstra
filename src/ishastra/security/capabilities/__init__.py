"""Capability tokens for worker authorization (IshAstra v4.0 Security Spine).

Ed25519-signed JWT tokens binding worker to job/scope/policy.
TTL <= 15 minutes. Revocation via database-backed list.

Called by:
- src/ishastra/control_plane/dispatcher.py (imports CapabilityIssuer)
- src/ishastra/security/egress/gateway.py (imports CapabilityVerifier)
- src/ishastra/execution/worker_manager.py (imports CapabilityToken, CapabilityIssuer)
- Tests in tests/unit/test_capabilities.py

No existing file serves this purpose - new v4.0 capabilities package for Phase 2.

Data schemas: Re-exports token, issuer, revocation, verifier modules

User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from ishastra.security.capabilities.issuer import (
    CapabilityIssuer,
    IssuerConfig,
)
from ishastra.security.capabilities.revocation import (
    REVOCATION_TABLE_PG,
    REVOCATION_TABLE_SQLITE,
    RevocationEntry,
    RevocationList,
)
from ishastra.security.capabilities.token import (
    CAPABILITY_VERSION,
    MAX_TTL_SECONDS,
    CapabilityToken,
    canonical,
    create_capability_token,
    fingerprint,
    new_keypair,
    public_key,
    sign,
    verify_signature,
)
from ishastra.security.capabilities.verifier import (
    CapabilityVerifier,
    VerificationResult,
)

__all__ = [
    "CAPABILITY_VERSION",
    "MAX_TTL_SECONDS",
    "CapabilityToken",
    "create_capability_token",
    "fingerprint",
    "new_keypair",
    "public_key",
    "sign",
    "verify_signature",
    "canonical",
    "IssuerConfig",
    "CapabilityIssuer",
    "RevocationList",
    "RevocationEntry",
    "REVOCATION_TABLE_SQLITE",
    "REVOCATION_TABLE_PG",
    "VerificationResult",
    "CapabilityVerifier",
]
