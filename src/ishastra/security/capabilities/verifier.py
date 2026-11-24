"""Capability token verifier.

Validates capability tokens for the egress gateway and worker manager.

``verify_async`` performs the full set of checks: signature, exp/iat, revocation,
job state and policy binding. The sync ``verify`` only does the cryptographic
checks and refuses to answer when database-backed checks are configured, so a
caller cannot accidentally treat an unchecked token as valid.

Called by:
- src/ishastra/security/egress/gateway.py (authorize_connection)
- src/ishastra/execution/worker_manager.py (before starting a worker)
- Tests in tests/unit/test_egress_gateway.py
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ishastra.core.store import Database, _fetchone
from ishastra.security.capabilities.revocation import RevocationList
from ishastra.security.capabilities.token import (
    CAPABILITY_VERSION,
    DEFAULT_AUDIENCE,
    CapabilityToken,
    verify_signature,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerificationResult:
    """Result of capability token verification."""

    valid: bool
    reason: str
    token: CapabilityToken | None = None
    key_id: str | None = None


class CapabilityVerifier:
    """Verifies capability tokens for worker authorization.

    Checks, in order:
    1. Signature validity (Ed25519, issuer key must be trusted)
    2. Not-before / expiration (iat/exp)
    3. Revocation status (database-backed, async only)
    4. Job state must be RUNNING (database-backed, async only)
    """

    def __init__(
        self,
        *,
        verification_keys: dict[str, str],  # key_id -> public_key (base64 URL-safe)
        revocation: RevocationList | None = None,
        database: Database | None = None,
        require_job_running: bool = True,
        expected_audience: str = DEFAULT_AUDIENCE,
    ) -> None:
        """Initialize verifier.

        Args:
            verification_keys: map of key_id -> public_key for all trusted keys
            revocation: RevocationList instance (requires database)
            database: Database for job state checks
            require_job_running: verify the job is in RUNNING state
        """
        if not verification_keys:
            raise ValueError("verification_keys cannot be empty")
        self.verification_keys = verification_keys
        self.revocation = revocation
        self.database = database
        self.require_job_running = require_job_running
        self.expected_audience = expected_audience

    def _verify_crypto(self, token_dict: dict[str, Any], *, now: float | None = None) -> VerificationResult:
        """Signature and time checks; no database access."""
        moment = time.time() if now is None else now

        try:
            token = CapabilityToken.from_dict(token_dict)
        except ValueError as exc:
            return VerificationResult(valid=False, reason=f"malformed token: {exc}")

        if token.version != CAPABILITY_VERSION:
            return VerificationResult(
                valid=False,
                reason=f"unsupported token version: {token.version}",
                token=token,
            )
        if token.audience != self.expected_audience:
            return VerificationResult(
                valid=False,
                reason=f"wrong audience: {token.audience}",
                token=token,
            )

        key_id = token.issuer
        if key_id not in self.verification_keys:
            return VerificationResult(
                valid=False,
                reason=f"unknown issuer key_id: {key_id}",
                token=token,
                key_id=key_id,
            )

        public_key = self.verification_keys[key_id]
        if not token.signature:
            return VerificationResult(valid=False, reason="token not signed", token=token, key_id=key_id)
        if not verify_signature(token.body(), token.signature, public_key):
            return VerificationResult(
                valid=False,
                reason="signature verification failed",
                token=token,
                key_id=key_id,
            )
        if moment < token.iat:
            return VerificationResult(
                valid=False,
                reason=f"token not yet valid (iat: {token.iat})",
                token=token,
                key_id=key_id,
            )
        if moment >= token.exp:
            return VerificationResult(
                valid=False,
                reason=f"token expired at {token.exp}",
                token=token,
                key_id=key_id,
            )
        return VerificationResult(valid=True, reason="", token=token, key_id=key_id)

    def verify(self, token_dict: dict[str, Any], *, now: float | None = None) -> VerificationResult:
        """Crypto-only verification. Fails closed when DB checks are configured."""
        result = self._verify_crypto(token_dict, now=now)
        if not result.valid:
            return result

        if self.revocation is not None or (self.database is not None and self.require_job_running):
            return VerificationResult(
                valid=False,
                reason="revocation/job-state checks require verify_async()",
                token=result.token,
                key_id=result.key_id,
            )
        return result

    async def verify_async(
        self, token_dict: dict[str, Any], *, now: float | None = None
    ) -> VerificationResult:
        """Full verification: crypto plus revocation and job state."""
        result = self._verify_crypto(token_dict, now=now)
        if not result.valid:
            return result

        token = result.token
        assert token is not None

        if self.revocation is not None and token.jti and await self.revocation.is_revoked(token.jti):
            return VerificationResult(
                valid=False,
                reason=f"token revoked (jti: {token.jti})",
                token=token,
                key_id=result.key_id,
            )

        if self.database is not None and self.require_job_running and token.job_id:
            job_state = await self._get_job_state(token.tenant_id, token.job_id)
            if job_state.strip().lower() != "running":
                return VerificationResult(
                    valid=False,
                    reason=f"job not running (state: {job_state})",
                    token=token,
                    key_id=result.key_id,
                )

        return VerificationResult(valid=True, reason="", token=token, key_id=result.key_id)

    async def _get_job_state(self, tenant_id: str, job_id: str) -> str:
        """Get job state from the database (SQLite or PostgreSQL)."""
        if self.database is None:
            return "unknown"
        sql = "SELECT state FROM jobs WHERE tenant = ? AND id = ?"
        async with self.database.read_transaction() as conn:
            row = await _fetchone(conn, sql, tenant_id, job_id)
        return row["state"] if row else "unknown"

    @classmethod
    def from_issuer_config(
        cls,
        issuer_config: Any,  # IssuerConfig - avoid circular import
        database: Database | None = None,
        require_job_running: bool = True,
    ) -> CapabilityVerifier:
        """Create a verifier from an issuer config."""
        from ishastra.security.capabilities.token import public_key

        verification_keys = {}
        verification_keys[issuer_config.key_id] = public_key(issuer_config.signing_key_private)
        for key_id, private_key in issuer_config.previous_keys.items():
            verification_keys[key_id] = public_key(private_key)

        revocation = RevocationList(database) if database else None
        return cls(
            verification_keys=verification_keys,
            revocation=revocation,
            database=database,
            require_job_running=require_job_running,
        )
