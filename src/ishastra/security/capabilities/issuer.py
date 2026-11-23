"""Capability Issuer Service.

Generates Ed25519-signed capability tokens for worker authorization.
Manages signing key rotation and revocation list persistence.

Called by:
- src/ishastra/control_plane/dispatcher.py (Dispatcher issues tokens for jobs)
- src/ishastra/api/routers/assessments.py (API endpoint for manual token issuance)
- Tests in tests/unit/test_capability_issuer.py

No existing file serves this purpose - new v4.0 capability issuer for Phase 2.

Data schemas:
- Reads: Ed25519 private key from config, Scope from engagement policy, policy/RoE hashes
- Writes: CapabilityToken to worker env, revocation entries to database (capability_revocations table)
- Revocation schema: jti, key_id, reason, revoked_at, revoked_by
- Token registry: capability_tokens table for bulk revocation tracking

User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ishastra.core.store import Database
from ishastra.security.authorization.scope import Scope
from ishastra.security.capabilities.revocation import RevocationList
from ishastra.security.capabilities.token import (
    MAX_TTL_SECONDS,
    CapabilityToken,
    create_capability_token,
    fingerprint,
    new_keypair,
    public_key,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class IssuerConfig:
    """Configuration for the Capability Issuer."""

    signing_key_private: str
    key_id: str
    previous_keys: dict[str, str] = None  # type: ignore[assignment]
    default_ttl_seconds: int = MAX_TTL_SECONDS
    database: Database | None = None

    def __post_init__(self) -> None:
        if self.previous_keys is None:
            object.__setattr__(self, "previous_keys", {})
        expected_id = fingerprint(public_key(self.signing_key_private))
        if self.key_id != expected_id:
            raise ValueError(f"key_id {self.key_id} does not match signing key fingerprint {expected_id}")
        if self.default_ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError(
                f"default_ttl_seconds {self.default_ttl_seconds} "
                f"exceeds maximum {MAX_TTL_SECONDS}"
            )


class CapabilityIssuer:
    """Issues short-lived capability tokens for worker authorization.

    Tokens bind a worker to a specific job, scope, and policy.
    All tokens are signed with Ed25519 and have TTL <= 15 minutes.
    Revocation is handled via a database-backed revocation list.
    """

    def __init__(self, config: IssuerConfig):
        self.config = config
        self.revocation = RevocationList(config.database) if config.database else None

    @classmethod
    def generate_keys(cls) -> tuple[str, str]:
        """Generate a new Ed25519 keypair for capability signing.

        Returns:
            (private_key, public_key) both base64 URL-safe without padding
        """
        return new_keypair()

    @classmethod
    def create_config(
        cls,
        *,
        signing_key_private: str | None = None,
        database: Database | None = None,
        default_ttl_seconds: int = MAX_TTL_SECONDS,
    ) -> IssuerConfig:
        """Create an IssuerConfig, generating keys if not provided."""
        if signing_key_private is None:
            signing_key_private, _ = new_keypair()
        key_id = fingerprint(public_key(signing_key_private))
        return IssuerConfig(
            signing_key_private=signing_key_private,
            key_id=key_id,
            default_ttl_seconds=default_ttl_seconds,
            database=database,
        )

    def rotate_key(self, new_private_key: str | None = None) -> IssuerConfig:
        """Rotate the signing key.

        The old key is added to previous_keys for verifying existing tokens.
        Returns a new IssuerConfig with the rotated key.
        """
        if new_private_key is None:
            new_private_key, _ = new_keypair()
        new_key_id = fingerprint(public_key(new_private_key))

        previous_keys = dict(self.config.previous_keys)
        previous_keys[self.config.key_id] = self.config.signing_key_private

        return IssuerConfig(
            signing_key_private=new_private_key,
            key_id=new_key_id,
            previous_keys=previous_keys,
            default_ttl_seconds=self.config.default_ttl_seconds,
            database=self.config.database,
        )

    def get_verification_keys(self) -> dict[str, str]:
        """Get all public keys for token verification (current + previous).

        Returns:
            Dict mapping key_id -> public_key (base64 URL-safe)
        """
        keys = {self.config.key_id: public_key(self.config.signing_key_private)}
        for key_id, private_key in self.config.previous_keys.items():
            keys[key_id] = public_key(private_key)
        return keys

    async def initialize(self) -> None:
        """Initialize database tables for revocation and token registry."""
        if self.revocation:
            await self.revocation.initialize()
            await self.revocation.initialize_token_registry()

    def issue_token(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        job_id: str,
        scope: Scope,
        policy_hash: str,
        rules_of_engagement_hash: str,
        allowed_tools: list[str],
        request_budget: int,
        bandwidth_limit_mb: int,
        pinned_ips: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> CapabilityToken:
        """Issue a new capability token for a job.

        Args:
            tenant_id: Tenant identifier
            engagement_id: Engagement identifier
            job_id: Job identifier
            scope: The authorized Scope (provides targets, ports, networks)
            policy_hash: SHA-256 of the engagement policy document
            rules_of_engagement_hash: SHA-256 of RoE document
            allowed_tools: Tool names the worker may invoke
            request_budget: Max HTTP requests worker may make
            bandwidth_limit_mb: Max MB worker may transfer
            pinned_ips: Layer 3 pinned destination IPs, resolved by the
                dispatcher. Empty means the gateway denies every connection.
            ttl_seconds: Token TTL (defaults to config default, max 900s)

        Returns:
            Signed CapabilityToken
        """
        ttl = ttl_seconds or self.config.default_ttl_seconds
        if ttl > MAX_TTL_SECONDS:
            raise ValueError(f"TTL {ttl}s exceeds maximum {MAX_TTL_SECONDS}s")

        targets = list(scope.include)
        allowed_ports = list(scope.allowed_ports) if scope.allowed_ports else [80, 443]
        allowed_protocols = ["tcp", "http", "https"]

        token = create_capability_token(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            job_id=job_id,
            targets=targets,
            pinned_ips=list(pinned_ips or ()),
            allowed_ports=allowed_ports,
            allowed_protocols=allowed_protocols,
            allowed_tools=allowed_tools,
            policy_hash=policy_hash,
            rules_of_engagement_hash=rules_of_engagement_hash,
            request_budget=request_budget,
            bandwidth_limit_mb=bandwidth_limit_mb,
            issuer_private_key=self.config.signing_key_private,
            ttl_seconds=ttl,
        )

        log.info(
            "issued capability token",
            extra={
                "jti": token.jti,
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "job_id": job_id,
                "exp": token.exp,
                "key_id": self.config.key_id,
            },
        )
        return token

    async def issue_and_register_token(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        job_id: str,
        scope: Scope,
        policy_hash: str,
        rules_of_engagement_hash: str,
        allowed_tools: list[str],
        request_budget: int,
        bandwidth_limit_mb: int,
        pinned_ips: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> CapabilityToken:
        """Issue a token and register it in the token registry (async)."""
        token = self.issue_token(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            job_id=job_id,
            scope=scope,
            policy_hash=policy_hash,
            rules_of_engagement_hash=rules_of_engagement_hash,
            allowed_tools=allowed_tools,
            request_budget=request_budget,
            bandwidth_limit_mb=bandwidth_limit_mb,
            pinned_ips=pinned_ips,
            ttl_seconds=ttl_seconds,
        )

        if self.revocation:
            await self.revocation.register_token(
                jti=token.jti,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                job_id=job_id,
                key_id=self.config.key_id,
                iat=token.iat,
                exp=token.exp,
                policy_hash=policy_hash,
            )

        return token

    async def revoke_token_async(self, jti: str, reason: str = "") -> bool:
        """Async revoke a capability token by JTI."""
        if not self.revocation:
            raise RuntimeError("Revocation not configured (no database)")
        return await self.revocation.revoke(jti, reason, self.config.key_id)

    async def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI is revoked."""
        if not self.revocation:
            return False
        return await self.revocation.is_revoked(jti)

    async def revoke_all_for_job(self, job_id: str, reason: str = "") -> int:
        """Revoke all tokens for a specific job.

        Returns:
            Number of tokens revoked
        """
        if not self.revocation:
            raise RuntimeError("Revocation not configured (no database)")
        return await self.revocation.revoke_by_job(job_id, reason, self.config.key_id)

    async def revoke_all_for_engagement(self, engagement_id: str, reason: str = "") -> int:
        """Revoke all tokens for an engagement.

        Returns:
            Number of tokens revoked
        """
        if not self.revocation:
            raise RuntimeError("Revocation not configured (no database)")
        return await self.revocation.revoke_by_engagement(engagement_id, reason, self.config.key_id)

    async def revoke_all_for_tenant(self, tenant_id: str, reason: str = "") -> int:
        """Revoke all tokens for a tenant.

        Returns:
            Number of tokens revoked
        """
        if not self.revocation:
            raise RuntimeError("Revocation not configured (no database)")
        return await self.revocation.revoke_by_tenant(tenant_id, reason, self.config.key_id)
