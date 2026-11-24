"""Evidence Signing Service.

Separate Ed25519 key from capability key.
Creates canonical JSON manifests with SHA-256 artifact hashes.
Supports key ID and rotation.

Note: ``canonical_json`` sorts keys and strips whitespace but does not
implement RFC 8785 number/string formatting. Signing and verification use the
same bytes, so tampering is still detected, but do not claim JCS compliance.
Provides `ishastra evidence verify` offline command.

Called by:
- src/ishastra/execution/worker_manager.py (WorkerManager creates evidence after job)
- src/ishastra/control_plane/dispatcher.py (Dispatcher triggers evidence creation)
- src/ishastra/cli.py (ishastra evidence verify command)
- Tests in tests/unit/test_evidence_signing.py

No existing file serves this purpose - new v4.0 evidence signing for Phase 2.

Data schemas:
- Reads: Ed25519 private key, workspace artifacts
- Writes: SignedEvidence manifest (JSON with artifacts[], signatures, key_id)
- Verification: RFC 8785 canonical JSON, SHA-256 hashes, Ed25519 signatures

User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
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

log = logging.getLogger(__name__)

EVIDENCE_VERSION = "ishastra-evidence/1"
PRIVATE_KEY_PREFIX = "ishastra-evidence-private:"
PUBLIC_KEY_PREFIX = "ishastra-evidence-public:"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_json(value: Any) -> bytes:
    """Stable JSON bytes for signing: sorted keys, no whitespace.

    Not full RFC 8785 (number formatting differs). Signer and verifier both
    use this function, so a modified manifest is still rejected.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hash(data: bytes) -> str:
    """SHA-256 hash as hex string."""
    return hashlib.sha256(data).hexdigest()


def new_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair for evidence signing.

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


def sign(payload: bytes, private_key: str) -> str:
    """Sign a payload with Ed25519 private key."""
    key = Ed25519PrivateKey.from_private_bytes(_unb64(private_key))
    return _b64(key.sign(payload))


def verify_signature(payload: bytes, signature: str, public: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public)).verify(_unb64(signature), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def write_private_key(path: str | Path, private_key: str) -> None:
    """Write a key file readable by its owner only."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(PRIVATE_KEY_PREFIX + private_key + "\n")
    os.chmod(target, 0o600)


def load_private_key(path: str | Path) -> str:
    text = Path(path).expanduser().read_text().strip()
    if text.startswith(PRIVATE_KEY_PREFIX):
        text = text[len(PRIVATE_KEY_PREFIX) :]
    public_key(text)  # Validate
    return text


def load_public_key(path: str | Path) -> str:
    text = Path(path).expanduser().read_text().strip()
    if text.startswith(PRIVATE_KEY_PREFIX):
        raise ValueError(f"{path} holds a private key; pass the matching public key instead")
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(text))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid Ed25519 public key in {path}: {exc}") from None
    return text


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to an artifact in the evidence pack."""

    name: str
    path: str
    sha256: str
    size: int
    media_type: str = "application/octet-stream"


@dataclass(frozen=True)
class EvidenceManifest:
    """Canonical evidence manifest for signing."""

    version: str = EVIDENCE_VERSION
    manifest_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    tenant_id: str = ""
    job_id: str = ""
    engagement_id: str = ""
    artifacts: tuple[ArtifactRef, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    key_id: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.job_id or not self.engagement_id:
            raise ValueError("tenant_id, job_id, engagement_id are required")
        if not self.artifacts:
            raise ValueError("artifacts cannot be empty")

    def body(self) -> dict[str, Any]:
        """The signed content."""
        return {
            "version": self.version,
            "manifest_id": self.manifest_id,
            "created_at": self.created_at,
            "tenant_id": self.tenant_id,
            "job_id": self.job_id,
            "engagement_id": self.engagement_id,
            "artifacts": [
                {
                    "name": a.name,
                    "path": a.path,
                    "sha256": a.sha256,
                    "size": a.size,
                    "media_type": a.media_type,
                }
                for a in self.artifacts
            ],
            "metadata": self.metadata,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature, "key_id": self.key_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceManifest:
        try:
            artifacts = tuple(ArtifactRef(**a) for a in data.get("artifacts", []))
            return cls(
                version=data.get("version", EVIDENCE_VERSION),
                manifest_id=data["manifest_id"],
                created_at=data["created_at"],
                tenant_id=data["tenant_id"],
                job_id=data["job_id"],
                engagement_id=data["engagement_id"],
                artifacts=artifacts,
                metadata=data.get("metadata", {}),
                signature=data.get("signature", ""),
                key_id=data.get("key_id", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed evidence manifest: {exc}") from None


class EvidenceSigningService:
    """Service for creating and verifying signed evidence manifests."""

    def __init__(
        self,
        *,
        signing_key_private: str,
        key_id: str | None = None,
        previous_keys: dict[str, str] | None = None,
    ):
        """Initialize the evidence signing service.

        Args:
            signing_key_private: Ed25519 private key (URL-safe base64)
            key_id: Key identifier (defaults to fingerprint of signing key)
            previous_keys: Previous keys for rotation (key_id -> private_key)
        """
        self.signing_key_private = signing_key_private
        self.key_id = key_id or fingerprint(public_key(signing_key_private))
        self.previous_keys = previous_keys or {}

        if self.key_id != fingerprint(public_key(signing_key_private)):
            raise ValueError("key_id does not match signing key fingerprint")

    @classmethod
    def generate_keys(cls) -> tuple[str, str]:
        """Generate a new keypair for evidence signing."""
        return new_keypair()

    @classmethod
    def create_service(cls, *, signing_key_private: str | None = None) -> EvidenceSigningService:
        """Create a service, generating keys if not provided."""
        if signing_key_private is None:
            signing_key_private, _ = new_keypair()
        return cls(signing_key_private=signing_key_private)

    def rotate_key(self, new_private_key: str | None = None) -> EvidenceSigningService:
        """Rotate the signing key."""
        if new_private_key is None:
            new_private_key, _ = new_keypair()
        new_key_id = fingerprint(public_key(new_private_key))

        previous_keys = dict(self.previous_keys)
        previous_keys[self.key_id] = self.signing_key_private

        return EvidenceSigningService(
            signing_key_private=new_private_key,
            key_id=new_key_id,
            previous_keys=previous_keys,
        )

    def get_verification_keys(self) -> dict[str, str]:
        """Get all public keys for verification (current + previous)."""
        keys = {self.key_id: public_key(self.signing_key_private)}
        for key_id, private_key in self.previous_keys.items():
            keys[key_id] = public_key(private_key)
        return keys

    def create_manifest(
        self,
        *,
        tenant_id: str,
        job_id: str,
        engagement_id: str,
        artifacts: list[ArtifactRef],
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceManifest:
        """Create an evidence manifest (unsigned)."""
        return EvidenceManifest(
            tenant_id=tenant_id,
            job_id=job_id,
            engagement_id=engagement_id,
            artifacts=tuple(artifacts),
            metadata=metadata or {},
        )

    def sign_manifest(self, manifest: EvidenceManifest) -> EvidenceManifest:
        """Sign an evidence manifest."""
        body_bytes = canonical_json(manifest.body())
        signature = sign(body_bytes, self.signing_key_private)
        return EvidenceManifest(
            version=manifest.version,
            manifest_id=manifest.manifest_id,
            created_at=manifest.created_at,
            tenant_id=manifest.tenant_id,
            job_id=manifest.job_id,
            engagement_id=manifest.engagement_id,
            artifacts=manifest.artifacts,
            metadata=manifest.metadata,
            signature=signature,
            key_id=self.key_id,
        )

    def create_signed_evidence(
        self,
        *,
        tenant_id: str,
        job_id: str,
        engagement_id: str,
        artifacts: list[ArtifactRef],
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceManifest:
        """Create and sign an evidence manifest in one call."""
        manifest = self.create_manifest(
            tenant_id=tenant_id,
            job_id=job_id,
            engagement_id=engagement_id,
            artifacts=artifacts,
            metadata=metadata,
        )
        return self.sign_manifest(manifest)

    def verify_evidence(self, manifest: EvidenceManifest, *, key_id: str | None = None) -> tuple[bool, str]:
        """Verify a signed evidence manifest.

        Args:
            manifest: The signed evidence to verify
            key_id: Specific key ID to use (defaults to manifest.key_id)

        Returns:
            (valid, reason)
        """
        verify_key_id = key_id or manifest.key_id
        keys = self.get_verification_keys()

        if verify_key_id not in keys:
            return False, f"unknown key_id: {verify_key_id}"

        if not manifest.signature:
            return False, "manifest not signed"
        if manifest.key_id != verify_key_id:
            return False, f"key_id mismatch: expected {verify_key_id}, got {manifest.key_id}"
        if not verify_signature(canonical_json(manifest.body()), manifest.signature, keys[verify_key_id]):
            return False, "signature verification failed"
        return True, ""

    async def create_evidence_from_workspace(
        self,
        *,
        tenant_id: str,
        job_id: str,
        engagement_id: str,
        workspace_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceManifest:
        """Create signed evidence from a workspace directory.

        Walks the workspace, hashes all files, creates manifest, signs it.
        """
        workspace = Path(workspace_path)
        if not workspace.exists():
            raise ValueError(f"workspace not found: {workspace_path}")

        artifacts = []
        for file_path in workspace.rglob("*"):
            if file_path.is_file():
                content = file_path.read_bytes()
                rel_path = file_path.relative_to(workspace)
                artifacts.append(
                    ArtifactRef(
                        name=rel_path.name,
                        path=str(rel_path),
                        sha256=sha256_hash(content),
                        size=len(content),
                        media_type=self._guess_media_type(file_path),
                    )
                )

        if not artifacts:
            raise ValueError("workspace contains no files")

        return self.create_signed_evidence(
            tenant_id=tenant_id,
            job_id=job_id,
            engagement_id=engagement_id,
            artifacts=artifacts,
            metadata=metadata,
        )

    def _guess_media_type(self, path: Path) -> str:
        """Guess media type from file extension."""
        suffix = path.suffix.lower()
        types = {
            ".json": "application/json",
            ".txt": "text/plain",
            ".html": "text/html",
            ".pdf": "application/pdf",
            ".sarif": "application/sarif+json",
            ".xml": "application/xml",
            ".csv": "text/csv",
            ".log": "text/plain",
            ".pcap": "application/vnd.tcpdump.pcap",
        }
        return types.get(suffix, "application/octet-stream")


def verify_evidence_file(
    evidence_path: str | Path,
    public_key_path: str | Path,
    artifacts_dir: str | Path | None = None,
) -> tuple[bool, str]:
    """Offline verification for `ishastra evidence verify`.

    Args:
        evidence_path: Path to signed evidence JSON file
        public_key_path: Path to the trusted public key file
        artifacts_dir: When given, re-hash every artifact under this directory
            so edited artifact bytes are rejected too.

    Returns:
        (valid, reason)
    """
    evidence_data = json.loads(Path(evidence_path).read_text())
    manifest = EvidenceManifest.from_dict(evidence_data)
    public_key_str = load_public_key(public_key_path)

    if not manifest.signature:
        return False, "manifest not signed"
    if manifest.key_id != fingerprint(public_key_str):
        return False, f"key_id mismatch: expected {fingerprint(public_key_str)}, got {manifest.key_id}"
    if not verify_signature(canonical_json(manifest.body()), manifest.signature, public_key_str):
        return False, "signature verification failed"

    if artifacts_dir is not None:
        base = Path(artifacts_dir)
        for artifact in manifest.artifacts:
            target = base / artifact.path
            if not target.is_file():
                return False, f"missing artifact: {artifact.path}"
            if sha256_hash(target.read_bytes()) != artifact.sha256:
                return False, f"artifact hash mismatch: {artifact.path}"

    return True, ""
