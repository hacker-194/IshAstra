"""Ed25519 signatures for scope documents, with a JWKS-style key set.

A signed scope document carries the signature inline::

    "signature": {"alg": "Ed25519", "kid": "2026-11", "sig": "<base64url>"}

The signature covers the canonical JSON of the document with the ``signature``
block removed (sorted keys, no whitespace). Every other field is covered --
``include``, ``exclude``, ``authorized_networks``, ``allowed_ports``, the
revocation fields, ``expires_at`` and ``metadata`` -- so widening a document or
un-revoking one invalidates it.

Rotation is the same story as any JWKS deployment: publish the new key next to
the old one in the key set, sign new documents with the new ``kid``, and retire
the old key once every live document has been re-signed. Removing a key from the
set is the revoke step -- documents signed with it stop loading.

Signing material never belongs in the document: the private key stays on the
issuing host (mode 0600), and verifiers only ever see public JWKs.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_FIELD = "signature"
SIGNATURE_ALG = "Ed25519"
DEFAULT_MAX_AGE_SECONDS = 86_400
# A verifier's clock is never exactly the signer's, so a stamp slightly in the
# future is tolerated; anything older than the limit is refused.
CLOCK_SKEW = timedelta(minutes=5)
_ED25519_PUBLIC_BYTES = 32
_MAX_KID = 128


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("signature values must be non-empty base64url strings")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise ValueError("value is not valid base64url") from None


def canonical_payload(document: dict[str, Any]) -> bytes:
    """The exact bytes a signature covers: the document without its signature.

    Keys are sorted and separators are compact, so field order in the file does
    not matter; any value change does.
    """
    if not isinstance(document, dict):
        raise ValueError("scope document must be a JSON object")
    payload = {key: value for key, value in document.items() if key != SIGNATURE_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def is_signed(document: dict[str, Any]) -> bool:
    """Whether the document carries a signature block."""
    return isinstance(document, dict) and isinstance(document.get(SIGNATURE_FIELD), dict)


def generate_keypair(kid: str) -> tuple[bytes, dict[str, str]]:
    """A fresh Ed25519 private key (PEM, unencrypted) and its public JWK."""
    if not isinstance(kid, str) or not kid.strip() or len(kid) > _MAX_KID:
        raise ValueError(f"kid must be a non-empty string of at most {_MAX_KID} characters")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pem, {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid.strip(),
        "x": _b64url_encode(public_raw),
    }


def rotate_keypair(kid: str, private_key_path: Path | str, jwks_path: Path | str) -> dict[str, str]:
    """Create a new key and atomically append its public JWK to an existing JWKS.

    Previous public keys are deliberately retained so already-issued scope
    documents remain verifiable until an operator explicitly retires them.
    """
    private_path = Path(private_key_path)
    public_path = Path(jwks_path)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("private key and JWKS paths must be different")
    if private_path.exists():
        raise ValueError(f"private key already exists: {private_path}")
    try:
        jwks = json.loads(public_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"JWKS {public_path} cannot be read: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"JWKS {public_path} is not valid JSON: {exc.msg}") from None
    keys = parse_jwks(jwks)
    pem, jwk = generate_keypair(kid)
    if jwk["kid"] in keys:
        raise ValueError(f"JWKS already contains kid {jwk['kid']!r}")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private_key_exclusive(private_path, pem)
    _write_jwks(public_path, {**jwks, "keys": [*jwks["keys"], jwk]})
    return jwk


def _write_private_key_exclusive(path: Path, data: bytes) -> None:
    """Install a private key with owner-only permissions, refusing replacement."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o600)
        os.link(temp_path, path)
    except FileExistsError:
        raise ValueError(f"private key already exists: {path}") from None
    finally:
        temp_path.unlink(missing_ok=True)


def _write_jwks(path: Path, jwks: dict[str, Any]) -> None:
    """Replace the public key set atomically so readers never see partial JSON."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(jwks, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def parse_jwks(data: Any) -> dict[str, Ed25519PublicKey]:
    """Public keys from a JWKS object, keyed by ``kid``.

    RFC 8037 shape: every entry is ``kty=OKP``, ``crv=Ed25519`` with a base64url
    ``x``. A set that parses to no usable keys is refused rather than treated as
    "no signing" -- an empty key set that silently disables verification is the
    one failure mode worth being loud about.
    """
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("JWKS must be an object with a 'keys' list")
    keys: dict[str, Ed25519PublicKey] = {}
    for entry in data["keys"]:
        if not isinstance(entry, dict):
            raise ValueError("JWKS key entries must be objects")
        kid = entry.get("kid")
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            raise ValueError(f"JWKS key {kid!r} must be kty=OKP, crv=Ed25519")
        if not isinstance(kid, str) or not kid.strip() or len(kid) > _MAX_KID:
            raise ValueError(f"JWKS key entries need a non-empty 'kid' of at most {_MAX_KID} characters")
        raw = _b64url_decode(entry.get("x"))
        if len(raw) != _ED25519_PUBLIC_BYTES:
            raise ValueError(f"JWKS key {kid!r} must carry a {_ED25519_PUBLIC_BYTES}-byte Ed25519 public key")
        keys[kid.strip()] = Ed25519PublicKey.from_public_bytes(raw)
    if not keys:
        raise ValueError("JWKS contains no keys; a key set that can verify nothing must not be installed")
    return keys


def load_jwks(path: Path | str) -> dict[str, Ed25519PublicKey]:
    """Public keys from a JWKS file."""
    document = Path(path)
    try:
        data = json.loads(document.read_text())
    except OSError as exc:
        raise ValueError(f"JWKS {document} cannot be read: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"JWKS {document} is not valid JSON: {exc.msg}") from None
    try:
        return parse_jwks(data)
    except ValueError as exc:
        raise ValueError(f"JWKS {document}: {exc}") from None


def key_set(source: dict[str, Any] | Path | str) -> dict[str, Ed25519PublicKey]:
    """Public keys from a JWKS object or a JWKS file path."""
    return parse_jwks(source) if isinstance(source, dict) else load_jwks(Path(source))


def load_private_key_file(path: Path | str) -> Ed25519PrivateKey:
    """An Ed25519 private key from an unencrypted PEM file."""
    document = Path(path)
    try:
        raw = document.read_bytes()
    except OSError as exc:
        raise ValueError(f"signing key {document} cannot be read: {exc}") from None
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"signing key {document} is not a readable unencrypted PEM private key: {exc}"
        ) from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"signing key {document} must be Ed25519, not {type(key).__name__}")
    return key


def sign_document(
    document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    kid: str,
    *,
    issued_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Return ``document`` signed by ``private_key``, stamped with ``issued_at``.

    ``issued_at`` is part of the signed payload, so it cannot be edited after
    the fact. Verification refuses a document older than its freshness limit:
    that is what stops an older, correctly signed copy from being replayed after
    the live document was revoked or narrowed. A naive ``datetime`` is taken as
    UTC; a string is used as given and must carry a timezone.
    """
    stamp = issued_at if issued_at is not None else datetime.now(UTC)
    if isinstance(stamp, datetime):
        stamp = (stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp).isoformat()
    signed = {key: value for key, value in document.items() if key != SIGNATURE_FIELD}
    signed["issued_at"] = str(stamp).strip()
    signed[SIGNATURE_FIELD] = {
        "alg": SIGNATURE_ALG,
        "kid": kid.strip(),
        "sig": _b64url_encode(private_key.sign(canonical_payload(signed))),
    }
    return signed


def verify_document(
    document: dict[str, Any],
    keys: dict[str, Ed25519PublicKey],
    *,
    max_age: int | None = DEFAULT_MAX_AGE_SECONDS,
    now: datetime | None = None,
) -> str:
    """Verify ``document`` against ``keys`` and return the ``kid`` that signed it.

    Raises ``ValueError`` naming the problem: not signed, unknown algorithm,
    unknown/retired key, a signature that does not match the payload, or a
    document whose signed ``issued_at`` is missing, in the future or older than
    ``max_age`` seconds. ``max_age=None`` disables the freshness check, which
    lets an older signed copy be replayed.
    """
    block = document.get(SIGNATURE_FIELD) if isinstance(document, dict) else None
    if not isinstance(block, dict):
        raise ValueError("scope document is not signed and a signing key set is configured")
    if block.get("alg") != SIGNATURE_ALG:
        raise ValueError(f"unsupported scope signature algorithm {block.get('alg')!r}")
    kid = block.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise ValueError("scope signature is missing a key id (kid)")
    key = keys.get(kid.strip())
    if key is None:
        raise ValueError(
            f"scope signature key {kid!r} is not in the configured key set (rotated out or never published)"
        )
    try:
        key.verify(_b64url_decode(block.get("sig")), canonical_payload(document))
    except InvalidSignature:
        raise ValueError(
            f"scope document signature does not verify under key {kid!r}; the document was modified"
        ) from None
    except ValueError as exc:
        raise ValueError(f"scope signature is malformed: {exc}") from None
    if max_age is not None:
        _check_freshness(document, max_age=max_age, now=now)
    return kid.strip()


def _check_freshness(document: dict[str, Any], *, max_age: int, now: datetime | None) -> None:
    """Refuse a correctly signed but old document, so a revoked copy cannot be replayed."""
    issued = document.get("issued_at")
    if not isinstance(issued, str) or not issued.strip():
        raise ValueError("scope document has no issued_at, so an older signed copy could be replayed")
    try:
        issued_at = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("issued_at must be a valid ISO 8601 timestamp") from None
    if issued_at.tzinfo is None:
        raise ValueError("issued_at must carry a timezone (Z or an offset)")
    current = now or datetime.now(UTC)
    if issued_at > current + CLOCK_SKEW:
        raise ValueError(f"scope document issued_at {issued} is in the future")
    age = (current - issued_at).total_seconds()
    if age > max_age:
        raise ValueError(
            f"scope document is stale: signed {int(age)}s ago, the limit is {max_age}s; re-sign it"
        )
