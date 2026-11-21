"""Dual-approval break-glass workflow for emergency scope authorization.

A break-glass scope document allows emergency access when the normal authorization
process cannot be followed. It requires TWO Ed25519 signatures from different
approvers (from a configured JWKS), has a maximum 4-hour expiry, and writes
an immutable audit trail entry.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ishastra import metrics
from ishastra.core import scope_signing

log = logging.getLogger(__name__)


BREAK_GLASS_MAX = timedelta(hours=4)


BREAK_GLASS_EVENT = "break_glass_activation"


BREAK_GLASS_RESULT_SUCCESS = "success"
BREAK_GLASS_RESULT_FAILURE = "failure"


class BreakGlassError(ValueError):
    """Raised when break-glass workflow fails."""


def _parse_duration(text: str) -> timedelta:
    """'90m', '24h', '7d', '3600s' -> timedelta; a bare number means seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    raw = str(text).strip().lower()
    unit = units.get(raw[-1]) if raw else None
    if unit is None:
        if not raw.isdigit():
            raise ValueError(f"duration {text!r} must look like 90m, 24h or 7d")
        return timedelta(seconds=int(raw))
    number = raw[:-1]
    if not number.isdigit() or int(number) <= 0:
        raise ValueError(f"duration {text!r} must be a positive number followed by s/m/h/d")
    return timedelta(seconds=int(number) * unit)


def _compute_scope_hash(document: dict[str, Any]) -> str:
    """Compute SHA-256 hash of the canonical scope document (without signatures)."""

    payload = {k: v for k, v in document.items() if k != "signatures"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_approver_signature(
    document: dict[str, Any],
    signature_block: dict[str, Any],
    jwks: dict[str, Any],
) -> str:
    """Verify a single approver signature and return the kid."""

    if not isinstance(signature_block, dict):
        raise BreakGlassError("signature block must be an object")
    if signature_block.get("alg") != "Ed25519":
        raise BreakGlassError(f"unsupported algorithm {signature_block.get('alg')!r}")
    kid = signature_block.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise BreakGlassError("signature block missing kid")
    sig = signature_block.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        raise BreakGlassError("signature block missing sig")

    keys = scope_signing.parse_jwks(jwks)
    key = keys.get(kid.strip())
    if key is None:
        raise BreakGlassError(f"approver key {kid!r} not found in JWKS")

    payload = {k: v for k, v in document.items() if k != "signatures"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    import base64
    import binascii

    from cryptography.exceptions import InvalidSignature

    try:
        sig_bytes = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        key.verify(sig_bytes, canonical)
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise BreakGlassError(f"signature verification failed for {kid}: {exc}") from None

    return kid.strip()


def create_break_glass_scope(
    *,
    scope_document: dict[str, Any],
    approver1_key_path: str,
    approver1_kid: str,
    approver2_key_path: str,
    approver2_kid: str,
    jwks_path: str,
    tenant_id: str,
    reason: str,
    duration: str,
) -> dict[str, Any]:
    """Create a dual-approval break-glass scope document.

    Args:
        scope_document: The base scope document (unsigned) to authorize
        approver1_key_path: Path to first approver's private key PEM
        approver1_kid: Key ID for first approver (must exist in JWKS)
        approver2_key_path: Path to second approver's private key PEM
        approver2_kid: Key ID for second approver (must exist in JWKS)
        jwks_path: Path to JWKS file containing both approver public keys
        tenant_id: Tenant identifier for audit trail
        reason: Human-readable reason for break-glass activation
        duration: Duration string (e.g., "4h", "90m") - capped at 4 hours

    Returns:
        Signed scope document with break_glass metadata and dual signatures

    Raises:
        BreakGlassError: If validation fails
    """

    ttl = _parse_duration(duration)
    if ttl > BREAK_GLASS_MAX:
        raise BreakGlassError(f"break-glass duration {duration} exceeds maximum of {BREAK_GLASS_MAX}")

    jwks_data = json.loads(Path(jwks_path).expanduser().read_text())
    jwks_keys = scope_signing.parse_jwks(jwks_data)
    if approver1_kid not in jwks_keys:
        raise BreakGlassError(f"approver1 kid {approver1_kid!r} not found in JWKS")
    if approver2_kid not in jwks_keys:
        raise BreakGlassError(f"approver2 kid {approver2_kid!r} not found in JWKS")
    if approver1_kid == approver2_kid:
        raise BreakGlassError("approver1 and approver2 must be different keys")

    approver1_key = scope_signing.load_private_key_file(Path(approver1_key_path).expanduser())
    approver2_key = scope_signing.load_private_key_file(Path(approver2_key_path).expanduser())

    now = datetime.now(UTC)
    expires_at = (now + ttl).isoformat(timespec="seconds")
    issued_at = now.isoformat(timespec="seconds")

    document = {k: v for k, v in scope_document.items() if k not in ("signatures", "signature")}

    metadata = dict(document.get("metadata") or {})
    metadata["break_glass"] = "true"
    metadata["break_glass_reason"] = reason
    metadata["break_glass_tenant"] = tenant_id
    metadata["break_glass_approvers"] = f"{approver1_kid},{approver2_kid}"
    metadata["break_glass_issued_at"] = issued_at
    metadata["break_glass_expires_at"] = expires_at

    document = {**document, "metadata": metadata, "expires_at": expires_at}

    sig1 = scope_signing.sign_document(document, approver1_key, approver1_kid, issued_at=issued_at)
    sig2 = scope_signing.sign_document(document, approver2_key, approver2_kid, issued_at=issued_at)

    signatures = [
        sig1["signature"],
        sig2["signature"],
    ]

    document_with_issued = {**document, "issued_at": issued_at}

    signed_document = {**document_with_issued, "signatures": signatures}

    for sig_block in signatures:
        _verify_approver_signature(signed_document, sig_block, jwks_data)

    _write_audit_entry(
        tenant_id=tenant_id,
        approvers=(approver1_kid, approver2_kid),
        reason=reason,
        scope_hash=_compute_scope_hash(document),
        expires_at=expires_at,
        issued_at=issued_at,
        duration=duration,
    )

    metrics.init_metrics()
    if m := metrics._metric("BREAK_GLASS_ACTIVATIONS"):
        m.labels(tenant=tenant_id, result=BREAK_GLASS_RESULT_SUCCESS).inc()

    log.info(
        "break-glass scope created for tenant %s by approvers %s, %s (expires %s)",
        tenant_id,
        approver1_kid,
        approver2_kid,
        expires_at,
    )

    return signed_document


def _write_audit_entry(
    *,
    tenant_id: str,
    approvers: tuple[str, str],
    reason: str,
    scope_hash: str,
    expires_at: str,
    issued_at: str,
    duration: str,
) -> None:
    """Write an immutable audit trail entry for break-glass activation."""
    from ishastra import audit

    entry = {
        "event": BREAK_GLASS_EVENT,
        "type": BREAK_GLASS_EVENT,
        "tenant": tenant_id,
        "approver1": approvers[0],
        "approver2": approvers[1],
        "reason": reason,
        "scope_hash": scope_hash,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "duration": duration,
        "timestamp": time.time(),
    }

    try:
        audit_log = audit.AuditLog(persistent=True)
        audit_log.record(entry)
    except Exception:
        log.exception("failed to write break-glass audit log entry")

    try:
        audit_chain = audit.AuditChain(persistent=True)
        audit_chain.append(entry)
    except Exception:
        log.exception("failed to write break-glass audit chain entry")


def verify_break_glass_scope(
    document: dict[str, Any],
    jwks: dict[str, Any] | str | Path,
    *,
    max_age: int | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify a break-glass scope document.

    Args:
        document: The signed scope document
        jwks: JWKS object or path for verification
        max_age: Maximum age in seconds for the issued_at timestamp

    Returns:
        Tuple of (is_valid, message, metadata_dict)
    """
    if not isinstance(document, dict):
        return False, "document must be a JSON object", None

    metadata = document.get("metadata", {})
    if metadata.get("break_glass") != "true":
        return False, "not a break-glass document", None

    signatures = document.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 2:
        return False, "break-glass document must have exactly 2 signatures", None

    expires_at = document.get("expires_at")
    if not expires_at:
        return False, "break-glass document missing expires_at", None

    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid expires_at format", None

    now = datetime.now(UTC)
    if now >= expires:
        return False, "break-glass scope has expired", None

    issued_at = metadata.get("break_glass_issued_at") or document.get("issued_at")
    if max_age is not None and issued_at:
        try:
            issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
            age = (now - issued).total_seconds()
            if age > max_age:
                return False, f"break-glass document is stale: {int(age)}s old, max {max_age}s", None
        except ValueError:
            pass

    if isinstance(jwks, (str, Path)):
        with open(Path(jwks).expanduser()) as f:
            jwks_data = json.load(f)
    else:
        jwks_data = jwks

    verified_kids = set()

    for sig_block in signatures:
        try:
            kid = _verify_approver_signature(document, sig_block, jwks_data)
            verified_kids.add(kid)
        except BreakGlassError as exc:
            return False, str(exc), None

    if len(verified_kids) != 2:
        return False, "both signatures must be from different approvers", None

    meta = {
        "tenant_id": metadata.get("break_glass_tenant"),
        "reason": metadata.get("break_glass_reason"),
        "approvers": metadata.get("break_glass_approvers", "").split(","),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "scope_hash": _compute_scope_hash(document),
    }

    return True, "valid", meta


def revoke_break_glass_scope(
    document: dict[str, Any],
    jwks: dict[str, Any] | str | Path,
    revoked_by: str,
    reason: str,
) -> dict[str, Any]:
    """Revoke a break-glass scope document by adding revocation metadata.

    Args:
        document: The signed break-glass scope document
        jwks: JWKS for verification
        revoked_by: Identity of party revoking
        reason: Reason for revocation

    Returns:
        Updated document with revocation metadata
    """

    valid, msg, meta = verify_break_glass_scope(document, jwks)
    if not valid:
        raise BreakGlassError(f"cannot revoke invalid break-glass document: {msg}")
    meta = meta or {}

    metadata = dict(document.get("metadata") or {})
    metadata["revoked"] = "true"
    metadata["revoked_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    metadata["revoked_by"] = revoked_by
    metadata["revocation_reason"] = reason

    document = {k: v for k, v in document.items() if k != "signatures"}
    document = {**document, "metadata": metadata, "revoked": True}

    _write_audit_entry(
        tenant_id=meta["tenant_id"] or "unknown",
        approvers=tuple(meta["approvers"]),
        reason=f"REVOKED: {reason}",
        scope_hash=meta["scope_hash"],
        expires_at=meta["expires_at"],
        issued_at=meta["issued_at"],
        duration="revoked",
    )

    return document
