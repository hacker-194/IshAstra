"""Signed, hash-pinned evidence bundles.

A bundle is a zip of the artifacts that justify a scan — the job result, the
findings as SARIF, the rendered HTML report, the audit chain entries and the
authorization document as it was loaded — plus a manifest that lists each
member's SHA-256 and size. The manifest is signed with
Ed25519 (the same key type the scope gate uses), so an auditor can verify
offline that the evidence they were handed is the evidence that was produced,
and that nobody widened the authorization afterwards.

Verification rejects: an unsigned manifest, an unknown or retired key, a
manifest edited after signing, a member whose bytes changed, a missing member,
and any member the manifest does not list.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ishastra.core.scope_signing import canonical_payload

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
ALGORITHM = "Ed25519"
VERSION = 1


class BundleError(ValueError):
    """The bundle is malformed, tampered with, or signed by an unknown key."""


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise BundleError("bundle signature must be a non-empty base64url string")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        raise BundleError("bundle signature is not valid base64url") from None


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")


def build_bundle(
    *,
    job: dict[str, Any],
    audit: list[dict[str, Any]],
    scope_document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    kid: str,
    created_at: str | None = None,
    sarif: dict[str, Any] | None = None,
    report_html: str | None = None,
) -> bytes:
    """Return a signed zip of ``job``, ``audit`` and ``scope_document``.

    ``sarif`` and ``report_html`` are included when supplied, so a verifier gets
    the same findings a reader would see without re-running the assessment.
    """
    if not isinstance(kid, str) or not kid.strip():
        raise BundleError("a key id (kid) is required to sign a bundle")
    files = {
        "job.json": _dump(job),
        "audit.json": _dump(audit),
        "scope.json": _dump(scope_document),
    }
    if sarif is not None:
        files["sarif.json"] = _dump(sarif)
    if report_html is not None:
        files["report.html"] = report_html.encode("utf-8")
    manifest: dict[str, Any] = {
        "version": VERSION,
        "created_at": created_at or datetime.now(UTC).isoformat(),
        "job_id": str(job.get("id") or ""),
        "files": {
            name: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)} for name, raw in files.items()
        },
    }
    signature = {
        "alg": ALGORITHM,
        "kid": kid.strip(),
        "sig": _b64url_encode(private_key.sign(canonical_payload(manifest))),
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
        archive.writestr(MANIFEST, _dump(manifest))
        archive.writestr(SIGNATURE, _dump(signature))
    return buffer.getvalue()


def verify_bundle(data: bytes, keys: dict[str, Ed25519PublicKey]) -> dict[str, Any]:
    """Verify a bundle and return its manifest, or raise :class:`BundleError`."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise BundleError("bundle is not a zip archive") from None

    with archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise BundleError("bundle contains duplicate entries")
        present = set(names)
        for required in (MANIFEST, SIGNATURE):
            if required not in present:
                raise BundleError(f"bundle is missing {required}")

        try:
            manifest = json.loads(archive.read(MANIFEST))
            signature = json.loads(archive.read(SIGNATURE))
        except json.JSONDecodeError:
            raise BundleError("bundle manifest is not valid JSON") from None
        if not isinstance(manifest, dict) or not isinstance(signature, dict):
            raise BundleError("bundle manifest and signature must be JSON objects")
        if manifest.get("version") != VERSION:
            raise BundleError(f"unsupported bundle version {manifest.get('version')!r}")

        if signature.get("alg") != ALGORITHM:
            raise BundleError(f"unsupported bundle signature algorithm {signature.get('alg')!r}")
        kid = signature.get("kid")
        if not isinstance(kid, str) or kid.strip() not in keys:
            raise BundleError(f"bundle signing key {kid!r} is not in the configured key set")
        try:
            keys[kid.strip()].verify(_b64url_decode(signature.get("sig")), canonical_payload(manifest))
        except InvalidSignature:
            raise BundleError("bundle manifest signature does not verify; it was modified") from None

        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise BundleError("bundle manifest lists no files")
        for name, meta in files.items():
            if name not in present:
                raise BundleError(f"bundle is missing {name}")
            if not isinstance(meta, dict):
                raise BundleError(f"bundle manifest entry {name!r} is malformed")
            raw = archive.read(name)
            if len(raw) != meta.get("size"):
                raise BundleError(f"{name} size does not match the manifest")
            if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
                raise BundleError(f"{name} does not match its manifest hash")

        unlisted = present - set(files) - {MANIFEST, SIGNATURE}
        if unlisted:
            raise BundleError(f"bundle contains unlisted entries: {', '.join(sorted(unlisted))}")

    return manifest
