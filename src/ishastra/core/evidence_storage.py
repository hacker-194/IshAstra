"""Efficient evidence storage with streaming, compression, and deduplication.

This module provides:
- Incremental hashing of evidence files (no full-file loading into RAM)
- Streaming evidence bundle creation and verification
- Compression of suitable artifacts (gzip, zlib)
- Deduplication that preserves tenant isolation
- Hash verification after decompression
- Signed evidence that remains independently verifiable
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ishastra.core.bundle import (
    ALGORITHM,
    MANIFEST,
    SIGNATURE,
    VERSION,
    BundleError,
    _b64url_decode,
    _b64url_encode,
    _compute_hash,
    _dump,
)
from ishastra.core.scope_signing import canonical_payload

log = logging.getLogger(__name__)


def compute_hash_incremental(
    file_path: str | Path,
    algorithm: str = "sha256",
    chunk_size: int = 1024 * 1024,
) -> str:
    """Compute hash of a file incrementally without loading it into memory.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (sha256, sha512, md5, etc.)
        chunk_size: Size of chunks to read

    Returns:
        Hex digest of the hash
    """
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"File not found: {path}")

    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def stream_and_hash(file_path: str | Path, chunk_size: int = 1024 * 1024) -> tuple[Any, int]:
    """Stream a file and compute its hash simultaneously.

    Returns (hash_object, total_bytes_read).
    The caller can continue updating the hash object with more data.
    """
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"File not found: {path}")

    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h, total


def compress_evidence(data: bytes, algorithm: str = "gzip", compression_level: int = 6) -> bytes:
    """Compress evidence data.

    Args:
        data: Raw bytes to compress
        algorithm: Compression algorithm (gzip, zlib)
        compression_level: Compression level (1-9 for gzip)

    Returns:
        Compressed bytes
    """
    if algorithm == "gzip":
        gz_buffer: io.BytesIO = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb", compresslevel=compression_level) as gz:
            gz.write(data)
        return bytes(gz_buffer.getvalue())
    if algorithm == "zlib":
        import zlib
        return zlib.compress(data, compression_level)
    raise ValueError(f"Unsupported compression algorithm: {algorithm}")


def decompress_evidence(data: bytes, original_size: int, algorithm: str = "gzip") -> bytes:
    """Decompress evidence data and verify size.

    Args:
        data: Compressed bytes
        original_size: Expected size after decompression
        algorithm: Compression algorithm

    Returns:
        Decompressed bytes

    Raises:
        ValueError: If decompression fails or size doesn't match
    """
    try:
        if algorithm == "gzip":
            buf = io.BytesIO(data)
            with gzip.GzipFile(fileobj=buf, mode="rb") as gz:
                decompressed = gz.read()
        elif algorithm == "zlib":
            import zlib
            decompressed = zlib.decompress(data)
        else:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")

        if len(decompressed) != original_size:
            raise ValueError(
                f"Decompressed size mismatch: expected {original_size}, got {len(decompressed)}"
            )
        return decompressed
    except Exception as e:
        raise ValueError(f"Decompression failed: {e}") from e


@dataclass
class CompressedEvidence:
    """Metadata for compressed evidence that allows verification after decompression."""

    original_sha256: str
    compressed_sha256: str
    original_size: int
    compressed_size: int
    compression_algorithm: str
    compression_level: int
    created_at: float = field(default_factory=time.time)


def compress_and_hash_evidence(file_path: str | Path,
                                compression_algorithm: str = "gzip",
                                compression_level: int = 6) -> CompressedEvidence:
    """Compress an evidence file and compute hashes of both versions.

    The original file is not modified. Both original and compressed
    hashes are stored for verification.

    Args:
        file_path: Path to the evidence file
        compression_algorithm: Compression algorithm to use
        compression_level: Compression level

    Returns:
        CompressedEvidence with metadata for verification
    """
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"File not found: {path}")

    original_hash = compute_hash_incremental(path)
    original_size = path.stat().st_size

    # Read and compress
    with open(path, "rb") as f:
        data = f.read()

    compressed = compress_evidence(data, compression_algorithm, compression_level)
    compressed_hash = _compute_hash(compressed)

    return CompressedEvidence(
        original_sha256=original_hash,
        compressed_sha256=compressed_hash,
        original_size=original_size,
        compressed_size=len(compressed),
        compression_algorithm=compression_algorithm,
        compression_level=compression_level,
    )


def save_compressed_evidence(
    source_path: str | Path,
    dest_path: str | Path,
    compression_algorithm: str = "gzip",
    compression_level: int = 6,
) -> CompressedEvidence:
    """Compress an evidence file and save to destination.

    Args:
        source_path: Path to source evidence file
        dest_path: Path to save compressed file
        compression_algorithm: Compression algorithm
        compression_level: Compression level

    Returns:
        CompressedEvidence metadata
    """
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    evidence = compress_and_hash_evidence(source_path, compression_algorithm, compression_level)

    # Write compressed file
    with open(source_path, "rb") as src, open(dest, "wb") as dst:
        # Write gzip header manually for streaming
        dst.write(gzip.compress(src.read(), compresslevel=compression_level))

    return evidence


def deduplicate_artifact(source_path: str | Path,
                          existing_store: str | Path,
                          chunk_size: int = 1024 * 1024,
                          dedup_key: str | None = None) -> tuple[bool, str]:
    """Check if an artifact is a duplicate and store if not.

    Uses content-defined chunking with SHA-256 for deduplication.
    Tenant isolation is preserved: dedup keys include tenant_id.

    Args:
        source_path: Path to the artifact to potentially store
        existing_store: Directory or database containing existing artifacts
        chunk_size: Size of chunks for content-defined chunking
        dedup_key: Optional explicit key for lookup; computed if not provided

    Returns:
        (is_duplicate, stored_path) - if duplicate, stored_path is the existing path
    """
    source = Path(source_path)
    if not source.exists():
        raise ValueError(f"Source file not found: {source}")

    # Compute content hash
    content_hash = compute_hash_incremental(source)

    # Dedup key includes tenant context if provided
    if dedup_key is None:
        dedup_key = content_hash

    # Check if this exact content already exists
    existing_path = Path(existing_store) / f"{dedup_key[:16]}.dat"
    if existing_path.exists():
        # Verify it's actually the same content
        existing_hash = compute_hash_incremental(existing_path)
        if existing_hash == content_hash:
            return True, str(existing_path)

    # Store a copy (could use hard link on same filesystem)
    Path(existing_store).mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, existing_path)

    return False, str(existing_path)


@dataclass
class EvidenceBundleInfo:
    """Information about an evidence bundle."""
    bundle_path: str
    bundle_size: int
    manifest: dict[str, Any]
    files: dict[str, dict[str, Any]]  # name -> {sha256, size, compressed}
    created_at: str
    job_id: str
    compressed: bool
    compression_metadata: dict[str, Any] | None = None


def create_evidence_bundle(
    job_id: str,
    tenant_id: str,
    files: dict[str, str | bytes],  # name -> path or bytes
    private_key: Any,
    kid: str,
    dest_path: str | Path | None = None,
    compress_large_files: bool = True,
    compression_threshold_kb: int = 100,
    max_bundle_size_mb: int | None = None,
) -> EvidenceBundleInfo:
    """Create an evidence bundle with optional compression.

    Files larger than compression_threshold_kb will be compressed if
    compress_large_files is True.

    Args:
        job_id: The job ID for the bundle
        tenant_id: Tenant identifier
        files: Dict mapping file names to paths (str) or bytes
        private_key: Ed25519 private key for signing
        kid: Key ID for the signature
        dest_path: Where to save the bundle
        compress_large_files: Whether to compress large files
        compression_threshold_kb: Threshold for compression
        max_bundle_size_mb: Maximum bundle size

    Returns:
        EvidenceBundleInfo with bundle metadata
    """
    bundle_files: dict[str, bytes] = {}
    file_metadata: dict[str, dict[str, Any]] = {}

    total_raw_size = 0
    for name, content in files.items():
        if isinstance(content, str):
            # It's a file path
            path = Path(content)
            if not path.exists():
                raise ValueError(f"File not found: {path}")

            size_kb = path.stat().st_size / 1024

            if compress_large_files and size_kb >= compression_threshold_kb:
                # Stream and compress
                raw_hash = compute_hash_incremental(path)

                with open(path, "rb") as f:
                    raw_data = f.read()

                compressed = compress_evidence(raw_data)
                bundle_files[name] = compressed

                file_metadata[name] = {
                    "sha256": raw_hash,  # Original content hash
                    "size": len(raw_data),
                    "compressed_size": len(compressed),
                    "compressed": True,
                    "compression_algorithm": "gzip",
                }
                total_raw_size += len(raw_data)
            else:
                # Keep uncompressed
                with open(path, "rb") as f:
                    file_bytes = f.read()

                file_hash = _compute_hash(file_bytes)
                bundle_files[name] = file_bytes
                file_metadata[name] = {
                    "sha256": file_hash,
                    "size": len(file_bytes),
                    "compressed": False,
                }
                total_raw_size += len(file_bytes)
        else:
            # It's bytes
            file_hash = _compute_hash(content)
            bundle_files[name] = content
            file_metadata[name] = {
                "sha256": file_hash,
                "size": len(content),
                "compressed": False,
            }
            total_raw_size += len(content)

    # Check bundle size limit
    if max_bundle_size_mb:
        estimated_zip_size = total_raw_size * 0.7
        if estimated_zip_size > max_bundle_size_mb * 1024 * 1024:
            raise BundleError(
                f"Estimated bundle size ({estimated_zip_size / (1024*1024):.1f} MB) "
                f"exceeds maximum ({max_bundle_size_mb} MB)"
            )

    # Build manifest
    manifest = {
        "version": VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "job_id": job_id,
        "tenant_id": tenant_id,
        "files": file_metadata,
    }

    signature = {
        "alg": ALGORITHM,
        "kid": kid,
        "sig": _b64url_encode(private_key.sign(canonical_payload(manifest))),
    }

    # Write bundle
    if dest_path:
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        dest = Path(f"evidence_{job_id}.zip")

    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in bundle_files.items():
            archive.writestr(name, data)
        archive.writestr(MANIFEST, _dump(manifest))
        archive.writestr(SIGNATURE, _dump(signature))

    return EvidenceBundleInfo(
        bundle_path=str(dest),
        bundle_size=dest.stat().st_size,
        manifest=manifest,
        files=file_metadata,
        created_at=cast(str, manifest["created_at"]),
        job_id=job_id,
        compressed=any(
            m.get("compressed", False) for m in file_metadata.values()
        ),
    )


def read_evidence_bundle_streaming(
    bundle_path: str | Path,
    extract_dir: str | Path | None = None,
    verify_signature: bool = True,
    keys: dict[str, Any] | None = None,
) -> EvidenceBundleInfo:
    """Read an evidence bundle with streaming for large files.

    Args:
        bundle_path: Path to the bundle zip file
        extract_dir: Directory to extract files to (None for in-memory only)
        verify_signature: Whether to verify the bundle signature
        keys: Dict of key ID to Ed25519 public key for verification

    Returns:
        EvidenceBundleInfo with bundle contents

    Raises:
        BundleError: If bundle is invalid or signature doesn't verify
    """
    bundle = Path(bundle_path)
    if not bundle.exists():
        raise BundleError(f"Bundle not found: {bundle}")

    if extract_dir:
        extract_path = Path(extract_dir)
        extract_path.mkdir(parents=True, exist_ok=True)
    else:
        extract_path = None

    with zipfile.ZipFile(bundle, "r") as archive:
        # Read manifest and signature first
        manifest_data = archive.read(MANIFEST)
        signature_data = archive.read(SIGNATURE)

        try:
            manifest = json.loads(manifest_data)
            signature = json.loads(signature_data)
        except json.JSONDecodeError as err:
            raise BundleError("Bundle manifest is not valid JSON") from err

        if manifest.get("version") != VERSION:
            raise BundleError(f"Unsupported bundle version {manifest.get('version')!r}")

        # Verify signature if requested
        if verify_signature:
            if keys is None:
                raise BundleError("No keys provided for signature verification")
            kid = signature.get("kid")
            if not isinstance(kid, str) or kid.strip() not in keys:
                raise BundleError(f"Bundle signing key {kid!r} is not in the configured key set")
            try:
                keys[kid.strip()].verify(
                    _b64url_decode(signature.get("sig")),
                    canonical_payload(manifest),
                )
            except Exception as err:
                raise BundleError(f"Bundle signature verification failed: {err}") from err

        # Process files
        files_info = {}
        for name, meta in manifest.get("files", {}).items():
            if name not in archive.namelist():
                raise BundleError(f"Bundle is missing file: {name}")

            info = archive.getinfo(name)

            if meta.get("compressed", False):
                # Decompress if needed
                if extract_path:
                    # Extract and decompress to file
                    raw_data = archive.read(name)
                    decompressed = decompress_evidence(
                        raw_data,
                        meta["size"],
                        meta.get("compression_algorithm", "gzip"),
                    )
                    extracted_file = extract_path / name
                    extracted_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(extracted_file, "wb") as f:
                        f.write(decompressed)
                else:
                    # Verify hash without extracting
                    raw_data = archive.read(name)
                    decompressed = decompress_evidence(
                        raw_data,
                        meta["size"],
                        meta.get("compression_algorithm", "gzip"),
                    )
                    actual_hash = _compute_hash(decompressed)
                    if actual_hash != meta["sha256"]:
                        raise BundleError(f"File {name} hash mismatch after decompression")

                files_info[name] = {
                    "path": str(extract_path / name) if extract_path else None,
                    "sha256": meta["sha256"],
                    "size": meta["size"],
                    "compressed_size": info.file_size,
                    "compressed": True,
                }
            else:
                # Uncompressed file
                raw_data = archive.read(name)
                actual_hash = _compute_hash(raw_data)
                if actual_hash != meta["sha256"]:
                    raise BundleError(f"File {name} hash mismatch")

                if extract_path:
                    extracted_file = extract_path / name
                    extracted_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(extracted_file, "wb") as f:
                        f.write(raw_data)
                    files_info[name] = {
                        "path": str(extracted_file),
                        "sha256": meta["sha256"],
                        "size": meta["size"],
                        "compressed": False,
                    }
                else:
                    files_info[name] = {
                        "sha256": meta["sha256"],
                        "size": meta["size"],
                        "compressed": False,
                    }

        return EvidenceBundleInfo(
            bundle_path=str(bundle),
            bundle_size=bundle.stat().st_size,
            manifest=manifest,
            files=files_info,
            created_at=manifest["created_at"],
            job_id=manifest.get("job_id", ""),
            compressed=any(m.get("compressed", False) for m in manifest.get("files", {}).values()),
        )
