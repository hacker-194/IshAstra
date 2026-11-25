"""Object storage abstraction for S3, GCS, and local filesystem.

Provides a unified interface for storing/retrieving large artifacts:
findings, reports, evidence packs, and scan results.

Integration points:
- evidence.py: store_evidence_pack, load_evidence_pack for monthly compliance packs
- assessments.py: store_report, store_findings for per-job artifacts
- scheduler.py: list_tenant_artifacts for evidence pack listing
- k8s_job_runner.py: store_scan_results for raw scan output

Data schemas:
- Evidence packs: dict with metadata, summary, by_framework, by_category, controls, findings
- Reports: HTML string and PDF bytes
- Findings: list of finding dicts (from Finding.to_dict())
- Scan results: raw adapter output dict

User instruction: "complete phase 4" (Object storage backend for findings/reports/evidence)
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import hashlib
import io
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, BinaryIO

from ishastra.config import Settings, get_settings

log = logging.getLogger(__name__)


@dataclass
class ObjectMetadata:
    """Metadata for a stored object."""

    key: str
    size: int
    content_type: str
    etag: str
    created_at: float
    metadata: dict[str, str]


class ObjectStore(abc.ABC):
    """Abstract base class for object storage backends."""

    @abc.abstractmethod
    async def put_object(
        self,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> ObjectMetadata:
        """Store an object. Returns metadata including ETag."""

    @abc.abstractmethod
    async def get_object(self, key: str) -> bytes:
        """Retrieve an object as bytes."""

    @abc.abstractmethod
    async def get_object_stream(self, key: str) -> BinaryIO:
        """Retrieve an object as a readable stream."""

    @abc.abstractmethod
    async def delete_object(self, key: str) -> None:
        """Delete an object."""

    @abc.abstractmethod
    async def list_objects(self, prefix: str) -> list[ObjectMetadata]:
        """List objects with the given prefix."""

    @abc.abstractmethod
    async def object_exists(self, key: str) -> bool:
        """Check if an object exists."""

    @abc.abstractmethod
    async def get_metadata(self, key: str) -> ObjectMetadata | None:
        """Get object metadata without downloading the object."""

    @abc.abstractmethod
    def get_public_url(self, key: str, expires_in: int = 3600) -> str | None:
        """Generate a pre-signed/public URL for an object (if supported)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Close any connections/clients."""


class LocalObjectStore(ObjectStore):
    """Local filesystem object store (for development/single-node)."""

    def __init__(self, base_path: str) -> None:
        self.base_path = os.path.abspath(base_path)
        os.makedirs(self.base_path, exist_ok=True)

    def _tenant_path(self, key: str) -> str:
        """Resolve tenant-scoped path. Keys are prefixed with tenant_id/.

        Refuses keys that resolve outside the tenant directory: object keys are
        a trust boundary, and ``../`` or an absolute path would otherwise read
        or write another tenant's files.
        """
        parts = key.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid key format (expected tenant_id/object_key): {key}")
        tenant_id, object_key = parts
        base = os.path.realpath(self.base_path)
        tenant_dir = os.path.realpath(os.path.join(base, tenant_id))
        path = os.path.realpath(os.path.join(tenant_dir, object_key))
        if (
            os.path.commonpath([base, tenant_dir]) != base
            or os.path.commonpath([tenant_dir, path]) != tenant_dir
        ):
            raise ValueError(f"Invalid key: path escapes the tenant directory: {key}")
        os.makedirs(tenant_dir, exist_ok=True)
        return path

    async def put_object(
        self,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> ObjectMetadata:
        path = self._tenant_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        content = data if isinstance(data, bytes) else data.read()

        tmp_path = path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(content)
        os.replace(tmp_path, path)

        stat = os.stat(path)
        etag = hashlib.sha256(content).hexdigest()[:32]

        return ObjectMetadata(
            key=key,
            size=stat.st_size,
            content_type=content_type,
            etag=etag,
            created_at=stat.st_mtime,
            metadata=metadata or {},
        )

    async def get_object(self, key: str) -> bytes:
        path = self._tenant_path(key)
        with open(path, "rb") as f:
            return f.read()

    async def get_object_stream(self, key: str) -> BinaryIO:
        path = self._tenant_path(key)
        return open(path, "rb")

    async def delete_object(self, key: str) -> None:
        path = self._tenant_path(key)
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)

    async def list_objects(self, prefix: str) -> list[ObjectMetadata]:
        results: list[ObjectMetadata] = []
        parts = prefix.split("/", 1)
        if len(parts) != 2:
            return results
        tenant_id, object_prefix = parts
        tenant_dir = os.path.join(self.base_path, tenant_id)
        if not os.path.isdir(tenant_dir):
            return results

        for root, _dirs, files in os.walk(tenant_dir):
            for fname in files:
                if fname.endswith(".tmp"):
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, tenant_dir)
                key = f"{tenant_id}/{rel}"
                if not key.startswith(prefix):
                    continue
                stat = os.stat(full)
                with open(full, "rb") as f:
                    etag = hashlib.sha256(f.read()).hexdigest()[:32]
                results.append(
                    ObjectMetadata(
                        key=key,
                        size=stat.st_size,
                        content_type="application/octet-stream",
                        etag=etag,
                        created_at=stat.st_mtime,
                        metadata={},
                    )
                )
        return results

    async def object_exists(self, key: str) -> bool:
        path = self._tenant_path(key)
        return os.path.isfile(path)

    async def get_metadata(self, key: str) -> ObjectMetadata | None:
        path = self._tenant_path(key)
        if not os.path.isfile(path):
            return None
        stat = os.stat(path)
        with open(path, "rb") as f:
            etag = hashlib.sha256(f.read()).hexdigest()[:32]
        return ObjectMetadata(
            key=key,
            size=stat.st_size,
            content_type="application/octet-stream",
            etag=etag,
            created_at=stat.st_mtime,
            metadata={},
        )

    def get_public_url(self, key: str, expires_in: int = 3600) -> str | None:
        return None

    async def close(self) -> None:
        pass


class S3ObjectStore(ObjectStore):
    """AWS S3 / S3-compatible object store (MinIO, Cloudflare R2, etc.)."""

    def __init__(
        self,
        bucket: str,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        prefix: str = "",
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.endpoint_url = endpoint_url
        self.prefix = prefix.rstrip("/")
        self._client = None
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key

    def _get_client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config

            session = boto3.session.Session(
                aws_access_key_id=self._access_key_id,
                aws_secret_access_key=self._secret_access_key,
                region_name=self.region,
            )
            self._client = session.client(
                "s3",
                endpoint_url=self.endpoint_url,
                config=Config(
                    s3={"addressing_style": "virtual" if not self.endpoint_url else "path"},
                    retries={"max_attempts": 3, "mode": "adaptive"},
                ),
            )
        return self._client

    def _full_key(self, key: str) -> str:
        if self.prefix:
            return f"{self.prefix}/{key}"
        return key

    async def put_object(
        self,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> ObjectMetadata:
        client = self._get_client()
        full_key = self._full_key(key)

        body = data if isinstance(data, bytes) else data.read()

        etag = hashlib.sha256(body if isinstance(body, bytes) else body.read()).hexdigest()[:32]

        await asyncio.to_thread(
            client.put_object,
            Bucket=self.bucket,
            Key=full_key,
            Body=body,
            ContentType=content_type,
            Metadata=metadata or {},
        )

        head = await asyncio.to_thread(client.head_object, Bucket=self.bucket, Key=full_key)

        return ObjectMetadata(
            key=key,
            size=head["ContentLength"],
            content_type=head.get("ContentType", content_type),
            etag=etag,
            created_at=head["LastModified"].timestamp(),
            metadata=head.get("Metadata", {}),
        )

    async def get_object(self, key: str) -> bytes:
        client = self._get_client()
        full_key = self._full_key(key)
        response = await asyncio.to_thread(client.get_object, Bucket=self.bucket, Key=full_key)
        return await asyncio.to_thread(response["Body"].read)

    async def get_object_stream(self, key: str) -> BinaryIO:
        client = self._get_client()
        full_key = self._full_key(key)
        response = await asyncio.to_thread(client.get_object, Bucket=self.bucket, Key=full_key)
        return response["Body"]

    async def delete_object(self, key: str) -> None:
        client = self._get_client()
        full_key = self._full_key(key)
        await asyncio.to_thread(client.delete_object, Bucket=self.bucket, Key=full_key)

    async def list_objects(self, prefix: str) -> list[ObjectMetadata]:
        client = self._get_client()
        full_prefix = self._full_key(prefix)
        results = []

        paginator = client.get_paginator("list_objects_v2")
        pages = await asyncio.to_thread(paginator.paginate, Bucket=self.bucket, Prefix=full_prefix)
        for page in pages:
            for obj in page.get("Contents", []):
                obj_key = obj["Key"]
                if self.prefix and obj_key.startswith(self.prefix + "/"):
                    key = obj_key[len(self.prefix) + 1 :]
                else:
                    key = obj_key
                results.append(
                    ObjectMetadata(
                        key=key,
                        size=obj["Size"],
                        content_type=obj.get("ContentType", "application/octet-stream"),
                        etag=obj["ETag"].strip('"'),
                        created_at=obj["LastModified"].timestamp(),
                        metadata={},
                    )
                )
        return results

    async def object_exists(self, key: str) -> bool:
        client = self._get_client()
        full_key = self._full_key(key)
        try:
            await asyncio.to_thread(client.head_object, Bucket=self.bucket, Key=full_key)
            return True
        except client.exceptions.NoSuchKey:
            return False
        except Exception:
            return False

    async def get_metadata(self, key: str) -> ObjectMetadata | None:
        client = self._get_client()
        full_key = self._full_key(key)
        try:
            head = await asyncio.to_thread(client.head_object, Bucket=self.bucket, Key=full_key)
            return ObjectMetadata(
                key=key,
                size=head["ContentLength"],
                content_type=head.get("ContentType", "application/octet-stream"),
                etag=head["ETag"].strip('"'),
                created_at=head["LastModified"].timestamp(),
                metadata=head.get("Metadata", {}),
            )
        except client.exceptions.NoSuchKey:
            return None
        except Exception:
            return None

    def get_public_url(self, key: str, expires_in: int = 3600) -> str | None:
        client = self._get_client()
        full_key = self._full_key(key)
        try:
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": full_key},
                ExpiresIn=expires_in,
            )
        except Exception as exc:
            log.warning("Failed to generate presigned URL: %s", exc)
            return None

    async def close(self) -> None:
        if self._client:
            await asyncio.to_thread(self._client.close)
            self._client = None


class GCSObjectStore(ObjectStore):
    """Google Cloud Storage object store."""

    def __init__(
        self,
        bucket: str,
        project: str | None = None,
        credentials_path: str | None = None,
        prefix: str = "",
    ) -> None:
        self.bucket_name = bucket
        self.project = project
        self.credentials_path = credentials_path
        self.prefix = prefix.rstrip("/")
        self._client: Any = None
        self._bucket: Any = None

    def _get_client(self):
        if self._client is None:
            from google.cloud import storage

            if self.credentials_path:
                self._client = storage.Client.from_service_account_json(
                    self.credentials_path, project=self.project
                )
            else:
                self._client = storage.Client(project=self.project)
            self._bucket = self._client.bucket(self.bucket_name)
        return self._client

    def _full_key(self, key: str) -> str:
        if self.prefix:
            return f"{self.prefix}/{key}"
        return key

    async def put_object(
        self,
        key: str,
        data: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> ObjectMetadata:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)

        content = data if isinstance(data, bytes) else data.read()

        await asyncio.to_thread(
            blob.upload_from_string,
            content,
            content_type=content_type,
        )

        if metadata:
            blob.metadata = metadata
            await asyncio.to_thread(blob.patch)

        await asyncio.to_thread(blob.reload)

        etag = blob.md5_hash or hashlib.sha256(content).hexdigest()[:32]

        return ObjectMetadata(
            key=key,
            size=blob.size or len(content),
            content_type=blob.content_type or content_type,
            etag=etag,
            created_at=blob.time_created.timestamp() if blob.time_created else time.time(),
            metadata=blob.metadata or {},
        )

    async def get_object(self, key: str) -> bytes:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        return await asyncio.to_thread(blob.download_as_bytes)

    async def get_object_stream(self, key: str) -> BinaryIO:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        content = await asyncio.to_thread(blob.download_as_bytes)
        return io.BytesIO(content)

    async def delete_object(self, key: str) -> None:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        await asyncio.to_thread(blob.delete)

    async def list_objects(self, prefix: str) -> list[ObjectMetadata]:
        self._get_client()
        full_prefix = self._full_key(prefix)
        results: list[ObjectMetadata] = []

        blobs = await asyncio.to_thread(self._client.list_blobs, self._bucket, prefix=full_prefix)

        for blob in blobs:
            obj_key = blob.name
            if self.prefix and obj_key.startswith(self.prefix + "/"):
                key = obj_key[len(self.prefix) + 1 :]
            else:
                key = obj_key
            results.append(
                ObjectMetadata(
                    key=key,
                    size=blob.size or 0,
                    content_type=blob.content_type or "application/octet-stream",
                    etag=blob.md5_hash or "",
                    created_at=blob.time_created.timestamp() if blob.time_created else time.time(),
                    metadata=blob.metadata or {},
                )
            )
        return results

    async def object_exists(self, key: str) -> bool:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        return await asyncio.to_thread(blob.exists)

    async def get_metadata(self, key: str) -> ObjectMetadata | None:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        try:
            await asyncio.to_thread(blob.reload)
        except Exception:
            return None
        return ObjectMetadata(
            key=key,
            size=blob.size or 0,
            content_type=blob.content_type or "application/octet-stream",
            etag=blob.md5_hash or "",
            created_at=blob.time_created.timestamp() if blob.time_created else time.time(),
            metadata=blob.metadata or {},
        )

    def get_public_url(self, key: str, expires_in: int = 3600) -> str | None:
        self._get_client()
        full_key = self._full_key(key)
        blob = self._bucket.blob(full_key)
        try:
            return blob.generate_signed_url(
                expiration=expires_in,
                method="GET",
            )
        except Exception as exc:
            log.warning("Failed to generate signed URL: %s", exc)
            return None

    async def close(self) -> None:
        if self._client:
            self._client = None
            self._bucket = None


def create_object_store(settings: Settings | None = None) -> ObjectStore:
    """Factory function to create the configured object store."""
    settings = settings or get_settings()
    store_type = settings.object_store

    if store_type == "s3":
        bucket = settings.s3_bucket
        if not bucket:
            raise ValueError("ISHASTRA_S3_BUCKET must be set for S3 object store")
        return S3ObjectStore(
            bucket=bucket,
            region=settings.s3_region,
            endpoint_url=settings.s3_endpoint or None,
            access_key_id=settings.s3_access_key or None,
            secret_access_key=settings.s3_secret_key or None,
            prefix=settings.object_store_prefix,
        )
    if store_type == "gcs":
        bucket = settings.gcs_bucket
        if not bucket:
            raise ValueError("ISHASTRA_GCS_BUCKET must be set for GCS object store")
        return GCSObjectStore(
            bucket=bucket,
            project=settings.gcs_project_id or None,
            credentials_path=settings.gcs_credentials_file or None,
            prefix=settings.object_store_prefix,
        )
    if store_type == "local":
        base_path = settings.object_store_local_root
        return LocalObjectStore(base_path)
    raise ValueError(f"Unknown object store type: {store_type}")


EVIDENCE_PACK_PREFIX = "evidence-packs"
REPORT_PREFIX = "reports"
FINDINGS_PREFIX = "findings"
SCAN_RESULTS_PREFIX = "scan-results"


def _tenant_key(tenant_id: str, prefix: str, name: str) -> str:
    """Generate a tenant-scoped object key."""
    return f"{tenant_id}/{prefix}/{name}"


async def store_evidence_pack(
    store: ObjectStore,
    tenant_id: str,
    pack_id: str,
    pack_data: dict[str, Any],
) -> ObjectMetadata:
    """Store an evidence pack as JSON."""
    key = _tenant_key(tenant_id, EVIDENCE_PACK_PREFIX, f"{pack_id}.json")
    data = json.dumps(pack_data, indent=2).encode()
    return await store.put_object(
        key,
        data,
        content_type="application/json",
        metadata={"pack_id": pack_id, "tenant_id": tenant_id},
    )


async def load_evidence_pack(
    store: ObjectStore,
    tenant_id: str,
    pack_id: str,
) -> dict[str, Any] | None:
    """Load an evidence pack from object storage."""
    key = _tenant_key(tenant_id, EVIDENCE_PACK_PREFIX, f"{pack_id}.json")
    if not await store.object_exists(key):
        return None
    data = await store.get_object(key)
    return json.loads(data)


async def store_report(
    store: ObjectStore,
    tenant_id: str,
    job_id: str,
    report_html: str,
    report_pdf: bytes | None = None,
) -> dict[str, ObjectMetadata]:
    """Store HTML and optionally PDF report."""
    results = {}
    html_key = _tenant_key(tenant_id, REPORT_PREFIX, f"{job_id}.html")
    results["html"] = await store.put_object(
        html_key,
        report_html.encode(),
        content_type="text/html",
        metadata={"job_id": job_id, "tenant_id": tenant_id},
    )
    if report_pdf:
        pdf_key = _tenant_key(tenant_id, REPORT_PREFIX, f"{job_id}.pdf")
        results["pdf"] = await store.put_object(
            pdf_key,
            report_pdf,
            content_type="application/pdf",
            metadata={"job_id": job_id, "tenant_id": tenant_id},
        )
    return results


async def store_findings(
    store: ObjectStore,
    tenant_id: str,
    job_id: str,
    findings: list[dict[str, Any]],
) -> ObjectMetadata:
    """Store findings as JSON."""
    key = _tenant_key(tenant_id, FINDINGS_PREFIX, f"{job_id}.json")
    data = json.dumps(findings, indent=2).encode()
    return await store.put_object(
        key,
        data,
        content_type="application/json",
        metadata={"job_id": job_id, "tenant_id": tenant_id, "count": str(len(findings))},
    )


async def store_scan_results(
    store: ObjectStore,
    tenant_id: str,
    job_id: str,
    results: dict[str, Any],
) -> ObjectMetadata:
    """Store raw scan results."""
    key = _tenant_key(tenant_id, SCAN_RESULTS_PREFIX, f"{job_id}.json")
    data = json.dumps(results, indent=2).encode()
    return await store.put_object(
        key,
        data,
        content_type="application/json",
        metadata={"job_id": job_id, "tenant_id": tenant_id},
    )


async def list_tenant_artifacts(
    store: ObjectStore,
    tenant_id: str,
    prefix: str,
) -> list[ObjectMetadata]:
    """List all artifacts for a tenant under a prefix."""
    return await store.list_objects(f"{tenant_id}/{prefix}")


_object_store: ObjectStore | None = None


def get_object_store() -> ObjectStore:
    """Get the global object store instance."""
    global _object_store
    if _object_store is None:
        _object_store = create_object_store()
    return _object_store


def set_object_store(store: ObjectStore) -> None:
    """Set the global object store instance (for testing)."""
    global _object_store
    _object_store = store


async def close_object_store() -> None:
    """Close the global object store."""
    global _object_store
    if _object_store:
        await _object_store.close()
        _object_store = None
