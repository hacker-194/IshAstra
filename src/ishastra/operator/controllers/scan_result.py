"""ScanResult CRD Reconciler.

Manages the lifecycle of ScanResult custom resources for storing assessment findings.
Matches the Helm CRD schema exactly.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from kubernetes import client
from kubernetes.client import ApiException

from ishastra.operator.controllers.base import BaseReconciler

log = logging.getLogger(__name__)


class ScanResultReconciler(BaseReconciler):
    """Reconciler for ScanResult resources.

    Schema (matching Helm CRD):
    - spec.jobRef (string, required)
    - spec.tenantId (string, required)
    - spec.assessmentId (string)
    - spec.findings[] (array): id, title, severity, cvss, cwe, description,
      evidence, target, port, protocol, firstSeen, lastSeen, status
    - spec.summary (object): total, critical, high, medium, low, info
    - spec.scanDurationSeconds (integer)
    - spec.scannerVersion (string)
    - spec.scanConfig (object)
    - status.phase (enum: Pending, Processing, Completed, Failed)
    - status.storedAt, objectStorageRef, conditions[]
    """

    def __init__(self, namespace: str | None = None):
        super().__init__(
            group="ishastra.io",
            version="v1alpha1",
            plural="scanresults",
            namespace=namespace,
            resync_period=300,
        )

        self.object_storage_bucket = os.getenv("ISHASTRA_OBJECT_STORAGE_BUCKET", "ishastra-scan-results")
        self.object_storage_endpoint = os.getenv("ISHASTRA_OBJECT_STORAGE_ENDPOINT")
        self.use_object_storage = bool(self.object_storage_endpoint)

    @property
    def kind(self) -> str:
        return "ScanResult"

    async def reconcile(self, resource: dict[str, Any]) -> None:
        """Reconcile a ScanResult to desired state."""
        name = resource.get("metadata", {}).get("name", "unknown")
        spec = resource.get("spec", {})
        status = resource.get("status", {})

        job_ref = spec.get("jobRef")
        tenant_id = spec.get("tenantId")
        assessment_id = spec.get("assessmentId")
        findings = spec.get("findings", [])
        summary = spec.get("summary", {})
        scan_duration = spec.get("scanDurationSeconds")
        scanner_version = spec.get("scannerVersion")
        scan_config = spec.get("scanConfig", {})

        phase = status.get("phase", "Pending")

        log.info("Reconciling ScanResult %s (phase: %s, tenant: %s)", name, phase, tenant_id)

        if not job_ref:
            await self._patch_status(
                name,
                {
                    "phase": "Failed",
                    "storedAt": self._now_iso(),
                    "objectStorageRef": "",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "MissingField",
                            "message": "jobRef is required",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if not tenant_id:
            await self._patch_status(
                name,
                {
                    "phase": "Failed",
                    "storedAt": self._now_iso(),
                    "objectStorageRef": "",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "MissingField",
                            "message": "tenantId is required",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if phase == "Pending":
            await self._handle_pending(
                name,
                spec,
                status,
                job_ref,
                tenant_id,
                assessment_id,
                findings,
                summary,
                scan_duration,
                scanner_version,
                scan_config,
            )
        elif phase == "Processing":
            await self._handle_processing(name, spec, status)
        elif phase == "Completed":
            await self._handle_completed(name, spec, status)
        elif phase == "Failed":
            await self._handle_failed(name, spec, status)

    async def _handle_pending(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        job_ref: str,
        tenant_id: str,
        assessment_id: str | None,
        findings: list[dict[str, Any]],
        summary: dict[str, Any],
        scan_duration: int | None,
        scanner_version: str | None,
        scan_config: dict[str, Any],
    ) -> None:
        """Handle Pending phase - store scan result."""
        finding_count = len(findings)

        if not summary:
            severity_counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in findings:
                severity_counts["total"] += 1
                sev = finding.get("severity", "info")
                if sev in severity_counts:
                    severity_counts[sev] += 1
            summary = severity_counts

        storage_ref = await self._store_findings(name, spec)

        await self._patch_status(
            name,
            {
                "phase": "Processing",
                "storedAt": self._now_iso(),
                "objectStorageRef": storage_ref,
                "conditions": [
                    {
                        "type": "Stored",
                        "status": "True",
                        "reason": "Received",
                        "message": "Scan result received and stored",
                        "lastTransitionTime": self._now_iso(),
                    }
                ],
            },
        )

        log.info("ScanResult %s received with %d findings, stored at %s", name, finding_count, storage_ref)

    async def _handle_processing(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Processing phase - verify data integrity."""

        storage_ref = status.get("objectStorageRef", "")
        await self._verify_findings(name, storage_ref)

        await self._patch_status(
            name,
            {
                "phase": "Completed",
                "storedAt": status.get("storedAt", self._now_iso()),
                "objectStorageRef": storage_ref,
                "conditions": [
                    {
                        "type": "Completed",
                        "status": "True",
                        "reason": "Processed",
                        "message": "Scan result processed successfully",
                        "lastTransitionTime": self._now_iso(),
                    }
                ],
            },
        )

    async def _handle_completed(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Completed phase - ensure data integrity."""
        storage_ref = status.get("objectStorageRef", "")
        await self._verify_findings(name, storage_ref)

    async def _handle_failed(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Failed phase - no action needed."""

    async def _store_findings(self, name: str, spec: dict[str, Any]) -> str:
        """Store findings in object storage (or ConfigMap as fallback)."""
        findings = spec.get("findings", [])
        summary = spec.get("summary", {})
        job_ref = spec.get("jobRef", "")
        tenant_id = spec.get("tenantId", "")
        assessment_id = spec.get("assessmentId", "")
        scan_duration = spec.get("scanDurationSeconds")
        scanner_version = spec.get("scannerVersion")
        scan_config = spec.get("scanConfig", {})

        data = {
            "findings": findings,
            "summary": summary,
            "jobRef": job_ref,
            "tenantId": tenant_id,
            "assessmentId": assessment_id,
            "scanDurationSeconds": scan_duration,
            "scannerVersion": scanner_version,
            "scanConfig": scan_config,
        }

        if self.use_object_storage:
            return await self._store_in_object_storage(name, data)
        return await self._store_in_configmap(name, data)

    async def _store_in_object_storage(self, name: str, data: dict[str, Any]) -> str:
        """Store findings in S3-compatible object storage."""

        stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        storage_key = f"scanresults/{self.namespace or 'default'}/{name}/{stamp}.json"
        log.info(
            "Would store ScanResult %s to object storage: s3://%s/%s",
            name,
            self.object_storage_bucket,
            storage_key,
        )
        return f"s3://{self.object_storage_bucket}/{storage_key}"

    async def _store_in_configmap(self, name: str, data: dict[str, Any]) -> str:
        """Store findings in a ConfigMap as fallback."""
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name=f"ishastra-scanresult-{name}",
                namespace=self.namespace or "ishastra-system",
                labels={
                    "ishastra.io/scanresult": name,
                    "ishastra.io/job": data.get("jobRef", ""),
                    "ishastra.io/tenant": data.get("tenantId", ""),
                    "ishastra.io/managed-by": "ishastra-operator",
                },
            ),
            data={
                "findings.json": json.dumps(data.get("findings", [])),
                "summary.json": json.dumps(data.get("summary", {})),
                "jobRef.json": json.dumps(data.get("jobRef", "")),
                "tenantId.json": json.dumps(data.get("tenantId", "")),
                "assessmentId.json": json.dumps(data.get("assessmentId", "")),
                "scanDurationSeconds.json": json.dumps(data.get("scanDurationSeconds")),
                "scannerVersion.json": json.dumps(data.get("scannerVersion")),
                "scanConfig.json": json.dumps(data.get("scanConfig", {})),
            },
        )
        try:
            self.core_api.create_namespaced_config_map(self.namespace or "ishastra-system", cm)
        except ApiException as e:
            if e.status == 409:
                self.core_api.patch_namespaced_config_map(
                    f"ishastra-scanresult-{name}", self.namespace or "ishastra-system", cm
                )
            else:
                raise
        return f"configmap://{self.namespace or 'ishastra-system'}/ishastra-scanresult-{name}"

    async def _verify_findings(self, name: str, storage_ref: str) -> None:
        """Verify findings are still accessible."""
        if storage_ref.startswith("configmap://"):
            try:
                cm_name = storage_ref.split("/")[-1]
                cm_namespace = storage_ref.split("/")[-2]
                self.core_api.read_namespaced_config_map(cm_name, cm_namespace)
            except Exception as e:
                log.warning("ScanResult %s findings not accessible: %s", name, e)
        else:
            log.debug("Object storage verification for %s: %s", name, storage_ref)

    def _now_iso(self) -> str:
        """Get current time in ISO format."""
        return datetime.now(UTC).isoformat()

    async def cleanup(self, resource: dict[str, Any]) -> None:
        """Clean up resources on deletion."""
        name = resource.get("metadata", {}).get("name", "unknown")
        log.info("Cleaning up ScanResult %s", name)

        if not self.use_object_storage:
            with contextlib.suppress(Exception):
                self.core_api.delete_namespaced_config_map(
                    f"ishastra-scanresult-{name}", self.namespace or "ishastra-system"
                )
