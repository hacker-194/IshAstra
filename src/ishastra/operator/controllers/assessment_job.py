"""AssessmentJob CRD Reconciler.

Manages the lifecycle of AssessmentJob custom resources.
Matches the Helm CRD schema exactly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from kubernetes import client
from kubernetes.client import ApiException

from ishastra.operator.controllers.base import BaseReconciler

log = logging.getLogger(__name__)


VALID_PRIORITIES = {"low", "normal", "high", "critical"}
VALID_PHASES = {"Pending", "Queued", "Running", "Succeeded", "Failed", "Cancelled"}
VALID_CONDITION_STATUSES = {"True", "False", "Unknown"}


REQUIRED_SCOPE_FIELDS = {"program", "authorized_by", "authorization_ref"}


class AssessmentJobReconciler(BaseReconciler):
    """Reconciler for AssessmentJob resources.

    Schema (matching Helm CRD exactly):
    - spec.tenantId (string, required)
    - spec.scope (object, required): program, authorized_by, authorization_ref, include[], exclude[],
      authorized_networks[], allowed_ports[], allow_broad_networks, auth{}
    - spec.policyRef (string, required)
    - spec.priority (enum: low, normal, high, critical, default: normal)
    - spec.scheduleAt (date-time string, RFC3339)
    - spec.ttlSecondsAfterFinished (integer, default: 3600)
    - spec.resources (limits/requests cpu/memory)
    - spec.nodeSelector, tolerations, affinity, env
    - status.phase (enum: Pending, Queued, Running, Succeeded, Failed, Cancelled)
    - status.jobId, podName, startTime, completionTime, message, conditions[], findingsSummary{}
    """

    def __init__(self, namespace: str | None = None):
        super().__init__(
            group="ishastra.io",
            version="v1alpha1",
            plural="assessmentjobs",
            namespace=namespace,
            resync_period=30,
        )

    @property
    def kind(self) -> str:
        return "AssessmentJob"

    async def reconcile(self, resource: dict[str, Any]) -> None:
        """Reconcile an AssessmentJob to desired state."""
        name = resource.get("metadata", {}).get("name", "unknown")
        spec = resource.get("spec", {})
        status = resource.get("status", {})

        tenant_id = spec.get("tenantId")
        scope = spec.get("scope", {})
        policy_ref = spec.get("policyRef")
        priority = spec.get("priority", "normal")
        schedule_at = spec.get("scheduleAt")

        phase = status.get("phase", "Pending")

        log.info("Reconciling AssessmentJob %s (phase: %s, tenant: %s)", name, phase, tenant_id)

        if not tenant_id:
            await self._patch_status(
                name,
                self._failed_status(
                    "spec.tenantId is required", "ValidationFailed", "MissingField", "tenantId is required"
                ),
            )
            return

        if not scope:
            await self._patch_status(
                name,
                self._failed_status(
                    "spec.scope is required", "ValidationFailed", "MissingField", "scope is required"
                ),
            )
            return

        missing_scope = REQUIRED_SCOPE_FIELDS - set(scope.keys())
        if missing_scope:
            await self._patch_status(
                name,
                self._failed_status(
                    f"spec.scope missing required fields: {', '.join(sorted(missing_scope))}",
                    "ValidationFailed",
                    "MissingField",
                    f"scope missing: {', '.join(sorted(missing_scope))}",
                ),
            )
            return

        if not policy_ref:
            await self._patch_status(
                name,
                self._failed_status(
                    "spec.policyRef is required", "ValidationFailed", "MissingField", "policyRef is required"
                ),
            )
            return

        if priority not in VALID_PRIORITIES:
            await self._patch_status(
                name,
                self._failed_status(
                    f"spec.priority must be one of: {', '.join(sorted(VALID_PRIORITIES))}",
                    "ValidationFailed",
                    "InvalidPriority",
                    f"invalid priority: {priority}",
                ),
            )
            return

        if phase == "Pending":
            await self._handle_pending(
                name, spec, status, tenant_id, scope, policy_ref, priority, schedule_at
            )
        elif phase == "Queued":
            await self._handle_queued(name, spec, status)
        elif phase == "Running":
            await self._handle_running(name, spec, status)
        elif phase == "Succeeded":
            await self._handle_succeeded(name, spec, status)
        elif phase == "Failed":
            await self._handle_failed(name, spec, status)
        elif phase == "Cancelled":
            await self._handle_cancelled(name, spec, status)
        else:
            log.warning("Unknown phase %s for AssessmentJob %s", phase, name)
            await self._patch_status(
                name,
                self._failed_status(
                    f"Unknown phase: {phase}", "InvalidState", "UnknownPhase", f"phase '{phase}' is not valid"
                ),
            )

    def _failed_status(
        self, message: str, condition_type: str, reason: str, condition_message: str
    ) -> dict[str, Any]:
        """Build a Failed status with proper condition structure."""
        return {
            "phase": "Failed",
            "message": message,
            "conditions": [self._condition(condition_type, "True", reason, condition_message)],
        }

    def _condition(
        self,
        condition_type: str,
        status: str,
        reason: str,
        message: str,
    ) -> dict[str, Any]:
        """Build a condition matching CRD schema exactly."""
        return {
            "type": condition_type,
            "status": status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": self._now_iso(),
        }

    async def _handle_pending(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        tenant_id: str,
        scope: dict[str, Any],
        policy_ref: str,
        priority: str,
        schedule_at: str | None,
    ) -> None:
        """Handle Pending phase - validate and transition to Queued."""

        if schedule_at:
            try:
                schedule_time = datetime.fromisoformat(schedule_at.replace("Z", "+00:00"))
                if schedule_time > datetime.now(UTC):
                    await self._patch_status(
                        name,
                        {
                            "phase": "Pending",
                            "message": f"Scheduled for {schedule_at}",
                            "conditions": [
                                self._condition(
                                    "Scheduled", "True", "FutureSchedule", f"Waiting until {schedule_at}"
                                )
                            ],
                        },
                    )
                    return
            except ValueError:
                pass

        job_id = str(uuid.uuid4())

        await self._patch_status(
            name,
            {
                "phase": "Queued",
                "jobId": job_id,
                "message": "Assessment job queued for execution",
                "startTime": self._now_iso(),
                "conditions": [
                    self._condition("Queued", "True", "JobCreated", "Job queued successfully"),
                ],
            },
        )

        log.info("AssessmentJob %s queued with job ID %s", name, job_id)

    async def _handle_queued(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Queued phase - create Kubernetes Job."""
        job_id = status.get("jobId")
        if not job_id:
            await self._patch_status(
                name,
                self._failed_status(
                    "No jobId in status", "JobCreationFailed", "MissingJobId", "Job ID missing from status"
                ),
            )
            return

        pod_name = status.get("podName")
        if pod_name:
            await self._transition_to_running(name, job_id, pod_name)
            return

        try:
            pod_name = await self._create_assessment_job(name, spec, job_id)
            await self._transition_to_running(name, job_id, pod_name)
        except Exception as e:
            log.error("Failed to create Job for AssessmentJob %s: %s", name, e)
            await self._patch_status(
                name,
                self._failed_status(
                    f"Failed to create Kubernetes Job: {e}", "JobCreationFailed", "CreateJobError", str(e)
                ),
            )

    async def _transition_to_running(self, name: str, job_id: str, pod_name: str) -> None:
        """Transition from Queued to Running."""
        await self._patch_status(
            name,
            {
                "phase": "Running",
                "jobId": job_id,
                "podName": pod_name,
                "message": "Assessment job is running",
                "startTime": self._now_iso(),
                "conditions": [
                    self._condition("Running", "True", "JobStarted", "Job started successfully"),
                ],
            },
        )
        log.info("AssessmentJob %s running in pod %s", name, pod_name)

    async def _handle_running(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Running phase - check Job completion."""
        job_id = status.get("jobId")
        pod_name = status.get("podName")

        if not job_id or not pod_name:
            await self._patch_status(
                name,
                self._failed_status(
                    "Missing jobId or podName in status",
                    "InvalidState",
                    "MissingFields",
                    "jobId or podName missing",
                ),
            )
            return

        job_state = await self._get_job_state(pod_name)

        if job_state == "Succeeded":
            findings = await self._get_job_findings(job_id)
            await self._patch_status(
                name,
                {
                    "phase": "Succeeded",
                    "jobId": job_id,
                    "podName": pod_name,
                    "message": "Assessment completed successfully",
                    "completionTime": self._now_iso(),
                    "findingsSummary": self._compute_findings_summary(findings),
                    "conditions": [
                        self._condition(
                            "Completed", "True", "JobSucceeded", "Assessment completed successfully"
                        ),
                    ],
                },
            )
        elif job_state == "Failed":
            await self._patch_status(
                name,
                {
                    "phase": "Failed",
                    "jobId": job_id,
                    "podName": pod_name,
                    "message": "Assessment job failed",
                    "completionTime": self._now_iso(),
                    "conditions": [
                        self._condition("Failed", "True", "JobFailed", "Assessment job failed"),
                    ],
                },
            )

    async def _handle_succeeded(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Succeeded phase - TTL cleanup."""
        ttl_seconds = spec.get("ttlSecondsAfterFinished", 3600)
        completion_time_str = status.get("completionTime")
        if completion_time_str:
            try:
                completion_time = datetime.fromisoformat(completion_time_str.replace("Z", "+00:00"))
                elapsed = (datetime.now(UTC) - completion_time).total_seconds()
                if elapsed > ttl_seconds:
                    log.info("AssessmentJob %s TTL expired, cleaning up Job", name)

                    try:
                        batch_api = client.BatchV1Api()
                        batch_api.delete_namespaced_job(
                            f"ishastra-assessment-{name}",
                            self.namespace or "ishastra-system",
                            propagation_policy="Foreground",
                        )
                    except ApiException as e:
                        if e.status != 404:
                            log.warning("Failed to delete Job for %s: %s", name, e)
            except ValueError:
                pass

    async def _handle_failed(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Failed phase - retry logic if configured."""
        retry_count = status.get("retryCount", 0)
        max_retries = 3

        if retry_count < max_retries:
            await self._patch_status(
                name,
                {
                    "phase": "Queued",
                    "retryCount": retry_count + 1,
                    "message": f"Retrying ({retry_count + 1}/{max_retries})",
                    "conditions": [
                        self._condition("Retrying", "True", "Retry", f"Retry attempt {retry_count + 1}"),
                    ],
                },
            )
        else:
            log.warning("AssessmentJob %s failed after %d retries", name, max_retries)

    async def _handle_cancelled(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Cancelled phase - no action needed."""

    async def _create_assessment_job(self, name: str, spec: dict[str, Any], job_id: str) -> str:
        """Create Kubernetes Job for assessment using batch/v1 Job API."""
        tenant_id = spec.get("tenantId") or "unknown"
        scope = spec.get("scope", {})
        policy_ref = spec.get("policyRef") or ""
        resources = spec.get("resources", {})
        node_selector = spec.get("nodeSelector", {})
        tolerations = spec.get("tolerations", [])
        affinity = spec.get("affinity", {})
        env_vars = spec.get("env", [])

        env = [
            client.V1EnvVar(name="ISHASTRA_JOB_ID", value=job_id),
            client.V1EnvVar(name="ISHASTRA_TENANT_ID", value=tenant_id),
            client.V1EnvVar(name="ISHASTRA_SCOPE", value=json.dumps(scope)),
            client.V1EnvVar(name="ISHASTRA_POLICY_REF", value=policy_ref),
            client.V1EnvVar(name="ISHASTRA_ASSESSMENT_JOB_NAME", value=name),
        ]
        for ev in env_vars:
            env.append(client.V1EnvVar(name=ev.get("name"), value=ev.get("value")))

        resource_reqs = None
        if resources:
            limits = resources.get("limits", {})
            requests = resources.get("requests", {})
            if limits or requests:
                resource_reqs = client.V1ResourceRequirements(
                    limits=limits if limits else None,
                    requests=requests if requests else None,
                )

        pod_template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(
                labels={
                    "ishastra.io/assessment-job": name,
                    "ishastra.io/tenant": tenant_id,
                    "ishastra.io/managed-by": "ishastra-operator",
                },
            ),
            spec=client.V1PodSpec(
                service_account_name="ishastra-worker",
                restart_policy="Never",
                containers=[
                    client.V1Container(
                        name="worker",
                        image="ishastra/worker:latest",
                        env=env,
                        resources=resource_reqs,
                        security_context=client.V1SecurityContext(
                            allow_privilege_escalation=False,
                            capabilities=client.V1Capabilities(drop=["ALL"]),
                            read_only_root_filesystem=True,
                            run_as_non_root=True,
                            run_as_user=10001,
                            run_as_group=10001,
                        ),
                    ),
                ],
                node_selector=node_selector if node_selector else None,
                tolerations=[client.V1Toleration(**t) for t in tolerations] if tolerations else None,
                affinity=client.V1Affinity(**affinity) if affinity else None,
            ),
        )

        job = client.V1Job(
            metadata=client.V1ObjectMeta(
                name=f"ishastra-assessment-{name}",
                namespace=self.namespace or "ishastra-system",
                labels={
                    "ishastra.io/assessment-job": name,
                    "ishastra.io/tenant": tenant_id,
                    "ishastra.io/managed-by": "ishastra-operator",
                },
            ),
            spec=client.V1JobSpec(
                ttl_seconds_after_finished=spec.get("ttlSecondsAfterFinished", 3600),
                backoff_limit=0,
                template=pod_template,
            ),
        )

        batch_api = client.BatchV1Api()
        try:
            created = batch_api.create_namespaced_job(self.namespace or "ishastra-system", job)
            pod_name = created.metadata.name if created.metadata else f"ishastra-assessment-{name}"

            await asyncio.sleep(2)

            pods = client.CoreV1Api().list_namespaced_pod(
                self.namespace or "ishastra-system",
                label_selector=f"job-name=ishastra-assessment-{name}",
            )
            if pods.items and pods.items[0].metadata and pods.items[0].metadata.name:
                return pods.items[0].metadata.name
            return pod_name or f"ishastra-assessment-{name}"
        except ApiException as e:
            if e.status == 409:
                pods = client.CoreV1Api().list_namespaced_pod(
                    self.namespace or "ishastra-system",
                    label_selector=f"job-name=ishastra-assessment-{name}",
                )
                if pods.items and pods.items[0].metadata and pods.items[0].metadata.name:
                    return pods.items[0].metadata.name
            raise

    async def _get_job_state(self, pod_name: str) -> str:
        """Get the state of a job pod."""
        try:
            pod = client.CoreV1Api().read_namespaced_pod(pod_name, self.namespace or "ishastra-system")
            phase = pod.status.phase if pod.status else "Unknown"
            if phase == "Succeeded":
                return "Succeeded"
            if phase == "Failed":
                return "Failed"
            if phase == "Running":
                return "Running"
            return "Running"
        except ApiException as e:
            if e.status == 404:
                return "Failed"
            return "Running"

    async def _get_job_findings(self, job_id: str) -> list[dict[str, Any]]:
        """Get findings for a completed job."""

        return []

    def _compute_findings_summary(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Compute findings summary by severity matching CRD schema."""
        summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            summary["total"] += 1
            severity = finding.get("severity", "info")
            if severity in summary:
                summary[severity] += 1
        return summary

    def _now_iso(self) -> str:
        """Get current time in ISO format (RFC3339)."""
        return datetime.now(UTC).isoformat()

    async def cleanup(self, resource: dict[str, Any]) -> None:
        """Clean up resources on deletion."""
        name = resource.get("metadata", {}).get("name", "unknown")

        try:
            batch_api = client.BatchV1Api()
            batch_api.delete_namespaced_job(
                f"ishastra-assessment-{name}",
                self.namespace or "ishastra-system",
                propagation_policy="Foreground",
            )
        except Exception as e:
            log.warning("Failed to delete Job for %s: %s", name, e)

        log.info("Cleaned up AssessmentJob %s", name)
