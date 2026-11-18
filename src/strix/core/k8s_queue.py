"""Kubernetes Jobs queue implementation for Strix assessments.

Replaces in-process/Celery queue with K8s Job API.
Used when STRIX_QUEUE_MODE=k8s-jobs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from strix.core import store
from strix.core.jobs import Job, JobState
from strix.core.worker import AssessmentQueueFull

log = logging.getLogger(__name__)

# Queue mode constant
QUEUE_MODE_K8S_JOBS = "k8s-jobs"


@dataclass
class K8sJobConfig:
    """Configuration for K8s Job creation."""

    namespace: str = "strix-assessments"
    image: str = ""
    service_account: str = "strix"
    runtime_class: str | None = "gvisor"
    priority_class: str | None = "strix-spot-priority"
    ttl_seconds_after_finished: int = 3600
    backoff_limit: int = 2
    active_deadline_seconds: int = 7200
    resources: dict[str, Any] | None = None
    db_secret_name: str = "strix-secrets"
    db_secret_key: str = "database-url"
    scope_configmap_name: str = "strix-scope"
    scope_configmap_key: str = "scope.json"
    auth_secret_name: str | None = None
    auth_secret_key: str = "auth-config"
    network_policy_enabled: bool = True
    env_from_secrets: list[dict[str, str]] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)


class K8sAssessmentQueue:
    """Kubernetes Jobs-backed assessment queue compatible with AssessmentWorker interface."""

    def __init__(
        self,
        *,
        concurrency: int | None = None,
        queue_max: int | None = None,
        config: K8sJobConfig | None = None,
    ) -> None:
        self.concurrency = concurrency or 1
        self.queue_max = queue_max or 1000
        self.config = config or K8sJobConfig()
        self._started = False
        self._start_lock = threading.Lock()
        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._job_names: dict[str, str] = {}
        self._lock = threading.Lock()
        self.name = f"k8s-queue-{os.getpid()}-{id(self) & 0xFFFF:x}"
        self._monitor_task: asyncio.Task | None = None

        # Initialize K8s client
        self._init_k8s_client()

    def _init_k8s_client(self) -> None:
        """Initialize Kubernetes API clients."""
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        self.batch_v1 = client.BatchV1Api()
        self.core_v1 = client.CoreV1Api()
        self.networking_v1 = client.NetworkingV1Api()

    async def start(self) -> None:
        """Idempotent start: sweep interrupted jobs and start monitor."""
        with self._start_lock:
            if self._started:
                return
            self._started = True
            await store.fail_interrupted(created_before=time.time())
            self._monitor_task = asyncio.create_task(self._monitor_jobs())
            log.info("K8s assessment queue started")

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Submit a job by creating a K8s Job resource."""
        await self.start()

        # Persist job to database first (queued state)
        job.state = JobState.QUEUED
        await store.save_job(job, tenant=job.actor)

        with self._lock:
            if len(self._active) >= self.queue_max:
                raise AssessmentQueueFull(f"assessment queue is full ({self.queue_max} waiting)")
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish

        # Create K8s Job
        k8s_job_name = f"strix-assess-{job.id}"
        try:
            await self._create_k8s_job(job, k8s_job_name)
            with self._lock:
                self._job_names[job.id] = k8s_job_name
            log.info("Submitted job %s as K8s Job %s", job.id, k8s_job_name)
        except Exception as exc:
            with self._lock:
                self._active.pop(job.id, None)
                self._on_finish.pop(job.id, None)
            job.state = JobState.FAILED
            job.error = f"Failed to create K8s Job: {exc}"
            job.finished_at = time.time()
            await store.save_job(job, tenant=job.actor)
            raise

    def _build_job_manifest(self, job: Job, k8s_job_name: str) -> client.V1Job:
        """Build the K8s Job manifest."""
        # Parse scope from job policy
        scope_data = {
            "authorization_ref": job.policy.get("authorization_ref", ""),
            "policy_id": job.policy.get("policy_id", ""),
            "policy_version": job.policy.get("policy_version", 0),
            "tenant_id": job.policy.get("tenant_id", ""),
            "program": job.policy.get("scope_program", ""),
            "authorized_by": job.policy.get("scope_authorized_by", ""),
            "include": job.policy.get("scope_include", []),
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [80, 443, 8443, 9443],
            "allow_broad_networks": False,
        }

        # Build pod template
        pod_template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(
                labels={
                    **self.config.labels,
                    "app.kubernetes.io/component": "assessment-job",
                    "strix.job-id": job.id,
                    "strix.tenant": job.actor,
                }
                if self.config.labels
                else {
                    "app.kubernetes.io/component": "assessment-job",
                    "strix.job-id": job.id,
                    "strix.tenant": job.actor,
                },
                annotations=self.config.annotations or {},
            ),
            spec=client.V1PodSpec(
                service_account_name=self.config.service_account,
                runtime_class_name=self.config.runtime_class,
                priority_class_name=self.config.priority_class,
                restart_policy="Never",
                security_context=self._pod_security_context(),
                containers=[
                    client.V1Container(
                        name="assessment",
                        image=self.config.image,
                        image_pull_policy="IfNotPresent",
                        command=[
                            "/usr/local/bin/python",
                            "-m",
                            "strix.core.k8s_job_runner",
                        ],
                        env=[
                            client.V1EnvVar(name="STRIX_JOB_ID", value=job.id),
                            client.V1EnvVar(name="STRIX_TENANT_ID", value=job.actor),
                            client.V1EnvVar(name="STRIX_TARGET", value=job.target),
                            client.V1EnvVar(name="STRIX_PROFILE", value=job.profile),
                            client.V1EnvVar(
                                name="STRIX_TIMEOUT_SECONDS", value=str(job.policy.get("timeout", 3600))
                            ),
                            client.V1EnvVar(name="STRIX_SCOPE_JSON", value=json.dumps(scope_data)),
                            client.V1EnvVar(name="STRIX_LOG_FORMAT", value="json"),
                            client.V1EnvVar(name="STRIX_LOG_LEVEL", value="INFO"),
                            client.V1EnvVar(name="PYTHONUNBUFFERED", value="1"),
                            client.V1EnvVar(name="PYTHONDONTWRITEBYTECODE", value="1"),
                            client.V1EnvVar(
                                name="STRIX_DATABASE_URL",
                                value_from=client.V1EnvVarSource(
                                    secret_key_ref=client.V1SecretKeySelector(
                                        name=self.config.db_secret_name,
                                        key=self.config.db_secret_key,
                                    )
                                ),
                            ),
                        ],
                        env_from=self._env_from_secrets(),
                        resources=self._resource_requirements(),
                        security_context=self._container_security_context(),
                    )
                ],
                volumes=self._volumes(),
            ),
        )

        # Add auth config if present
        if job.policy.get("encrypted_auth_config"):
            pod_template.spec.containers[0].env.append(
                client.V1EnvVar(
                    name="STRIX_AUTH_CONFIG",
                    value=json.dumps(job.policy["encrypted_auth_config"]),
                )
            )

        job_spec = client.V1JobSpec(
            ttl_seconds_after_finished=self.config.ttl_seconds_after_finished,
            backoff_limit=self.config.backoff_limit,
            active_deadline_seconds=self.config.active_deadline_seconds,
            completion_mode="NonIndexed",
            suspend=False,
            template=pod_template,
        )

        return client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(
                name=k8s_job_name,
                namespace=self.config.namespace,
                labels={
                    "app.kubernetes.io/component": "assessment-job",
                    "strix.job-id": job.id,
                    "strix.tenant": job.actor,
                },
            ),
            spec=job_spec,
        )

    def _pod_security_context(self) -> client.V1PodSecurityContext:
        return client.V1PodSecurityContext(
            fs_group=10001,
            fs_group_change_policy="OnRootMismatch",
            run_as_non_root=True,
            run_as_user=10001,
            run_as_group=10001,
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )

    def _container_security_context(self) -> client.V1SecurityContext:
        return client.V1SecurityContext(
            allow_privilege_escalation=False,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            read_only_root_filesystem=True,
            run_as_non_root=True,
            run_as_user=10001,
            run_as_group=10001,
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        )

    def _resource_requirements(self) -> client.V1ResourceRequirements | None:
        if not self.config.resources:
            return None
        return client.V1ResourceRequirements(
            limits=self.config.resources.get("limits"),
            requests=self.config.resources.get("requests"),
        )

    def _volumes(self) -> list[client.V1Volume]:
        return [
            client.V1Volume(
                name="strix-tmp",
                empty_dir=client.V1EmptyDirVolumeSource(medium="Memory", size_limit="100Mi"),
            )
        ]

    def _env_from_secrets(self) -> list[client.V1EnvFromSource] | None:
        if not self.config.env_from_secrets:
            return None
        return [
            client.V1EnvFromSource(secret_ref=client.V1SecretEnvSource(name=item["name"]))
            for item in self.config.env_from_secrets
        ]

    async def _create_k8s_job(self, job: Job, k8s_job_name: str) -> None:
        """Create the K8s Job and optional NetworkPolicy."""
        job_manifest = self._build_job_manifest(job, k8s_job_name)

        try:
            self.batch_v1.create_namespaced_job(
                namespace=self.config.namespace,
                body=job_manifest,
            )
        except ApiException as exc:
            if exc.status == 409:
                log.warning("K8s Job %s already exists", k8s_job_name)
            else:
                raise

        if self.config.network_policy_enabled:
            await self._create_network_policy(job, k8s_job_name)

    async def _create_network_policy(self, job: Job, k8s_job_name: str) -> None:
        """Create NetworkPolicy restricting egress to scope targets."""
        authorized_networks = job.policy.get("scope_authorized_networks", [])
        allowed_ports = job.policy.get("scope_allowed_ports", [80, 443, 8443, 9443])

        egress_rules = []

        # 1. DNS
        egress_rules.append(
            client.V1NetworkPolicyEgressRule(
                to=[
                    client.V1NetworkPolicyPeer(
                        namespace_selector=client.V1LabelSelector(
                            match_labels={"kubernetes.io/metadata.name": "kube-system"}
                        )
                    )
                ],
                ports=[
                    client.V1NetworkPolicyPort(protocol="UDP", port=53),
                    client.V1NetworkPolicyPort(protocol="TCP", port=53),
                ],
            )
        )

        # 2. Scope targets
        if authorized_networks:
            for cidr in authorized_networks:
                for port in allowed_ports:
                    egress_rules.append(
                        client.V1NetworkPolicyEgressRule(
                            to=[client.V1NetworkPolicyPeer(ip_block=client.V1IPBlock(cidr=cidr))],
                            ports=[client.V1NetworkPolicyPort(protocol="TCP", port=port)],
                        )
                    )

        # 3. Database
        egress_rules.append(
            client.V1NetworkPolicyEgressRule(
                to=[
                    client.V1NetworkPolicyPeer(
                        pod_selector=client.V1LabelSelector(
                            match_labels={"app.kubernetes.io/name": "postgresql"}
                        )
                    )
                ],
                ports=[client.V1NetworkPolicyPort(protocol="TCP", port=5432)],
            )
        )

        # 4. K8s API
        egress_rules.append(
            client.V1NetworkPolicyEgressRule(
                to=[
                    client.V1NetworkPolicyPeer(
                        namespace_selector=client.V1LabelSelector(
                            match_labels={"kubernetes.io/metadata.name": "kube-system"}
                        )
                    )
                ],
                ports=[client.V1NetworkPolicyPort(protocol="TCP", port=443)],
            )
        )

        netpol = client.V1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(
                name=f"{k8s_job_name}-netpol",
                namespace=self.config.namespace,
                labels={
                    "app.kubernetes.io/component": "assessment-job",
                    "strix.job-id": job.id,
                },
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(match_labels={"strix.job-id": job.id}),
                policy_types=["Egress"],
                egress=egress_rules,
            ),
        )

        try:
            self.networking_v1.create_namespaced_network_policy(
                namespace=self.config.namespace,
                body=netpol,
            )
        except ApiException as exc:
            if exc.status != 409:
                log.warning("Failed to create NetworkPolicy: %s", exc)

    def cancel(self, job_id: str) -> bool:
        """Cancel a job by deleting its K8s Job."""
        with self._lock:
            job = self._active.get(job_id)
            k8s_job_name = self._job_names.get(job_id)

        if job is None:
            return False

        job.cancel()

        if k8s_job_name:
            try:
                self.batch_v1.delete_namespaced_job(
                    name=k8s_job_name,
                    namespace=self.config.namespace,
                    body=client.V1DeleteOptions(propagation_policy="Foreground"),
                )
                log.info("Deleted K8s Job %s", k8s_job_name)
            except ApiException as exc:
                if exc.status != 404:
                    log.exception("Failed to delete K8s Job %s", k8s_job_name)

        if k8s_job_name:
            with contextlib.suppress(ApiException):
                self.networking_v1.delete_namespaced_network_policy(
                    name=f"{k8s_job_name}-netpol",
                    namespace=self.config.namespace,
                )

        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel all jobs bound to a policy."""
        with self._lock:
            targets = [
                job for job in self._active.values() if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in targets:
            self.cancel(job.id)
        return len(targets)

    async def shutdown(self, timeout: float = 30.0) -> None:
        """Shutdown: cancel all active jobs."""
        with self._start_lock:
            if not self._started:
                return
            self._started = False

        if self._monitor_task:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task

        with self._lock:
            job_ids = list(self._active.keys())

        log.info("Shutting down K8s queue, cancelling %d jobs", len(job_ids))
        for job_id in job_ids:
            self.cancel(job_id)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not self._active:
                    break
            await asyncio.sleep(0.5)

        with self._lock:
            self._active.clear()
            self._on_finish.clear()
            self._job_names.clear()

    async def _monitor_jobs(self) -> None:
        """Background task to monitor K8s Job status and trigger callbacks."""
        while self._started:
            await asyncio.sleep(5.0)
            await self._reconcile_jobs()

    async def _reconcile_jobs(self) -> None:
        """Check K8s Job status and call on_finish for completed jobs."""
        with self._lock:
            job_items = list(self._active.items())

        for job_id, job in job_items:
            k8s_job_name = self._job_names.get(job_id)
            if not k8s_job_name:
                continue

            try:
                k8s_job = self.batch_v1.read_namespaced_job(
                    name=k8s_job_name,
                    namespace=self.config.namespace,
                )
            except ApiException as exc:
                if exc.status == 404:
                    job.state = JobState.FAILED
                    job.error = "K8s Job not found"
                    job.finished_at = time.time()
                    await self._finish_job(job_id)
                continue

            if k8s_job.status.succeeded and k8s_job.status.succeeded > 0:
                await self._finish_job(job_id)
            elif k8s_job.status.failed and k8s_job.status.failed > k8s_job.spec.backoff_limit:
                job.state = JobState.FAILED
                job.error = "K8s Job failed after retries"
                job.finished_at = time.time()
                await store.save_job(job, tenant=job.actor)
                await self._finish_job(job_id)

    async def _finish_job(self, job_id: str) -> None:
        """Call on_finish callback and clean up."""
        with self._lock:
            job = self._active.pop(job_id, None)
            on_finish = self._on_finish.pop(job_id, None)
            self._job_names.pop(job_id, None)

        if job and on_finish:
            try:
                on_finish(job)
            except Exception:
                log.exception("on_finish callback failed for job %s", job_id)


def get_k8s_assessment_queue(
    *,
    concurrency: int | None = None,
    queue_max: int | None = None,
) -> K8sAssessmentQueue:
    """Factory for K8s Jobs queue."""
    from strix.config import get_settings

    settings = get_settings()

    config = K8sJobConfig(
        namespace=os.environ.get("STRIX_K8S_NAMESPACE", "strix-assessments"),
        image=os.environ.get("STRIX_K8S_IMAGE", "")
        or f"{settings.k8s_image_repository}:{settings.k8s_image_tag}",
        service_account=os.environ.get("STRIX_K8S_SERVICE_ACCOUNT", "strix"),
        runtime_class=os.environ.get("STRIX_K8S_RUNTIME_CLASS", "gvisor") or None,
        priority_class=os.environ.get("STRIX_K8S_PRIORITY_CLASS") or None,
        ttl_seconds_after_finished=int(os.environ.get("STRIX_K8S_TTL", "3600")),
        backoff_limit=int(os.environ.get("STRIX_K8S_BACKOFF_LIMIT", "2")),
        active_deadline_seconds=int(os.environ.get("STRIX_K8S_ACTIVE_DEADLINE", "7200")),
        resources={
            "limits": {
                "cpu": os.environ.get("STRIX_K8S_CPU_LIMIT", "2000m"),
                "memory": os.environ.get("STRIX_K8S_MEMORY_LIMIT", "2Gi"),
            },
            "requests": {
                "cpu": os.environ.get("STRIX_K8S_CPU_REQUEST", "1000m"),
                "memory": os.environ.get("STRIX_K8S_MEMORY_REQUEST", "1Gi"),
            },
        }
        if os.environ.get("STRIX_K8S_CPU_LIMIT")
        else None,
        db_secret_name=os.environ.get("STRIX_K8S_DB_SECRET", "strix-secrets"),
        scope_configmap_name=os.environ.get("STRIX_K8S_SCOPE_CM", "strix-scope"),
        network_policy_enabled=os.environ.get("STRIX_K8S_NETPOL", "true").lower() == "true",
    )

    return K8sAssessmentQueue(
        concurrency=concurrency,
        queue_max=queue_max,
        config=config,
    )
