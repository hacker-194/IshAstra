# Ishastra K8s Jobs-Based Queue Architecture

## Overview

Replace in-process/k8s-jobs workers with Kubernetes Jobs for assessment execution. Each assessment runs in an isolated pod with the `ishastra-assessment` image, writing results directly to PostgreSQL.

---

## 1. Architecture Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            STRIX K8S JOBS ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────────┐
│   Client     │────▶│  Ishastra API   │────▶│  PostgreSQL (jobs, findings)     │
│  (REST)      │     │  (FastAPI)   │     │  + Advisory Lock (lease)         │
└──────────────┘     └──────┬───────┘     └──────────────────────────────────┘
                            │
                            │ 1. POST /api/assess
                            │    - Validate scope, target, profile
                            │    - Persist Job row (state=QUEUED)
                            │    - Return 202 + job_id
                            ▼
                     ┌──────────────┐
                     │  K8s Job     │
                     │  Controller  │
                     │  (Python)    │
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │ 2. Create   │ 3. Watch    │ 4. Webhook (optional)
              │    Job      │    Job      │    Callback
              ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KUBERNETES CLUSTER                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    NAMESPACE: ishastra-assessments                          │ │
│  │                                                                         │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐  │ │
│  │  │  Job: ishastra-    │  │  Job: ishastra-    │  │  Job: ishastra-            │  │ │
│  │  │  assess-abc123  │  │  assess-def456  │  │  assess-ghi789          │  │ │
│  │  │                 │  │                 │  │                         │  │ │
│  │  │  runtimeClass:  │  │  runtimeClass:  │  │  runtimeClass:          │  │ │
│  │  │  gvisor         │  │  kata           │  │  gvisor                 │  │ │
│  │  │                 │  │                 │  │                         │  │ │
│  │  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐          │  │ │
│  │  │  │ Container │  │  │  │ Container │  │  │  │ Container │          │  │ │
│  │  │  │ ishastra-    │  │  │  │ ishastra-    │  │  │  │ ishastra-    │          │  │ │
│  │  │  │ assessment│  │  │  │ assessment│  │  │  │ assessment│          │  │ │
│  │  │  │           │  │  │  │           │  │  │  │           │          │  │ │
│  │  │  │ Env:      │  │  │  │ Env:      │  │  │  │ Env:      │          │  │ │
│  │  │  │ JOB_ID    │  │  │  │ JOB_ID    │  │  │  │ JOB_ID    │          │  │ │
│  │  │  │ DB_DSN    │  │  │  │ DB_DSN    │  │  │  │ DB_DSN    │          │  │ │
│  │  │  │ SCOPE_JSON│  │  │  │ SCOPE_JSON│  │  │  │ SCOPE_JSON│          │  │ │
│  │  │  └───────────┘  │  │  └───────────┘  │  │  └───────────┘          │  │ │
│  │  │                 │  │                 │  │                         │  │ │
│  │  │  NetworkPolicy  │  │  NetworkPolicy  │  │  NetworkPolicy          │  │ │
│  │  │  egress: scope  │  │  egress: scope  │  │  egress: scope          │  │ │
│  │  │  targets only   │  │  targets only   │  │  targets only           │  │ │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────┘  │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    SPOT INSTANCE NODE POOL                       │   │ │
│  │  │  • Preemptible pods (priorityClass: low)                        │   │ │
│  │  │  • PodDisruptionBudget: minAvailable=0                          │   │ │
│  │  │  • Scale-to-zero via cluster-autoscaler                         │   │ │
│  │  │  • TTL: .spec.ttlSecondsAfterFinished = 3600                   │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘

                            ▲
                            │ 5. Write results to PostgreSQL
                            │    - UPDATE jobs SET state=COMPLETED, ...
                            │    - INSERT findings
                            │    - Advisory lock released
                            │
                     ┌──────┴───────┐
                     │  API Polls   │
                     │  GET /api/   │
                     │  assess/{id} │
                     └──────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY BOUNDARIES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  API Pod                    │  Assessment Job Pod                            │
│  ─────────                  │  ─────────────────                             │
│  • read/write DB            │  • write DB only (own job_id)                  │
│  • create K8s Jobs          │  • egress: scope.targets only                  │
│  • read K8s Jobs            │  • runtimeClass: gvisor/kata                   │
│  • no scanner tools         │  • scanner tools (nmap, nuclei, etc.)          │
│  • non-root, read-only fs   │  • non-root, read-only fs                      │
│  • seccomp: RuntimeDefault  │  • seccomp: RuntimeDefault + custom            │
└─────────────────────────────┴────────────────────────────────────────────────┘
```

---

## 2. K8s Job Manifest Template

**File:** `deploy/helm/ishastra/templates/job-assessment.yaml`

```yaml
{{- if .Values.k8sJobs.enabled }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "ishastra-assess-%s" .Values.k8sJobs.jobNameSuffix | trunc 63 | trimSuffix "-" }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "ishastra.labels" . | nindent 4 }}
    app.kubernetes.io/component: assessment-job
    ishastra.job-id: {{ .Values.k8sJobs.jobId }}
    ishastra.tenant: {{ .Values.k8sJobs.tenantId }}
  annotations:
    {{- if .Values.k8sJobs.annotations }}
    {{- toYaml .Values.k8sJobs.annotations | nindent 4 }}
    {{- end }}
    {{- if .Values.global.podSecurityStandard }}
    seccomp.security.alpha.kubernetes.io/pod: runtime/default
    {{- end }}
spec:
  # Job-level settings
  ttlSecondsAfterFinished: {{ .Values.k8sJobs.ttlSecondsAfterFinished | default 3600 }}
  backoffLimit: {{ .Values.k8sJobs.backoffLimit | default 2 }}
  activeDeadlineSeconds: {{ .Values.k8sJobs.activeDeadlineSeconds | default 3600 }}
  completionMode: NonIndexed
  suspend: false

  # Pod template
  template:
    metadata:
      labels:
        {{- include "ishastra.selectorLabels" . | nindent 8 }}
        app.kubernetes.io/component: assessment-job
        ishastra.job-id: {{ .Values.k8sJobs.jobId }}
        ishastra.tenant: {{ .Values.k8sJobs.tenantId }}
      annotations:
        {{- if .Values.k8sJobs.podAnnotations }}
        {{- toYaml .Values.k8sJobs.podAnnotations | nindent 8 }}
        {{- end }}
        {{- if .Values.global.podSecurityStandard }}
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
        {{- end }}
    spec:
      serviceAccountName: {{- if .Values.serviceAccount.enabled }} {{ .Values.serviceAccount.name | default (include "ishastra.fullname" .) }}{{- else }} default{{- end }}
      {{- include "ishastra.priorityClassName" . | nindent 6 }}
      {{- if .Values.k8sJobs.runtimeClassName }}
      runtimeClassName: {{ .Values.k8sJobs.runtimeClassName }}
      {{- end }}
      {{- if .Values.k8sJobs.priorityClassName }}
      priorityClassName: {{ .Values.k8sJobs.priorityClassName }}
      {{- end }}
      {{- if .Values.topologySpreadConstraints }}
      {{- include "ishastra.topologySpreadConstraints" . | nindent 6 }}
      {{- end }}
      {{- if .Values.k8sJobs.affinity }}
      {{- include "ishastra.k8sJobs.affinity" . | nindent 6 }}
      {{- end }}
      {{- if .Values.k8sJobs.tolerations }}
      {{- include "ishastra.k8sJobs.tolerations" . | nindent 6 }}
      {{- end }}
      restartPolicy: Never
      securityContext:
        {{- if .Values.k8sJobs.podSecurityContext }}
        {{- toYaml .Values.k8sJobs.podSecurityContext | nindent 8 }}
        {{- else }}
        {{- include "ishastra.podSecurityContext" . | nindent 8 }}
        {{- end }}
      {{- include "ishastra.imagePullSecrets" . }}
      containers:
        - name: assessment
          image: "{{ .Values.global.image.repository }}:{{ .Values.global.image.tag }}"
          imagePullPolicy: {{ .Values.global.image.pullPolicy }}
          command:
            - /usr/local/bin/python
            - -m
            - ishastra.core.k8s_job_runner
          env:
            # Job identification
            - name: ISHASTRA_JOB_ID
              value: {{ .Values.k8sJobs.jobId | quote }}
            - name: ISHASTRA_TENANT_ID
              value: {{ .Values.k8sJobs.tenantId | quote }}
            # Database (from secret)
            - name: ISHASTRA_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.k8sJobs.dbSecretName | default "ishastra-secrets" }}
                  key: database-url
                  optional: false
            # Scope configuration (from ConfigMap)
            - name: ISHASTRA_SCOPE_JSON
              valueFrom:
                configMapKeyRef:
                  name: {{ .Values.k8sJobs.scopeConfigMapName | default "ishastra-scope" }}
                  key: scope.json
                  optional: false
            # Assessment configuration
            - name: ISHASTRA_TARGET
              value: {{ .Values.k8sJobs.target | quote }}
            - name: ISHASTRA_PROFILE
              value: {{ .Values.k8sJobs.profile | default "web" | quote }}
            - name: ISHASTRA_TIMEOUT_SECONDS
              value: {{ .Values.k8sJobs.timeoutSeconds | default 3600 | quote }}
            - name: ISHASTRA_LOG_FORMAT
              value: "json"
            - name: ISHASTRA_LOG_LEVEL
              value: {{ .Values.k8sJobs.logLevel | default "INFO" | quote }}
            # Authentication (optional, from secret)
            {{- if .Values.k8sJobs.authSecretName }}
            - name: ISHASTRA_AUTH_CONFIG
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.k8sJobs.authSecretName }}
                  key: auth-config
                  optional: true
            {{- end }}
            # Runtime configuration
            - name: PYTHONUNBUFFERED
              value: "1"
            - name: PYTHONDONTWRITEBYTECODE
              value: "1"
          envFrom:
            {{- if .Values.k8sJobs.envFromSecrets }}
            {{- toYaml .Values.k8sJobs.envFromSecrets | nindent 12 }}
            {{- end }}
          {{- if .Values.k8sJobs.resources }}
          resources:
            {{- toYaml .Values.k8sJobs.resources | nindent 12 }}
          {{- end }}
          {{- if .Values.k8sJobs.livenessProbe }}
          livenessProbe:
            {{- toYaml .Values.k8sJobs.livenessProbe | nindent 12 }}
          {{- end }}
          {{- if .Values.k8sJobs.readinessProbe }}
          readinessProbe:
            {{- toYaml .Values.k8sJobs.readinessProbe | nindent 12 }}
          {{- end }}
          securityContext:
            {{- if .Values.k8sJobs.securityContext }}
            {{- toYaml .Values.k8sJobs.securityContext | nindent 12 }}
            {{- else }}
            {{- include "ishastra.containerSecurityContext" . | nindent 12 }}
            {{- end }}
      {{- if .Values.k8sJobs.volumes }}
      volumes:
        {{- toYaml .Values.k8sJobs.volumes | nindent 8 }}
      {{- end }}
{{- end }}
```

---

## 3. NetworkPolicy for Assessment Jobs

**File:** `deploy/helm/ishastra/templates/networkpolicy-assessment-job.yaml`

```yaml
{{- if and .Values.k8sJobs.enabled .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ printf "ishastra-assess-%s-netpol" .Values.k8sJobs.jobNameSuffix | trunc 63 | trimSuffix "-" }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "ishastra.labels" . | nindent 4 }}
    app.kubernetes.io/component: assessment-job
    ishastra.job-id: {{ .Values.k8sJobs.jobId }}
spec:
  podSelector:
    matchLabels:
      ishastra.job-id: {{ .Values.k8sJobs.jobId }}
  policyTypes:
    - Egress
  egress:
    # 1. Allow DNS resolution (required for target scanning)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # 2. Allow egress to scope-authorized targets only
    {{- if .Values.k8sJobs.scopeEgress }}
    {{- toYaml .Values.k8sJobs.scopeEgress | nindent 4 }}
    {{- else }}
    # Default: deny all egress (override with scopeEgress in values)
    - to: []
      ports: []
    {{- end }}
    # 3. Allow database writes (PostgreSQL)
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
      ports:
        - protocol: TCP
          port: 5432
    # 4. Allow K8s API (for self-status updates, optional)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: TCP
          port: 443
{{- end }}
```

---

## 4. Python Client: K8s Job Runner

**File:** `src/ishastra/core/k8s_job_runner.py`

```python
"""Kubernetes Job entry point for assessment execution.

Runs inside the assessment Job pod. Executes the assessment and writes
results directly to PostgreSQL. Designed for K8s Jobs mode (ISHASTRA_QUEUE_MODE=k8s-jobs).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any

from ishastra.config import Settings
from ishastra.core import jobs, store
from ishastra.core.jobs import Job, JobState
from ishastra.core.scope import Scope

log = logging.getLogger(__name__)


class K8sJobRunner:
    """Runs a single assessment job in a Kubernetes Job pod."""

    def __init__(self) -> None:
        self.job_id = os.environ.get("ISHASTRA_JOB_ID")
        self.tenant_id = os.environ.get("ISHASTRA_TENANT_ID")
        self.target = os.environ.get("ISHASTRA_TARGET")
        self.profile = os.environ.get("ISHASTRA_PROFILE", "web")
        self.timeout_seconds = float(os.environ.get("ISHASTRA_TIMEOUT_SECONDS", "3600"))
        self.scope_json = os.environ.get("ISHASTRA_SCOPE_JSON")
        self.auth_config_json = os.environ.get("ISHASTRA_AUTH_CONFIG")

        if not all([self.job_id, self.tenant_id, self.target, self.scope_json]):
            raise RuntimeError("Missing required environment variables")

    def _parse_scope(self) -> Scope:
        """Parse scope snapshot from JSON environment variable."""
        data = json.loads(self.scope_json)
        return Scope(
            authorization_ref=data.get("authorization_ref", ""),
            policy_id=data.get("policy_id", ""),
            policy_version=data.get("policy_version", 0),
            tenant_id=data.get("tenant_id", ""),
            program=data.get("program", ""),
            authorized_by=data.get("authorized_by", ""),
            include=tuple(data.get("include", [])),
            exclude=tuple(data.get("exclude", [])),
            authorized_networks=tuple(data.get("authorized_networks", [])),
            allowed_ports=tuple(data.get("allowed_ports", [])),
            allow_broad_networks=bool(data.get("allow_broad_networks", False)),
        )

    def _build_policy(self) -> dict[str, Any]:
        """Build job policy dict including encrypted auth if provided."""
        policy = {
            "timeout": self.timeout_seconds,
        }
        if self.auth_config_json:
            try:
                policy["encrypted_auth_config"] = json.loads(self.auth_config_json)
            except json.JSONDecodeError:
                log.warning("Failed to parse ISHASTRA_AUTH_CONFIG")
        return policy

    async def run(self) -> int:
        """Execute the assessment and persist results. Returns exit code."""
        log.info("Starting K8s Job assessment: job_id=%s tenant=%s target=%s",
                 self.job_id, self.tenant_id, self.target)

        # Configure store from DATABASE_URL
        db_url = os.environ.get("ISHASTRA_DATABASE_URL")
        if not db_url:
            log.error("ISHASTRA_DATABASE_URL not set")
            return 1
        store.configure(db_url)

        # Build job from environment
        scope_snapshot = self._parse_scope()
        policy = self._build_policy()

        job = jobs.prepare(
            target=self.target,
            profile=self.profile,
            actor=self.tenant_id,
            timeout=self.timeout_seconds,
            scope_snapshot=scope_snapshot,
            policy=policy,
        )
        job.id = self.job_id  # Override with K8s Job ID

        # Mark job as running in DB
        try:
            claimed = await store.claim_job(job.id, tenant=self.tenant_id, worker=f"k8s-job-{self.job_id}")
            if not claimed:
                existing = await store.get_job(job.id, tenant=self.tenant_id)
                if existing and existing["state"] in ("completed", "partial", "failed", "cancelled"):
                    log.info("Job %s already in terminal state %s", job.id, existing["state"])
                    return 0
                log.error("Job %s was already claimed", job.id)
                return 1
        except Exception as exc:
            log.exception("Failed to claim job %s", job.id)
            return 1

        job.attempts = 1
        job.worker_id = f"k8s-job-{self.job_id}"
        job.state = JobState.RUNNING
        job.started_at = time.time()

        # Execute assessment
        try:
            jobs.execute(job)
        except Exception as exc:
            log.exception("Assessment %s crashed", job.id)
            job.state = JobState.FAILED
            job.error = f"internal error: {type(exc).__name__}"
            job.finished_at = time.time()

        # Persist final state
        try:
            await store.save_job(job, tenant=self.tenant_id)
            log.info("Job %s completed with state=%s verdict=%s",
                     job.id, job.state.value, job.verdict)
        except Exception as exc:
            log.exception("Failed to save job %s", job.id)
            return 1

        # Return non-zero for failed/partial jobs (K8s Job will retry if backoffLimit > 0)
        if job.state in (JobState.FAILED, JobState.PARTIAL):
            return 1
        return 0


def main() -> int:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    runner = K8sJobRunner()
    try:
        return asyncio.run(runner.run())
    except KeyboardInterrupt:
        log.info("Interrupted")
        return 130
    except Exception:
        log.exception("Fatal error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. Python Client: Job Submission & Monitoring

**File:** `src/ishastra/core/k8s_queue.py`

```python
"""Kubernetes Jobs queue implementation for Ishastra assessments.

Replaces in-process/Kubernetes Jobs queue with K8s Job API.
Used when ISHASTRA_QUEUE_MODE=k8s-jobs.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from ishastra.core import store
from ishastra.core.jobs import Job, JobState
from ishastra.core.queue import AssessmentWorker, AssessmentQueueFull, WorkerLeaseError

log = logging.getLogger(__name__)

# Queue mode constant
QUEUE_MODE_K8S_JOBS = "k8s-jobs"


@dataclass
class K8sJobConfig:
    """Configuration for K8s Job creation."""
    namespace: str = "default"
    image: str = "ghcr.io/your-org/ishastra:3.5.0"
    service_account: str = "ishastra"
    runtime_class: str | None = "gvisor"  # gvisor, kata, or None
    priority_class: str | None = "ishastra-low-priority"  # for spot instances
    ttl_seconds_after_finished: int = 3600
    backoff_limit: int = 2
    active_deadline_seconds: int = 3600
    resources: dict[str, Any] | None = None
    db_secret_name: str = "ishastra-secrets"
    db_secret_key: str = "database-url"
    scope_configmap_name: str = "ishastra-scope"
    scope_configmap_key: str = "scope.json"
    auth_secret_name: str | None = None
    auth_secret_key: str = "auth-config"
    network_policy_enabled: bool = True
    labels: dict[str, str] | None = None
    annotations: dict[str, str] | None = None


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
        self._job_names: dict[str, str] = {}  # job_id -> k8s job name
        self._lock = threading.Lock()
        self.name = f"k8s-queue-{os.getpid()}-{id(self) & 0xFFFF:x}"

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
        """Idempotent start: sweep interrupted jobs."""
        with self._start_lock:
            if self._started:
                return
            self._started = True
            # Sweep interrupted jobs on startup
            await store.fail_interrupted(created_before=time.time())
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
        k8s_job_name = f"ishastra-assess-{job.id}"
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
                    "ishastra.job-id": job.id,
                    "ishastra.tenant": job.actor,
                } if self.config.labels else {
                    "app.kubernetes.io/component": "assessment-job",
                    "ishastra.job-id": job.id,
                    "ishastra.tenant": job.actor,
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
                            "ishastra.core.k8s_job_runner",
                        ],
                        env=[
                            client.V1EnvVar(name="ISHASTRA_JOB_ID", value=job.id),
                            client.V1EnvVar(name="ISHASTRA_TENANT_ID", value=job.actor),
                            client.V1EnvVar(name="ISHASTRA_TARGET", value=job.target),
                            client.V1EnvVar(name="ISHASTRA_PROFILE", value=job.profile),
                            client.V1EnvVar(name="ISHASTRA_TIMEOUT_SECONDS", value=str(job.policy.get("timeout", 3600))),
                            client.V1EnvVar(name="ISHASTRA_SCOPE_JSON", value=json.dumps(scope_data)),
                            client.V1EnvVar(name="ISHASTRA_LOG_FORMAT", value="json"),
                            client.V1EnvVar(name="ISHASTRA_LOG_LEVEL", value="INFO"),
                            client.V1EnvVar(name="PYTHONUNBUFFERED", value="1"),
                            client.V1EnvVar(name="PYTHONDONTWRITEBYTECODE", value="1"),
                            client.V1EnvVar(
                                name="ISHASTRA_DATABASE_URL",
                                value_from=client.V1EnvVarSource(
                                    secret_key_ref=client.V1SecretKeySelector(
                                        name=self.config.db_secret_name,
                                        key=self.config.db_secret_key,
                                    )
                                ),
                            ),
                        ],
                        env_from=self.config.env_from_secrets,
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
                    name="ISHASTRA_AUTH_CONFIG",
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
                    "ishastra.job-id": job.id,
                    "ishastra.tenant": job.actor,
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

    def _volumes(self) -> list[client.V1Volume] | None:
        # EmptyDir for tmp
        return [
            client.V1Volume(
                name="ishastra-tmp",
                empty_dir=client.V1EmptyDirVolumeSource(medium="Memory", size_limit="100Mi"),
            )
        ]

    async def _create_k8s_job(self, job: Job, k8s_job_name: str) -> None:
        """Create the K8s Job and optional NetworkPolicy."""
        job_manifest = self._build_job_manifest(job, k8s_job_name)

        # Create Job
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

        # Create NetworkPolicy if enabled
        if self.config.network_policy_enabled:
            await self._create_network_policy(job, k8s_job_name)

    async def _create_network_policy(self, job: Job, k8s_job_name: str) -> None:
        """Create NetworkPolicy restricting egress to scope targets."""
        # Build egress rules from scope
        authorized_networks = job.policy.get("scope_authorized_networks", [])
        allowed_ports = job.policy.get("scope_allowed_ports", [80, 443, 8443, 9443])

        egress_rules = []

        # 1. DNS
        egress_rules.append(client.V1NetworkPolicyEgressRule(
            to=[client.V1NetworkPolicyPeer(
                namespace_selector=client.V1LabelSelector(
                    match_labels={"kubernetes.io/metadata.name": "kube-system"}
                )
            )],
            ports=[
                client.V1NetworkPolicyPort(protocol="UDP", port=53),
                client.V1NetworkPolicyPort(protocol="TCP", port=53),
            ],
        ))

        # 2. Scope targets (CIDR-based)
        if authorized_networks:
            for cidr in authorized_networks:
                for port in allowed_ports:
                    egress_rules.append(client.V1NetworkPolicyEgressRule(
                        to=[client.V1NetworkPolicyPeer(
                            ip_block=client.V1IPBlock(cidr=cidr)
                        )],
                        ports=[client.V1NetworkPolicyPort(protocol="TCP", port=port)],
                    ))
        else:
            # No authorized networks = deny all egress (except DNS and DB)
            pass

        # 3. Database
        egress_rules.append(client.V1NetworkPolicyEgressRule(
            to=[client.V1NetworkPolicyPeer(
                pod_selector=client.V1LabelSelector(
                    match_labels={"app.kubernetes.io/name": "postgresql"}
                )
            )],
            ports=[client.V1NetworkPolicyPort(protocol="TCP", port=5432)],
        ))

        # 4. K8s API (for self-status)
        egress_rules.append(client.V1NetworkPolicyEgressRule(
            to=[client.V1NetworkPolicyPeer(
                namespace_selector=client.V1LabelSelector(
                    match_labels={"kubernetes.io/metadata.name": "kube-system"}
                )
            )],
            ports=[client.V1NetworkPolicyPort(protocol="TCP", port=443)],
        ))

        netpol = client.V1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(
                name=f"{k8s_job_name}-netpol",
                namespace=self.config.namespace,
                labels={
                    "app.kubernetes.io/component": "assessment-job",
                    "ishastra.job-id": job.id,
                },
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(
                    match_labels={"ishastra.job-id": job.id}
                ),
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

        # Signal cancellation in DB (polled by runner)
        job.cancel()

        # Delete K8s Job
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

        # Clean up NetworkPolicy
        if k8s_job_name:
            try:
                self.networking_v1.delete_namespaced_network_policy(
                    name=f"{k8s_job_name}-netpol",
                    namespace=self.config.namespace,
                )
            except ApiException:
                pass

        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel all jobs bound to a policy."""
        with self._lock:
            targets = [
                job for job in self._active.values()
                if (job.policy or {}).get("policy_id") == policy_id
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

        with self._lock:
            job_ids = list(self._active.keys())

        log.info("Shutting down K8s queue, cancelling %d jobs", len(job_ids))
        for job_id in job_ids:
            self.cancel(job_id)

        # Wait for cleanup
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
                    # Job deleted externally, mark as failed
                    job.state = JobState.FAILED
                    job.error = "K8s Job not found"
                    job.finished_at = time.time()
                    await self._finish_job(job_id)
                continue

            # Check if Job completed
            if k8s_job.status.succeeded and k8s_job.status.succeeded > 0:
                # Job succeeded, results already in DB via runner
                # Just trigger callback
                await self._finish_job(job_id)
            elif k8s_job.status.failed and k8s_job.status.failed > k8s_job.spec.backoff_limit:
                # Job failed permanently
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


# Factory function integration
def get_k8s_assessment_queue(
    *,
    concurrency: int | None = None,
    queue_max: int | None = None,
) -> K8sAssessmentQueue:
    """Factory for K8s Jobs queue."""
    from ishastra.config import Settings

    settings = Settings.from_env()

    config = K8sJobConfig(
        namespace=os.environ.get("ISHASTRA_K8S_NAMESPACE", "ishastra"),
        image=os.environ.get("ISHASTRA_K8S_IMAGE", settings.k8s_image),
        service_account=os.environ.get("ISHASTRA_K8S_SERVICE_ACCOUNT", "ishastra"),
        runtime_class=os.environ.get("ISHASTRA_K8S_RUNTIME_CLASS", "gvisor"),
        priority_class=os.environ.get("ISHASTRA_K8S_PRIORITY_CLASS"),
        ttl_seconds_after_finished=int(os.environ.get("ISHASTRA_K8S_TTL", "3600")),
        backoff_limit=int(os.environ.get("ISHASTRA_K8S_BACKOFF_LIMIT", "2")),
        active_deadline_seconds=int(os.environ.get("ISHASTRA_K8S_ACTIVE_DEADLINE", "3600")),
        resources={
            "limits": {
                "cpu": os.environ.get("ISHASTRA_K8S_CPU_LIMIT", "2000m"),
                "memory": os.environ.get("ISHASTRA_K8S_MEMORY_LIMIT", "2Gi"),
            },
            "requests": {
                "cpu": os.environ.get("ISHASTRA_K8S_CPU_REQUEST", "1000m"),
                "memory": os.environ.get("ISHASTRA_K8S_MEMORY_REQUEST", "1Gi"),
            },
        } if os.environ.get("ISHASTRA_K8S_CPU_LIMIT") else None,
        db_secret_name=os.environ.get("ISHASTRA_K8S_DB_SECRET", "ishastra-secrets"),
        scope_configmap_name=os.environ.get("ISHASTRA_K8S_SCOPE_CM", "ishastra-scope"),
    )

    return K8sAssessmentQueue(
        concurrency=concurrency,
        queue_max=queue_max,
        config=config,
    )


# Update get_assessment_queue to support k8s-jobs mode
# In src/ishastra/core/queue.py, add:
#
# QUEUE_MODE_K8S_JOBS = "k8s-jobs"
#
# def get_assessment_queue(...):
#     if QUEUE_MODE == "k8s-jobs":
#         return get_k8s_assessment_queue(...)
```