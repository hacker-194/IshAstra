"""Ishastra Kubernetes Operator main entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import signal
import sys
import time
from contextlib import asynccontextmanager, suppress
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from ishastra.metrics import get_registry, init_metrics
from ishastra.operator.controllers import (
    AssessmentJobReconciler,
    PolicyReconciler,
    ScanResultReconciler,
    TenantReconciler,
)

log = logging.getLogger(__name__)


_shutdown_event = asyncio.Event()
_health_server: uvicorn.Server | None = None
_metrics_server: uvicorn.Server | None = None
_webhook_server: uvicorn.Server | None = None
_controllers: list[Any] = []
_leader_elector: Any = None
_redis_client: Any = None
_pg_pool: Any = None


class AdmissionRequest(BaseModel):
    """Kubernetes AdmissionReview request."""

    uid: str
    kind: dict[str, str]
    resource: dict[str, str]
    requestKind: dict[str, str]
    requestResource: dict[str, str]
    name: str
    namespace: str | None = None
    operation: str
    userInfo: dict[str, Any]
    object: dict[str, Any] | None = None
    oldObject: dict[str, Any] | None = None
    options: dict[str, Any] | None = None
    dryRun: bool = False


class AdmissionResponse(BaseModel):
    """Kubernetes AdmissionReview response."""

    uid: str
    allowed: bool
    status: dict[str, Any] | None = None
    patch: str | None = None
    patchType: str | None = None
    warnings: list[str] | None = None


class AdmissionReview(BaseModel):
    """Kubernetes AdmissionReview (v1)."""

    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    request: AdmissionRequest | None = None
    response: AdmissionResponse | None = None


VALID_PRIORITIES = {"low", "normal", "high", "critical"}
VALID_ASSESSMENT_PHASES = {"Pending", "Queued", "Running", "Succeeded", "Failed", "Cancelled"}
VALID_TENANT_STATUSES = {"Active", "Suspended", "Deleted"}
VALID_TENANT_PHASES = {"Provisioning", "Ready", "Suspended", "Terminating"}
VALID_POLICY_TIERS = {"free", "starter", "professional", "enterprise", "custom"}
VALID_POLICY_PHASES = {"Pending", "Ready", "Deprecated"}
VALID_WEBHOOK_EVENTS = {
    "assessment.started",
    "assessment.completed",
    "assessment.failed",
    "finding.critical",
    "finding.high",
}
VALID_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_FINDING_STATUSES = {"open", "in_progress", "resolved", "false_positive", "risk_accepted"}
VALID_SCANRESULT_PHASES = {"Pending", "Processing", "Completed", "Failed"}
REQUIRED_SCOPE_FIELDS = {"program", "authorized_by", "authorization_ref"}
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
EMAIL_PATTERN = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
URI_PATTERN = re.compile(r"^https?://")


def _configure_logging(log_level: str = "INFO", log_format: str = "text") -> None:
    """Configure structured JSON logging for the operator."""
    handler = logging.StreamHandler()
    if log_format == "json":
        import json

        class _JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                entry = {
                    "time": self.formatTime(record),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                }
                if record.exc_info:
                    entry["exception"] = self.formatException(record.exc_info)
                return json.dumps(entry)

        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=log_level.upper(), handlers=[handler])


def _handle_signal(signum: int, _frame: Any) -> None:
    """Handle shutdown signals."""
    sig_name = signal.Signals(signum).name
    log.info("Received signal %s, initiating graceful shutdown...", sig_name)
    _shutdown_event.set()


def _setup_signal_handlers() -> None:
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _handle_signal)


async def _check_postgresql() -> None:
    """Verify PostgreSQL connectivity for k8s jobs mode."""
    global _pg_pool
    try:
        import asyncpg

        dsn = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_DSN")
        if not dsn:
            raise RuntimeError(
                "DATABASE_URL or POSTGRES_DSN must be set when --enable-k8s-jobs-mode is enabled"
            )
        _pg_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
        await _pg_pool.execute("SELECT 1")
        log.info("PostgreSQL connection verified")
    except Exception as e:
        log.error("PostgreSQL connection failed: %s", e)
        raise


async def _check_redis(redis_address: str) -> None:
    """Verify Redis connectivity for streams mode."""
    global _redis_client
    try:
        import redis.asyncio as redis

        _redis_client = redis.from_url(redis_address, decode_responses=True)
        await _redis_client.ping()
        log.info("Redis connection verified at %s", redis_address)
    except Exception as e:
        log.error("Redis connection failed: %s", e)
        raise


async def _start_leader_election(namespace: str, lease_name: str = "ishastra-operator-leader") -> None:
    """Start leader election via Kubernetes leases."""
    global _leader_elector
    try:
        from kubernetes import client, config
        from kubernetes.client import CoordinationV1Api

        config.load_incluster_config()
        coordination_api = CoordinationV1Api()

        import uuid

        holder_id = f"{lease_name}-{uuid.uuid4().hex[:8]}"

        async def _renew_lease():
            while not _shutdown_event.is_set():
                try:
                    lease = client.V1Lease(
                        metadata=client.V1ObjectMeta(name=lease_name, namespace=namespace),
                        spec=client.V1LeaseSpec(
                            holder_identity=holder_id,
                            lease_duration_seconds=15,
                            renew_time=client.V1MicroTime(time=time.time()),
                        ),
                    )
                    try:
                        coordination_api.patch_namespaced_lease(lease_name, namespace, lease)
                    except client.ApiException as e:
                        if e.status == 404:
                            coordination_api.create_namespaced_lease(namespace, lease)
                        else:
                            raise
                except Exception as e:
                    log.warning("Leader election lease renewal failed: %s", e)
                await asyncio.sleep(5)

        _leader_elector = asyncio.create_task(_renew_lease())
        log.info("Leader election started for %s/%s", namespace, lease_name)
    except Exception as e:
        log.warning("Leader election not available: %s", e)


async def _stop_leader_election() -> None:
    """Stop leader election."""
    global _leader_elector
    if _leader_elector:
        _leader_elector.cancel()
        with suppress(asyncio.CancelledError):
            await _leader_elector
        _leader_elector = None


async def _start_controllers(namespace: str) -> None:
    """Start all CRD controllers."""
    global _controllers

    _controllers = [
        AssessmentJobReconciler(namespace=namespace),
        TenantReconciler(namespace=namespace),
        PolicyReconciler(namespace=namespace),
        ScanResultReconciler(namespace=namespace),
    ]

    for controller in _controllers:
        try:
            await controller.start()
            log.info("Started %s reconciler", controller.kind)
        except Exception as e:
            log.error("Failed to start %s reconciler: %s", controller.kind, e)


async def _stop_controllers() -> None:
    """Stop all CRD controllers."""
    global _controllers
    for controller in _controllers:
        try:
            await controller.stop()
            log.info("Stopped %s reconciler", controller.kind)
        except Exception as e:
            log.error("Failed to stop %s reconciler: %s", controller.kind, e)
    _controllers = []


class WebhookServer:
    """Admission webhook server for Ishastra CRDs."""

    def __init__(self, cert_dir: str, port: int):
        self.cert_dir = cert_dir
        self.port = port
        self.cert_file = os.path.join(cert_dir, "tls.crt")
        self.key_file = os.path.join(cert_dir, "tls.key")
        self.app = self._create_app()
        self.server: uvicorn.Server | None = None

    def _create_app(self) -> FastAPI:
        """Create the FastAPI app with webhook endpoints."""
        app = FastAPI(
            title="Ishastra Webhook",
            version="0.1.0",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )

        @app.get("/healthz", include_in_schema=False)
        async def webhook_health() -> Response:
            return Response(content="OK", media_type="text/plain")

        @app.post("/mutate-ishastra-io-v1alpha1-assessmentjob", include_in_schema=False)
        async def mutate_assessmentjob(request: Request) -> Response:
            return await self._handle_mutate_assessmentjob(request)

        @app.post("/validate-ishastra-io-v1alpha1-assessmentjob", include_in_schema=False)
        async def validate_assessmentjob(request: Request) -> Response:
            return await self._handle_validate_assessmentjob(request)

        @app.post("/validate-ishastra-io-v1alpha1-tenant", include_in_schema=False)
        async def validate_tenant(request: Request) -> Response:
            return await self._handle_validate_tenant(request)

        @app.post("/validate-ishastra-io-v1alpha1-policy", include_in_schema=False)
        async def validate_policy(request: Request) -> Response:
            return await self._handle_validate_policy(request)

        @app.post("/validate-ishastra-io-v1alpha1-scanresult", include_in_schema=False)
        async def validate_scanresult(request: Request) -> Response:
            return await self._handle_validate_scanresult(request)

        return app

    async def start(self) -> None:
        """Start the webhook server."""
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            log.warning("Webhook certs not found at %s, skipping webhook server", self.cert_dir)
            return

        config = uvicorn.Config(
            app=self.app,
            host="0.0.0.0",
            port=self.port,
            ssl_certfile=self.cert_file,
            ssl_keyfile=self.key_file,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        asyncio.create_task(self.server.serve())
        log.info("Webhook server listening on port %d", self.port)

    async def stop(self) -> None:
        """Stop the webhook server."""
        if self.server:
            self.server.should_exit = True
            self.server = None

    async def _handle_mutate_assessmentjob(self, request: Request) -> Response:
        """Handle mutating webhook for AssessmentJob CREATE/UPDATE."""
        try:
            body = await request.json()
            review = AdmissionReview(**body)
        except Exception as e:
            log.error("Failed to parse admission review: %s", e)
            return self._error_response(str(e), "BadRequest")

        if not review.request:
            return self._error_response("Missing request", "BadRequest")

        req = review.request
        obj = req.object or {}

        if req.operation not in ("CREATE", "UPDATE"):
            return self._allow_response(req.uid)

        patches: list[dict[str, Any]] = []
        spec = obj.get("spec", {})

        if "priority" not in spec:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/priority",
                    "value": "normal",
                }
            )

        if "ttlSecondsAfterFinished" not in spec:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/ttlSecondsAfterFinished",
                    "value": 3600,
                }
            )

        scope = spec.get("scope", {})
        if scope:
            if "include" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/include",
                        "value": [],
                    }
                )
            if "exclude" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/exclude",
                        "value": [],
                    }
                )
            if "authorized_networks" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/authorized_networks",
                        "value": [],
                    }
                )
            if "allowed_ports" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/allowed_ports",
                        "value": [],
                    }
                )
            if "allow_broad_networks" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/allow_broad_networks",
                        "value": False,
                    }
                )
            if "auth" not in scope:
                patches.append(
                    {
                        "op": "add",
                        "path": "/spec/scope/auth",
                        "value": {},
                    }
                )

        if "resources" not in spec:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/resources",
                    "value": {},
                }
            )

        if "env" not in spec:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/env",
                    "value": [],
                }
            )

        for field in ["nodeSelector", "tolerations", "affinity"]:
            if field not in spec:
                patches.append(
                    {
                        "op": "add",
                        "path": f"/spec/{field}",
                        "value": {} if field != "tolerations" else [],
                    }
                )

        if patches:
            patch_bytes = base64.b64encode(json.dumps(patches).encode()).decode()
            response = AdmissionResponse(
                uid=req.uid,
                allowed=True,
                patch=patch_bytes,
                patchType="JSONPatch",
            )
        else:
            response = AdmissionResponse(uid=req.uid, allowed=True)

        return Response(
            content=AdmissionReview(
                apiVersion="admission.k8s.io/v1", kind="AdmissionReview", response=response
            ).model_dump_json(),
            media_type="application/json",
        )

    async def _handle_validate_assessmentjob(self, request: Request) -> Response:
        """Handle validating webhook for AssessmentJob CREATE/UPDATE/DELETE."""
        try:
            body = await request.json()
            review = AdmissionReview(**body)
        except Exception as e:
            log.error("Failed to parse admission review: %s", e)
            return self._error_response(str(e), "BadRequest")

        if not review.request:
            return self._error_response("Missing request", "BadRequest")

        req = review.request
        obj = req.object or {}
        old_obj = req.oldObject or {}

        if req.operation in ("CREATE", "UPDATE"):
            errors = self._validate_assessmentjob_spec(obj.get("spec", {}))
            if errors:
                return self._deny_response(req.uid, "; ".join(errors))

            if req.operation == "UPDATE":
                immutable_errors = self._validate_assessmentjob_immutable(obj, old_obj)
                if immutable_errors:
                    return self._deny_response(req.uid, "; ".join(immutable_errors))

        return self._allow_response(req.uid)

    async def _handle_validate_tenant(self, request: Request) -> Response:
        """Handle validating webhook for Tenant CREATE/UPDATE/DELETE (cluster-scoped)."""
        try:
            body = await request.json()
            review = AdmissionReview(**body)
        except Exception as e:
            log.error("Failed to parse admission review: %s", e)
            return self._error_response(str(e), "BadRequest")

        if not review.request:
            return self._error_response("Missing request", "BadRequest")

        req = review.request
        obj = req.object or {}
        old_obj = req.oldObject or {}

        if req.operation in ("CREATE", "UPDATE"):
            errors = self._validate_tenant_spec(obj.get("spec", {}))
            if errors:
                return self._deny_response(req.uid, "; ".join(errors))

            if req.operation == "UPDATE":
                immutable_errors = self._validate_tenant_immutable(obj, old_obj)
                if immutable_errors:
                    return self._deny_response(req.uid, "; ".join(immutable_errors))

        return self._allow_response(req.uid)

    async def _handle_validate_policy(self, request: Request) -> Response:
        """Handle validating webhook for Policy CREATE/UPDATE/DELETE."""
        try:
            body = await request.json()
            review = AdmissionReview(**body)
        except Exception as e:
            log.error("Failed to parse admission review: %s", e)
            return self._error_response(str(e), "BadRequest")

        if not review.request:
            return self._error_response("Missing request", "BadRequest")

        req = review.request
        obj = req.object or {}
        old_obj = req.oldObject or {}

        if req.operation in ("CREATE", "UPDATE"):
            errors = self._validate_policy_spec(obj.get("spec", {}))
            if errors:
                return self._deny_response(req.uid, "; ".join(errors))

            if req.operation == "UPDATE":
                immutable_errors = self._validate_policy_immutable(obj, old_obj)
                if immutable_errors:
                    return self._deny_response(req.uid, "; ".join(immutable_errors))

        return self._allow_response(req.uid)

    async def _handle_validate_scanresult(self, request: Request) -> Response:
        """Handle validating webhook for ScanResult CREATE/UPDATE/DELETE."""
        try:
            body = await request.json()
            review = AdmissionReview(**body)
        except Exception as e:
            log.error("Failed to parse admission review: %s", e)
            return self._error_response(str(e), "BadRequest")

        if not review.request:
            return self._error_response("Missing request", "BadRequest")

        req = review.request
        obj = req.object or {}
        old_obj = req.oldObject or {}

        if req.operation in ("CREATE", "UPDATE"):
            errors = self._validate_scanresult_spec(obj.get("spec", {}))
            if errors:
                return self._deny_response(req.uid, "; ".join(errors))

            if req.operation == "UPDATE":
                immutable_errors = self._validate_scanresult_immutable(obj, old_obj)
                if immutable_errors:
                    return self._deny_response(req.uid, "; ".join(immutable_errors))

        return self._allow_response(req.uid)

    def _validate_assessmentjob_spec(self, spec: dict[str, Any]) -> list[str]:
        """Validate AssessmentJob spec against CRD schema."""
        errors = []

        if not spec.get("tenantId"):
            errors.append("spec.tenantId is required")

        scope = spec.get("scope", {})
        if not scope:
            errors.append("spec.scope is required")
        else:
            missing_scope = REQUIRED_SCOPE_FIELDS - set(scope.keys())
            if missing_scope:
                errors.append(f"spec.scope missing required fields: {', '.join(sorted(missing_scope))}")

            if "allowed_ports" in scope and not isinstance(scope["allowed_ports"], list):
                errors.append("spec.scope.allowed_ports must be an array")
            elif "allowed_ports" in scope:
                for port in scope["allowed_ports"]:
                    if not isinstance(port, int) or port < 1 or port > 65535:
                        errors.append("spec.scope.allowed_ports must contain integers 1-65535")

            if "authorized_networks" in scope and not isinstance(scope["authorized_networks"], list):
                errors.append("spec.scope.authorized_networks must be an array")

            if "allow_broad_networks" in scope and not isinstance(scope["allow_broad_networks"], bool):
                errors.append("spec.scope.allow_broad_networks must be boolean")

            if "include" in scope and not isinstance(scope["include"], list):
                errors.append("spec.scope.include must be an array")

            if "exclude" in scope and not isinstance(scope["exclude"], list):
                errors.append("spec.scope.exclude must be an array")

            if "auth" in scope and not isinstance(scope["auth"], dict):
                errors.append("spec.scope.auth must be an object")

        if not spec.get("policyRef"):
            errors.append("spec.policyRef is required")

        priority = spec.get("priority", "normal")
        if priority not in VALID_PRIORITIES:
            errors.append(f"spec.priority must be one of: {', '.join(sorted(VALID_PRIORITIES))}")

        ttl = spec.get("ttlSecondsAfterFinished")
        if ttl is not None and (not isinstance(ttl, int) or ttl < 0):
            errors.append("spec.ttlSecondsAfterFinished must be a non-negative integer")

        schedule_at = spec.get("scheduleAt")
        if schedule_at:
            try:
                from datetime import datetime

                datetime.fromisoformat(schedule_at.replace("Z", "+00:00"))
            except ValueError:
                errors.append("spec.scheduleAt must be a valid RFC3339 timestamp")

        resources = spec.get("resources", {})
        if resources:
            for limit_type in ["limits", "requests"]:
                if limit_type in resources:
                    res = resources[limit_type]
                    if not isinstance(res, dict):
                        errors.append(f"spec.resources.{limit_type} must be an object")
                    else:
                        for resource_name in ["cpu", "memory"]:
                            if resource_name in res and not isinstance(res[resource_name], str):
                                errors.append(f"spec.resources.{limit_type}.{resource_name} must be a string")

        node_selector = spec.get("nodeSelector")
        if node_selector is not None and not isinstance(node_selector, dict):
            errors.append("spec.nodeSelector must be an object")

        tolerations = spec.get("tolerations")
        if tolerations is not None and not isinstance(tolerations, list):
            errors.append("spec.tolerations must be an array")

        affinity = spec.get("affinity")
        if affinity is not None and not isinstance(affinity, dict):
            errors.append("spec.affinity must be an object")

        env = spec.get("env")
        if env is not None:
            if not isinstance(env, list):
                errors.append("spec.env must be an array")
            else:
                for i, e in enumerate(env):
                    if not isinstance(e, dict):
                        errors.append(f"spec.env[{i}] must be an object")
                    elif "name" not in e:
                        errors.append(f"spec.env[{i}].name is required")
                    elif not isinstance(e["name"], str):
                        errors.append(f"spec.env[{i}].name must be a string")

        return errors

    def _validate_assessmentjob_immutable(self, obj: dict[str, Any], old_obj: dict[str, Any]) -> list[str]:
        """Validate immutable fields on AssessmentJob UPDATE."""
        errors = []
        spec = obj.get("spec", {})
        old_spec = old_obj.get("spec", {})

        if spec.get("tenantId") != old_spec.get("tenantId"):
            errors.append("spec.tenantId is immutable")

        if spec.get("policyRef") != old_spec.get("policyRef"):
            errors.append("spec.policyRef is immutable")

        old_scope = old_spec.get("scope", {})
        new_scope = spec.get("scope", {})
        for field in ["program", "authorized_by", "authorization_ref"]:
            if new_scope.get(field) != old_scope.get(field):
                errors.append(f"spec.scope.{field} is immutable")

        return errors

    def _validate_tenant_spec(self, spec: dict[str, Any]) -> list[str]:
        """Validate Tenant spec against CRD schema."""
        errors = []

        name = spec.get("name")
        if not name:
            errors.append("spec.name is required")
        elif not self._is_valid_dns_label(name):
            errors.append(
                "spec.name must be a valid DNS-1123 label "
                "(lowercase alphanumeric, hyphens allowed, max 63 chars)"
            )

        if not spec.get("displayName"):
            errors.append("spec.displayName is required")
        elif len(spec["displayName"]) > 255:
            errors.append("spec.displayName must be at most 255 characters")

        contact_email = spec.get("contactEmail")
        if contact_email and not EMAIL_PATTERN.match(contact_email):
            errors.append("spec.contactEmail must be a valid email address")

        settings = spec.get("settings", {})
        if settings:
            if "maxConcurrentAssessments" in settings:
                v = settings["maxConcurrentAssessments"]
                if not isinstance(v, int) or v < 1:
                    errors.append("spec.settings.maxConcurrentAssessments must be a positive integer")

            if "allowedRegions" in settings and not isinstance(settings["allowedRegions"], list):
                errors.append("spec.settings.allowedRegions must be an array")

            quota = settings.get("quota", {})
            if quota:
                for field in ["monthlyBudgetUSD", "maxAssessmentsPerMonth", "maxFindingsRetentionDays"]:
                    if field in quota:
                        v = quota[field]
                        if field == "monthlyBudgetUSD":
                            if not isinstance(v, (int, float)) or v < 0:
                                errors.append(
                                    "spec.settings.quota.monthlyBudgetUSD must be a non-negative number"
                                )
                        else:
                            if not isinstance(v, int) or v < 0:
                                errors.append(f"spec.settings.quota.{field} must be a non-negative integer")

        status = spec.get("status", "Active")
        if status not in VALID_TENANT_STATUSES:
            errors.append(f"spec.status must be one of: {', '.join(sorted(VALID_TENANT_STATUSES))}")

        return errors

    def _validate_tenant_immutable(self, obj: dict[str, Any], old_obj: dict[str, Any]) -> list[str]:
        """Validate immutable fields on Tenant UPDATE."""
        errors = []
        spec = obj.get("spec", {})
        old_spec = old_obj.get("spec", {})

        if spec.get("name") != old_spec.get("name"):
            errors.append("spec.name is immutable")

        return errors

    def _validate_policy_spec(self, spec: dict[str, Any]) -> list[str]:
        """Validate Policy spec against CRD schema."""
        errors = []

        name = spec.get("name")
        if not name:
            errors.append("spec.name is required")
        elif not self._is_valid_dns_label(name):
            errors.append(
                "spec.name must be a valid DNS-1123 label "
                "(lowercase alphanumeric, hyphens allowed, max 63 chars)"
            )

        if not spec.get("tier"):
            errors.append("spec.tier is required")
        elif spec["tier"] not in VALID_POLICY_TIERS:
            errors.append(f"spec.tier must be one of: {', '.join(sorted(VALID_POLICY_TIERS))}")

        checks = spec.get("checks", {})
        if checks and not all(isinstance(v, bool) for v in checks.values()):
            errors.append("spec.checks values must be boolean")

        limits = spec.get("limits", {})
        if limits:
            for field in ["maxTargets", "maxConcurrentScans", "maxScanDurationMinutes"]:
                if field in limits:
                    v = limits[field]
                    if not isinstance(v, int) or v < 1:
                        errors.append(f"spec.limits.{field} must be a positive integer")

            if "allowedPorts" in limits and not isinstance(limits["allowedPorts"], list):
                errors.append("spec.limits.allowedPorts must be an array")
            elif "allowedPorts" in limits:
                for port in limits["allowedPorts"]:
                    if not isinstance(port, int) or port < 1 or port > 65535:
                        errors.append("spec.limits.allowedPorts must contain integers 1-65535")

            if "allowedNetworks" in limits and not isinstance(limits["allowedNetworks"], list):
                errors.append("spec.limits.allowedNetworks must be an array")

            rate_limit = limits.get("rateLimit", {})
            if rate_limit:
                if "requestsPerSecond" in rate_limit:
                    v = rate_limit["requestsPerSecond"]
                    if not isinstance(v, (int, float)) or v <= 0:
                        errors.append("spec.limits.rateLimit.requestsPerSecond must be a positive number")
                if "burst" in rate_limit:
                    v = rate_limit["burst"]
                    if not isinstance(v, int) or v < 1:
                        errors.append("spec.limits.rateLimit.burst must be a positive integer")

        notifications = spec.get("notifications", {})
        if notifications:
            webhook_url = notifications.get("webhookUrl")
            if webhook_url and not URI_PATTERN.match(webhook_url):
                errors.append("spec.notifications.webhookUrl must be a valid HTTP/HTTPS URI")

            webhook_events = notifications.get("webhookEvents", [])
            if webhook_events:
                for event in webhook_events:
                    if event not in VALID_WEBHOOK_EVENTS:
                        errors.append(
                            "spec.notifications.webhookEvents contains invalid event: "
                            f"{event}. Valid: {', '.join(sorted(VALID_WEBHOOK_EVENTS))}"
                        )

            email_recipients = notifications.get("emailRecipients", [])
            if email_recipients:
                for email in email_recipients:
                    if not EMAIL_PATTERN.match(email):
                        errors.append(f"spec.notifications.emailRecipients contains invalid email: {email}")

        compliance = spec.get("compliance", {})
        if compliance and not all(isinstance(v, list) for v in compliance.values()):
            errors.append("spec.compliance values must be arrays")

        return errors

    def _validate_policy_immutable(self, obj: dict[str, Any], old_obj: dict[str, Any]) -> list[str]:
        """Validate immutable fields on Policy UPDATE."""
        errors = []
        spec = obj.get("spec", {})
        old_spec = old_obj.get("spec", {})

        if spec.get("name") != old_spec.get("name"):
            errors.append("spec.name is immutable")

        if spec.get("tier") != old_spec.get("tier"):
            errors.append("spec.tier is immutable")

        return errors

    def _validate_scanresult_spec(self, spec: dict[str, Any]) -> list[str]:
        """Validate ScanResult spec against CRD schema."""
        errors = []

        if not spec.get("jobRef"):
            errors.append("spec.jobRef is required")

        if not spec.get("tenantId"):
            errors.append("spec.tenantId is required")

        findings = spec.get("findings", [])
        if findings:
            if not isinstance(findings, list):
                errors.append("spec.findings must be an array")
            else:
                for i, finding in enumerate(findings):
                    if not isinstance(finding, dict):
                        errors.append(f"spec.findings[{i}] must be an object")
                        continue

                    if not finding.get("id"):
                        errors.append(f"spec.findings[{i}].id is required")
                    if not finding.get("title"):
                        errors.append(f"spec.findings[{i}].title is required")

                    severity = finding.get("severity", "info")
                    if severity not in VALID_FINDING_SEVERITIES:
                        errors.append(
                            f"spec.findings[{i}].severity must be one of: "
                            f"{', '.join(sorted(VALID_FINDING_SEVERITIES))}"
                        )

                    cvss = finding.get("cvss")
                    if cvss is not None and (not isinstance(cvss, (int, float)) or cvss < 0 or cvss > 10):
                        errors.append(f"spec.findings[{i}].cvss must be a number between 0 and 10")

                    status = finding.get("status", "open")
                    if status not in VALID_FINDING_STATUSES:
                        errors.append(
                            f"spec.findings[{i}].status must be one of: "
                            f"{', '.join(sorted(VALID_FINDING_STATUSES))}"
                        )

                    port = finding.get("port")
                    if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                        errors.append(f"spec.findings[{i}].port must be an integer 1-65535")

                    for ts_field in ["firstSeen", "lastSeen"]:
                        ts = finding.get(ts_field)
                        if ts:
                            try:
                                from datetime import datetime

                                datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            except ValueError:
                                errors.append(
                                    f"spec.findings[{i}].{ts_field} must be a valid RFC3339 timestamp"
                                )

        summary = spec.get("summary", {})
        if summary:
            for field in ["total", "critical", "high", "medium", "low", "info"]:
                if field in summary:
                    v = summary[field]
                    if not isinstance(v, int) or v < 0:
                        errors.append(f"spec.summary.{field} must be a non-negative integer")

        scan_duration = spec.get("scanDurationSeconds")
        if scan_duration is not None and (not isinstance(scan_duration, int) or scan_duration < 0):
            errors.append("spec.scanDurationSeconds must be a non-negative integer")

        return errors

    def _validate_scanresult_immutable(self, obj: dict[str, Any], old_obj: dict[str, Any]) -> list[str]:
        """Validate immutable fields on ScanResult UPDATE."""
        errors = []
        spec = obj.get("spec", {})
        old_spec = old_obj.get("spec", {})

        if spec.get("jobRef") != old_spec.get("jobRef"):
            errors.append("spec.jobRef is immutable")

        if spec.get("tenantId") != old_spec.get("tenantId"):
            errors.append("spec.tenantId is immutable")

        if spec.get("assessmentId") != old_spec.get("assessmentId"):
            errors.append("spec.assessmentId is immutable")

        return errors

    def _is_valid_dns_label(self, name: str) -> bool:
        """Validate DNS-1123 label format."""
        if len(name) > 63:
            return False
        return bool(DNS_LABEL_PATTERN.match(name))

    def _allow_response(self, uid: str) -> Response:
        """Create allowed admission response."""
        response = AdmissionResponse(uid=uid, allowed=True)
        return Response(
            content=AdmissionReview(
                apiVersion="admission.k8s.io/v1", kind="AdmissionReview", response=response
            ).model_dump_json(),
            media_type="application/json",
        )

    def _deny_response(self, uid: str, message: str) -> Response:
        """Create denied admission response."""
        response = AdmissionResponse(
            uid=uid,
            allowed=False,
            status={"code": 422, "message": message},
        )
        return Response(
            content=AdmissionReview(
                apiVersion="admission.k8s.io/v1", kind="AdmissionReview", response=response
            ).model_dump_json(),
            media_type="application/json",
        )

    def _error_response(self, message: str, reason: str = "InternalError") -> Response:
        """Create error admission response."""

        response = AdmissionResponse(
            uid="",
            allowed=False,
            status={"code": 400, "message": f"{reason}: {message}"},
        )
        return Response(
            content=AdmissionReview(
                apiVersion="admission.k8s.io/v1", kind="AdmissionReview", response=response
            ).model_dump_json(),
            media_type="application/json",
        )


async def _start_webhook_server(
    cert_dir: str,
    port: int,
) -> WebhookServer | None:
    """Start the webhook server for admission control."""
    webhook_server = WebhookServer(cert_dir, port)
    await webhook_server.start()
    return webhook_server


async def _stop_webhook_server(webhook_server: WebhookServer | None) -> None:
    """Stop the webhook server."""
    if webhook_server:
        await webhook_server.stop()


def _create_health_app() -> FastAPI:
    """Create the FastAPI app for health probes."""
    app = FastAPI(
        title="Ishastra Operator Health",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz", include_in_schema=False)
    async def liveness() -> Response:
        """Kubernetes liveness probe - process is running."""
        return Response(content="OK", media_type="text/plain")

    @app.get("/ready", include_in_schema=False)
    async def readiness() -> Response:
        """Kubernetes readiness probe - operator is ready."""
        for controller in _controllers:
            if not hasattr(controller, "_running") or not controller._running:
                return Response(content="Not Ready", media_type="text/plain", status_code=503)
        return Response(content="OK", media_type="text/plain")

    return app


def _create_metrics_app() -> FastAPI:
    """Create the FastAPI app for metrics."""
    app = FastAPI(
        title="Ishastra Operator Metrics",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Prometheus metrics endpoint."""
        registry = get_registry()
        return Response(
            content=generate_latest(registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    return app


async def _run_server(config: uvicorn.Config) -> uvicorn.Server:
    """Run a uvicorn server and return it."""
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())

    await asyncio.sleep(0.1)
    return server


async def _start_servers(
    health_host: str,
    health_port: int,
    metrics_host: str,
    metrics_port: int,
) -> None:
    """Start health and metrics servers."""
    global _health_server, _metrics_server

    health_app = _create_health_app()
    metrics_app = _create_metrics_app()

    health_config = uvicorn.Config(
        app=health_app,
        host=health_host,
        port=health_port,
        log_level="warning",
        access_log=False,
    )
    metrics_config = uvicorn.Config(
        app=metrics_app,
        host=metrics_host,
        port=metrics_port,
        log_level="warning",
        access_log=False,
    )

    _health_server = await _run_server(health_config)
    _metrics_server = await _run_server(metrics_config)

    log.info("Health probe server listening on %s:%d", health_host, health_port)
    log.info("Metrics server listening on %s:%d", metrics_host, metrics_port)


async def _stop_servers() -> None:
    """Stop health and metrics servers."""
    global _health_server, _metrics_server
    if _health_server:
        _health_server.should_exit = True
        _health_server = None
    if _metrics_server:
        _metrics_server.should_exit = True
        _metrics_server = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Combined lifespan for the operator (used by webhook)."""

    init_metrics()
    yield


async def _run_operator(args: argparse.Namespace) -> int:
    """Run the operator asynchronously."""

    init_metrics()

    health_host, health_port_str = args.health_probe_bind_address.split(":")
    health_port = int(health_port_str)

    metrics_host, metrics_port_str = args.metrics_bind_address.split(":")
    metrics_port = int(metrics_port_str)

    namespace = os.environ.get("ISHASTRA_OPERATOR_NAMESPACE", "ishastra-system")

    log.info(
        "Starting Ishastra Operator: health=%s:%d, metrics=%s:%d, webhook=%d",
        health_host,
        health_port,
        metrics_host,
        metrics_port,
        args.webhook_port,
    )

    if args.enable_k8s_jobs_mode:
        await _check_postgresql()

    if args.enable_redis_streams_mode:
        await _check_redis(args.redis_address)

    await _start_servers(health_host, health_port, metrics_host, metrics_port)

    await _start_controllers(namespace)

    if args.leader_elect:
        await _start_leader_election(namespace)

    webhook_server = await _start_webhook_server(args.webhook_cert_dir, args.webhook_port)

    log.info("Ishastra Operator started successfully")

    await _shutdown_event.wait()

    log.info("Shutting down...")
    await _stop_webhook_server(webhook_server)
    await _stop_leader_election()
    await _stop_controllers()
    await _stop_servers()

    global _redis_client, _pg_pool
    if _redis_client:
        await _redis_client.close()
    if _pg_pool:
        await _pg_pool.close()

    log.info("Operator stopped cleanly")
    return 0


def parse_args() -> argparse.Namespace:
    """Parse command line arguments matching Helm chart expectations."""
    parser = argparse.ArgumentParser(description="Ishastra Kubernetes Operator")
    parser.add_argument("--leader-elect", action="store_true", help="Enable leader election")
    parser.add_argument("--metrics-bind-address", default=":8080", help="Address to bind metrics server")
    parser.add_argument("--health-probe-bind-address", default=":8081", help="Address to bind health probes")
    parser.add_argument("--webhook-port", type=int, default=9443, help="Port for webhook server")
    parser.add_argument(
        "--webhook-cert-dir",
        default="/tmp/k8s-webhook-server/serving-certs",
        help="Directory for webhook certificates",
    )
    parser.add_argument(
        "--enable-k8s-jobs-mode", action="store_true", help="Enable Kubernetes Jobs queue mode"
    )
    parser.add_argument(
        "--enable-redis-streams-mode", action="store_true", help="Enable Redis Streams queue mode"
    )
    parser.add_argument(
        "--redis-address", default="redis://localhost:6379", help="Redis address for streams mode"
    )
    parser.add_argument("--log-level", default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--log-format", default="text", choices=["text", "json"], help="Log format")
    return parser.parse_args()


def main() -> int:
    """Main entrypoint for the ishastra operator."""
    args = parse_args()

    _configure_logging(args.log_level, args.log_format)
    _setup_signal_handlers()

    try:
        return asyncio.run(_run_operator(args))
    except KeyboardInterrupt:
        log.info("Interrupted")
        return 130
    except Exception as e:
        log.exception("Operator failed: %s", e)
        return 1


def run_operator() -> None:
    """Entry point for console script."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
