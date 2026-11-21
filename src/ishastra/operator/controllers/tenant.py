"""Tenant CRD Reconciler.

Manages the lifecycle of Tenant custom resources for multi-tenancy.
Matches the Helm CRD schema exactly.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from kubernetes import client
from kubernetes.client import ApiException, RbacAuthorizationV1Api
from kubernetes.client import RbacV1Subject as V1Subject

from ishastra.operator.controllers.base import BaseReconciler

log = logging.getLogger(__name__)


class TenantReconciler(BaseReconciler):
    """Reconciler for Tenant resources.

    Schema (matching Helm CRD):
    - spec.name (DNS-1123 label, required)
    - spec.displayName (string, required)
    - spec.description (string)
    - spec.contactEmail (email format)
    - spec.settings (object): defaultPolicy, maxConcurrentAssessments, allowedRegions[],
      quota{monthlyBudgetUSD, maxAssessmentsPerMonth, maxFindingsRetentionDays}
    - spec.status (enum: Active, Suspended, Deleted, default: Active)
    - status.phase (enum: Provisioning, Ready, Suspended, Terminating)
    - status.namespace, createdAt, lastAssessmentAt, assessmentsCount, conditions[]
    """

    def __init__(self, namespace: str | None = None):
        super().__init__(
            group="ishastra.io",
            version="v1alpha1",
            plural="tenants",
            namespace=None,
            resync_period=60,
        )

    @property
    def kind(self) -> str:
        return "Tenant"

    async def reconcile(self, resource: dict[str, Any]) -> None:
        """Reconcile a Tenant to desired state."""
        name = resource.get("metadata", {}).get("name", "unknown")
        spec = resource.get("spec", {})
        status = resource.get("status", {})

        tenant_name = spec.get("name")
        display_name = spec.get("displayName")
        description = spec.get("description")
        contact_email = spec.get("contactEmail")
        settings = spec.get("settings", {})
        tenant_status = spec.get("status", "Active")

        phase = status.get("phase", "Provisioning")
        tenant_namespace = status.get("namespace")
        last_assessment_at = status.get("lastAssessmentAt")
        assessments_count = status.get("assessmentsCount", 0)

        log.info("Reconciling Tenant %s (phase: %s)", name, phase)

        if not tenant_name:
            await self._patch_status(
                name,
                {
                    "phase": "Provisioning",
                    "message": "spec.name is required",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "MissingField",
                            "message": "name is required",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if not display_name:
            await self._patch_status(
                name,
                {
                    "phase": "Provisioning",
                    "message": "spec.displayName is required",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "MissingField",
                            "message": "displayName is required",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if not self._is_valid_dns_label(tenant_name):
            await self._patch_status(
                name,
                {
                    "phase": "Provisioning",
                    "message": "spec.name must be a valid DNS-1123 label",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "InvalidName",
                            "message": "name must be a valid DNS-1123 label",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if phase == "Provisioning":
            await self._handle_provisioning(
                name, spec, status, tenant_name, display_name, description, contact_email, settings
            )
        elif phase == "Ready":
            await self._handle_ready(
                name,
                spec,
                status,
                tenant_name,
                tenant_namespace,
                settings,
                tenant_status,
                assessments_count,
                last_assessment_at,
            )
        elif phase == "Suspended":
            await self._handle_suspended(name, spec, status, tenant_name, tenant_namespace)
        elif phase == "Terminating":
            await self._handle_terminating(name, spec, status, tenant_name, tenant_namespace)

    def _is_valid_dns_label(self, name: str) -> bool:
        """Validate DNS-1123 label format."""
        if len(name) > 63:
            return False

        pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
        return bool(re.match(pattern, name))

    async def _handle_provisioning(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        tenant_name: str,
        display_name: str,
        description: str | None,
        contact_email: str | None,
        settings: dict[str, Any],
    ) -> None:
        """Handle Provisioning phase - create tenant resources."""

        ns_name = f"ishastra-tenant-{tenant_name}"
        await self._create_tenant_namespace(ns_name, tenant_name, display_name, description, contact_email)

        await self._create_tenant_rbac(ns_name)

        quota = settings.get("quota", {})
        await self._create_resource_quotas(ns_name, quota)

        await self._create_settings_configmap(ns_name, tenant_name, settings)

        now = self._now_iso()
        await self._patch_status(
            name,
            {
                "phase": "Ready",
                "namespace": ns_name,
                "createdAt": now,
                "lastAssessmentAt": None,
                "assessmentsCount": 0,
                "message": "Tenant provisioned successfully",
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "Provisioned",
                        "message": "Tenant resources created",
                        "lastTransitionTime": now,
                    },
                ],
            },
        )

        log.info("Tenant %s provisioned with namespace %s", tenant_name, ns_name)

    async def _handle_ready(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        tenant_name: str,
        tenant_namespace: str | None,
        settings: dict[str, Any],
        tenant_status: str,
        assessments_count: int,
        last_assessment_at: str | None,
    ) -> None:
        """Handle Ready phase - ensure resources are up to date."""
        ns_name = tenant_namespace or f"ishastra-tenant-{tenant_name}"
        now = self._now_iso()

        if tenant_status == "Suspended":
            await self._patch_status(
                name,
                {
                    "phase": "Suspended",
                    "message": "Tenant suspended",
                    "conditions": [
                        {
                            "type": "Suspended",
                            "status": "True",
                            "reason": "UserSuspended",
                            "message": "Tenant suspended by user",
                            "lastTransitionTime": now,
                        }
                    ],
                },
            )
            return

        if tenant_status == "Deleted":
            await self._patch_status(
                name,
                {
                    "phase": "Terminating",
                    "message": "Tenant marked for deletion",
                    "conditions": [
                        {
                            "type": "Terminating",
                            "status": "True",
                            "reason": "UserDeleted",
                            "message": "Tenant marked for deletion",
                            "lastTransitionTime": now,
                        }
                    ],
                },
            )
            return

        await self._ensure_namespace(ns_name, tenant_name, spec.get("displayName", ""))

        quota = settings.get("quota", {})
        await self._sync_resource_quotas(ns_name, quota)

        await self._sync_settings_configmap(ns_name, tenant_name, settings)

        await self._patch_status(
            name,
            {
                "phase": "Ready",
                "namespace": ns_name,
                "assessmentsCount": assessments_count,
                "lastAssessmentAt": last_assessment_at,
                "message": "Tenant is ready",
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "Reconciled",
                        "message": "Tenant resources up to date",
                        "lastTransitionTime": now,
                    }
                ],
            },
        )

    async def _handle_suspended(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        tenant_name: str,
        tenant_namespace: str | None,
    ) -> None:
        """Handle Suspended phase - scale down resources."""
        ns_name = tenant_namespace or f"ishastra-tenant-{tenant_name}"
        now = self._now_iso()

        await self._scale_down_tenant_workloads(ns_name)

        tenant_status = spec.get("status", "Active")
        if tenant_status == "Active":
            await self._patch_status(
                name,
                {
                    "phase": "Ready",
                    "message": "Tenant reactivated",
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "True",
                            "reason": "Reactivated",
                            "message": "Tenant reactivated",
                            "lastTransitionTime": now,
                        }
                    ],
                },
            )

    async def _handle_terminating(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        tenant_name: str,
        tenant_namespace: str | None,
    ) -> None:
        """Handle Terminating phase - cleanup before final deletion."""

    async def _create_tenant_namespace(
        self,
        ns_name: str,
        tenant_name: str,
        display_name: str,
        description: str | None,
        contact_email: str | None,
    ) -> None:
        """Create namespace for tenant."""
        ns = client.V1Namespace(
            metadata=client.V1ObjectMeta(
                name=ns_name,
                labels={
                    "ishastra.io/tenant": tenant_name,
                    "ishastra.io/managed-by": "ishastra-operator",
                    "ishastra.io/display-name": display_name,
                },
                annotations={
                    "ishastra.io/description": description or "",
                    "ishastra.io/contact-email": contact_email or "",
                },
            )
        )
        try:
            self.core_api.create_namespace(ns)
        except ApiException as e:
            if e.status != 409:
                raise

    async def _create_tenant_rbac(self, ns_name: str) -> None:
        """Create RBAC roles for tenant."""

        role = client.V1Role(
            metadata=client.V1ObjectMeta(
                name="ishastra-tenant-role",
                namespace=ns_name,
            ),
            rules=[
                client.V1PolicyRule(
                    api_groups=["", "apps", "batch"],
                    resources=["pods", "services", "configmaps", "secrets", "jobs", "cronjobs"],
                    verbs=["get", "list", "watch", "create", "update", "patch", "delete"],
                ),
            ],
        )
        rbac_api = RbacAuthorizationV1Api()
        try:
            rbac_api.create_namespaced_role(ns_name, role)
        except ApiException as e:
            if e.status != 409:
                raise

        binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(
                name="ishastra-tenant-binding",
                namespace=ns_name,
            ),
            subjects=[
                V1Subject(
                    kind="ServiceAccount",
                    name="default",
                    namespace=ns_name,
                ),
            ],
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name="ishastra-tenant-role",
            ),
        )
        try:
            rbac_api.create_namespaced_role_binding(ns_name, binding)
        except ApiException as e:
            if e.status != 409:
                raise

    async def _create_resource_quotas(self, ns_name: str, quota: dict[str, Any]) -> None:
        """Create resource quotas for tenant namespace based on spec.settings.quota."""
        hard = {}

        hard = {
            "limits.cpu": str(quota.get("cpu", "2")),
            "requests.cpu": str(quota.get("cpuRequest", "1")),
            "limits.memory": str(quota.get("memory", "4Gi")),
            "requests.memory": str(quota.get("memoryRequest", "2Gi")),
            "pods": str(quota.get("pods", "10")),
            "services": str(quota.get("services", "5")),
            "secrets": str(quota.get("secrets", "20")),
            "configmaps": str(quota.get("configmaps", "20")),
        }

        annotations = {
            "ishastra.io/monthly-budget-usd": str(quota.get("monthlyBudgetUSD", "")),
            "ishastra.io/max-assessments-per-month": str(quota.get("maxAssessmentsPerMonth", "")),
            "ishastra.io/max-findings-retention-days": str(quota.get("maxFindingsRetentionDays", "")),
        }

        quota_obj = client.V1ResourceQuota(
            metadata=client.V1ObjectMeta(
                name="ishastra-tenant-quota",
                namespace=ns_name,
                annotations={k: v for k, v in annotations.items() if v},
            ),
            spec=client.V1ResourceQuotaSpec(hard=hard),
        )
        try:
            self.core_api.create_namespaced_resource_quota(ns_name, quota_obj)
        except ApiException as e:
            if e.status != 409:
                raise

    async def _create_settings_configmap(
        self, ns_name: str, tenant_name: str, settings: dict[str, Any]
    ) -> None:
        """Create settings ConfigMap."""
        quota = settings.get("quota", {})
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name="ishastra-tenant-settings",
                namespace=ns_name,
            ),
            data={
                "tenantName": tenant_name,
                "defaultPolicy": settings.get("defaultPolicy", ""),
                "maxConcurrentAssessments": str(settings.get("maxConcurrentAssessments", 10)),
                "allowedRegions": ",".join(settings.get("allowedRegions", [])),
                "monthlyBudgetUSD": str(quota.get("monthlyBudgetUSD", "")),
                "maxAssessmentsPerMonth": str(quota.get("maxAssessmentsPerMonth", "")),
                "maxFindingsRetentionDays": str(quota.get("maxFindingsRetentionDays", "")),
            },
        )
        try:
            self.core_api.create_namespaced_config_map(ns_name, cm)
        except ApiException as e:
            if e.status == 409:
                self.core_api.patch_namespaced_config_map("ishastra-tenant-settings", ns_name, cm)
            else:
                raise

    async def _ensure_namespace(self, ns_name: str, tenant_name: str, display_name: str) -> None:
        """Ensure tenant namespace exists."""
        try:
            self.core_api.read_namespace(ns_name)
        except ApiException as e:
            if e.status == 404:
                await self._create_tenant_namespace(ns_name, tenant_name, display_name, "", "")
            else:
                raise

    async def _sync_resource_quotas(self, ns_name: str, quota: dict[str, Any]) -> None:
        """Sync resource quotas with spec."""

        try:
            self.core_api.delete_namespaced_resource_quota("ishastra-tenant-quota", ns_name)
        except ApiException as e:
            if e.status != 404:
                raise
        await self._create_resource_quotas(ns_name, quota)

    async def _sync_settings_configmap(
        self, ns_name: str, tenant_name: str, settings: dict[str, Any]
    ) -> None:
        """Sync tenant settings."""
        await self._create_settings_configmap(ns_name, tenant_name, settings)

    async def _scale_down_tenant_workloads(self, ns_name: str) -> None:
        """Scale down all deployments in tenant namespace."""
        apps_api = client.AppsV1Api()
        try:
            deployments = apps_api.list_namespaced_deployment(ns_name)
            for dep in deployments.items:
                if dep.spec and dep.spec.replicas != 0:
                    dep_name = dep.metadata.name if dep.metadata else ""
                    if dep_name:
                        apps_api.patch_namespaced_deployment_scale(
                            dep_name, ns_name, {"spec": {"replicas": 0}}
                        )
        except ApiException as e:
            if e.status != 404:
                raise

    def _now_iso(self) -> str:
        """Get current time in ISO format."""
        return datetime.now(UTC).isoformat()

    async def cleanup(self, resource: dict[str, Any]) -> None:
        """Clean up resources on deletion."""
        name = resource.get("metadata", {}).get("name", "unknown")
        tenant_name = resource.get("spec", {}).get("name", name)
        ns_name = f"ishastra-tenant-{tenant_name}"

        log.info("Cleaning up Tenant %s (namespace: %s)", name, ns_name)

        try:
            self.core_api.delete_namespace(ns_name)
        except ApiException as e:
            if e.status != 404:
                raise

        log.info("Tenant %s namespace deleted", name)
