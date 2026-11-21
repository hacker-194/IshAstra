"""Policy CRD Reconciler.

Manages the lifecycle of Policy custom resources for scope and compliance policies.
Matches the Helm CRD schema exactly.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from kubernetes import client
from kubernetes.client import ApiException

from ishastra.operator.controllers.base import BaseReconciler

log = logging.getLogger(__name__)


VALID_TIERS = ["free", "starter", "professional", "enterprise", "custom"]
VALID_PHASES = ["Pending", "Ready", "Deprecated"]
VALID_WEBHOOK_EVENTS = [
    "assessment.started",
    "assessment.completed",
    "assessment.failed",
    "finding.critical",
    "finding.high",
]
DEFAULT_LIMITS = {
    "maxTargets": 100,
    "maxConcurrentScans": 5,
    "maxScanDurationMinutes": 120,
}
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


class PolicyReconciler(BaseReconciler):
    """Reconciler for Policy resources.

    Schema (matching Helm CRD):
    - spec.name (DNS-1123 label, required)
    - spec.displayName (string)
    - spec.description (string)
    - spec.tier (enum: free, starter, professional, enterprise, custom, required)
    - spec.checks (object with boolean values)
    - spec.limits (object): maxTargets, maxConcurrentScans, maxScanDurationMinutes,
      allowedPorts[], allowedNetworks[], rateLimit{requestsPerSecond, burst}
    - spec.notifications (webhookUrl, webhookEvents[], emailRecipients[])
    - spec.compliance (object with array values)
    - status.phase (enum: Pending, Ready, Deprecated)
    - status.createdAt, updatedAt
    """

    def __init__(self, namespace: str | None = None):
        super().__init__(
            group="ishastra.io",
            version="v1alpha1",
            plural="policies",
            namespace=namespace,
            resync_period=120,
        )

    @property
    def kind(self) -> str:
        return "Policy"

    async def reconcile(self, resource: dict[str, Any]) -> None:
        """Reconcile a Policy to desired state."""
        name = resource.get("metadata", {}).get("name", "unknown")
        spec = resource.get("spec", {})
        status = resource.get("status", {})

        policy_name = spec.get("name")
        display_name = spec.get("displayName")
        description = spec.get("description")
        tier = spec.get("tier")
        checks = spec.get("checks", {})
        limits = self._apply_default_limits(spec.get("limits", {}))
        notifications = spec.get("notifications", {})
        compliance = spec.get("compliance", {})

        phase = status.get("phase", "Pending")
        spec_hash = status.get("specHash")

        log.info("Reconciling Policy %s (tier: %s, phase: %s)", name, tier, phase)

        if not policy_name:
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
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

        if not tier:
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
                    "message": "spec.tier is required",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "MissingField",
                            "message": "tier is required",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if tier not in VALID_TIERS:
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
                    "message": f"spec.tier must be one of: {', '.join(VALID_TIERS)}",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "InvalidTier",
                            "message": f"tier must be one of: {', '.join(VALID_TIERS)}",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if not self._is_valid_dns_label(policy_name):
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
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

        if checks and not all(isinstance(v, bool) for v in checks.values()):
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
                    "message": "spec.checks values must be boolean",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "InvalidChecks",
                            "message": "checks values must be boolean",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        validation_error = self._validate_notifications(notifications)
        if validation_error:
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
                    "message": validation_error,
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "InvalidNotifications",
                            "message": validation_error,
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        if compliance and not all(isinstance(v, list) for v in compliance.values()):
            await self._patch_status(
                name,
                {
                    "phase": "Pending",
                    "message": "spec.compliance values must be arrays",
                    "conditions": [
                        {
                            "type": "ValidationFailed",
                            "status": "True",
                            "reason": "InvalidCompliance",
                            "message": "compliance values must be arrays",
                            "lastTransitionTime": self._now_iso(),
                        }
                    ],
                },
            )
            return

        new_hash = self._compute_hash(spec)

        if phase == "Pending":
            await self._handle_pending(
                name,
                spec,
                status,
                policy_name,
                display_name,
                description,
                tier,
                checks,
                limits,
                notifications,
                compliance,
                new_hash,
            )
        elif phase == "Ready":
            await self._handle_ready(name, spec, status, policy_name, new_hash, spec_hash)
        elif phase == "Deprecated":
            await self._handle_deprecated(name, spec, status)

    def _is_valid_dns_label(self, name: str) -> bool:
        """Validate DNS-1123 label format."""
        if len(name) > 63:
            return False
        return bool(DNS_LABEL_PATTERN.match(name))

    def _apply_default_limits(self, limits: dict[str, Any]) -> dict[str, Any]:
        """Apply default values for limits per CRD schema."""
        result = DEFAULT_LIMITS.copy()
        result.update(limits)
        return result

    def _validate_notifications(self, notifications: dict[str, Any]) -> str | None:
        """Validate notifications per CRD schema."""
        if not notifications:
            return None

        webhook_url = notifications.get("webhookUrl")
        if webhook_url and not self._is_valid_uri(webhook_url):
            return "spec.notifications.webhookUrl must be a valid URI"

        webhook_events = notifications.get("webhookEvents", [])
        if webhook_events:
            for event in webhook_events:
                if event not in VALID_WEBHOOK_EVENTS:
                    return (
                        "spec.notifications.webhookEvents contains invalid event: "
                        f"{event}. Valid: {', '.join(VALID_WEBHOOK_EVENTS)}"
                    )

        email_recipients = notifications.get("emailRecipients", [])
        if email_recipients:
            for email in email_recipients:
                if not self._is_valid_email(email):
                    return f"spec.notifications.emailRecipients contains invalid email: {email}"

        return None

    def _is_valid_uri(self, uri: str) -> bool:
        """Basic URI validation."""
        return uri.startswith(("http://", "https://"))

    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation."""
        return "@" in email and "." in email.split("@")[-1]

    async def _handle_pending(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        policy_name: str,
        display_name: str,
        description: str,
        tier: str,
        checks: dict[str, Any],
        limits: dict[str, Any],
        notifications: dict[str, Any],
        compliance: dict[str, Any],
        new_hash: str,
    ) -> None:
        """Handle Pending phase - create/distribute policy."""

        await self._store_policy_configmap(name, spec)

        await self._patch_status(
            name,
            {
                "phase": "Ready",
                "specHash": new_hash,
                "createdAt": self._now_iso(),
                "updatedAt": self._now_iso(),
                "message": "Policy activated",
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "Activated",
                        "message": "Policy activated and distributed",
                        "lastTransitionTime": self._now_iso(),
                    },
                ],
            },
        )

        log.info("Policy %s activated with tier %s", name, tier)

    async def _handle_ready(
        self,
        name: str,
        spec: dict[str, Any],
        status: dict[str, Any],
        policy_name: str,
        new_hash: str,
        current_hash: str,
    ) -> None:
        """Handle Ready phase - ensure policy is up to date."""

        if current_hash != new_hash:
            await self._store_policy_configmap(name, spec)
            await self._patch_status(
                name,
                {
                    "specHash": new_hash,
                    "updatedAt": self._now_iso(),
                    "message": "Policy updated",
                    "conditions": [
                        {
                            "type": "Updated",
                            "status": "True",
                            "reason": "SpecChanged",
                            "message": "Policy spec updated",
                            "lastTransitionTime": self._now_iso(),
                        },
                    ],
                },
            )
            log.info("Policy %s updated", name)
            return

        await self._patch_status(
            name,
            {
                "updatedAt": self._now_iso(),
            },
        )

    async def _handle_deprecated(self, name: str, spec: dict[str, Any], status: dict[str, Any]) -> None:
        """Handle Deprecated phase - no action needed."""

    async def _store_policy_configmap(self, name: str, spec: dict[str, Any]) -> None:
        """Store policy in ConfigMaps - system namespace and tenant namespaces."""
        policy_name: str = spec.get("name", name)
        display_name = spec.get("displayName")
        description = spec.get("description")
        tier: str = spec.get("tier", "standard")
        checks = spec.get("checks", {})
        limits = self._apply_default_limits(spec.get("limits", {}))
        notifications = spec.get("notifications", {})
        compliance = spec.get("compliance", {})

        policy_data = {
            "name": policy_name,
            "displayName": display_name,
            "description": description,
            "tier": tier,
            "checks": checks,
            "limits": limits,
            "notifications": notifications,
            "compliance": compliance,
        }

        await self._create_or_update_configmap(
            name=f"ishastra-policy-{name}",
            namespace=self.namespace or "ishastra-system",
            policy_data=policy_data,
            policy_name=policy_name,
            tier=tier,
        )

        try:
            namespaces = self.core_api.list_namespace(
                label_selector="ishastra.io/managed-by=ishastra-operator"
            )
            for ns in namespaces.items:
                ns_name = ns.metadata.name if ns.metadata else "default"
                assert ns_name is not None
                await self._create_or_update_configmap(
                    name=f"ishastra-policy-{name}",
                    namespace=ns_name,
                    policy_data=policy_data,
                    policy_name=policy_name,
                    tier=tier,
                )
        except ApiException as e:
            log.warning("Failed to distribute policy to tenant namespaces: %s", e)

    async def _create_or_update_configmap(
        self,
        name: str,
        namespace: str,
        policy_data: dict[str, Any],
        policy_name: str,
        tier: str,
    ) -> None:
        """Create or update a ConfigMap with policy data."""
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace,
                labels={
                    "ishastra.io/policy": name.replace("ishastra-policy-", ""),
                    "ishastra.io/policy-name": policy_name,
                    "ishastra.io/tier": tier,
                    "ishastra.io/managed-by": "ishastra-operator",
                },
            ),
            data={
                "policy.json": json.dumps(policy_data, indent=2),
            },
        )
        try:
            self.core_api.create_namespaced_config_map(namespace, cm)
        except ApiException as e:
            if e.status == 409:
                self.core_api.patch_namespaced_config_map(name, namespace, cm)
            else:
                raise

    def _compute_hash(self, spec: dict[str, Any]) -> str:
        """Compute hash of spec for change detection."""
        spec_str = json.dumps(spec, sort_keys=True)
        return hashlib.sha256(spec_str.encode()).hexdigest()[:16]

    def _now_iso(self) -> str:
        """Get current time in ISO format."""
        return datetime.now(UTC).isoformat()

    async def cleanup(self, resource: dict[str, Any]) -> None:
        """Clean up resources on deletion."""
        name = resource.get("metadata", {}).get("name", "unknown")
        log.info("Cleaning up Policy %s", name)

        with contextlib.suppress(Exception):
            self.core_api.delete_namespaced_config_map(
                f"ishastra-policy-{name}", self.namespace or "ishastra-system"
            )

        try:
            namespaces = self.core_api.list_namespace(
                label_selector="ishastra.io/managed-by=ishastra-operator"
            )
            for ns in namespaces.items:
                try:
                    ns_name = ns.metadata.name if ns.metadata else "default"
                    assert ns_name is not None
                    self.core_api.delete_namespaced_config_map(f"ishastra-policy-{name}", ns_name)
                except Exception:
                    pass
        except Exception:
            pass
