"""Base reconciler for Ishastra CRD controllers."""

from __future__ import annotations

import abc
import asyncio
import contextlib
import logging
from typing import Any, cast

from kubernetes import client, config
from kubernetes.client import ApiException

log = logging.getLogger(__name__)


class BaseReconciler(abc.ABC):
    """Base class for all Ishastra CRD reconcilers."""

    def __init__(
        self,
        group: str,
        version: str,
        plural: str,
        namespace: str | None = None,
        resync_period: int = 300,
    ):
        self.group = group
        self.version = version
        self.plural = plural
        self.namespace = namespace
        self.resync_period = resync_period
        self._running = False
        self._task: asyncio.Task | None = None

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        self.api = client.CustomObjectsApi()
        self.core_api = client.CoreV1Api()

    @property
    @abc.abstractmethod
    def kind(self) -> str:
        """CRD kind (e.g., AssessmentJob, Tenant)."""

    @abc.abstractmethod
    async def reconcile(self, resource: dict[str, Any]) -> None:
        """Reconcile a single resource to desired state."""

    async def _get_resource(self, name: str) -> dict[str, Any] | None:
        """Get a single resource by name."""
        try:
            if self.namespace:
                obj = self.api.get_namespaced_custom_object(
                    self.group, self.version, self.namespace, self.plural, name
                )
            else:
                obj = self.api.get_cluster_custom_object(self.group, self.version, self.plural, name)
            return obj if isinstance(obj, dict) else None
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    async def _list_resources(self) -> list[dict[str, Any]]:
        """List all resources of this type."""
        try:
            if self.namespace:
                result = self.api.list_namespaced_custom_object(
                    self.group, self.version, self.namespace, self.plural
                )
            else:
                result = self.api.list_cluster_custom_object(self.group, self.version, self.plural)
            items = result.get("items", []) if isinstance(result, dict) else []
            return [item for item in items if isinstance(item, dict)]
        except ApiException as e:
            log.error("Failed to list %s: %s", self.kind, e)
            return []

    async def _patch_status(self, name: str, status: dict[str, Any]) -> None:
        """Patch the status subresource."""
        try:
            if self.namespace:
                self.api.patch_namespaced_custom_object_status(
                    self.group,
                    self.version,
                    self.namespace,
                    self.plural,
                    name,
                    {"status": status},
                )
            else:
                self.api.patch_cluster_custom_object_status(
                    self.group,
                    self.version,
                    self.plural,
                    name,
                    {"status": status},
                )
        except ApiException as e:
            log.error("Failed to patch status for %s/%s: %s", self.kind, name, e)

    async def _add_finalizer(self, name: str, finalizer: str) -> None:
        """Add a finalizer to the resource."""
        try:
            if self.namespace:
                resource = cast(
                    dict[str, Any],
                    self.api.get_namespaced_custom_object(
                        self.group, self.version, self.namespace, self.plural, name
                    ),
                )
            else:
                resource = cast(
                    dict[str, Any],
                    self.api.get_cluster_custom_object(self.group, self.version, self.plural, name),
                )

            finalizers = resource.get("metadata", {}).get("finalizers", [])
            if finalizer not in finalizers:
                finalizers.append(finalizer)
                if self.namespace:
                    self.api.patch_namespaced_custom_object(
                        self.group,
                        self.version,
                        self.namespace,
                        self.plural,
                        name,
                        {"metadata": {"finalizers": finalizers}},
                    )
                else:
                    self.api.patch_cluster_custom_object(
                        self.group,
                        self.version,
                        self.plural,
                        name,
                        {"metadata": {"finalizers": finalizers}},
                    )
        except ApiException as e:
            log.error("Failed to add finalizer to %s/%s: %s", self.kind, name, e)

    async def _remove_finalizer(self, name: str, finalizer: str) -> None:
        """Remove a finalizer from the resource."""
        try:
            if self.namespace:
                resource = cast(
                    dict[str, Any],
                    self.api.get_namespaced_custom_object(
                        self.group, self.version, self.namespace, self.plural, name
                    ),
                )
            else:
                resource = cast(
                    dict[str, Any],
                    self.api.get_cluster_custom_object(self.group, self.version, self.plural, name),
                )

            finalizers = resource.get("metadata", {}).get("finalizers", [])
            if finalizer in finalizers:
                finalizers.remove(finalizer)
                if self.namespace:
                    self.api.patch_namespaced_custom_object(
                        self.group,
                        self.version,
                        self.namespace,
                        self.plural,
                        name,
                        {"metadata": {"finalizers": finalizers}},
                    )
                else:
                    self.api.patch_cluster_custom_object(
                        self.group,
                        self.version,
                        self.plural,
                        name,
                        {"metadata": {"finalizers": finalizers}},
                    )
        except ApiException as e:
            log.error("Failed to remove finalizer from %s/%s: %s", self.kind, name, e)

    async def _has_finalizer(self, resource: dict[str, Any], finalizer: str) -> bool:
        """Check if resource has a finalizer."""
        finalizers = resource.get("metadata", {}).get("finalizers", [])
        return finalizer in finalizers

    async def _is_deleted(self, resource: dict[str, Any]) -> bool:
        """Check if resource is being deleted."""
        return resource.get("metadata", {}).get("deletionTimestamp") is not None

    async def start(self) -> None:
        """Start the reconciler loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("Started %s reconciler", self.kind)

    async def stop(self) -> None:
        """Stop the reconciler loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("Stopped %s reconciler", self.kind)

    async def _run(self) -> None:
        """Main reconciliation loop."""
        while self._running:
            try:
                await self._reconcile_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Error in %s reconciler: %s", self.kind, e)

            await asyncio.sleep(self.resync_period)

    async def _reconcile_all(self) -> None:
        """Reconcile all resources."""
        resources = await self._list_resources()
        for resource in resources:
            try:
                await self._reconcile_one(resource)
            except Exception as e:
                name = resource.get("metadata", {}).get("name", "unknown")
                log.error("Failed to reconcile %s/%s: %s", self.kind, name, e)

    async def _reconcile_one(self, resource: dict[str, Any]) -> None:
        """Reconcile a single resource."""
        name = resource.get("metadata", {}).get("name", "unknown")

        if await self._is_deleted(resource):
            await self._handle_deletion(resource)
            return

        finalizer = f"ishastra.io/{self.plural}-finalizer"
        if not await self._has_finalizer(resource, finalizer):
            await self._add_finalizer(name, finalizer)
            return

        await self.reconcile(resource)

    async def _handle_deletion(self, resource: dict[str, Any]) -> None:
        """Handle resource deletion."""
        name = resource.get("metadata", {}).get("name", "unknown")
        finalizer = f"ishastra.io/{self.plural}-finalizer"

        if await self._has_finalizer(resource, finalizer):
            try:
                await self.cleanup(resource)
            except Exception as e:
                log.error("Cleanup failed for %s/%s: %s", self.kind, name, e)
                return

            await self._remove_finalizer(name, finalizer)

    @abc.abstractmethod
    async def cleanup(self, resource: dict[str, Any]) -> None:
        """Clean up resources on deletion."""
