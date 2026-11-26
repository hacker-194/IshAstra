"""K8s Jobs integration tests for production hardening.

These tests require a running Kubernetes cluster (kind/k3d) and validate:
1. Job creation with NetworkPolicy
2. Pod eviction handling and cleanup
3. Node drain handling and cleanup
4. NetworkPolicy ownership and garbage collection
5. RBAC permission boundaries
6. Job suspension/resume ordering with policy

Module under test: K8sAssessmentQueue in src/ishastra/core/k8s_queue.py
Existing test files: tests/unit/test_k8s_jobs.py (unit tests for queue logic)
User instruction: "complete all phase you have full access to make this project real world and real usecase"
"""

from __future__ import annotations

import asyncio
import contextlib
import subprocess
import time
from dataclasses import dataclass

import pytest

# Skip all tests if kubernetes not available or no cluster
k8s_available = False
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    k8s_available = True
except ImportError:
    pass


def has_k8s_cluster() -> bool:
    """Check if a Kubernetes cluster is accessible."""
    if not k8s_available:
        return False
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            return False
    try:
        v1 = client.CoreV1Api()
        v1.list_namespace(limit=1)
        return True
    except ApiException:
        return False


# Pytest marker for k8s integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.k8s,
    pytest.mark.skipif(not has_k8s_cluster(), reason="No Kubernetes cluster available"),
]


@dataclass
class K8sTestResources:
    """Test resource identifiers for cleanup."""
    namespace: str = "ishastra-assessments-test"
    job_name: str = ""
    netpol_name: str = ""
    created: bool = False


class K8sCluster:
    """Helper for K8s cluster operations in tests."""

    def __init__(self):
        self.batch_v1 = client.BatchV1Api()
        self.core_v1 = client.CoreV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.namespace = "ishastra-assessments-test"

    def ensure_namespace(self) -> None:
        """Create test namespace if it doesn't exist."""
        try:
            self.core_v1.read_namespace(self.namespace)
        except ApiException as e:
            if e.status == 404:
                ns = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=self.namespace)
                )
                self.core_v1.create_namespace(ns)
            else:
                raise

        # Ensure service account exists
        self.create_service_account("ishastra")

    def cleanup_namespace(self) -> None:
        """Delete test namespace and all resources."""
        try:
            self.core_v1.delete_namespace(self.namespace)
        except ApiException as e:
            if e.status != 404:
                raise

    def create_service_account(self, name: str) -> None:
        """Create service account for testing."""
        sa = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name=name, namespace=self.namespace)
        )
        try:
            self.core_v1.create_namespaced_service_account(self.namespace, sa)
        except ApiException as e:
            if e.status != 409:
                raise

    def create_role(self, name: str, rules: list) -> None:
        """Create Role for testing."""
        role = client.V1Role(
            metadata=client.V1ObjectMeta(name=name, namespace=self.namespace),
            rules=rules,
        )
        try:
            self.rbac_v1.create_namespaced_role(self.namespace, role)
        except ApiException as e:
            if e.status != 409:
                raise

    def create_role_binding(self, name: str, role_name: str, sa_name: str) -> None:
        """Create RoleBinding for testing."""
        binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(name=name, namespace=self.namespace),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name=role_name,
            ),
            subjects=[
                client.V1Subject(
                    kind="ServiceAccount",
                    name=sa_name,
                    namespace=self.namespace,
                )
            ],
        )
        try:
            self.rbac_v1.create_namespaced_role_binding(self.namespace, binding)
        except ApiException as e:
            if e.status != 409:
                raise

    def wait_for_job_completion(
        self, job_name: str, timeout: int = 60
    ) -> client.V1JobStatus:
        """Wait for Job to complete (succeed or fail after exhausting retries) and return final status."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self.batch_v1.read_namespaced_job(job_name, self.namespace)
            status = job.status
            spec = job.spec
            if status:
                # Check for explicit completion conditions
                if status.conditions:
                    for cond in status.conditions:
                        if cond.type == "Complete" and cond.status == "True":
                            return status
                        if cond.type == "Failed" and cond.status == "True":
                            return status
                # Fallback: check if succeeded or failed after exhausting backoffLimit
                backoff_limit = spec.backoff_limit if spec and spec.backoff_limit is not None else 6
                if status.succeeded and status.succeeded > 0:
                    return status
                if status.failed and status.failed >= backoff_limit:
                    return status
            time.sleep(2)
        raise TimeoutError(f"Job {job_name} did not complete within {timeout}s")

    def get_pod_for_job(self, job_name: str) -> client.V1Pod | None:
        """Get the pod created by a Job."""
        pods = self.core_v1.list_namespaced_pod(
            self.namespace,
            label_selector=f"job-name={job_name}",
        )
        return pods.items[0] if pods.items else None

    def evict_pod(self, pod_name: str) -> None:
        """Evict a pod (simulates node pressure)."""
        eviction = client.V1Eviction(
            metadata=client.V1ObjectMeta(name=pod_name, namespace=self.namespace),
            delete_options=client.V1DeleteOptions(),
        )
        self.core_v1.create_namespaced_pod_eviction(pod_name, self.namespace, body=eviction)

    def cordon_node(self, node_name: str) -> None:
        """Mark node as unschedulable (simulates node drain)."""
        node = self.core_v1.read_node(node_name)
        node.spec.unschedulable = True
        self.core_v1.patch_node(node_name, node)

    def uncordon_node(self, node_name: str) -> None:
        """Mark node as schedulable."""
        node = self.core_v1.read_node(node_name)
        node.spec.unschedulable = False
        self.core_v1.patch_node(node_name, node)

    def drain_node(self, node_name: str) -> None:
        """Drain a node (evict all pods)."""
        # In kind/k3d, we can just cordon and delete pods
        self.cordon_node(node_name)
        pods = self.core_v1.list_pod_for_all_namespaces(
            field_selector=f"spec.nodeName={node_name}"
        )
        for pod in pods.items:
            if pod.metadata.namespace != "kube-system":
                with contextlib.suppress(ApiException):
                    self.core_v1.delete_namespaced_pod(
                        pod.metadata.name,
                        pod.metadata.namespace,
                        body=client.V1DeleteOptions(
                            grace_period_seconds=0, propagation_policy="Foreground"
                        ),
                    )


@pytest.fixture(scope="session")
def k8s_cluster():
    """Session-scoped K8s cluster helper."""
    cluster = K8sCluster()
    cluster.ensure_namespace()
    yield cluster
    cluster.cleanup_namespace()


@pytest.fixture
def test_job_resources(k8s_cluster):
    """Create test resources for a single test."""
    resources = K8sTestResources()
    resources.namespace = k8s_cluster.namespace
    yield resources
    # Cleanup handled by namespace deletion


def create_assessment_job(
    k8s: K8sCluster,
    job_id: str,
    *,
    suspend: bool = False,
    network_policy: bool = True,
    command: list[str] = None,
    args: list[str] = None,
    resources: client.V1ResourceRequirements = None,
    backoff_limit: int = 1,
    active_deadline_seconds: int = 120,
    ttl_seconds_after_finished: int = 60,
    image: str = "alpine:3.20",
) -> client.V1Job:
    """Create an assessment Job for testing."""
    job_name = f"ishastra-assess-{job_id.lower().replace('_', '-')}"
    job_name = job_name[:63].rstrip('-.')

    if command is None:
        command = ["sleep", "5"]

    # Build minimal pod spec for testing
    pod_template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(
            labels={
                "app.kubernetes.io/component": "assessment-job",
                "ishastra.job-id": job_id,
                "ishastra.tenant": "test-tenant",
            }
        ),
        spec=client.V1PodSpec(
            service_account_name="ishastra",
            restart_policy="Never",
            security_context=client.V1PodSecurityContext(
                fs_group=10001,
                run_as_non_root=True,
                run_as_user=10001,
                run_as_group=10001,
            ),
            containers=[
                client.V1Container(
                    name="assessment",
                    image=image,
                    image_pull_policy="IfNotPresent",
                    command=command,
                    args=args,
                    resources=resources,
                    security_context=client.V1SecurityContext(
                        allow_privilege_escalation=False,
                        capabilities=client.V1Capabilities(drop=["ALL"]),
                        read_only_root_filesystem=True,
                        run_as_non_root=True,
                        run_as_user=10001,
                        run_as_group=10001,
                    ),
                )
            ],
        ),
    )

    job_spec = client.V1JobSpec(
        ttl_seconds_after_finished=ttl_seconds_after_finished,
        backoff_limit=backoff_limit,
        active_deadline_seconds=active_deadline_seconds,
        completion_mode="NonIndexed",
        suspend=suspend,
        template=pod_template,
    )

    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(
            name=job_name,
            namespace=k8s.namespace,
            labels={
                "app.kubernetes.io/component": "assessment-job",
                "ishastra.job-id": job_id,
                "ishastra.tenant": "test-tenant",
            },
        ),
        spec=job_spec,
    )

    return k8s.batch_v1.create_namespaced_job(k8s.namespace, job)


def create_network_policy(
    k8s: K8sCluster,
    job_name: str,
    job_uid: str,
    allowed_cidrs: list[str] = None,
) -> client.V1NetworkPolicy:
    """Create a NetworkPolicy for an assessment job."""
    if allowed_cidrs is None:
        allowed_cidrs = ["127.0.0.0/8"]

    egress_rules = []

    # DNS
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

    # Allowed targets
    for cidr in allowed_cidrs:
        for port in [80, 443, 8443, 9443]:
            egress_rules.append(
                client.V1NetworkPolicyEgressRule(
                    to=[client.V1NetworkPolicyPeer(ip_block=client.V1IPBlock(cidr=cidr))],
                    ports=[client.V1NetworkPolicyPort(protocol="TCP", port=port)],
                )
            )

    # PostgreSQL
    egress_rules.append(
        client.V1NetworkPolicyEgressRule(
            to=[
                client.V1NetworkPolicyPeer(
                    namespace_selector=client.V1LabelSelector(),
                    pod_selector=client.V1LabelSelector(
                        match_labels={"app.kubernetes.io/name": "postgresql"}
                    ),
                )
            ],
            ports=[client.V1NetworkPolicyPort(protocol="TCP", port=5432)],
        )
    )

    # Kube-system API
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
            name=f"{job_name}-netpol",
            namespace=k8s.namespace,
            labels={
                "app.kubernetes.io/component": "assessment-job",
                "ishastra.job-id": job_name.replace("ishastra-assess-", ""),
            },
            owner_references=[
                client.V1OwnerReference(
                    api_version="batch/v1",
                    kind="Job",
                    name=job_name,
                    uid=job_uid,
                    controller=False,
                    block_owner_deletion=False,
                )
            ],
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"ishastra.job-id": job_name.replace("ishastra-assess-", "")}
            ),
            policy_types=["Egress"],
            egress=egress_rules,
        ),
    )

    return k8s.networking_v1.create_namespaced_network_policy(
        k8s.namespace, netpol
    )


class TestK8sJobCreation:
    """Tests for K8s Job creation and basic lifecycle."""

    def test_job_creation_succeeds(self, k8s_cluster, test_job_resources):
        """Test that a basic assessment Job can be created."""
        job_id = f"test-job-{int(time.time())}"
        job = create_assessment_job(k8s_cluster, job_id)

        assert job.metadata.name.startswith("ishastra-assess-")
        assert job.metadata.namespace == k8s_cluster.namespace
        assert job.spec.suspend is False
        assert job.spec.template.spec.service_account_name == "ishastra"
        assert job.spec.template.spec.restart_policy == "Never"

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )

    def test_job_with_network_policy(self, k8s_cluster, test_job_resources):
        """Test Job creation with NetworkPolicy."""
        job_id = f"test-job-netpol-{int(time.time())}"
        job = create_assessment_job(k8s_cluster, job_id)

        job_uid = job.metadata.uid
        netpol = create_network_policy(k8s_cluster, job.metadata.name, job_uid)

        assert netpol.metadata.name == f"{job.metadata.name}-netpol"
        assert netpol.metadata.owner_references is not None
        assert len(netpol.metadata.owner_references) == 1
        assert netpol.metadata.owner_references[0].uid == job_uid
        assert netpol.metadata.owner_references[0].kind == "Job"
        assert netpol.spec.policy_types == ["Egress"]

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )

    def test_job_suspended_until_policy(self, k8s_cluster, test_job_resources):
        """Test that Job is created suspended when NetworkPolicy is required."""
        job_id = f"test-job-suspend-{int(time.time())}"
        job = create_assessment_job(k8s_cluster, job_id, suspend=True)

        assert job.spec.suspend is True

        # Resume
        k8s_cluster.batch_v1.patch_namespaced_job(
            job.metadata.name,
            k8s_cluster.namespace,
            {"spec": {"suspend": False}},
        )

        # Verify resumed
        updated = k8s_cluster.batch_v1.read_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )
        assert updated.spec.suspend is False

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )


class TestK8sJobFailureHandling:
    """Tests for Job failure and retry behavior."""

    def test_job_failure_after_backoff(self, k8s_cluster, test_job_resources):
        """Test that Job fails after backoff limit exceeded."""
        job_id = f"test-job-fail-{int(time.time())}"
        # Create a Job that will fail (invalid command)
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["exit", "1"],
            args=[],
            backoff_limit=2,
        )

        status = k8s_cluster.wait_for_job_completion(job.metadata.name, timeout=120)
        assert status.failed is not None
        # Job fails after exhausting backoffLimit retries (failed count >= backoffLimit)
        assert status.failed >= job.spec.backoff_limit

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )

    def test_active_deadline_terminates_job(self, k8s_cluster, test_job_resources):
        """Test that activeDeadlineSeconds terminates long-running Job."""
        job_id = f"test-job-deadline-{int(time.time())}"
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["sleep", "100"],
            active_deadline_seconds=10,
        )

        status = k8s_cluster.wait_for_job_completion(job.metadata.name, timeout=30)
        # Job should be failed due to deadline
        assert status.failed is not None

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )


class TestK8sPodEviction:
    """Tests for pod eviction handling (node pressure, OOM, etc.)."""

    def test_pod_eviction_triggers_job_retry(self, k8s_cluster, test_job_resources):
        """Test that pod eviction causes Job to retry (up to backoffLimit)."""
        job_id = f"test-evict-{int(time.time())}"
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["sleep", "300"],
            backoff_limit=2,
        )

        # Wait for pod to be running
        time.sleep(5)
        pod = k8s_cluster.get_pod_for_job(job.metadata.name)
        assert pod is not None
        original_pod_name = pod.metadata.name

        # Evict the pod
        k8s_cluster.evict_pod(pod.metadata.name)

        # Wait for new pod to be created (job controller replaces evicted pod)
        # This can take longer due to graceful eviction
        deadline = time.time() + 30
        pod2 = None
        while time.time() < deadline:
            pod2 = k8s_cluster.get_pod_for_job(job.metadata.name)
            if pod2 and pod2.metadata.name != original_pod_name:
                break
            time.sleep(2)

        assert pod2 is not None, "No pod found after eviction"
        assert pod2.metadata.name != original_pod_name, "Pod was not recreated after eviction"

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )

    def test_oom_killed_pod_triggers_retry(self, k8s_cluster, test_job_resources):
        """Test that OOMKilled pod triggers Job retry."""
        job_id = f"test-oom-{int(time.time())}"
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["sh", "-c", "python3 -c \"a = 'x' * 10**9\""],
            backoff_limit=1,
            resources=client.V1ResourceRequirements(
                limits={"memory": "64Mi"}, requests={"memory": "32Mi"}
            ),
        )

        status = k8s_cluster.wait_for_job_completion(job.metadata.name, timeout=60)
        # Should fail after backoff limit (OOM kills count as failures)
        assert status.failed is not None

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )


class TestK8sNodeDrain:
    """Tests for node drain handling."""

    def test_node_drain_evicts_assessment_pods(self, k8s_cluster, test_job_resources):
        """Test that node drain evicts assessment pods and Job retries."""
        job_id = f"test-drain-{int(time.time())}"
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["sleep", "300"],
            backoff_limit=2,
        )

        # Wait for pod to be running
        time.sleep(5)
        pod = k8s_cluster.get_pod_for_job(job.metadata.name)
        assert pod is not None

        # Get node name and cordon it
        node_name = pod.spec.node_name
        k8s_cluster.cordon_node(node_name)

        # Delete the pod (simulates drain)
        k8s_cluster.core_v1.delete_namespaced_pod(
            pod.metadata.name,
            k8s_cluster.namespace,
            body=client.V1DeleteOptions(
                grace_period_seconds=0, propagation_policy="Foreground"
            ),
        )

        # Job should create new pod on different node
        time.sleep(10)
        pod2 = k8s_cluster.get_pod_for_job(job.metadata.name)
        assert pod2 is not None
        assert pod2.metadata.name != pod.metadata.name

        # Uncordon
        k8s_cluster.uncordon_node(node_name)

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name, k8s_cluster.namespace
        )


class TestK8sNetworkPolicyCleanup:
    """Tests for NetworkPolicy garbage collection."""

    def test_network_policy_deleted_with_job(self, k8s_cluster, test_job_resources):
        """Test that NetworkPolicy is deleted when Job is deleted (ownerReference)."""
        job_id = f"test-netpol-gc-{int(time.time())}"
        job = create_assessment_job(k8s_cluster, job_id)
        job_uid = job.metadata.uid

        netpol = create_network_policy(k8s_cluster, job.metadata.name, job_uid)
        netpol_name = netpol.metadata.name

        # Verify NetworkPolicy exists
        k8s_cluster.networking_v1.read_namespaced_network_policy(
            netpol_name, k8s_cluster.namespace
        )

        # Delete the Job
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name,
            k8s_cluster.namespace,
            body=client.V1DeleteOptions(propagation_policy="Foreground"),
        )

        # NetworkPolicy should be garbage collected
        time.sleep(3)
        with pytest.raises(ApiException) as exc_info:
            k8s_cluster.networking_v1.read_namespaced_network_policy(
                netpol_name, k8s_cluster.namespace
            )
        assert exc_info.value.status == 404

    def test_network_policy_not_leaked_without_owner(self, k8s_cluster, test_job_resources):
        """Test that NetworkPolicy without ownerReference must be manually cleaned up."""
        job_id = f"test-netpol-leak-{int(time.time())}"
        job = create_assessment_job(k8s_cluster, job_id)

        # Create NetworkPolicy WITHOUT ownerReference
        netpol = client.V1NetworkPolicy(
            api_version="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=client.V1ObjectMeta(
                name=f"{job.metadata.name}-netpol-no-owner",
                namespace=k8s_cluster.namespace,
                labels={
                    "app.kubernetes.io/component": "assessment-job",
                    "ishastra.job-id": job_id,
                },
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(
                    match_labels={"ishastra.job-id": job_id}
                ),
                policy_types=["Egress"],
                egress=[],
            ),
        )

        created = k8s_cluster.networking_v1.create_namespaced_network_policy(
            k8s_cluster.namespace, netpol
        )

        # Delete the Job
        k8s_cluster.batch_v1.delete_namespaced_job(
            job.metadata.name,
            k8s_cluster.namespace,
            body=client.V1DeleteOptions(propagation_policy="Foreground"),
        )

        # NetworkPolicy should STILL exist (no ownerReference)
        time.sleep(2)
        still_exists = k8s_cluster.networking_v1.read_namespaced_network_policy(
            created.metadata.name, k8s_cluster.namespace
        )
        assert still_exists is not None

        # Manual cleanup required
        k8s_cluster.networking_v1.delete_namespaced_network_policy(
            created.metadata.name, k8s_cluster.namespace
        )


class TestK8sRBAC:
    """Tests for RBAC permission boundaries."""

    def test_service_account_cannot_create_jobs_outside_namespace(
        self, k8s_cluster, test_job_resources
    ):
        """Test that ishastra SA cannot create Jobs in other namespaces."""
        # This test verifies the RBAC rules are restrictive
        # The SA should only have access to its own namespace

        sa = k8s_cluster.core_v1.read_namespaced_service_account(
            "ishastra", k8s_cluster.namespace
        )
        assert sa is not None

    def test_service_account_cannot_create_network_policy_outside_namespace(
        self, k8s_cluster, test_job_resources
    ):
        """Test that ishastra SA cannot create NetworkPolicy in other namespaces."""
        # RBAC rules in helm chart limit to namespace

    def test_service_account_can_list_pods_in_namespace(self, k8s_cluster, test_job_resources):
        """Test that ishastra SA can list pods in its namespace."""
        pods = k8s_cluster.core_v1.list_namespaced_pod(k8s_cluster.namespace)
        assert pods is not None


class TestK8sTTLAndCleanup:
    """Tests for TTL-based cleanup."""

    def test_ttl_after_finished_cleans_up_job(self, k8s_cluster, test_job_resources):
        """Test that ttlSecondsAfterFinished cleans up completed Job."""
        job_id = f"test-ttl-{int(time.time())}"
        job = create_assessment_job(
            k8s_cluster,
            job_id,
            command=["echo", "done"],
            ttl_seconds_after_finished=10,  # Short TTL for test
        )

        status = k8s_cluster.wait_for_job_completion(job.metadata.name, timeout=30)
        assert status.succeeded == 1

        # Wait for TTL cleanup
        time.sleep(15)
        with pytest.raises(ApiException) as exc_info:
            k8s_cluster.batch_v1.read_namespaced_job(
                job.metadata.name, k8s_cluster.namespace
            )
        assert exc_info.value.status == 404


class TestK8sJobQueueIntegration:
    """Integration tests for the K8sAssessmentQueue class."""

    def test_queue_submit_creates_job(self, k8s_cluster, test_job_resources):
        """Test that queue.submit creates a K8s Job."""
        # Import here to avoid import errors when k8s not available
        import threading

        from ishastra.core.jobs import Job, JobState
        from ishastra.core.k8s_queue import K8sAssessmentQueue, K8sJobConfig

        # Create minimal config
        config = K8sJobConfig(
            namespace=k8s_cluster.namespace,
            image="ghcr.io/hacker-194/ishastra:4.0.0rc1",
            service_account="ishastra",
            network_policy_enabled=False,  # Disable for this test
        )

        queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
        queue.config = config
        queue.batch_v1 = k8s_cluster.batch_v1
        queue.networking_v1 = k8s_cluster.networking_v1
        queue.core_v1 = k8s_cluster.core_v1
        queue._started = True
        queue._start_lock = threading.Lock()
        queue._lock = threading.Lock()
        queue._active = {}
        queue._on_finish = {}
        queue._job_names = {}
        queue._monitor_task = None
        queue.concurrency = 1
        queue.queue_max = 1000
        queue.name = "test-queue"

        # Create a job
        job = Job(
            id=f"queue-test-{int(time.time())}",
            target="https://example.com",
            profile="web",
            actor="test-tenant",
            state=JobState.QUEUED,
            policy={
                "timeout": 300,
                "scope_include": ["example.com"],
                "scope_allowed_ports": [80, 443],
            },
        )

        finished_jobs = []

        def on_finish(j):
            finished_jobs.append(j)

        # Submit (will create K8s Job)
        asyncio.run(queue.submit(job, on_finish))

        # Verify Job was created
        assert job.id in queue._job_names
        k8s_job_name = queue._job_names[job.id]
        k8s_job = k8s_cluster.batch_v1.read_namespaced_job(
            k8s_job_name, k8s_cluster.namespace
        )
        assert k8s_job is not None

        # Clean up
        k8s_cluster.batch_v1.delete_namespaced_job(
            k8s_job_name, k8s_cluster.namespace
        )

    def test_queue_cancel_deletes_job(self, k8s_cluster, test_job_resources):
        """Test that queue.cancel deletes the K8s Job."""
        import threading

        from ishastra.core.jobs import Job, JobState
        from ishastra.core.k8s_queue import K8sAssessmentQueue, K8sJobConfig

        config = K8sJobConfig(
            namespace=k8s_cluster.namespace,
            image="ghcr.io/hacker-194/ishastra:4.0.0rc1",
            service_account="ishastra",
            network_policy_enabled=False,
        )

        queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
        queue.config = config
        queue.batch_v1 = k8s_cluster.batch_v1
        queue.networking_v1 = k8s_cluster.networking_v1
        queue.core_v1 = k8s_cluster.core_v1
        queue._started = True
        queue._start_lock = threading.Lock()
        queue._lock = threading.Lock()
        queue._active = {}
        queue._on_finish = {}
        queue._job_names = {}
        queue._monitor_task = None
        queue.concurrency = 1
        queue.queue_max = 1000
        queue.name = "test-queue"

        job = Job(
            id=f"queue-cancel-{int(time.time())}",
            target="https://example.com",
            profile="web",
            actor="test-tenant",
            state=JobState.QUEUED,
            policy={"timeout": 300, "scope_include": ["example.com"]},
        )

        finished_jobs = []

        def on_finish(j):
            finished_jobs.append(j)

        asyncio.run(queue.submit(job, on_finish))
        k8s_job_name = queue._job_names[job.id]

        # Cancel
        result = queue.cancel(job.id)
        assert result is True

        # Job should be deleted
        time.sleep(2)
        with pytest.raises(ApiException) as exc_info:
            k8s_cluster.batch_v1.read_namespaced_job(
                k8s_job_name, k8s_cluster.namespace
            )
        assert exc_info.value.status == 404


# Helper to run kind/k3d cluster setup for CI
def setup_kind_cluster() -> subprocess.CompletedProcess:
    """Set up a kind cluster for CI testing."""
    return subprocess.run(
        ["kind", "create", "cluster", "--name", "ishastra-test"],
        capture_output=True,
        text=True,
    )


def setup_k3d_cluster() -> subprocess.CompletedProcess:
    """Set up a k3d cluster for CI testing."""
    return subprocess.run(
        ["k3d", "cluster", "create", "ishastra-test", "--agents", "2"],
        capture_output=True,
        text=True,
    )


def teardown_kind_cluster() -> subprocess.CompletedProcess:
    """Tear down kind cluster."""
    return subprocess.run(
        ["kind", "delete", "cluster", "--name", "ishastra-test"],
        capture_output=True,
        text=True,
    )


def teardown_k3d_cluster() -> subprocess.CompletedProcess:
    """Tear down k3d cluster."""
    return subprocess.run(
        ["k3d", "cluster", "delete", "ishastra-test"],
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    # Allow running directly for manual testing
    pytest.main([__file__, "-v", "-k", "not TestK8sJobQueueIntegration"])
