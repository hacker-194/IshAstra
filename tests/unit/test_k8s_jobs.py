"""K8s Jobs mode: the Job name and the scope must survive into the manifest.

These regression tests cover the two defects found by running the chart against
a real cluster: Kubernetes rejects ``_`` in a Job name, and the Job used to be
built with default ports/networks instead of the authorized policy.
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

pytest.importorskip("kubernetes")

from ishastra.core import jobs
from ishastra.core.k8s_queue import (
    K8sAssessmentQueue,
    K8sJobConfig,
    _job_name,
    get_k8s_assessment_queue,
)
from ishastra.security.authorization.scope import Scope


def test_job_name_is_an_rfc1123_subdomain():
    assert _job_name("job_abc123") == "ishastra-assess-job-abc123"
    assert _job_name("job_" + "x" * 100) == ("ishastra-assess-job-" + "x" * 100)[:63]

    assert all(c.islower() or c.isdigit() or c in "-." for c in _job_name("job_A_B"))


def test_production_k8s_queue_rejects_placeholder_image(monkeypatch):
    monkeypatch.setenv("ISHASTRA_ENV", "production")
    monkeypatch.delenv("ISHASTRA_K8S_IMAGE", raising=False)
    monkeypatch.delenv("ISHASTRA_K8S_IMAGE_REPOSITORY", raising=False)
    with pytest.raises(ValueError, match="published Ishastra image"):
        get_k8s_assessment_queue()


def test_job_manifest_carries_the_authorized_scope():
    scope = Scope(
        program="p",
        authorized_by="a@example.com",
        authorization_ref="REF-1",
        include=["127.0.0.1"],
        authorized_networks=["127.0.0.0/8"],
        allowed_ports=[8080],
    )
    job = jobs.prepare(target="http://127.0.0.1:8080", profile="web", actor="t", scope_snapshot=scope)

    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="ishastra:test")
    manifest = queue._build_job_manifest(job, "ishastra-assess-test")
    env = {e.name: e.value for e in manifest.spec.template.spec.containers[0].env}
    carried = json.loads(env["ISHASTRA_SCOPE_JSON"])
    assert carried["allowed_ports"] == [8080]
    assert carried["authorized_networks"] == ["127.0.0.0/8"]


class _StubNetworking:
    def __init__(self) -> None:
        self.body = None

    def create_namespaced_network_policy(self, namespace: str, body) -> None:
        self.body = body


def test_network_policy_is_collected_with_its_job():
    """Without an ownerReference, one NetworkPolicy leaks per assessment."""
    import asyncio

    scope = Scope(program="p", authorized_by="a", authorization_ref="r", include=["127.0.0.1"])
    job = jobs.prepare(target="http://127.0.0.1:8080", profile="web", actor="t", scope_snapshot=scope)
    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="ishastra:test")
    queue.networking_v1 = _StubNetworking()

    asyncio.run(queue._create_network_policy(job, "ishastra-assess-test", owner_uid="uid-123"))

    refs = queue.networking_v1.body.metadata.owner_references
    assert refs, "network policy has no owner, so nothing deletes it"
    assert (refs[0].kind, refs[0].uid, refs[0].name) == ("Job", "uid-123", "ishastra-assess-test")


def test_wildcard_only_scope_cannot_be_pinned_and_is_refused(monkeypatch):
    """NetworkPolicy has no hostname match, so an unpinnable scope must fail."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    scope = Scope(
        program="p",
        authorized_by="a",
        authorization_ref="r",
        include=["*.example.com"],
    )
    job = jobs.prepare(target="https://app.example.com", profile="web", actor="t", scope_snapshot=scope)
    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="ishastra:test")
    queue.networking_v1 = _StubNetworking()

    with pytest.raises(RuntimeError, match="egress"):
        asyncio.run(queue._create_network_policy(job, "ishastra-assess-test"))


def test_hostname_scope_is_pinned_to_its_resolved_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    scope = Scope(program="p", authorized_by="a", authorization_ref="r", include=["app.example.com"])
    job = jobs.prepare(target="https://app.example.com", profile="web", actor="t", scope_snapshot=scope)

    assert K8sAssessmentQueue._scope_egress_cidrs(job) == ["93.184.216.34/32"]


def test_authorized_networks_win_over_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("must not resolve"))
    scope = Scope(
        program="p",
        authorized_by="a",
        authorization_ref="r",
        include=["app.example.com"],
        authorized_networks=["198.51.100.0/24"],
    )
    job = jobs.prepare(target="https://app.example.com", profile="web", actor="t", scope_snapshot=scope)

    assert K8sAssessmentQueue._scope_egress_cidrs(job) == ["198.51.100.0/24"]


class _StubBatch:
    """Records job lifecycle calls so ordering can be asserted."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.created_body = None

    def create_namespaced_job(self, namespace: str, body):
        self.created_body = body
        self.calls.append(("create", body.metadata.name))
        return body

    def delete_namespaced_job(self, name: str, namespace: str, body) -> None:
        self.calls.append(("delete", name))

    def patch_namespaced_job(self, name: str, namespace: str, body) -> None:
        self.calls.append(("patch", name))
        self.patched_body = body


class _FailingNetworking:
    def create_namespaced_network_policy(self, namespace: str, body) -> None:
        raise RuntimeError("apiserver said no")


def _queue_with(batch, networking) -> K8sAssessmentQueue:
    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="ishastra:test")
    queue.batch_v1 = batch
    queue.networking_v1 = networking
    return queue


def test_job_is_suspended_until_its_egress_policy_exists():
    scope = Scope(program="p", authorized_by="a", authorization_ref="r", include=["127.0.0.1"])
    job = jobs.prepare(target="http://127.0.0.1:8080", profile="web", actor="t", scope_snapshot=scope)
    batch = _StubBatch()
    queue = _queue_with(batch, _StubNetworking())

    asyncio.run(queue._create_k8s_job(job, "ishastra-assess-test"))

    assert batch.created_body.spec.suspend is True
    assert [call[0] for call in batch.calls] == ["create", "patch"]
    assert batch.patched_body == {"spec": {"suspend": False}}


def test_policy_failure_deletes_the_job_instead_of_running_it_open():
    scope = Scope(program="p", authorized_by="a", authorization_ref="r", include=["127.0.0.1"])
    job = jobs.prepare(target="http://127.0.0.1:8080", profile="web", actor="t", scope_snapshot=scope)
    batch = _StubBatch()
    queue = _queue_with(batch, _FailingNetworking())

    with pytest.raises(RuntimeError, match="apiserver said no"):
        asyncio.run(queue._create_k8s_job(job, "ishastra-assess-test"))

    assert ("delete", "ishastra-assess-test") in batch.calls
    assert not hasattr(batch, "patched_body"), "a job must never be resumed without its policy"
