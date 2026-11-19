"""K8s Jobs mode: the Job name and the scope must survive into the manifest.

These regression tests cover the two defects found by running the chart against
a real cluster: Kubernetes rejects ``_`` in a Job name, and the Job used to be
built with default ports/networks instead of the authorized policy.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("kubernetes")

from strix.core import jobs  # noqa: E402
from strix.core.k8s_queue import (
    K8sAssessmentQueue,
    K8sJobConfig,
    _job_name,
    get_k8s_assessment_queue,
)  # noqa: E402
from strix.core.scope import Scope  # noqa: E402


def test_job_name_is_an_rfc1123_subdomain():
    assert _job_name("job_abc123") == "strix-assess-job-abc123"
    assert _job_name("job_" + "x" * 100) == ("strix-assess-job-" + "x" * 100)[:63]
    # every emitted name satisfies the DNS-1123 subdomain rule
    assert all(c.islower() or c.isdigit() or c in "-." for c in _job_name("job_A_B"))


def test_production_k8s_queue_rejects_placeholder_image(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.delenv("STRIX_K8S_IMAGE", raising=False)
    monkeypatch.delenv("STRIX_K8S_IMAGE_REPOSITORY", raising=False)
    with pytest.raises(ValueError, match="published Strix image"):
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
    # no cluster needed: the manifest builder only reads self.config
    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="strix:test")
    manifest = queue._build_job_manifest(job, "strix-assess-test")
    env = {e.name: e.value for e in manifest.spec.template.spec.containers[0].env}
    carried = json.loads(env["STRIX_SCOPE_JSON"])
    assert carried["allowed_ports"] == [8080]
    assert carried["authorized_networks"] == ["127.0.0.0/8"]


class _StubNetworking:
    def __init__(self) -> None:
        self.body = None

    def create_namespaced_network_policy(self, namespace: str, body) -> None:  # noqa: ANN001
        self.body = body


def test_network_policy_is_collected_with_its_job():
    """Without an ownerReference, one NetworkPolicy leaks per assessment."""
    import asyncio

    scope = Scope(program="p", authorized_by="a", authorization_ref="r", include=["127.0.0.1"])
    job = jobs.prepare(target="http://127.0.0.1:8080", profile="web", actor="t", scope_snapshot=scope)
    queue = K8sAssessmentQueue.__new__(K8sAssessmentQueue)
    queue.config = K8sJobConfig(image="strix:test")
    queue.networking_v1 = _StubNetworking()

    asyncio.run(queue._create_network_policy(job, "strix-assess-test", owner_uid="uid-123"))

    refs = queue.networking_v1.body.metadata.owner_references
    assert refs, "network policy has no owner, so nothing deletes it"
    assert (refs[0].kind, refs[0].uid, refs[0].name) == ("Job", "uid-123", "strix-assess-test")
