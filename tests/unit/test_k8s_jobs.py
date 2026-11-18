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
from strix.core.k8s_queue import K8sAssessmentQueue, K8sJobConfig, _job_name  # noqa: E402
from strix.core.scope import Scope  # noqa: E402


def test_job_name_is_an_rfc1123_subdomain():
    assert _job_name("job_abc123") == "strix-assess-job-abc123"
    assert _job_name("job_" + "x" * 100) == ("strix-assess-job-" + "x" * 100)[:63]
    # every emitted name satisfies the DNS-1123 subdomain rule
    assert all(c.islower() or c.isdigit() or c in "-." for c in _job_name("job_A_B"))


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
