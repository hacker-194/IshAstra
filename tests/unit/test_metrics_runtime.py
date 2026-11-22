"""The job, queue, adapter and database series are exported with runbook labels."""

from __future__ import annotations

import pytest

import ishastra.metrics as metrics
from ishastra.core.jobs import Job, JobState, execute
from ishastra.metrics import get_registry, init_metrics


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Start each test from a registry whose globals all point at it.

    Another test may have reset ``_registry``; reusing that stale object would
    make the samples and the recorders disagree about which registry is live.
    """
    metrics._registry = None
    init_metrics()
    yield


def _value(name: str, labels: dict[str, str]) -> float:
    return get_registry().get_sample_value(name, labels) or 0.0


def test_failed_job_records_state_transition_tenant_and_duration():
    init_metrics()
    job = Job(target="https://example.com/", profile="web", actor="test", policy={})
    job.scope_snapshot = None

    failed_before = _value("ishastra_jobs_total", {"state": "failed", "tenant": "global"})
    transition_before = _value("ishastra_job_state_transitions_total", {"from": "queued", "to": "failed"})
    duration_before = _value("ishastra_job_duration_seconds_count", {"profile": "web", "tenant": "global"})
    active_before = _value("ishastra_jobs_active", {"tenant": "global"})

    execute(job)

    assert job.state is JobState.FAILED
    assert _value("ishastra_jobs_total", {"state": "failed", "tenant": "global"}) == failed_before + 1
    assert (
        _value("ishastra_job_state_transitions_total", {"from": "queued", "to": "failed"})
        == transition_before + 1
    )
    assert (
        _value("ishastra_job_duration_seconds_count", {"profile": "web", "tenant": "global"})
        == duration_before + 1
    )

    assert _value("ishastra_jobs_active", {"tenant": "global"}) == active_before


def test_running_job_moves_the_active_gauge():
    init_metrics()
    job = Job(target="https://example.com/", profile="web", actor="acme", policy={})
    job.scope_snapshot = None
    before = _value("ishastra_jobs_active", {"tenant": "global"})

    from ishastra.core.jobs import _set_state

    _set_state(job, JobState.RUNNING)
    assert _value("ishastra_jobs_active", {"tenant": "global"}) == before + 1
    _set_state(job, JobState.COMPLETED)
    assert _value("ishastra_jobs_active", {"tenant": "global"}) == before


def test_adapter_error_and_timeout_series():
    init_metrics()
    tenant = "acme"
    errors = _value(
        "ishastra_adapter_errors_total",
        {"adapter": "ishastra-http", "error_type": "timeout", "tenant": tenant},
    )
    timeouts = _value("ishastra_adapter_timeout_total", {"adapter": "ishastra-http", "tenant": tenant})

    from ishastra import metrics

    metrics.record_adapter_error("ishastra-http", "timeout", tenant, timeout=True)

    assert (
        _value(
            "ishastra_adapter_errors_total",
            {"adapter": "ishastra-http", "error_type": "timeout", "tenant": tenant},
        )
        == errors + 1
    )
    assert (
        _value("ishastra_adapter_timeout_total", {"adapter": "ishastra-http", "tenant": tenant})
        == timeouts + 1
    )


def test_queue_and_worker_gauges_track_the_values_given():
    init_metrics()
    from ishastra import metrics

    metrics.record_queue_depth(3, "inprocess")
    metrics.record_worker_occupancy(total=4, busy=2, mode="inprocess")

    assert _value("ishastra_queue_depth", {"mode": "inprocess"}) == 3
    assert _value("ishastra_workers_total", {"mode": "inprocess"}) == 4
    assert _value("ishastra_worker_busy", {"mode": "inprocess"}) == 2


def test_db_pool_gauges_and_acquire_histogram():
    init_metrics()
    from ishastra import metrics

    metrics.record_db_pool("sqlite", 10, 7)
    before = _value("ishastra_db_pool_acquire_seconds_count", {"dialect": "sqlite"})
    metrics.observe_db_acquire("sqlite", 0.002)

    assert _value("ishastra_db_pool_size", {"dialect": "sqlite"}) == 10
    assert _value("ishastra_db_pool_available", {"dialect": "sqlite"}) == 7
    assert _value("ishastra_db_pool_acquire_seconds_count", {"dialect": "sqlite"}) == before + 1


def test_audit_append_records_event_and_chain_length():
    from ishastra.audit import AuditChain

    init_metrics()
    before = _value("ishastra_audit_events_total", {"tenant": "acme", "event_type": "policy_created"})
    chain = AuditChain(persistent=False, hmac_key="test-key")

    chain.append({"type": "policy_created", "tenant": "acme"})

    assert (
        _value("ishastra_audit_events_total", {"tenant": "acme", "event_type": "policy_created"})
        == before + 1
    )
    assert _value("ishastra_audit_chain_length", {}) == 1


def test_job_findings_are_counted_by_severity_and_detector():
    from ishastra.core.findings import Finding

    init_metrics()
    before = _value(
        "ishastra_findings_total",
        {"tenant": "global", "severity": "high", "adapter": "ishastra-http"},
    )
    job = Job(target="https://example.com/", profile="web", actor="test", policy={})
    job.scope_snapshot = None
    job.findings = [
        Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="high",
            confidence="high",
            detector="ishastra-http",
            detector_version="1",
            evidence="no header",
        )
    ]

    execute(job)

    assert (
        _value(
            "ishastra_findings_total", {"tenant": "global", "severity": "high", "adapter": "ishastra-http"}
        )
        == before + 1
    )


def test_queue_wait_and_webhook_and_auth_recorders():
    init_metrics()
    from ishastra import metrics

    queue_before = _value("ishastra_job_queue_duration_seconds_count", {"profile": "web"})
    metrics.observe_job_queue("web", 0.4)
    assert _value("ishastra_job_queue_duration_seconds_count", {"profile": "web"}) == queue_before + 1

    delivered_before = _value(
        "ishastra_webhook_deliveries_total", {"tenant": "global", "status": "delivered"}
    )
    metrics.record_webhook_delivery("delivered", None)
    assert (
        _value("ishastra_webhook_deliveries_total", {"tenant": "global", "status": "delivered"})
        == delivered_before + 1
    )

    failures_before = _value("ishastra_auth_failures_total", {"tenant": "global", "reason": "bad_key"})
    metrics.record_auth_failure("bad_key", None)
    assert (
        _value("ishastra_auth_failures_total", {"tenant": "global", "reason": "bad_key"})
        == failures_before + 1
    )
