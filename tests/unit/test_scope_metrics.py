"""Scope gate decisions are exported with the labels the runbook queries."""

from __future__ import annotations

from unittest.mock import patch

import ishastra.metrics as metrics
from ishastra.security.authorization.scope import ScopeGate, configure
from ishastra.metrics import get_registry, init_metrics

METRIC = "ishastra_scope_gate_decisions_total"
DURATION_METRIC = "ishastra_scope_gate_decision_duration_seconds_count"


def _count(decision: str, reason: str, tenant: str) -> float:
    value = get_registry().get_sample_value(
        METRIC, {"decision": decision, "reason": reason, "tenant": tenant}
    )
    return value or 0.0


def _scope(tenant: str):
    return configure(
        program="Metrics",
        authorized_by="Test",
        authorization_ref="MET-001",
        include=["example.com"],
        tenant_id=tenant,
    )


def test_allowed_and_blocked_decisions_are_counted():
    init_metrics()
    scope = _scope("acme")
    allowed_before = _count("allowed", "allowed", "acme")
    blocked_before = _count("blocked", "out_of_scope", "acme")
    duration_before = get_registry().get_sample_value(DURATION_METRIC, {"decision": "allowed"}) or 0.0

    with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
        assert scope.check("https://example.com/") == ("", "")
    assert _count("allowed", "allowed", "acme") == allowed_before + 1
    assert (
        get_registry().get_sample_value(DURATION_METRIC, {"decision": "allowed"}) or 0.0
    ) == duration_before + 1

    denial, _reason = scope.check("https://other.com/")
    assert denial == "out_of_scope"
    assert _count("blocked", "out_of_scope", "acme") == blocked_before + 1


def test_validate_outbound_counts_the_denial_code():
    init_metrics()
    scope = _scope("beta")
    before = _count("blocked", "invalid_target", "beta")
    duration_before = get_registry().get_sample_value(DURATION_METRIC, {"decision": "blocked"}) or 0.0

    result = ScopeGate.validate_outbound("not a url", scope)

    assert result.allowed is False
    assert result.denial_code == "invalid_target"
    assert _count("blocked", "invalid_target", "beta") == before + 1
    assert (
        get_registry().get_sample_value(DURATION_METRIC, {"decision": "blocked"}) or 0.0
    ) == duration_before + 1


def test_a_decision_before_any_scrape_is_still_counted(monkeypatch):

    monkeypatch.setattr(metrics, "SCOPE_GATE_DECISIONS", None)
    monkeypatch.setattr(metrics, "_registry", None)
    scope = _scope("delta")

    with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
        scope.check("https://example.com/")

    assert _count("allowed", "allowed", "delta") == 1.0


async def test_destination_async_counts_the_decision():
    init_metrics()
    scope = _scope("gamma")
    before = _count("blocked", "out_of_scope", "gamma")

    denial, _reason, destination = await scope.destination_async("https://other.com/")

    assert denial == "out_of_scope"
    assert destination is None
    assert _count("blocked", "out_of_scope", "gamma") == before + 1
