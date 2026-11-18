"""Chaos tests: a broken dependency must deny, never allow."""

from __future__ import annotations

import pytest

from strix.core import scope as scope_module

ALLOW_URL = "https://opa.example/v1/data/scope/allow"


def _scope():
    return scope_module.Scope(
        program="Chaos",
        authorized_by="Test",
        authorization_ref="CHAOS-1",
        include=("example.com",),
        authorized_networks=("93.184.216.0/24",),
    )


@pytest.fixture(autouse=True)
def fresh_buckets(monkeypatch):
    monkeypatch.setattr(scope_module, "_host_buckets", {})


def test_the_resolver_raising_is_a_denial(monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("resolver down")

    monkeypatch.setattr(scope_module.socket, "getaddrinfo", boom)
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "resolution_failed"
    assert destination is None


def test_an_empty_resolution_is_a_denial(monkeypatch):
    monkeypatch.setattr(scope_module.socket, "getaddrinfo", lambda *a, **k: [])
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "resolution_failed"
    assert destination is None


def test_a_loopback_answer_is_a_denial(monkeypatch):
    def loopback(_host, port, **_kwargs):
        return [(scope_module.socket.AF_INET, scope_module.socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(scope_module.socket, "getaddrinfo", loopback)
    denial, reason, destination = _scope().destination("https://example.com/")
    assert denial == "out_of_scope"
    assert "non-public" in reason
    assert destination is None


def test_the_resolver_budget_exhausting_is_a_denial(monkeypatch):
    monkeypatch.setattr(scope_module, "_host_bucket_allow", lambda host, **_: False)
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "resolution_failed"
    assert destination is None


def test_a_broken_intel_source_is_a_denial(monkeypatch):
    def boom(_ip):
        raise RuntimeError("geoip database corrupted")

    monkeypatch.setattr(scope_module, "resolve_sync", lambda host, port=None: ["93.184.216.34"])
    scope_module.register_intel(country=boom)
    try:
        scope = scope_module.Scope(
            program="Chaos",
            authorized_by="Test",
            authorization_ref="CHAOS-2",
            include=("example.com",),
            authorized_networks=("93.184.216.0/24",),
            allowed_countries=("NP",),
        )
        denial, _reason, destination = scope.destination("https://example.com/")
    finally:
        scope_module.register_intel()
    assert denial == "policy_unavailable"
    assert destination is None


def test_no_configured_scope_denies(monkeypatch):
    monkeypatch.setattr(scope_module, "_active", None)
    denial, reason = scope_module.check("https://example.com/")
    assert denial == "out_of_scope"
    assert "no authorized scope" in reason


def test_the_jit_service_being_down_denies(monkeypatch):
    import asyncio

    async def broken(_url, _payload):
        raise TimeoutError("decision point timed out")

    monkeypatch.setenv(scope_module.SCOPE_JIT_URL_ENV, ALLOW_URL)
    monkeypatch.setattr(scope_module, "_post_json", broken)
    monkeypatch.setattr(scope_module, "resolve_sync", lambda host, port=None: ["93.184.216.34"])
    result = asyncio.run(scope_module.ScopeGate.validate_outbound_async("https://example.com/", _scope()))
    assert result.allowed is False
    assert result.denial_code == "policy_unavailable"
