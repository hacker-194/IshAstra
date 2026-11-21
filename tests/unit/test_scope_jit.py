"""Just-in-time authorization: an unreachable decision point is a denial."""

from __future__ import annotations

import asyncio

import pytest

from ishastra.core import scope as scope_module

ALLOW_URL = "https://opa.example/v1/data/scope/allow"
ADDRESS = "93.184.216.34"


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def jit_environment(monkeypatch):
    monkeypatch.setenv(scope_module.SCOPE_JIT_URL_ENV, ALLOW_URL)
    monkeypatch.setattr(scope_module, "resolve_sync", lambda host, port=None: [ADDRESS])
    monkeypatch.setattr(scope_module, "_host_buckets", {})


def _scope():
    return scope_module.Scope(
        program="JIT",
        authorized_by="Test",
        authorization_ref="JIT-1",
        include=("example.com",),
        authorized_networks=("93.184.216.0/24",),
    )


def _validate(target="https://example.com/", scope=None):
    return asyncio.run(scope_module.ScopeGate.validate_outbound_async(target, scope or _scope()))


def test_an_allowing_decision_point_keeps_the_call(monkeypatch):
    async def allow(_url, _payload):
        return _Response(200, {"result": {"allow": True}})

    monkeypatch.setattr(scope_module, "_post_json", allow)
    result = _validate()
    assert result.allowed is True
    assert result.denial_code == ""


def test_an_explicit_refusal_is_a_denial(monkeypatch):
    async def refuse(_url, _payload):
        return _Response(200, {"result": {"allow": False}})

    monkeypatch.setattr(scope_module, "_post_json", refuse)
    result = _validate()
    assert result.allowed is False
    assert result.denial_code == "out_of_scope"


def test_a_server_error_is_policy_unavailable(monkeypatch):
    async def error(_url, _payload):
        return _Response(503, {})

    monkeypatch.setattr(scope_module, "_post_json", error)
    result = _validate()
    assert result.allowed is False
    assert result.denial_code == "policy_unavailable"


def test_a_malformed_answer_is_a_denial(monkeypatch):
    async def nonsense(_url, _payload):
        return _Response(200, {"result": "allow"})

    monkeypatch.setattr(scope_module, "_post_json", nonsense)
    assert _validate().allowed is False


def test_a_transport_failure_is_a_denial(monkeypatch):
    async def broken(_url, _payload):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(scope_module, "_post_json", broken)
    result = _validate()
    assert result.allowed is False
    assert result.denial_code == "policy_unavailable"


def test_without_an_endpoint_no_request_is_made(monkeypatch):
    monkeypatch.delenv(scope_module.SCOPE_JIT_URL_ENV)

    async def must_not_be_called(_url, _payload):
        raise AssertionError("the service must not be contacted when unconfigured")

    monkeypatch.setattr(scope_module, "_post_json", must_not_be_called)
    assert _validate().allowed is True


def test_a_locally_refused_target_never_reaches_the_service(monkeypatch):
    async def must_not_be_called(_url, _payload):
        raise AssertionError("out-of-scope targets must be refused locally first")

    monkeypatch.setattr(scope_module, "_post_json", must_not_be_called)
    result = _validate("https://other.test/")
    assert result.allowed is False
    assert result.denial_code == "out_of_scope"


def test_the_sync_scan_path_asks_the_decision_point(monkeypatch):
    monkeypatch.setattr(
        scope_module, "_post_json_sync", lambda url, payload: _Response(200, {"result": {"allow": False}})
    )
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "out_of_scope"
    assert destination is None


def test_the_sync_scan_path_denies_when_the_service_is_down(monkeypatch):
    def boom(_url, _payload):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(scope_module, "_post_json_sync", boom)
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "policy_unavailable"
    assert destination is None


def test_the_sync_scan_path_pins_only_an_allowed_target(monkeypatch):
    monkeypatch.setattr(
        scope_module, "_post_json_sync", lambda url, payload: _Response(200, {"result": {"allow": True}})
    )
    denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == ""
    assert destination is not None
    assert destination.ip == ADDRESS
