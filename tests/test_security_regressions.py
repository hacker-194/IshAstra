"""Security regressions found in audit: fail-closed config, metrics exposure,
oversized redaction, monitor baseline durability, webhook authenticity.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from strix import config as config_module
from strix.api.app import app
from strix.api.security import api_keys
from strix.audit import AuditChain
from strix.config import Settings
from strix.core import jobs, store
from strix.core.findings import Finding
from strix.core.redaction import redact, redact_text
from strix.monitor import AlertSink, Monitor, WebhookAlertSink

client = TestClient(app)


def _key(tenant: str, *, admin: bool = False) -> str:
    return api_keys.register(tenant, "enterprise", admin=admin)


# ---------------------------------------------------------------------------
# Configuration is fail-closed
# ---------------------------------------------------------------------------
CLEAN_ENV = {
    "STRIX_API_KEY": None, "STRIX_AUDIT_HMAC_KEY": None, "STRIX_WEBHOOK_SECRET": None,
    "STRIX_SCOPE_MODE": None, "STRIX_LOG_FORMAT": None, "STRIX_LOG_LEVEL": None,
    "STRIX_TRUSTED_PROXIES": None,
}


@pytest.fixture
def clean_env(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("value", [
    "change-me-to-a-long-random-string",
    "CHANGE-ME-TO-A-LONG-RANDOM-STRING",          # case does not hide a placeholder
    "please-replace-me-with-a-real-key",
    "your-api-key-goes-right-here",
    "changeme",                                   # too short as well
    "short",
])
def test_placeholder_or_short_bootstrap_keys_are_refused(clean_env, value):
    clean_env.setenv("STRIX_API_KEY", value)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_webhook_secret_is_validated_like_every_other_secret(clean_env):
    clean_env.setenv("STRIX_WEBHOOK_SECRET", "change-me-too")
    with pytest.raises(ValueError, match="STRIX_WEBHOOK_SECRET"):
        Settings.from_env()


def test_strong_secret_containing_an_ordinary_word_is_accepted(clean_env):
    value = "Hn7Qk2vB9sT4xW1zLm6R8pYc"        # high-entropy, no placeholder text
    clean_env.setenv("STRIX_API_KEY", value)
    assert Settings.from_env().api_key == value


def test_unknown_log_format_or_level_is_refused(clean_env):
    clean_env.setenv("STRIX_LOG_FORMAT", "yaml")
    with pytest.raises(ValueError, match="STRIX_LOG_FORMAT"):
        Settings.from_env()
    clean_env.delenv("STRIX_LOG_FORMAT")
    clean_env.setenv("STRIX_LOG_LEVEL", "LOUD")
    with pytest.raises(ValueError, match="STRIX_LOG_LEVEL"):
        Settings.from_env()


def test_trusted_proxies_accept_only_addresses_and_networks(clean_env):
    # A reverse proxy is identified by address or CIDR (the compose stack sits
    # on 172.28.0.0/24); anything that is neither must be refused at config load.
    clean_env.setenv("STRIX_TRUSTED_PROXIES", "10.0.0.0/8")
    assert [str(net) for net in Settings.from_env().trusted_proxies] == ["10.0.0.0/8"]
    clean_env.setenv("STRIX_TRUSTED_PROXIES", "10.1.2.3,::1")
    assert {str(net) for net in Settings.from_env().trusted_proxies} == {
        "10.1.2.3/32", "::1/128"
    }
    clean_env.setenv("STRIX_TRUSTED_PROXIES", "not-an-address")
    with pytest.raises(ValueError, match="STRIX_TRUSTED_PROXIES"):
        Settings.from_env()


def test_module_constants_document_the_policy():
    assert config_module.MIN_SECRET_LENGTH >= 16
    assert "json" in config_module._LOG_FORMATS


# ---------------------------------------------------------------------------
# Metrics are not public
# ---------------------------------------------------------------------------
def test_metrics_require_authentication():
    assert client.get("/api/metrics").status_code == 401


def test_metrics_require_an_administrator(clean_env):
    headers = {"Authorization": f"Bearer {_key('metrics-tenant')}"}
    res = client.get("/api/metrics", headers=headers)
    assert res.status_code == 403


def test_metrics_are_available_to_an_administrator():
    headers = {"Authorization": f"Bearer {_key('metrics-admin', admin=True)}"}
    res = client.get("/api/metrics", headers=headers)
    assert res.status_code == 200
    assert "strix_build_info" in res.text
    # aggregation only: never a tenant identifier or target
    assert "metrics-admin" not in res.text


# ---------------------------------------------------------------------------
# Oversized text is truncated, never passed through unredacted
# ---------------------------------------------------------------------------
def test_oversized_text_is_truncated_and_still_redacted():
    secret = "password=hunter2"
    oversized = ("a" * 2_000_000) + secret
    out = redact_text(oversized)
    assert len(out) <= 1_048_576 + 64
    assert "[TRUNCATED" in out
    assert "hunter2" not in out


def test_oversized_text_keeps_the_redaction_of_its_retained_head():
    out = redact_text("token=abcdef123456" + "b" * 2_000_000)
    assert "abcdef123456" not in out
    assert "token=[REDACTED]" in out


def test_redaction_of_a_dict_with_an_oversized_value_does_not_fail_open():
    payload = {"evidence": "api_key=supersecret " + "x" * 1_500_000}
    cleaned = redact(payload)
    assert "supersecret" not in cleaned["evidence"]


# ---------------------------------------------------------------------------
# Monitor: durable baseline and signed, retried webhooks
# ---------------------------------------------------------------------------
class Collect(AlertSink):
    def __init__(self):
        super().__init__("collect")
        self.alerts: list[dict] = []

    async def send(self, alert):
        self.alerts.append(alert)


def _finding(category: str, severity: str = "critical") -> Finding:
    return Finding(asset="http://example.com", category=category, title=category,
                   severity=severity, confidence="high", detector="t",
                   detector_version="1", evidence="seen", location="/")


def _job(findings: list[Finding]) -> jobs.Job:
    job = jobs.Job(target="http://example.com", profile="web", actor="system", policy={})
    job.state = jobs.JobState.COMPLETED
    job.findings = findings
    return job


def test_monitor_baseline_survives_a_restart():
    """A finding that appeared while the process was down still alerts."""
    first = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    first.alert_sinks = [AlertSink("noop")]

    class Quiet(AlertSink):
        async def send(self, alert):
            return None

    first.alert_sinks = [Quiet("quiet")]
    asyncio.run(first._evaluate("http://example.com", _job([_finding("missing_csp", "low")])))

    # New process: loads the persisted baseline instead of starting over.
    restarted = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    restarted.load()
    collector = Collect()
    restarted.alert_sinks = [collector]
    asyncio.run(restarted._evaluate("http://example.com",
                                    _job([_finding("missing_csp", "low"),
                                          _finding("sqli", "critical")])))
    assert [alert["rule_name"] for alert in collector.alerts] == ["new_finding"]


def test_removing_a_target_forgets_its_persisted_baseline():
    monitor = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    monitor._baseline = {"http://example.com": {"fp"}}
    store._run_async(store.save_monitor_baseline("http://example.com", ["fp"]))
    monitor.set_targets([])
    assert monitor._baseline == {}
    assert store._run_async(store.load_monitor_baseline()) == {}


def test_webhook_signature_is_hmac_sha256_of_the_body():
    sink = WebhookAlertSink("signed", "https://hooks.example.com/x", secret="s3cret-key-123456")
    body = json.dumps({"rule_name": "new_finding"}).encode()
    headers = sink._headers(body)
    expected = hmac.new(b"s3cret-key-123456", body, hashlib.sha256).hexdigest()
    assert headers["X-Strix-Signature"] == f"sha256={expected}"
    assert headers["X-Strix-Signature-Alg"] == "HMAC-SHA256"


def test_unsigned_webhook_sends_no_signature_header():
    sink = WebhookAlertSink("plain", "https://hooks.example.com/x")
    assert "X-Strix-Signature" not in sink._headers(b"{}")


def test_webhook_delivery_is_retried_before_giving_up(monkeypatch):
    sink = WebhookAlertSink("flaky", "https://hooks.example.com/x")
    attempts = {"n": 0}

    async def flaky(client, body):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("connection reset")

    monkeypatch.setattr(sink, "_post_async", flaky)
    monkeypatch.setattr("strix.monitor.DELIVERY_BACKOFF_SECONDS", 0.0)
    asyncio.run(sink.send({"rule_name": "new_finding"}))
    assert attempts["n"] == 3


def test_a_refused_webhook_destination_is_not_retried(monkeypatch):
    sink = WebhookAlertSink("refused", "https://hooks.example.com/x")
    attempts = {"n": 0}

    async def refused(client, body):
        attempts["n"] += 1
        raise ValueError("webhook host resolves to a non-public address")

    monkeypatch.setattr(sink, "_post_async", refused)
    asyncio.run(sink.send({"rule_name": "new_finding"}))
    assert attempts["n"] == 1
