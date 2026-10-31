"""Regression tests for fail-closed runtime configuration and monitoring secrets."""

from dataclasses import replace

import pytest

from strix.audit import AuditChain
from strix.config import Settings
from strix.monitor import Monitor, validate_webhook_url


def test_scope_mode_rejects_unknown_environment_value(monkeypatch):
    monkeypatch.setenv("STRIX_SCOPE_MODE", "glboal")
    with pytest.raises(ValueError, match="STRIX_SCOPE_MODE"):
        Settings.from_env()


def test_scope_mode_normalizes_case_and_whitespace(monkeypatch):
    monkeypatch.setenv("STRIX_SCOPE_MODE", "  MANAGED  ")
    assert Settings.from_env().scope_mode == "managed"


def test_managed_mode_fails_closed_for_invalid_runtime_value(monkeypatch):
    from strix.api import deps

    monkeypatch.setattr(deps, "settings", replace(deps.settings, scope_mode="unexpected"))
    assert deps.managed_mode() is True


def test_monitor_rejects_sensitive_query_params_without_mutating_targets():
    monitor = Monitor(audit_chain=AuditChain())
    monitor.targets = ["https://safe.example/path"]
    with pytest.raises(ValueError, match="credential-bearing"):
        monitor.add_target("https://example.com/?access_token=secret")
    with pytest.raises(ValueError, match="credential-bearing"):
        monitor.set_targets(["https://example.com/?X-Amz-Security-Token=secret"])
    assert monitor.targets == ["https://safe.example/path"]


def test_webhook_rejects_credential_query_params():
    assert "query parameters" in validate_webhook_url(
        "https://hooks.example.com/notify?access_token=secret"
    )


def test_duplicate_webhook_sink_fails_without_replacing_existing_sink(monkeypatch):
    from strix.core import store
    from strix.monitor import WebhookAlertSink

    saved = []
    monkeypatch.setattr(store, "save_webhook_sink", lambda name, url: saved.append((name, url)))
    monitor = Monitor(audit_chain=AuditChain())
    existing = WebhookAlertSink("alerts", "https://hooks.example.com/first")
    monitor.alert_sinks.append(existing)
    with pytest.raises(ValueError, match="already exists"):
        monitor.add_sink(WebhookAlertSink("alerts", "https://hooks.example.com/second"))
    assert monitor.alert_sinks[-1] is existing
    assert saved == []


@pytest.mark.parametrize("name,value", [
    ("STRIX_API_KEY", "change-me-to-a-long-random-string"),
    ("STRIX_API_KEY", "short"),
    ("STRIX_AUDIT_HMAC_KEY", "change-me-too"),
])
def test_settings_reject_example_or_weak_bootstrap_secrets(monkeypatch, name, value):
    monkeypatch.delenv("STRIX_API_KEY", raising=False)
    monkeypatch.delenv("STRIX_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="STRIX_API_KEY|STRIX_AUDIT_HMAC_KEY|placeholder"):
        Settings.from_env()


def test_invalid_bootstrap_key_aborts_startup_instead_of_using_persisted_key(monkeypatch):
    import asyncio

    from strix.api import app as app_module
    from strix.api import deps

    monkeypatch.setattr(deps, "settings", replace(deps.settings, api_key="too-short"))
    monkeypatch.setattr(app_module.api_keys, "adopt",
                        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("too short")))
    with pytest.raises(RuntimeError, match="refusing to start"):
        asyncio.run(app_module._bootstrap_admin_key_async())
