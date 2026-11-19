from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from strix.audit import AuditChain
from strix.core import store
from strix.crypto import decrypt, generate_key
from strix.monitor import Monitor, WebhookAlertSink


def _monitor(*, encryption_key: str = "") -> Monitor:
    return Monitor(
        audit_chain=AuditChain(persistent=False, hmac_key="test-key"),
        webhook_secret="test-secret",
        encryption_key=encryption_key,
    )


def test_webhook_sink_persistence_requires_encryption_key():
    monitor = _monitor()

    with pytest.raises(RuntimeError, match="STRIX_ENCRYPTION_KEY"):
        monitor.add_sink(WebhookAlertSink("alerts", "https://hooks.example.com/events", "secret"))


async def test_loading_persisted_sink_requires_encryption_key(monkeypatch):
    monitor = _monitor()
    monkeypatch.setattr(store, "load_monitor_config", AsyncMock(return_value=([], 0)))
    monkeypatch.setattr(store, "load_monitor_baseline", AsyncMock(return_value={}))
    monkeypatch.setattr(
        store,
        "load_webhook_sinks",
        AsyncMock(return_value=[{"name": "alerts", "url": "https://hooks.example.com/events"}]),
    )

    with pytest.raises(RuntimeError, match="STRIX_ENCRYPTION_KEY"):
        await monitor.load_async()


def test_webhook_sink_url_is_encrypted_before_persistence(monkeypatch):
    key = generate_key()
    monitor = _monitor(encryption_key=key)
    sink = WebhookAlertSink("alerts", "https://hooks.example.com/events", "secret")
    sink._ensure_pinned = AsyncMock()
    save_sink = AsyncMock()
    monkeypatch.setattr(store, "save_webhook_sink", save_sink)

    monitor.add_sink(sink)

    persisted = save_sink.await_args.args[1]
    assert persisted != sink.url
    assert decrypt(persisted, key) == sink.url


async def test_legacy_plaintext_sink_is_encrypted_during_load(monkeypatch):
    key = generate_key()
    url = "https://hooks.example.com/events"
    monitor = _monitor(encryption_key=key)
    monkeypatch.setattr(store, "load_monitor_config", AsyncMock(return_value=([], 0)))
    monkeypatch.setattr(store, "load_monitor_baseline", AsyncMock(return_value={}))
    monkeypatch.setattr(store, "load_webhook_sinks", AsyncMock(return_value=[{"name": "alerts", "url": url}]))
    save_sink = AsyncMock()
    monkeypatch.setattr(store, "save_webhook_sink", save_sink)

    await monitor.load_async()

    assert decrypt(save_sink.await_args.args[1], key) == url
    assert any(getattr(sink, "name", "") == "alerts" for sink in monitor.alert_sinks)
