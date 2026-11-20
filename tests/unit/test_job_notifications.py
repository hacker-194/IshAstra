"""Job-completion notifications must reuse the hardened webhook sink and no-op otherwise."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ishastra import monitor


def _job():
    return SimpleNamespace(
        id="job_notify",
        target="https://example.com/login?token=secret",
        state=SimpleNamespace(value="completed"),
        verdict="1 finding(s)",
        findings=[
            SimpleNamespace(severity="high"),
            SimpleNamespace(severity="high"),
            SimpleNamespace(severity="low"),
        ],
    )


@pytest.mark.asyncio
async def test_notification_posts_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, str, str, dict]] = []

    class FakeSink:
        def __init__(self, name: str, url: str, secret: str = "") -> None:
            self.name, self.url, self.secret = name, url, secret

        async def send(self, alert: dict) -> None:
            sent.append((self.name, self.url, self.secret, alert))

    monkeypatch.setattr(monitor, "WebhookAlertSink", FakeSink)
    settings = SimpleNamespace(notify_webhook_url="https://hooks.example.com/jobs", webhook_secret="s3cret")

    assert await monitor.notify_job_finished(_job(), settings) is True
    assert len(sent) == 1
    name, url, secret, payload = sent[0]
    assert name == "job-events"
    assert secret == "s3cret"
    assert payload["event"] == "assessment_job"
    assert payload["job"] == "job_notify"
    assert payload["state"] == "completed"
    assert payload["severity_counts"] == {"high": 2, "low": 1}
    assert "token=secret" not in payload["target"]
    assert payload["text"].startswith("[completed]")
    assert payload["blocks"][0]["text"]["text"] == "Assessment completed"
    fields = {field["text"] for field in payload["blocks"][1]["fields"]}
    assert any("*Findings*" in field and "high: 2" in field for field in fields)


@pytest.mark.asyncio
async def test_notification_is_off_without_url(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomSink:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("sink must not be constructed without a URL")

    monkeypatch.setattr(monitor, "WebhookAlertSink", BoomSink)
    settings = SimpleNamespace(notify_webhook_url="", webhook_secret="")

    assert await monitor.notify_job_finished(_job(), settings) is False
