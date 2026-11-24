"""Tests for the opt-in local-model advisor."""

from __future__ import annotations

import pytest

from ishastra.core import ai

JOB = {"target": "https://example.com", "verdict": "findings"}
FINDINGS = [
    {
        "severity": "high",
        "title": "Exposed admin panel",
        "category": "exposure",
        "asset": "https://example.com/admin",
        "evidence": "HTTP 200 with login form",
    }
]


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ISHASTRA_AI_ENABLED", raising=False)
    with pytest.raises(ai.AIError, match="disabled"):
        ai.advise(JOB, FINDINGS)


def test_remote_endpoint_is_refused(monkeypatch):
    monkeypatch.setenv("ISHASTRA_AI_ENABLED", "1")
    with pytest.raises(ai.AIError, match="must be local"):
        ai.advise(JOB, FINDINGS, endpoint="https://api.example.com")


def test_prompt_names_findings_without_credentials():
    prompt = ai.build_prompt(JOB, FINDINGS)
    assert "Exposed admin panel" in prompt
    assert "https://example.com/admin" in prompt
    assert "Do not propose new targets" in prompt


def test_advise_returns_model_text(monkeypatch):
    monkeypatch.setenv("ISHASTRA_AI_ENABLED", "1")
    captured = {}

    def fake_chat(endpoint, model, prompt, timeout):
        captured.update(endpoint=endpoint, model=model, prompt=prompt)
        return "Fix the admin panel exposure first."

    monkeypatch.setattr(ai, "_chat", fake_chat)
    text = ai.advise(JOB, FINDINGS, model="llama3.1")

    assert text.startswith("Fix the admin panel")
    assert captured["endpoint"] == "http://127.0.0.1:11434"
    assert "Exposed admin panel" in captured["prompt"]
