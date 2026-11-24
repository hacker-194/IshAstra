"""The AI advisory is optional: returns prose or raises AIError when disabled."""

from __future__ import annotations

import os

from ishastra.core.ai import AIError, advise, is_enabled

JOB = {"target": "example.com", "verdict": "completed"}
FINDINGS = [
    {
        "fingerprint": "fp-1",
        "severity": "high",
        "category": "xss",
        "title": "Reflected XSS",
        "asset": "example.com",
        "evidence": "<script>alert(1)</script>",
    },
    {
        "fingerprint": "fp-2",
        "severity": "low",
        "category": "headers",
        "title": "Missing CSP",
        "asset": "example.com",
        "evidence": "",
    },
]


def test_is_enabled_false_by_default():
    """AI advisory should be disabled by default."""
    assert is_enabled({}) is False
    assert is_enabled({"ISHASTRA_AI_ENABLED": "0"}) is False


def test_is_enabled_true_when_set():
    """AI advisory should be enabled when ISHASTRA_AI_ENABLED=1."""
    assert is_enabled({"ISHASTRA_AI_ENABLED": "1"}) is True
    assert is_enabled({"ISHASTRA_AI_ENABLED": "true"}) is True
    assert is_enabled({"ISHASTRA_AI_ENABLED": "yes"}) is True
    assert is_enabled({"ISHASTRA_AI_ENABLED": "on"}) is True


def test_advise_raises_when_disabled():
    """advise() should raise AIError when AI is not enabled."""
    try:
        advise(JOB, FINDINGS, endpoint="http://127.0.0.1:11434")
        assert False, "Expected AIError"
    except AIError as exc:
        assert "disabled" in str(exc).lower()


def test_advise_raises_on_non_local_endpoint(monkeypatch):
    """advise() should reject non-local endpoints."""
    monkeypatch.setenv("ISHASTRA_AI_ENABLED", "1")
    try:
        advise(JOB, FINDINGS, endpoint="https://api.openai.com")
        assert False, "Expected AIError"
    except AIError as exc:
        assert "local" in str(exc).lower()


def test_build_prompt_includes_findings():
    """Prompt should include target, verdict, and findings."""
    from ishastra.core.ai import build_prompt

    prompt = build_prompt(JOB, FINDINGS)
    assert "example.com" in prompt
    assert "completed" in prompt
    assert "Reflected XSS" in prompt
    assert "Missing CSP" in prompt


def test_describe_formats_finding():
    """_describe() should format finding with severity, title, category, asset."""
    from ishastra.core.ai import _describe

    finding = {
        "severity": "high",
        "title": "SQL Injection",
        "category": "sqli",
        "asset": "api.example.com",
        "evidence": "' OR 1=1 --",
    }
    desc = _describe(finding)
    assert "[high]" in desc
    assert "SQL Injection" in desc
    assert "sqli" in desc
    assert "api.example.com" in desc
    assert "OR 1=1" in desc