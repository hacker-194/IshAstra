"""The analyst is advisory: enrich, filter invented findings, never fail a request."""

from __future__ import annotations

import json

import httpx

from ishastra import analyst


def _transport(content: str | dict, *, status: int = 200) -> httpx.MockTransport:
    body = content if isinstance(content, str) else json.dumps(content)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.url.path.endswith("/chat/completions")
        return httpx.Response(status, json={"choices": [{"message": {"content": body}}]})

    return httpx.MockTransport(handler)


FINDINGS = [
    {
        "fingerprint": "fp-1",
        "severity": "high",
        "category": "xss",
        "title": "Reflected XSS",
        "asset": "example.com",
    },
    {
        "fingerprint": "fp-2",
        "severity": "low",
        "category": "headers",
        "title": "Missing CSP",
        "asset": "example.com",
    },
]


def _provider(content: str | dict, *, status: int = 200) -> analyst.EnvHTTPProvider:
    return analyst.EnvHTTPProvider(
        "https://ai.example/v1",
        "test-key",
        model="test-model",
        transport=_transport(content, status=status),
    )


def test_enriches_with_known_fingerprints_only():
    provider = _provider(
        {
            "summary": "One issue is urgent.",
            "attack_path": "XSS -> session theft",
            "limitations": "",
            "priorities": [
                {
                    "fingerprint": "fp-1",
                    "priority": "critical",
                    "rationale": "reachable",
                    "next_step": "fix encoding",
                },
                {"fingerprint": "fp-999", "priority": "low", "rationale": "x"},
                {"fingerprint": "fp-1", "priority": "low", "rationale": "dup"},
                {"fingerprint": "fp-2", "priority": "urgent", "rationale": "y"},
            ],
        }
    )

    result = analyst.analyze_findings(FINDINGS, provider)

    assert result.ai_enriched is True
    assert result.summary == "One issue is urgent."
    assert result.attack_path == "XSS -> session theft"
    assert [p.fingerprint for p in result.priorities] == ["fp-1"]
    assert result.priorities[0].priority == "critical"


def test_unparseable_reply_degrades_instead_of_raising():
    result = analyst.analyze_findings(FINDINGS, _provider("not json at all"))
    assert result.ai_enriched is False
    assert result.limitations.startswith("Analysis failed:")


def test_http_error_degrades():
    result = analyst.analyze_findings(FINDINGS, _provider({"priorities": []}, status=500))
    assert result.ai_enriched is False
    assert "HTTPStatusError" in result.limitations


def test_null_provider_leaves_findings_untouched():
    result = analyst.analyze_findings(FINDINGS, analyst.NullProvider())
    assert result.ai_enriched is False
    assert result.priorities == []
    assert result.limitations == "AI provider not configured"


def test_no_findings_short_circuits():
    result = analyst.analyze_findings([], _provider({"priorities": []}))
    assert result.ai_enriched is False
    assert result.summary == "No findings to analyze"


def test_provider_from_env_needs_both_url_and_key(monkeypatch):
    monkeypatch.delenv("ISHASTRA_AI_BASE_URL", raising=False)
    monkeypatch.delenv("ISHASTRA_AI_API_KEY", raising=False)
    assert isinstance(analyst.provider_from_env(), analyst.NullProvider)

    monkeypatch.setenv("ISHASTRA_AI_BASE_URL", "https://ai.example/v1")
    assert isinstance(analyst.provider_from_env(), analyst.NullProvider)

    monkeypatch.setenv("ISHASTRA_AI_API_KEY", "test-key")
    monkeypatch.setenv("ISHASTRA_AI_MODEL", "custom-model")
    provider = analyst.provider_from_env()
    assert isinstance(provider, analyst.EnvHTTPProvider)
    assert provider.model == "custom-model"
