"""The analyst is advisory: enrich, filter invented findings, never fail a request."""

from __future__ import annotations

from ishastra.analyst import analyze_findings, TriageOutput

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


def test_enriches_with_known_fingerprints_only():
    """Should return deterministic triage output without AI provider."""
    result = analyze_findings(FINDINGS)

    assert result.ai_enriched is False
    assert result.summary == "Analyzed 2 findings"
    assert result.attack_path == ""
    assert result.limitations == "AI provider not configured"
    assert result.priorities == []


def test_no_findings_short_circuits():
    """Empty findings list should short-circuit."""
    result = analyze_findings([])

    assert result.ai_enriched is False
    assert result.summary == "No findings to analyze"
    assert result.attack_path == ""
    assert result.limitations == "AI provider not configured"


def test_analyze_findings_with_priorities():
    """Test that analyze_findings returns proper TriageOutput structure."""
    result = analyze_findings(FINDINGS)

    assert isinstance(result, TriageOutput)
    assert hasattr(result, "summary")
    assert hasattr(result, "attack_path")
    assert hasattr(result, "priorities")
    assert hasattr(result, "limitations")
    assert hasattr(result, "ai_enriched")


def test_triage_output_to_dict():
    """Test TriageOutput.to_dict() method."""
    result = analyze_findings(FINDINGS)
    d = result.to_dict()

    assert "summary" in d
    assert "attack_path" in d
    assert "priorities" in d
    assert "limitations" in d
    assert "ai_enriched" in d
    assert d["ai_enriched"] is False