"""AI analyst: advisory triage layered on top of the deterministic findings.

Minimal stub that returns ai_enriched: false when no provider is configured.
Full implementation can be added when AI provider is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TriageItem:
    fingerprint: str
    priority: str
    rationale: str = ""
    next_step: str = ""


@dataclass
class TriageOutput:
    summary: str = ""
    attack_path: str = ""
    priorities: list[TriageItem] = field(default_factory=list)
    limitations: str = ""
    ai_enriched: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "attack_path": self.attack_path,
            "priorities": [
                {
                    "fingerprint": p.fingerprint,
                    "priority": p.priority,
                    "rationale": p.rationale,
                    "next_step": p.next_step,
                }
                for p in self.priorities
            ],
            "limitations": self.limitations,
            "ai_enriched": self.ai_enriched,
        }


class AnalystProvider:
    """Base class for AI providers."""

    name: str = "none"

    def complete(self, system: str, prompt: str, *, timeout: float) -> str:
        raise NotImplementedError


class NullProvider(AnalystProvider):
    """Provider that returns no enrichment."""

    name = "null"

    def complete(self, system: str, prompt: str, *, timeout: float) -> str:
        return '{"summary": "", "attack_path": "", "priorities": [], "limitations": "No AI provider configured", "ai_enriched": false}'


def provider_from_env() -> AnalystProvider:
    """Get analyst provider from environment. Returns NullProvider if not configured."""
    base_url = os.environ.get("STRIX_AI_BASE_URL")
    api_key = os.environ.get("STRIX_AI_API_KEY")
    if not base_url or not api_key:
        return NullProvider()
    # Full implementation would return EnvHTTPProvider here
    return NullProvider()


def analyze_findings(findings: list[dict[str, Any]], provider: AnalystProvider) -> TriageOutput:
    """Analyze findings with the given provider. Returns TriageOutput with ai_enriched flag."""
    if not findings:
        return TriageOutput(summary="No findings to analyze", ai_enriched=False)

    try:
        # In full implementation, this would call provider.complete()
        # For now, return empty enrichment
        return TriageOutput(
            summary=f"Analyzed {len(findings)} findings",
            ai_enriched=False,
            limitations="AI provider not configured"
        )
    except Exception:
        return TriageOutput(
            summary=f"Analyzed {len(findings)} findings",
            ai_enriched=False,
            limitations="Analysis failed"
        )


import os