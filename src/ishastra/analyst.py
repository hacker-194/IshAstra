"""Analysis module removed - AI analyst functionality deprecated."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TriageOutput:
    summary: str = ""
    attack_path: str = ""
    priorities: list = field(default_factory=list)
    limitations: str = ""
    ai_enriched: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "attack_path": self.attack_path,
            "priorities": [p for p in self.priorities],
            "limitations": self.limitations,
            "ai_enriched": self.ai_enriched,
        }


def analyze_findings(findings: list[dict[str, Any]]) -> TriageOutput:
    """Return deterministic triage output without AI provider.

    Without a configured AI provider, findings are returned unchanged
    with ai_enriched: false.
    """
    if not findings:
        return TriageOutput(summary="No findings to analyze", ai_enriched=False, limitations="AI provider not configured")

    return TriageOutput(
        summary=f"Analyzed {len(findings)} findings",
        ai_enriched=False,
        limitations="AI provider not configured",
    )