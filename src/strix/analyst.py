"""AI analyst: advisory triage layered on top of the deterministic findings.

The analyst may only attach priorities, rationales and next steps to findings
that already exist; it cannot create findings or change severity, status or
evidence. Without a configured provider every result is returned unchanged with
``ai_enriched: false``.

Configuration (environment):
    STRIX_AI_BASE_URL   OpenAI-compatible base URL, e.g. https://api.example.com/v1
    STRIX_AI_API_KEY    bearer token for that endpoint
    STRIX_AI_MODEL      model name (default: gpt-4o-mini)
    STRIX_AI_TIMEOUT    request timeout in seconds (default: 30)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

MAX_FINDINGS_IN_PROMPT = 50
MAX_RATIONALE_CHARS = 500

SYSTEM_PROMPT = (
    "You triage security findings. Reply with a single JSON object and nothing else:\n"
    '{"summary": str, "attack_path": str, "limitations": str, '
    '"priorities": [{"fingerprint": str, "priority": "critical"|"high"|"medium"|"low", '
    '"rationale": str, "next_step": str}]}\n'
    "Only use fingerprints from the input. Never invent findings."
)


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
        return json.dumps(
            {
                "summary": "",
                "attack_path": "",
                "priorities": [],
                "limitations": "No AI provider configured",
            }
        )


class EnvHTTPProvider(AnalystProvider):
    """OpenAI-compatible chat-completions endpoint.

    Works with OpenAI, Azure-style gateways, vLLM, Ollama and anything else that
    serves ``POST {base_url}/chat/completions``.
    """

    name = "http"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = "gpt-4o-mini",
        timeout: float = 30.0,
        transport: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._transport = transport

    def _client(self, timeout: float) -> Any:
        import httpx

        return httpx.Client(timeout=timeout, transport=self._transport, follow_redirects=False)

    def complete(self, system: str, prompt: str, *, timeout: float) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        with self._client(timeout or self.timeout) as client:
            response = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]


def provider_from_env() -> AnalystProvider:
    """Get the analyst provider from the environment, or a NullProvider."""
    base_url = os.environ.get("STRIX_AI_BASE_URL", "").strip()
    api_key = os.environ.get("STRIX_AI_API_KEY", "").strip()
    if not base_url or not api_key:
        return NullProvider()
    try:
        timeout = float(os.environ.get("STRIX_AI_TIMEOUT", "30"))
    except ValueError:
        timeout = 30.0
    return EnvHTTPProvider(
        base_url=base_url,
        api_key=api_key,
        model=os.environ.get("STRIX_AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
        timeout=timeout,
    )


def _build_prompt(findings: list[dict[str, Any]]) -> str:
    trimmed = findings[:MAX_FINDINGS_IN_PROMPT]
    lines = [
        f"- fingerprint={f.get('fingerprint', '')} severity={f.get('severity', '')} "
        f"category={f.get('category', '')} title={f.get('title', '')} "
        f"asset={f.get('asset', '')}"
        for f in trimmed
    ]
    note = ""
    if len(findings) > len(trimmed):
        note = f"\n({len(findings) - len(trimmed)} further findings were omitted.)"
    return "Findings to triage:\n" + "\n".join(lines) + note


def _parse(raw: str, findings: list[dict[str, Any]]) -> TriageOutput:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("analyst reply was not a JSON object")

    known = {str(f.get("fingerprint", "")) for f in findings if f.get("fingerprint")}
    priorities: list[TriageItem] = []
    seen: set[str] = set()
    for item in data.get("priorities") or []:
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("fingerprint", "")).strip()
        # Advisory only: an unknown fingerprint means the model invented one.
        if not fingerprint or fingerprint not in known or fingerprint in seen:
            continue
        priority = str(item.get("priority", "")).strip().lower()
        if priority not in {"critical", "high", "medium", "low"}:
            continue
        seen.add(fingerprint)
        priorities.append(
            TriageItem(
                fingerprint=fingerprint,
                priority=priority,
                rationale=str(item.get("rationale", ""))[:MAX_RATIONALE_CHARS],
                next_step=str(item.get("next_step", ""))[:MAX_RATIONALE_CHARS],
            )
        )

    return TriageOutput(
        summary=str(data.get("summary", "")),
        attack_path=str(data.get("attack_path", "")),
        priorities=priorities,
        limitations=str(data.get("limitations", "")),
        ai_enriched=True,
    )


def analyze_findings(findings: list[dict[str, Any]], provider: AnalystProvider) -> TriageOutput:
    """Enrich findings with priorities. Never fails a request."""
    if not findings:
        return TriageOutput(summary="No findings to analyze", ai_enriched=False)

    if isinstance(provider, NullProvider):
        return TriageOutput(
            summary=f"Analyzed {len(findings)} findings",
            ai_enriched=False,
            limitations="AI provider not configured",
        )

    try:
        raw = provider.complete(
            SYSTEM_PROMPT,
            _build_prompt(findings),
            timeout=getattr(provider, "timeout", 30.0),
        )
        return _parse(raw, findings)
    except Exception as exc:  # the analyst is advisory: degrade, never 500
        return TriageOutput(
            summary=f"Analyzed {len(findings)} findings",
            ai_enriched=False,
            limitations=f"Analysis failed: {type(exc).__name__}",
        )
