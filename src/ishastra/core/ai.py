"""Optional local-model advisor. Off unless explicitly enabled.

The advisor is deliberately the dumbest component in the system: it reads
the findings the deterministic pipeline already produced and returns prose.
It has no scope handle, no capability token, no job control and no write
access, so a bad model can waste an analyst's attention but cannot widen
an engagement or start a scan.

Only local endpoints are accepted, and only when the operator opts in.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.1"
MAX_FINDINGS = 50

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class AIError(RuntimeError):
    """Advisory unavailable or misconfigured; the caller should carry on without it."""


def is_enabled(environ: Any = None) -> bool:
    value = (environ or os.environ).get("ISHASTRA_AI_ENABLED", "")
    return value.strip().lower() in ("1", "true", "yes", "on")


def _endpoint(value: str | None) -> str:
    endpoint = value or os.environ.get("ISHASTRA_AI_ENDPOINT", DEFAULT_ENDPOINT)
    host = urlparse(endpoint).hostname
    if host not in _LOCAL_HOSTS:
        raise AIError(
            f"AI endpoint must be local ({', '.join(sorted(_LOCAL_HOSTS))}); got {host or endpoint!r}"
        )
    return endpoint.rstrip("/")


def _describe(finding: Any) -> str:
    if isinstance(finding, dict):
        severity = finding.get("severity", "info")
        title = finding.get("title", "untitled")
        asset = finding.get("asset", "")
        category = finding.get("category", "")
        evidence = finding.get("evidence", "")
    else:
        severity = getattr(finding, "severity", "info")
        title = getattr(finding, "title", "untitled")
        asset = getattr(finding, "asset", "")
        category = getattr(finding, "category", "")
        evidence = getattr(finding, "evidence", "")
    evidence = str(evidence).replace("\n", " ")[:300]
    return f"- [{severity}] {title} ({category}) at {asset}: {evidence}"


def build_prompt(job: dict[str, Any], findings: Iterable[Any]) -> str:
    lines = [_describe(finding) for finding in list(findings)[:MAX_FINDINGS]]
    return (
        "You are advising a human penetration tester reviewing an authorized "
        "assessment. Suggest prioritization and remediation questions only. "
        "Do not propose new targets or techniques.\n\n"
        f"Target: {job.get('target', '')}\n"
        f"Verdict: {job.get('verdict', '')}\n"
        f"Findings ({len(lines)}):\n" + ("\n".join(lines) or "- none")
    )


def _chat(endpoint: str, model: str, prompt: str, timeout: float) -> str:
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    ).encode()
    request = urllib.request.Request(
        f"{endpoint}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise AIError(f"local model call failed: {exc}") from exc
    try:
        return str(data["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise AIError("local model returned an unexpected response shape") from exc


def advise(
    job: dict[str, Any],
    findings: Iterable[Any],
    *,
    model: str | None = None,
    endpoint: str | None = None,
    timeout: float = 60.0,
) -> str:
    """Return advisory prose for ``job``. Never mutates anything."""
    if not is_enabled():
        raise AIError("AI advisory is disabled (set ISHASTRA_AI_ENABLED=1 to opt in)")
    base = _endpoint(endpoint)
    name = model or os.environ.get("ISHASTRA_AI_MODEL", DEFAULT_MODEL)
    return _chat(base, name, build_prompt(job, findings), timeout)
