"""Platform metrics: a small, dependency-free Prometheus text registry.

Counters and gauges are process-level and aggregate — never per-tenant and
never per-target: a metrics scrape must not leak who scans what. Job and
finding gauges are computed from the store at scrape time, so they are
consistent with what an operator sees in the API.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import Counter
from typing import Any

from strix import __version__
from strix.core import store_async as store


class MetricsRegistry:
    """Thread-safe counters with Prometheus text rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, Counter] = {}
        self._started = time.monotonic()

    def inc(self, name: str, labels: dict[str, str] | None = None, amount: int = 1) -> None:
        label_key = _label_key(labels or {})
        with self._lock:
            self._counters.setdefault(name, Counter())[label_key] += amount

    def value(self, name: str, labels: dict[str, str] | None = None) -> int:
        with self._lock:
            return int(self._counters.get(name, Counter()).get(_label_key(labels or {}), 0))

    def render(self, *, job_states: dict[str, int] | None = None,
               finding_severities: dict[str, int] | None = None,
               chain_entries: int = 0, chain_valid: bool = True) -> str:
        """Prometheus text exposition (metric name, help, type, samples)."""
        now = time.monotonic()
        lines: list[str] = []

        def emit(name: str, help_text: str, mtype: str, samples: list[tuple[str, Any]]) -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {mtype}")
            for sample, value in samples:
                lines.append(f"{sample} {value}")

        emit("strix_build_info", "Build metadata.", "gauge",
             [(f'strix_build_info{{version="{__version__}"}}', 1)])
        emit("strix_uptime_seconds", "Seconds since process start.", "gauge",
             [("strix_uptime_seconds", round(now - self._started, 1))])

        with self._lock:
            http = dict(self._counters.get("strix_http_requests_total", Counter()).items())
            triage = dict(self._counters.get("strix_ai_triage_total", Counter()).items())
        emit("strix_http_requests_total", "HTTP requests handled, by method, route and code.",
             "counter", [(f"strix_http_requests_total{{{labels}}}", count)
                         for labels, count in sorted(http.items())])
        emit("strix_ai_triage_total", "AI triage requests, by outcome.", "counter",
             [(f"strix_ai_triage_total{{{labels}}}", count)
              for labels, count in sorted(triage.items())])

        job_states = job_states or {}
        emit("strix_jobs", "Assessment jobs in the store, by state.", "gauge",
             [(f'strix_jobs{{state="{state}"}}', count)
              for state, count in sorted(job_states.items())])
        finding_severities = finding_severities or {}
        emit("strix_findings", "Findings in the store, by severity.", "gauge",
             [(f'strix_findings{{severity="{severity}"}}', count)
              for severity, count in sorted(finding_severities.items())])
        emit("strix_audit_chain_entries", "Entries in the tamper-evident audit chain.",
             "gauge", [("strix_audit_chain_entries", chain_entries)])
        emit("strix_audit_chain_valid", "1 when the audit chain verifies.", "gauge",
             [("strix_audit_chain_valid", 1 if chain_valid else 0)])
        return "\n".join(lines) + "\n"


def _label_key(labels: dict[str, str]) -> str:
    return ",".join(f'{key}="{_escape_label(str(value))}"'
                    for key, value in sorted(labels.items()))


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


metrics = MetricsRegistry()


def snapshot_from_store() -> tuple[dict[str, int], dict[str, int]]:
    """(jobs by state, findings by severity) — aggregate SQL, no identifiers."""
    jobs_by_state = asyncio.run(store.jobs_by_state())
    findings_by_severity = asyncio.run(store.findings_by_severity())
    return jobs_by_state, findings_by_severity


class MetricsMiddleware:
    """Request counter with bounded label cardinality (method + route template)."""

    def __init__(self, app) -> None:  # noqa: ANN001 - ASGI signature
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        status_holder = {"status": 0}

        async def send_wrapper(message) -> None:  # noqa: ANN001
            if message.get("type") == "http.response.start":
                status_holder["status"] = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            path = getattr(route, "path", None) or scope.get("path", "unmatched")[:120]
            metrics.inc("strix_http_requests_total", {
                "method": scope.get("method", "-"),
                "route": path,
                "code": str(status_holder["status"]),
            })
