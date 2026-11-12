#!/usr/bin/env python3
"""Production health check for a running Strix deployment.

Checks the unauthenticated liveness/readiness endpoints, then the authenticated
operator endpoints (monitoring state and Prometheus metrics) with STRIX_API_KEY.
Exit 0 only when every check passes; prints a JSON report either way.

Environment:
  STRIX_URL          base URL (default http://localhost:8000)
  STRIX_API_KEY      admin API key (required for the authenticated checks)
  STRIX_REDIS_URL    optional; if set, Redis is pinged
  STRIX_TLS_VERIFY   "0" to accept a self-signed certificate (staging only)
  STRIX_CA_BUNDLE    path to a private CA bundle instead
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx

REDIS_TIMEOUT = 3.0


@dataclass
class HealthCheck:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] | None = None


async def timed_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[httpx.Response, float]:
    started = time.perf_counter()
    response = await client.get(url, headers=headers, timeout=10.0)
    return response, (time.perf_counter() - started) * 1000


async def check_health(client: httpx.AsyncClient, base: str) -> HealthCheck:
    try:
        response, latency = await timed_get(client, f"{base}/api/health")
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return HealthCheck("health", False, f"{type(exc).__name__}: {exc}")
    ok = response.status_code == 200 and response.json().get("status") == "healthy"
    return HealthCheck(
        "health",
        ok,
        f"HTTP {response.status_code} in {latency:.0f} ms",
        {"body": response.text[:300]},
    )


async def check_ready(client: httpx.AsyncClient, base: str) -> HealthCheck:
    try:
        response, latency = await timed_get(client, f"{base}/api/ready")
    except Exception as exc:  # noqa: BLE001
        return HealthCheck("ready", False, f"{type(exc).__name__}: {exc}")
    if response.status_code != 200:
        return HealthCheck("ready", False, f"HTTP {response.status_code}")
    body = response.json()
    problems = [
        field
        for field in ("ready", "database", "audit_chain", "scope_configured")
        if not body.get(field)
    ]
    return HealthCheck(
        "ready",
        not problems,
        "ready" if not problems else f"not ready: {', '.join(problems)}",
        {**body, "latency_ms": round(latency, 2)},
    )


async def check_authenticated(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    auth: dict[str, str],
    validate: Any,
) -> HealthCheck:
    if not auth:
        return HealthCheck(name, False, "STRIX_API_KEY is not set")
    try:
        response, latency = await timed_get(client, url, headers=auth)
    except Exception as exc:  # noqa: BLE001
        return HealthCheck(name, False, f"{type(exc).__name__}: {exc}")
    if response.status_code != 200:
        return HealthCheck(name, False, f"HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError:
        # Prometheus exposition is text, not JSON.
        body = response.text
    passed, message = validate(body)
    return HealthCheck(
        name,
        passed,
        message,
        {"latency_ms": round(latency, 2), "body": str(body)[:300]},
    )


def validate_monitor(body: Any) -> tuple[bool, str]:
    if not isinstance(body, dict):
        return False, "unexpected response"
    if body.get("scope") != "platform":
        return False, "admin key required for platform monitoring state"
    return True, f"monitoring={'running' if body.get('running') else 'stopped'}"


def validate_metrics(body: Any) -> tuple[bool, str]:
    text = body if isinstance(body, str) else str(body)
    if "strix_" in text or "process_" in text:
        return True, "metrics exposed"
    return False, "unexpected metrics payload"


async def check_redis() -> HealthCheck:
    url = os.environ.get("STRIX_REDIS_URL")
    if not url:
        return HealthCheck("redis", True, "not configured (skipped)")
    try:
        from redis.asyncio import from_url

        client = from_url(url)
        try:
            pong = await asyncio.wait_for(client.ping(), REDIS_TIMEOUT)
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        return HealthCheck("redis", False, f"{type(exc).__name__}: {exc}")
    return HealthCheck("redis", bool(pong), "PONG" if pong else "no PONG")


def tls_verify() -> bool | str:
    if os.environ.get("STRIX_TLS_VERIFY", "1") == "0":
        return False
    return os.environ.get("STRIX_CA_BUNDLE") or True


async def main() -> int:
    base = os.environ.get("STRIX_URL", "http://localhost:8000").rstrip("/")
    api_key = os.environ.get("STRIX_API_KEY", "")
    auth = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async with httpx.AsyncClient(
        follow_redirects=True, verify=tls_verify(), timeout=10.0
    ) as client:
        checks = [
            await check_health(client, base),
            await check_ready(client, base),
            await check_authenticated(
                client, "monitor", f"{base}/api/monitor/status", auth, validate_monitor
            ),
            await check_authenticated(
                client, "metrics", f"{base}/api/metrics", auth, validate_metrics
            ),
            await check_redis(),
        ]

    all_passed = all(check.passed for check in checks)
    print(
        json.dumps(
            {
                "timestamp": time.time(),
                "url": base,
                "overall": "healthy" if all_passed else "unhealthy",
                "checks": [
                    {
                        "name": check.name,
                        "passed": check.passed,
                        "message": check.message,
                        "details": check.details,
                    }
                    for check in checks
                ],
            },
            indent=2,
        )
    )
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
