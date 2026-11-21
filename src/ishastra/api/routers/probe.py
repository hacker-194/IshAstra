"""Single-endpoint header probe."""

from __future__ import annotations

import contextlib
import time
from typing import Any, cast
from urllib.parse import ParseResult

from fastapi import APIRouter, Depends, HTTPException

from ishastra.api.csrf import validate_csrf_token
from ishastra.api.deps import Tenant, require_auth, tenant_scope_async
from ishastra.api.schemas import ProbeRequest
from ishastra.core import scope
from ishastra.core.probe import EndpointProbe, grade_security_headers
from ishastra.core.redaction import (
    redact,
    redact_cookie_value,
    redact_text,
    sanitize_target,
)
from ishastra.core.urls import parse_url

router = APIRouter(prefix="/api")


@router.post("/probe")
async def probe_endpoint(
    req: ProbeRequest,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    include_hosts = tenant.get("include_hosts")
    if include_hosts:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        target_host = parsed.hostname or ""
        if target_host:
            target_host = target_host.lower().strip(".")
            allowed = [h.strip().lower().strip(".") for h in include_hosts.split(",") if h.strip()]

            matched = False
            for pattern in allowed:
                if pattern.startswith("*."):
                    suffix = pattern[1:]
                    if target_host.endswith(suffix) and target_host != pattern[2:]:
                        matched = True
                        break
                elif target_host == pattern:
                    matched = True
                    break
            if not matched:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Target {target_host} is not within this API key's allowed hosts: {include_hosts}"
                    ),
                )

    snapshot = await tenant_scope_async(tenant)
    gate = scope.bound(snapshot) if snapshot is not None else contextlib.nullcontext()
    started = time.monotonic()
    with gate:
        result = EndpointProbe(timeout=req.timeout).probe(url, deadline=started + req.timeout)
    latency_ms = round((time.monotonic() - started) * 1000, 2)

    headers = result.get("headers", {})
    security_headers = result.get("security_headers", {})

    score_headers = headers if isinstance(headers, dict) else {}
    score_security_headers = security_headers if isinstance(security_headers, dict) else {}
    safe_headers = dict(score_headers)
    if "set-cookie" in safe_headers:
        value = safe_headers["set-cookie"]
        safe_headers["set-cookie"] = (
            [redact_cookie_value(item) for item in value]
            if isinstance(value, list)
            else redact_cookie_value(value)
        )
    safe_headers = redact(safe_headers)
    safe_security_headers = redact(score_security_headers)
    body: dict[str, Any] = {
        "url": sanitize_target(url),
        "status_code": result.get("status"),
        "latency_ms": latency_ms,
        "security_headers": safe_security_headers,
        "raw_headers": safe_headers,
        "body_snippet": redact_text(str(result.get("body_snippet", ""))),
    }

    if not isinstance(result.get("status"), int):
        reason = result.get("reason") or result.get("error") or "No HTTP response was received"
        return {
            **body,
            "security_score": None,
            "security_grade": "N/A",
            "deductions": [],
            "blocked": result.get("status") == "blocked",
            "reason": redact_text(str(reason)),
        }

    parsed = cast("ParseResult", parse_url(url))
    if parsed is None:
        parsed = cast("ParseResult", urlparse(url))
    score, grade, deductions = grade_security_headers(
        score_headers,
        score_security_headers,
        is_https=bool(parsed and parsed.scheme == "https"),
    )
    return {
        **body,
        "security_score": score,
        "security_grade": grade,
        "deductions": deductions,
        "error": redact_text(str(result.get("error"))) if result.get("error") else None,
    }
