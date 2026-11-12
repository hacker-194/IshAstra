"""Single-endpoint header probe."""

from __future__ import annotations

import contextlib
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from strix.api.deps import Tenant, require_auth, tenant_scope_async
from strix.api.schemas import ProbeRequest
from strix.core import scope
from strix.core.probe import EndpointProbe, grade_security_headers
from strix.core.redaction import (
    redact,
    redact_cookie_value,
    redact_text,
    sanitize_target,
)
from strix.core.urls import parse_url

router = APIRouter(prefix="/api")


@router.post("/probe")
async def probe_endpoint(
    req: ProbeRequest, tenant: Tenant = Depends(require_auth)
) -> dict[str, Any]:
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Managed mode: this probe is judged against the caller's engagement
    # policy, so a tenant cannot probe through someone else's authorization.
    snapshot = await tenant_scope_async(tenant)
    gate = scope.bound(snapshot) if snapshot is not None else contextlib.nullcontext()
    started = time.monotonic()
    with gate:
        result = EndpointProbe(timeout=req.timeout).probe(
            url, deadline=started + req.timeout
        )
    latency_ms = round((time.monotonic() - started) * 1000, 2)

    headers = result.get("headers", {})
    security_headers = result.get("security_headers", {})

    # Keep the original response material only for local scoring. Everything
    # crossing the API boundary is sanitized, including values nested in
    # response headers/body and error strings which may echo the requested URL.
    score_headers = headers if isinstance(headers, dict) else {}
    score_security_headers = (
        security_headers if isinstance(security_headers, dict) else {}
    )
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

    # Never grade an endpoint that did not return an HTTP response: no response, no score.
    if not isinstance(result.get("status"), int):
        reason = (
            result.get("reason")
            or result.get("error")
            or "No HTTP response was received"
        )
        return {
            **body,
            "security_score": None,
            "security_grade": "N/A",
            "deductions": [],
            "blocked": result.get("status") == "blocked",
            "reason": redact_text(str(reason)),
        }

    parsed = parse_url(url)
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
