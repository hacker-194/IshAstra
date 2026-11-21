"""Risk exception lifecycle API: request, decide, list, and audit."""

from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ishastra.api.csrf import validate_csrf_token
from ishastra.api.deps import Tenant, require_auth, require_tenant_admin
from ishastra.api.schemas import FindingExceptionDecision, FindingExceptionRequest, Page
from ishastra.core import exceptions, store
from ishastra.core.redaction import redact

router = APIRouter(prefix="/api")

_FINGERPRINT = r"[0-9a-f]{32}"


def _check_fingerprint(fingerprint: str) -> None:
    import re

    if not re.fullmatch(_FINGERPRINT, fingerprint):
        raise HTTPException(
            status_code=422,
            detail="fingerprint must be 32 lowercase hex characters",
        )


@router.post(
    "/findings/{fingerprint}/exception",
    status_code=status.HTTP_201_CREATED,
)
async def request_exception(
    fingerprint: str,
    req: FindingExceptionRequest,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Request a time-boxed risk acceptance for a finding.

    Creates a pending exception request that must be approved by a tenant
    administrator. The exception expires automatically at the specified
    timestamp unless approved before then.
    """
    _check_fingerprint(fingerprint)
    tenant_id = tenant["tenant_id"]

    if req.until <= time.time():
        raise HTTPException(status_code=400, detail="until must be in the future")

    updated = await exceptions.record_exception_request(
        tenant=tenant_id,
        fingerprint=fingerprint,
        until=req.until,
        reason=redact(req.reason.strip()),
        requested_by=tenant_id,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding")

    return updated


@router.post("/findings/{fingerprint}/exception/decision")
async def decide_exception(
    fingerprint: str,
    req: FindingExceptionDecision,
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Approve or reject a pending risk exception (tenant administrator only).

    Only pending exceptions can be decided. Approved exceptions become active
    until their expiry timestamp; rejected exceptions are closed.
    """
    _check_fingerprint(fingerprint)
    tenant_id = tenant["tenant_id"]

    try:
        updated = await exceptions.record_exception_decision(
            tenant=tenant_id,
            fingerprint=fingerprint,
            approved=req.approve,
            decided_by=tenant_id,
            note=redact(req.note.strip()) if req.note else "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None

    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding or no pending exception")

    return updated


@router.get("/findings/{fingerprint}/exception")
async def get_exception(
    fingerprint: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get the current exception state for a finding."""
    _check_fingerprint(fingerprint)
    tenant_id = tenant["tenant_id"]

    record = await store.get_finding_record(tenant=tenant_id, fingerprint=fingerprint)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown finding")

    exception_state = record.get("exception", {}).get("state", "none")
    return {
        "fingerprint": fingerprint,
        "exception_state": exception_state,
        "exception": record.get("exception", {}),
        "remediation": record.get("remediation", {}),
    }


@router.get("/exceptions")
async def list_exceptions(
    state: Literal["pending", "approved", "rejected", "expired", "all"] = Query(
        default="all", description="Filter by exception state"
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    tenant: Tenant = Depends(require_auth),
) -> Page[dict[str, Any]]:
    """List exception requests for this tenant, optionally filtered by state."""
    tenant_id = tenant["tenant_id"]

    all_exceptions = await exceptions.get_pending_exceptions(tenant=tenant_id)

    if state != "all":
        all_exceptions = [e for e in all_exceptions if e.get("exception_state") == state]

    total = len(all_exceptions)
    offset = (page - 1) * page_size
    items = all_exceptions[offset : offset + page_size]

    for item in items:
        from ishastra.core.store import _effective_exception_state

        item["exception_state"] = _effective_exception_state(
            item.get("exception_state", "none"),
            item.get("exception_until"),
        )

    return Page(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=page * page_size < total,
    )


@router.post("/exceptions/expire")
async def trigger_expiration_check(
    tenant: Tenant = Depends(require_tenant_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Manually trigger an exception expiration check (tenant administrator only).

    Immediately processes all pending/approved exceptions that have passed
    their expiry timestamp and flips them to 'expired'.
    """
    tenant_id = tenant["tenant_id"]
    count = await exceptions.expire_exceptions(tenant=tenant_id)
    return {"expired_count": count, "tenant": tenant_id}


@router.get("/exceptions/audit")
async def exception_audit_log(
    fingerprint: str | None = Query(default=None, description="Filter by finding fingerprint"),
    event: Literal[
        "exception_requested",
        "exception_approved",
        "exception_rejected",
        "exception_expired",
    ]
    | None = Query(default=None, description="Filter by event type"),
    limit: int = Query(default=100, ge=1, le=1000),
    tenant: Tenant = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Get audit log entries for exception lifecycle events."""
    tenant_id = tenant["tenant_id"]

    entries = await store.recent_audit(limit=limit)

    filtered = []
    for entry in entries:
        if entry.get("tenant") != tenant_id:
            continue
        if event and entry.get("event") != event:
            continue
        if fingerprint and entry.get("fingerprint") != fingerprint:
            continue
        if entry.get("event") not in (
            "exception_requested",
            "exception_approved",
            "exception_rejected",
            "exception_expired",
        ):
            continue
        filtered.append(entry)

    return filtered
