"""Tenant finding records aggregated across jobs by stable fingerprint."""

from __future__ import annotations

import csv
import re
import time
from io import StringIO
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, audit_async, require_auth
from strix.api.schemas import (
    FindingRemediationUpdate,
    FindingResolutionVerify,
)
from strix.core import store
from strix.core.redaction import redact

router = APIRouter(prefix="/api")

_FINGERPRINT = re.compile(r"[0-9a-f]{32}")


def _check_fingerprint(fingerprint: str) -> None:
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise HTTPException(status_code=422, detail="fingerprint must be 32 lowercase hex characters")


@router.get("/findings")
async def list_findings(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Distinct findings across this tenant's jobs, newest activity first."""
    tenant_id = tenant["tenant_id"]
    items = await store.list_cross_job_findings(
        tenant=tenant_id, limit=page_size, offset=(page - 1) * page_size
    )
    total = await store.count_cross_job_findings(tenant=tenant_id)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": page * page_size < total,
    }


@router.get("/findings/trends")
async def finding_trends(
    start: float | None = Query(default=None, description="Inclusive Unix timestamp"),
    end: float | None = Query(default=None, description="Inclusive Unix timestamp"),
    bucket: Literal["day", "week", "month"] = "day",
    range: Literal["quarter", "year", "all"] | None = Query(
        default=None,
        description="Predefined range: quarter (3m), year (12m), all (max 366d). Overrides start/end.",
    ),
    format: Literal["json", "csv"] = Query(default="json", description="Response format"),
    tenant: Tenant = Depends(require_auth),
) -> Any:
    """Observation, new-finding and verified-resolution counts over time.

    Supports predefined ranges (quarter=3 months, year=12 months, all=max 366 days)
    with monthly buckets and capped results (max 366 buckets). CSV export available.
    """
    now = time.time()

    if range:
        if range == "quarter":
            end = now
            start = end - 3 * 30 * 86400.0  # ~90 days
            bucket = "month"
        elif range == "year":
            end = now
            start = end - 12 * 30 * 86400.0  # ~360 days
            bucket = "month"
        elif range == "all":
            end = now
            start = end - 366 * 86400.0
            bucket = "month"
    else:
        end = now if end is None else end
        start = end - 30 * 86400.0 if start is None else start

    if start >= end:
        raise HTTPException(status_code=400, detail="start must be before end")
    if end - start > 366 * 86400.0:
        raise HTTPException(status_code=400, detail="trend range must not exceed 366 days")

    result = await store.finding_trends(tenant=tenant["tenant_id"], start=start, end=end, bucket=bucket)

    # Cap results to max 366 buckets (one per day for "all" range)
    max_buckets = 366
    if len(result["buckets"]) > max_buckets:
        result["buckets"] = result["buckets"][-max_buckets:]

    if format == "csv":
        return _trends_to_csv(result)

    return result


def _trends_to_csv(result: dict[str, Any]) -> Response:
    """Convert trends result to CSV response."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "bucket",
            "observations",
            "unique_findings",
            "new_findings",
            "resolved_findings",
            "severity_critical",
            "severity_high",
            "severity_medium",
            "severity_low",
            "severity_info",
        ]
    )
    for bucket in result["buckets"]:
        sev = bucket.get("severity", {})
        writer.writerow(
            [
                bucket["bucket"],
                bucket["observations"],
                bucket["unique_findings"],
                bucket["new_findings"],
                bucket["resolved_findings"],
                sev.get("critical", 0),
                sev.get("high", 0),
                sev.get("medium", 0),
                sev.get("low", 0),
                sev.get("info", 0),
            ]
        )
    csv_content = output.getvalue()
    filename = f"finding_trends_{result['start']:.0f}_{result['end']:.0f}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/findings/{fingerprint}")
async def get_finding(fingerprint: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """One finding record and its per-job occurrence history."""
    _check_fingerprint(fingerprint)
    finding = await store.get_cross_job_finding(tenant=tenant["tenant_id"], fingerprint=fingerprint)
    if finding is None:
        raise HTTPException(status_code=404, detail="Unknown finding")
    return finding


@router.patch("/findings/{fingerprint}/remediation")
async def update_finding_remediation(
    fingerprint: str,
    update: FindingRemediationUpdate,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Set tenant-level owner, deadline or risk-exception metadata."""
    _check_fingerprint(fingerprint)
    now = time.time()
    if update.due_at is not None and update.due_at < 0:
        raise HTTPException(status_code=400, detail="due_at must be a positive Unix timestamp")
    if update.exception_until is not None:
        if update.exception_until <= now:
            raise HTTPException(status_code=400, detail="exception_until must be in the future")
        if not update.exception_reason.strip() or not update.exception_approved_by.strip():
            raise HTTPException(
                status_code=400,
                detail="exception_reason and exception_approved_by are required for a risk exception",
            )
    updated = await store.set_finding_record_remediation(
        tenant=tenant["tenant_id"],
        fingerprint=fingerprint,
        owner=update.owner.strip(),
        due_at=update.due_at,
        exception_until=update.exception_until,
        exception_reason=redact(update.exception_reason.strip()),
        exception_approved_by=update.exception_approved_by.strip(),
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding")
    await audit_async(
        tenant,
        {
            "event": "finding_record_remediation_updated",
            "fingerprint": fingerprint,
            "owner": updated["owner"],
            "due_at": updated["due_at"],
            "exception_until": updated["exception_until"],
            "exception_approved_by": updated["exception_approved_by"],
        },
    )
    return updated


@router.post("/findings/{fingerprint}/resolve")
async def verify_finding_resolution(
    fingerprint: str,
    req: FindingResolutionVerify,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Mark a finding resolved only when a later clean job covered its detectors.

    A clean job with partial coverage, a missing detector run, a different
    target, or the fingerprint still present is refused.
    """
    _check_fingerprint(fingerprint)
    tenant_id = tenant["tenant_id"]
    finding = await store.get_cross_job_finding(tenant=tenant_id, fingerprint=fingerprint)
    if finding is None:
        raise HTTPException(status_code=404, detail="Unknown finding")
    job = await store.get_job(req.job_id, tenant=tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job")

    history = finding.get("history", [])
    if req.job_id in {entry["job_id"] for entry in history}:
        raise HTTPException(status_code=409, detail="Verification job must be later than the last occurrence")
    if job["state"] != "completed":
        raise HTTPException(status_code=409, detail="Verification job did not complete")
    if job["created_at"] <= finding["last_seen"]:
        raise HTTPException(status_code=409, detail="Verification job must post-date the finding")
    if any(item["fingerprint"] == fingerprint for item in job.get("findings", [])):
        raise HTTPException(status_code=409, detail="Finding is still present in the verification job")
    if job["target"].rstrip("/").lower() != finding["asset"].rstrip("/").lower():
        raise HTTPException(
            status_code=409, detail="Verification job target does not match the finding asset"
        )

    required = {entry["detector"] for entry in history}
    observed = {run["adapter"]: run["state"] for run in job.get("coverage", {}).get("adapters", [])}
    missing = sorted(detector for detector in required if observed.get(detector) != "ok")
    if missing:
        raise HTTPException(
            status_code=409,
            detail=(
                "Verification job lacks complete detector coverage for: "
                + ", ".join(missing)
                + "; an absent finding is not proof of resolution"
            ),
        )

    evidence = {
        "job_id": req.job_id,
        "target": job["target"],
        "verified_at": time.time(),
        "detector_states": {detector: observed[detector] for detector in sorted(required)},
        "coverage": job.get("coverage", {}),
    }
    updated = await store.set_finding_resolution(
        tenant=tenant_id,
        fingerprint=fingerprint,
        resolved_at=time.time(),
        job_id=req.job_id,
        evidence=evidence,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding")
    await audit_async(
        tenant,
        {
            "event": "finding_resolution_verified",
            "fingerprint": fingerprint,
            "job": req.job_id,
            "detectors": sorted(required),
        },
    )
    refreshed = await store.get_cross_job_finding(tenant=tenant_id, fingerprint=fingerprint)
    return refreshed or updated
