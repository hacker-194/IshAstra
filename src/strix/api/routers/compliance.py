"""Compliance reporting API endpoints."""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from strix.api.csrf import validate_csrf_token
from strix.api.deps import Tenant, require_admin, require_auth
from strix.api.schemas import Page
from strix.core.compliance_report import (
    ComplianceScheduler,
    ReportFrequency,
    delete_old_compliance_reports,
    get_compliance_export,
    get_compliance_report,
    get_frequency_cron,
    list_compliance_reports,
)

router = APIRouter(prefix="/api")


def get_compliance_scheduler() -> ComplianceScheduler:
    """Get the compliance scheduler instance from app state."""
    from strix.api.app import _compliance_scheduler

    if _compliance_scheduler is None:
        raise HTTPException(status_code=503, detail="Compliance scheduler not initialized")
    return _compliance_scheduler


@router.get("/compliance/schedules", response_model=Page[dict[str, Any]])
async def list_compliance_schedules(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    tenant: Tenant = Depends(require_auth),
    enabled: bool | None = Query(None, description="Filter by enabled status"),
) -> dict[str, Any]:
    """List all compliance report schedules with pagination."""
    scheduler = get_compliance_scheduler()
    schedules = await scheduler.list_schedules(tenant=tenant["tenant_id"])

    if enabled is not None:
        schedules = [s for s in schedules if s.enabled == enabled]

    total = len(schedules)
    start = (page - 1) * page_size
    end = start + page_size
    items = [s.to_dict() for s in schedules[start:end]]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": end < total,
    }


@router.get("/compliance/schedules/frequencies")
async def list_compliance_frequencies(
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """List predefined frequency options with example cron expressions."""
    return {
        "frequencies": [
            {
                "id": ReportFrequency.QUARTERLY,
                "name": "Quarterly",
                "description": "Run once per quarter (every 3 months)",
                "example_cron": get_frequency_cron(ReportFrequency.QUARTERLY),
                "example_description": "Quarterly on the 1st at 6:00 AM UTC",
            },
            {
                "id": ReportFrequency.YEARLY,
                "name": "Yearly",
                "description": "Run once per year",
                "example_cron": get_frequency_cron(ReportFrequency.YEARLY),
                "example_description": "Yearly on January 1st at 6:00 AM UTC",
            },
            {
                "id": ReportFrequency.CUSTOM,
                "name": "Custom",
                "description": "Custom cron expression",
                "example_cron": "0 6 1 */3 *",
                "example_description": "Custom quarterly schedule",
            },
        ],
        "frameworks": [
            {"id": "nrb", "name": "NRB", "description": "Nepal Rastra Bank Directives"},
            {"id": "nta", "name": "NTA", "description": "Nepal Telecommunications Authority Bylaws"},
            {"id": "ncsp", "name": "NCSP", "description": "National Cyber Security Policy 2080"},
        ],
        "timezone_examples": [
            "UTC",
            "America/New_York",
            "America/Los_Angeles",
            "Europe/London",
            "Europe/Paris",
            "Asia/Tokyo",
            "Australia/Sydney",
            "Asia/Kathmandu",
        ],
    }


@router.get("/compliance/schedules/{schedule_id}")
async def get_compliance_schedule(
    schedule_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get a compliance schedule by ID."""
    scheduler = get_compliance_scheduler()
    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # Check tenant access
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to access this schedule")
    return schedule.to_dict()


@router.post("/compliance/schedules", status_code=201)
async def create_compliance_schedule(
    request: dict[str, Any],
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new recurring compliance report schedule.

    Request body:
    - **cron_expression**: Standard cron expression (e.g., "0 6 1 */3 *" for quarterly)
    - **timezone**: IANA timezone (e.g., "America/New_York", "Europe/London", "UTC")
    - **frameworks**: List of frameworks ["nrb", "nta", "ncsp"] (optional, defaults to all)
    - **frequency**: "quarterly" | "yearly" | "custom" (optional, defaults to "quarterly")
    """
    scheduler = get_compliance_scheduler()

    cron_expression = request.get("cron_expression")
    if not cron_expression:
        raise HTTPException(status_code=400, detail="cron_expression is required")

    timezone = request.get("timezone", "UTC")
    frameworks = request.get("frameworks", ["nrb", "nta", "ncsp"])
    frequency = request.get("frequency", ReportFrequency.QUARTERLY)

    try:
        schedule = await scheduler.create_schedule(
            tenant=tenant["tenant_id"],
            cron_expression=cron_expression,
            timezone=timezone,
            frameworks=frameworks,
            frequency=frequency,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    return schedule.to_dict()


@router.patch("/compliance/schedules/{schedule_id}")
async def update_compliance_schedule(
    schedule_id: str,
    request: dict[str, Any],
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update an existing compliance schedule."""
    scheduler = get_compliance_scheduler()

    # Check ownership
    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to modify this schedule")

    try:
        schedule = await scheduler.update_schedule(
            schedule_id,
            cron_expression=request.get("cron_expression"),
            timezone=request.get("timezone"),
            frameworks=request.get("frameworks"),
            frequency=request.get("frequency"),
            enabled=request.get("enabled"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    return schedule.to_dict()


@router.delete("/compliance/schedules/{schedule_id}")
async def delete_compliance_schedule(
    schedule_id: str,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete a compliance schedule."""
    scheduler = get_compliance_scheduler()

    # Check ownership
    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete this schedule")

    try:
        await scheduler.delete_schedule(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    return {"deleted": True, "schedule_id": schedule_id}


@router.post("/compliance/schedules/{schedule_id}/enable")
async def enable_compliance_schedule(
    schedule_id: str,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Enable a compliance schedule."""
    scheduler = get_compliance_scheduler()

    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to modify this schedule")

    schedule = await scheduler.enable_schedule(schedule_id)
    return schedule.to_dict()


@router.post("/compliance/schedules/{schedule_id}/disable")
async def disable_compliance_schedule(
    schedule_id: str,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Disable a compliance schedule."""
    scheduler = get_compliance_scheduler()

    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to modify this schedule")

    schedule = await scheduler.disable_schedule(schedule_id)
    return schedule.to_dict()


@router.post("/compliance/schedules/{schedule_id}/run")
async def run_compliance_schedule_now(
    schedule_id: str,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Manually trigger a compliance report immediately."""
    scheduler = get_compliance_scheduler()

    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.tenant != tenant["tenant_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to run this schedule")

    try:
        result = await scheduler.run_now(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None

    return {
        "schedule_id": result.schedule_id,
        "tenant": result.tenant,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "state": result.state,
        "report_id": result.report_id,
        "total_findings": result.total_findings,
        "frameworks_covered": result.frameworks_covered,
        "error": result.error,
    }


@router.get("/compliance/scheduler/status")
async def compliance_scheduler_status(
    tenant: Tenant = Depends(require_admin),
) -> dict[str, Any]:
    """Get compliance scheduler status."""
    scheduler = get_compliance_scheduler()
    return await scheduler.status()


@router.get("/compliance/reports")
async def list_compliance_reports_endpoint(
    tenant: Tenant = Depends(require_auth),
    limit: int = Query(50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """List compliance reports for the current tenant."""
    return await list_compliance_reports(tenant["tenant_id"], limit=limit)


@router.get("/compliance/reports/{report_id}")
async def get_compliance_report_endpoint(
    report_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get a specific compliance report by ID."""
    report = await get_compliance_report(report_id, tenant["tenant_id"])
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    return report


@router.get("/compliance/reports/{report_id}/download")
async def download_compliance_report(
    report_id: str,
    format: Literal["json", "csv"] = Query(default="json"),
    tenant: Tenant = Depends(require_auth),
) -> Response:
    """Download a compliance report in the specified format."""

    report = await get_compliance_report(report_id, tenant["tenant_id"])
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")

    if format == "json":
        content: str = json.dumps(report, indent=2)
        media_type = "application/json"
        filename = f"{report_id}.json"
    else:  # format == "csv"
        csv_content = await get_compliance_export(report_id, tenant["tenant_id"], "csv")
        if not csv_content:
            raise HTTPException(status_code=404, detail="CSV export not found")
        content = csv_content
        media_type = "text/csv"
        filename = f"{report_id}.csv"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/compliance/evidence-packs/generate")
async def trigger_evidence_pack_generation(
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Manually trigger monthly evidence pack generation for all tenants."""
    from strix.api.deps import get_audit_chain
    from strix.core.evidence import generate_monthly_evidence_packs

    try:
        generated = await generate_monthly_evidence_packs(get_audit_chain())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate evidence packs: {exc}") from None

    return {
        "generated": len(generated),
        "packs": generated,
    }


@router.post("/compliance/reports/cleanup")
async def cleanup_old_compliance_reports(
    retention_days: int = Query(default=2555, ge=30, le=10000),
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete compliance reports older than retention_days."""
    deleted = await delete_old_compliance_reports(retention_days)
    return {"deleted": deleted, "retention_days": retention_days}
