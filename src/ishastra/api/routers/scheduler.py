"""Scheduler API endpoints for recurring assessments."""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ishastra.api.csrf import validate_csrf_token
from ishastra.api.deps import Tenant, require_admin, require_auth
from ishastra.api.schemas import (
    Page,
    ScheduleCreateRequest,
    ScheduleResponse,
    SchedulerStatusResponse,
    ScheduleRunResponse,
    ScheduleUpdateRequest,
)
from ishastra.core.evidence import get_evidence_pack, list_evidence_packs, printable_html, to_csv, to_oscal
from ishastra.core.scheduler import (
    ScheduleFrequency,
    Scheduler,
    ScheduleState,
)

router = APIRouter(prefix="/api")


def get_scheduler() -> Scheduler:
    """Get the scheduler instance from app state."""

    from ishastra.api.app import _scheduler

    if _scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    return _scheduler


@router.get("/schedules", response_model=Page[ScheduleResponse])
async def list_schedules(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    state: ScheduleState | None = None,
    tenant: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List all assessment schedules with pagination."""
    scheduler = get_scheduler()
    schedules = await scheduler.list_schedules()

    if state:
        schedules = [s for s in schedules if s.state == state]

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


@router.get("/schedules/frequencies")
async def list_frequencies(
    tenant: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List predefined frequency options with example cron expressions."""
    return {
        "frequencies": [
            {
                "id": ScheduleFrequency.DAILY,
                "name": "Daily",
                "description": "Run once per day at a specific time",
                "example_cron": "0 2 * * *",
                "example_description": "Daily at 2:00 AM",
            },
            {
                "id": ScheduleFrequency.WEEKLY,
                "name": "Weekly",
                "description": "Run once per week on a specific day",
                "example_cron": "0 2 * * 1",
                "example_description": "Weekly on Monday at 2:00 AM",
            },
            {
                "id": ScheduleFrequency.MONTHLY,
                "name": "Monthly",
                "description": "Run once per month on a specific day",
                "example_cron": "0 2 1 * *",
                "example_description": "Monthly on the 1st at 2:00 AM",
            },
            {
                "id": ScheduleFrequency.CUSTOM,
                "name": "Custom",
                "description": "Custom cron expression",
                "example_cron": "0 */6 * * *",
                "example_description": "Every 6 hours",
            },
        ],
        "timezone_examples": [
            "UTC",
            "America/New_York",
            "America/Los_Angeles",
            "Europe/London",
            "Europe/Paris",
            "Asia/Tokyo",
            "Australia/Sydney",
        ],
    }


@router.get("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: str,
    tenant: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Get a schedule by ID."""
    scheduler = get_scheduler()
    schedule = await scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule.to_dict()


@router.post("/schedules", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    request: ScheduleCreateRequest,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Create a new recurring assessment schedule.

    - **target**: The authorized target to assess (e.g., https://example.com)
    - **cron_expression**: Standard cron expression (e.g., "0 2 * * *" for daily at 2 AM)
    - **timezone**: IANA timezone (e.g., "America/New_York", "Europe/London", "UTC")
    - **profile**: Assessment profile (web, web-deep, api, api-deep, network, agent)
    - **policy_id**: Optional engagement policy to use (managed mode)
    - **max_concurrent**: Maximum concurrent runs for this schedule
    - **catch_up**: Run missed executions when scheduler restarts
    """
    scheduler = get_scheduler()
    try:
        schedule = await scheduler.create_schedule(
            target=request.target,
            cron_expression=request.cron_expression,
            timezone=request.timezone,
            profile=request.profile,
            policy_id=request.policy_id,
            max_concurrent=request.max_concurrent,
            catch_up=request.catch_up,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return schedule.to_dict()


@router.patch("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    request: ScheduleUpdateRequest,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Update an existing schedule."""
    scheduler = get_scheduler()
    try:
        schedule = await scheduler.update_schedule(
            schedule_id,
            cron_expression=request.cron_expression,
            timezone=request.timezone,
            profile=request.profile,
            state=ScheduleState(request.state) if request.state else None,
            policy_id=request.policy_id,
            max_concurrent=request.max_concurrent,
            catch_up=request.catch_up,
            enabled=request.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule.to_dict()


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Delete a schedule."""
    scheduler = get_scheduler()
    try:
        await scheduler.delete_schedule(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return {"deleted": True, "schedule_id": schedule_id}


@router.post("/schedules/{schedule_id}/pause", response_model=ScheduleResponse)
async def pause_schedule(
    schedule_id: str,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Pause a schedule."""
    scheduler = get_scheduler()
    try:
        schedule = await scheduler.pause_schedule(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return schedule.to_dict()


@router.post("/schedules/{schedule_id}/resume", response_model=ScheduleResponse)
async def resume_schedule(
    schedule_id: str,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Resume a paused schedule."""
    scheduler = get_scheduler()
    try:
        schedule = await scheduler.resume_schedule(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return schedule.to_dict()


@router.post("/schedules/{schedule_id}/run", response_model=ScheduleRunResponse)
async def run_schedule_now(
    schedule_id: str,
    tenant: dict[str, Any] = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Manually trigger a scheduled assessment immediately."""
    scheduler = get_scheduler()
    try:
        result = await scheduler.run_now(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return {
        "schedule_id": result.schedule_id,
        "job_id": result.job_id,
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "state": result.state,
        "findings_count": result.findings_count,
        "new_high_severity": result.new_high_severity,
        "error": result.error,
        "alert_emitted": result.alert_emitted,
    }


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
async def scheduler_status(
    tenant: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Get scheduler status."""
    scheduler = get_scheduler()
    return await scheduler.status()


@router.get("/evidence-packs")
async def list_evidence_packs_endpoint(
    tenant: Tenant = Depends(require_auth),
) -> list[dict[str, Any]]:
    """List monthly evidence packs for the current tenant."""
    return await list_evidence_packs(tenant["tenant_id"])


@router.get("/evidence-packs/{pack_id}")
async def get_evidence_pack_endpoint(
    pack_id: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Get a specific evidence pack by ID."""
    pack = await get_evidence_pack(pack_id, tenant["tenant_id"])
    if not pack:
        raise HTTPException(status_code=404, detail="Evidence pack not found")
    return pack


@router.get("/evidence-packs/{pack_id}/download")
async def download_evidence_pack(
    pack_id: str,
    format: Literal["json", "csv", "html", "oscal"] = Query(default="json"),
    tenant: Tenant = Depends(require_auth),
) -> Response:
    """Download an evidence pack in the specified format."""

    pack = await get_evidence_pack(pack_id, tenant["tenant_id"])
    if not pack:
        raise HTTPException(status_code=404, detail="Evidence pack not found")

    if format == "json":
        content = json.dumps(pack, indent=2)
        media_type = "application/json"
        filename = f"{pack_id}.json"
    elif format == "csv":
        content = to_csv(pack)
        media_type = "text/csv"
        filename = f"{pack_id}.csv"
    elif format == "html":
        content = printable_html(pack)
        media_type = "text/html"
        filename = f"{pack_id}.html"
    elif format == "oscal":
        content = to_oscal(pack)
        media_type = "application/json"
        filename = f"{pack_id}.oscal.json"
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
