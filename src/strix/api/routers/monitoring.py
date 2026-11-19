"""Continuous monitoring and alert sinks (administrator-controlled)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response

from strix.api import deps as api_deps
from strix.api.csrf import validate_csrf_token
from strix.api.deps import (
    Tenant,
    audit_async,
    check_target_or_raise,
    get_monitor,
    require_admin,
    require_auth,
)
from strix.api.schemas import MonitorConfig, WebhookSinkRequest
from strix.core import policies, store
from strix.core.redaction import has_sensitive_query_params, sanitize_target
from strix.monitor import MONITOR_TENANT, WebhookAlertSink, validate_webhook_url_async
from strix.otel import otel_metrics_endpoint

router = APIRouter(prefix="/api")


@router.get("/monitor/status")
async def monitor_status(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Platform state for administrators; liveness plus own counts for tenants."""
    monitor = get_monitor()
    state = await monitor.status_async()
    if tenant.get("admin"):
        return {**state, "scope": "platform", "tenant_id": tenant["tenant_id"]}
    tenant_id = tenant["tenant_id"]
    return {
        "scope": "tenant",
        "tenant_id": tenant_id,
        "running": state["running"],
        "jobs": await store.count_jobs(tenant=tenant_id),
        "findings": await store.count_findings(tenant=tenant_id),
    }


@router.post("/monitor/configure")
async def configure_monitor(
    config: MonitorConfig,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    # Monitoring runs as the dedicated system tenant, not as the configuring
    # administrator. Validate every target against the exact policy the worker
    # will bind to, and refuse persistent targets containing query credentials.
    snapshot = None
    monitor = get_monitor()
    if await api_deps.managed_mode_async():
        snapshot, reason = await policies.tenant_scope_snapshot_async(MONITOR_TENANT)
        if snapshot is None:
            raise HTTPException(
                status_code=403,
                detail=f"monitoring requires a valid system policy: {reason}",
            )
    for target in config.targets:
        if has_sensitive_query_params(target):
            raise HTTPException(
                status_code=400,
                detail="monitored targets cannot contain credential-bearing query parameters",
            )
        check_target_or_raise(target, snapshot)
    monitor.interval = config.interval_seconds
    if config.replace:
        await monitor.set_targets_async(config.targets)
    else:
        for target in config.targets:
            monitor.add_target(target)
    await monitor.save_async()
    await audit_async(
        tenant,
        {
            "event": "monitor_configured",
            "targets": [sanitize_target(target) for target in config.targets],
            "replace": config.replace,
            "interval_seconds": config.interval_seconds,
        },
    )
    return {
        "interval_seconds": monitor.interval,
        "monitored_targets": list(monitor.targets),
        "running": monitor.running,
    }


@router.post("/alerts/webhook")
async def add_webhook(
    req: WebhookSinkRequest,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    refusal = await validate_webhook_url_async(req.url)
    if refusal:
        raise HTTPException(status_code=400, detail=refusal)
    monitor = get_monitor()
    try:
        await monitor.add_sink_async(
            WebhookAlertSink(name=req.name, url=req.url, secret=monitor.webhook_secret)
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    await audit_async(tenant, {"event": "webhook_added", "sink": req.name})
    return {"sink_name": req.name, "added": True}


@router.get("/metrics/otel", include_in_schema=False)
async def otel_prometheus_metrics(_: Any = Depends(require_admin)) -> Response:
    """Prometheus metrics endpoint including OpenTelemetry metrics."""
    return otel_metrics_endpoint()
