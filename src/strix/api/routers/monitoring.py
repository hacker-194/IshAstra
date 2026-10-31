"""Continuous monitoring and alert sinks (administrator-controlled)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from strix.api import deps
from strix.api.deps import Tenant, audit_async, check_target_or_raise, require_admin, require_auth
from strix.api.schemas import MonitorConfig, WebhookSinkRequest
from strix.core import policies
from strix.core import store_async as store
from strix.core.redaction import has_sensitive_query_params, sanitize_target
from strix.monitor import MONITOR_TENANT, WebhookAlertSink, validate_webhook_url_async

# Call sites: monitor_status() uses store.count_jobs() and store.count_findings()
# Data schemas: jobs table (count), findings table (count)
# User instruction: "Critical Blockers for Production Use — Detailed Analysis
# fix this" -> "b" (Phase 1 async DB migration)

router = APIRouter(prefix="/api")


@router.get("/monitor/status")
async def monitor_status(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Platform state for administrators; liveness plus own counts for tenants."""
    state = await deps.monitor.status_async()
    if tenant.get("admin"):
        return {**state, "scope": "platform", "tenant_id": tenant["tenant_id"]}
    tenant_id = tenant["tenant_id"]
    return {"scope": "tenant", "tenant_id": tenant_id, "running": state["running"],
            "jobs": await store.count_jobs(tenant=tenant_id),
            "findings": await store.count_findings(tenant=tenant_id)}


@router.post("/monitor/configure")
async def configure_monitor(config: MonitorConfig,
                            tenant: Tenant = Depends(require_admin)) -> dict[str, Any]:
    # Monitoring runs as the dedicated system tenant, not as the configuring
    # administrator. Validate every target against the exact policy the worker
    # will bind to, and refuse persistent targets containing query credentials.
    snapshot = None
    if await deps.managed_mode_async():
        snapshot, reason = await policies.tenant_scope_snapshot_async(MONITOR_TENANT)
        if snapshot is None:
            raise HTTPException(status_code=403,
                                detail=f"monitoring requires a valid system policy: {reason}")
    for target in config.targets:
        if has_sensitive_query_params(target):
            raise HTTPException(status_code=400,
                                detail="monitored targets cannot contain credential-bearing query parameters")
        check_target_or_raise(target, snapshot)
    deps.monitor.interval = config.interval_seconds
    if config.replace:
        await deps.monitor.set_targets_async(config.targets)
    else:
        for target in config.targets:
            deps.monitor.add_target(target)
    await deps.monitor.save_async()
    await audit_async(tenant, {"event": "monitor_configured",
                   "targets": [sanitize_target(target) for target in config.targets],
                   "replace": config.replace,
                   "interval_seconds": config.interval_seconds})
    return {"interval_seconds": deps.monitor.interval,
            "monitored_targets": list(deps.monitor.targets),
            "running": deps.monitor.running}


@router.post("/alerts/webhook")
async def add_webhook(req: WebhookSinkRequest,
                      tenant: Tenant = Depends(require_admin)) -> dict[str, Any]:
    refusal = await validate_webhook_url_async(req.url)
    if refusal:
        raise HTTPException(status_code=400, detail=refusal)
    try:
        await deps.monitor.add_sink_async(WebhookAlertSink(name=req.name, url=req.url,
                                                           secret=deps.monitor.webhook_secret))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    await audit_async(tenant, {"event": "webhook_added", "sink": req.name})
    return {"sink_name": req.name, "added": True}
