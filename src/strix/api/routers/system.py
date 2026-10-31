"""Liveness, readiness, scope, adapter inventory, overview and audit trail."""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Query, Response

from strix import __version__
from strix.api import deps
from strix.api.deps import Tenant, require_admin, require_auth
from strix.core import policies, scope
from strix.core import store_async as store
from strix.core.adapters import ADAPTERS, PROFILES, StrixAgentAdapter

router = APIRouter(prefix="/api")

_STARTED = time.monotonic()


@router.get("/health")
def health() -> dict[str, Any]:
    """Liveness only. Unauthenticated, so it publishes no platform counters."""
    return {
        "status": "healthy",
        "service": "strix",
        "version": __version__,
        "uptime_seconds": round(time.monotonic() - _STARTED, 1),
    }


@router.get("/ready")
async def ready() -> dict[str, Any]:
    """Readiness: the database answers and the audit chain verifies."""
    try:
        await store.schema_version()
        database_ok = True
    except Exception:
        database_ok = False
    chain_ok = (await deps.audit_chain.verify_cached_async())[0]   # unauthenticated: must stay cheap
    managed = await deps.managed_mode_async()
    scope_ready = (bool(await policies.registry.list_async()) if managed
                   else scope.active() is not None)
    return {"ready": database_ok and chain_ok, "database": database_ok,
            "audit_chain": chain_ok, "monitoring": deps.monitor.running,
            "scope_configured": scope_ready,
            "scope_mode": "managed" if managed else "global"}


@router.get("/overview")
async def overview(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """The caller's own activity. Platform-wide state is under /api/monitor/status."""
    tenant_id = tenant["tenant_id"]
    recent = await store.list_jobs(tenant=tenant_id, limit=50)
    targets = list(dict.fromkeys(job["target"] for job in recent))
    return {
        "tenant_id": tenant_id,
        "tier": tenant["tier"],
        "total_jobs": await store.count_jobs(tenant=tenant_id),
        "total_findings": await store.count_findings(tenant=tenant_id),
        "targets": targets[:10],
        "total_targets": len(targets),
        "audit_events": len(deps.audit_log.entries(tenant=tenant_id)),
    }


@router.get("/scope")
def get_scope(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """The authorization record this caller is judged against.

    Managed mode shows the caller's *own* engagement policy — a tenant never
    sees another engagement's hosts, networks or ports. Global mode shows the
    single-organization scope document, as before.
    """
    if deps.managed_mode():
        policy, reason = policies.registry.resolve(tenant["tenant_id"])
        if policy is None:
            return {"configured": False, "mode": "managed",
                    "tenant_id": tenant["tenant_id"],
                    "detail": reason or "no usable authorization policy for this tenant"}
        return {"configured": True, "mode": "managed",
                "tenant_id": tenant["tenant_id"], "policy": policy.to_dict(include_hosts=True)}
    authorized = scope.active()
    if authorized is None:
        return {"configured": False, "mode": "global", "source": deps.settings.scope_file,
                "detail": "no authorized scope — every scan and probe is refused"}
    # Principal ids are configuration state; the credential values behind them
    # are never serialized anywhere (they exist only in process memory).
    auth_users = list(authorized.auth.ids) if authorized.auth else []
    return {
        "configured": True,
        "mode": "global",
        "source": deps.settings.scope_file,
        "program": authorized.program,
        "authorized_by": authorized.authorized_by,
        "authorization_ref": authorized.authorization_ref,
        "include": list(authorized.include),
        "exclude": list(authorized.exclude),
        "authorized_networks": list(authorized.authorized_networks),
        "allowed_ports": list(authorized.allowed_ports),
        "allow_broad_networks": authorized.allow_broad_networks,
        "auth_principals": auth_users,
    }


@router.get("/adapters")
def list_adapters(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """What each adapter can do, and whether its prerequisites are present."""
    return {
        "profiles": {name: list(names) for name, names in PROFILES.items()},
        "adapters": [adapter.info() for adapter in ADAPTERS.values()],
        "engine": StrixAgentAdapter().info(),
    }


@router.get("/audit")
def audit_trail(limit: int = Query(default=100, ge=1, le=500),
                tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    entries = deps.audit_log.entries(tenant=deps.tenant_filter(tenant))
    newest_first = entries[::-1][:limit]
    return {"tenant_id": tenant["tenant_id"], "total_records": len(entries),
            "returned": len(newest_first), "audit_logs": newest_first}


@router.get("/audit/verify")
def verify_audit(tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    valid, detail = deps.audit_chain.verify()
    if tenant.get("admin"):
        return {"valid": valid, "detail": detail, "scope": "platform",
                "entries": len(deps.audit_chain)}
    # The chain spans every tenant: its length or a break position would leak
    # other tenants' activity volume, so tenants get the verdict only.
    return {"valid": valid, "scope": "tenant",
            "detail": detail if valid else "integrity verification failed"}


@router.get("/metrics", include_in_schema=False)
def metrics_endpoint(tenant: Tenant = Depends(require_admin)) -> Response:
    """Prometheus text exposition. Aggregate counters only: no tenants, no targets.

    Administrator-only: even aggregated, the counters describe every tenant's
    job volume and finding severity mix (and the audit chain's length), which is
    platform-wide activity a single customer must not be able to read.
    """
    from fastapi.responses import Response as FastAPIResponse

    from strix.metrics import metrics as registry
    from strix.metrics import snapshot_from_store

    jobs_by_state, findings_by_severity = snapshot_from_store()
    chain_ok, _detail = deps.audit_chain.verify_cached()
    body = registry.render(job_states=jobs_by_state,
                           finding_severities=findings_by_severity,
                           chain_entries=deps.audit_chain.__len__(),
                           chain_valid=chain_ok)
    return FastAPIResponse(content=body, media_type="text/plain; version=0.0.4")
