"""Engagement authorization policy administration (administrator-only).

A customer must never authorize its own targets: policies are created, updated
and revoked by administrators here, and every mutation is audited and sealed in
the tamper-evident chain. Tenants read their own policy through ``/api/scope``.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ishastra.api import deps
from ishastra.api.csrf import validate_csrf_token
from ishastra.api.deps import Tenant, audit_async, require_admin
from ishastra.api.schemas import PolicyCreateRequest, PolicyUpdateRequest
from ishastra.core import policies, store
from ishastra.core.policies import PolicyError
from ishastra.core.queue import get_assessment_worker

router = APIRouter(prefix="/api")


_assessment_worker = None


def _get_assessment_worker():
    global _assessment_worker
    if _assessment_worker is None:
        _assessment_worker = get_assessment_worker()
    return _assessment_worker


@router.get("/policies")
async def list_policies(tenant: Tenant = Depends(require_admin)) -> dict[str, Any]:
    """Every engagement policy (administrators only)."""
    items = [policy.to_dict(include_hosts=True) for policy in await policies.registry.list_async()]
    return {
        "count": len(items),
        "mode": "managed" if await deps.managed_mode_async() else "global",
        "policies": items,
    }


@router.post("/policies")
async def create_policy(
    req: PolicyCreateRequest,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Authorize one engagement for one tenant. A normal customer cannot do this."""
    now = time.time()
    effective_at = now + req.effective_in_seconds if req.effective_in_seconds else None
    expires_at = now + req.ttl_seconds if req.ttl_seconds else None
    try:
        policy = await policies.registry.create_async(
            tenant_id=req.tenant,
            program=req.program,
            authorized_by=req.authorized_by,
            authorization_ref=req.authorization_ref,
            include=req.include,
            exclude=req.exclude,
            authorized_networks=req.authorized_networks,
            allowed_ports=req.allowed_ports,
            allowed_asns=req.allowed_asns,
            allowed_countries=req.allowed_countries,
            allow_broad_networks=req.allow_broad_networks,
            effective_at=effective_at,
            expires_at=expires_at,
            created_by=tenant["tenant_id"],
        )
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    await audit_async(
        tenant,
        {
            "event": "policy_created",
            "policy_id": policy.policy_id,
            "policy_tenant": policy.tenant_id,
            "version": policy.version,
            "program": policy.program,
            "authorization_ref": policy.authorization_ref,
            "allow_broad_networks": policy.allow_broad_networks,
            "expires_at": policy.expires_at,
        },
    )
    return {**policy.to_dict(include_hosts=True), "created_by": tenant["tenant_id"]}


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    req: PolicyUpdateRequest,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Change an authorization, increment its version and invalidate queued jobs."""
    fields_set = req.model_fields_set
    if not fields_set:
        raise HTTPException(status_code=400, detail="At least one policy field must be supplied")
    changes = req.model_dump(exclude_unset=True, exclude_none=True)
    now = time.time()
    if "ttl_seconds" in fields_set:
        ttl_seconds = req.ttl_seconds
        changes.pop("ttl_seconds", None)
        changes["expires_at"] = now + ttl_seconds if ttl_seconds else None
    if "effective_in_seconds" in fields_set:
        effective_in_seconds = req.effective_in_seconds
        changes.pop("effective_in_seconds", None)
        changes["effective_at"] = now + effective_in_seconds if effective_in_seconds is not None else None

    if not changes:
        raise HTTPException(status_code=400, detail="No usable policy changes were supplied")
    try:
        policy = await policies.registry.update_async(policy_id, **changes)
    except PolicyError as exc:
        status_code = 404 if str(exc).startswith("unknown policy") else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from None
    persisted = await store.request_cancel_for_policy(policy.policy_id)
    cancelled = _get_assessment_worker().cancel_for_policy(policy.policy_id) or persisted
    await audit_async(
        tenant,
        {
            "event": "policy_updated",
            "policy_id": policy.policy_id,
            "policy_tenant": policy.tenant_id,
            "version": policy.version,
            "changed_fields": sorted(changes),
            "cancelled_jobs": cancelled,
        },
    )
    return {**policy.to_dict(include_hosts=True), "cancelled_jobs": cancelled}


@router.post("/policies/{policy_id}/revoke")
async def revoke_policy(
    policy_id: str,
    tenant: Tenant = Depends(require_admin),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Withdraw an authorization: submissions are refused, and queued or running
    assessments bound to this policy are cancelled at the next adapter boundary."""
    try:
        policy = await policies.registry.revoke_async(policy_id)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    persisted = await store.request_cancel_for_policy(policy.policy_id)
    cancelled = _get_assessment_worker().cancel_for_policy(policy.policy_id) or persisted
    await audit_async(
        tenant,
        {
            "event": "policy_revoked",
            "policy_id": policy.policy_id,
            "policy_tenant": policy.tenant_id,
            "version": policy.version,
            "cancelled_jobs": cancelled,
        },
    )
    return {
        "policy_id": policy.policy_id,
        "status": policy.status,
        "version": policy.version,
        "cancelled_jobs": cancelled,
    }


@router.get("/policies/lifecycle")
async def policy_lifecycle(tenant: Tenant = Depends(require_admin)) -> dict[str, Any]:
    """Read-only lifecycle view: every policy in exactly one of four states."""
    now = time.time()
    states: dict[str, list[str]] = {"draft": [], "active": [], "revoked": [], "expired": []}
    for policy in await policies.registry.list_async():
        states[policy.lifecycle_state(now=now)].append(policy.policy_id)
    return {"counts": {state: len(ids) for state, ids in states.items()}, "policies": states}


@router.get("/policies/{policy_id}/diff/{other_id}")
async def diff_policies(
    policy_id: str, other_id: str, tenant: Tenant = Depends(require_admin)
) -> dict[str, Any]:
    """What changes between two authorizations: added/removed hosts, ports, networks."""
    before = await policies.registry.get_async(policy_id)
    after = await policies.registry.get_async(other_id)
    if before is None or after is None:
        raise HTTPException(status_code=404, detail="Unknown policy")
    try:
        left, right = before.to_scope(), after.to_scope()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {
        "from": {"policy_id": before.policy_id, "version": before.version},
        "to": {"policy_id": after.policy_id, "version": after.version},
        "diff": left.diff(right),
    }


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str, tenant: Tenant = Depends(require_admin)) -> dict[str, Any]:
    policy = await policies.registry.get_async(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Unknown policy")
    return policy.to_dict(include_hosts=True)
