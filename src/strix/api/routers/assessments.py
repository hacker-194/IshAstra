"""Assessment jobs: create, poll, cancel, SARIF export and evidence reports."""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse, Response

from strix import analyst
from strix.api import dependencies as deps
from strix.api.csrf import validate_csrf_token
from strix.api.dependencies import settings as deps_settings
from strix.api.deps import (
    Tenant,
    audit_async,
    check_scope_or_raise_async,
    check_target_or_raise,
    require_auth,
    tenant_filter,
    tenant_scope_async,
)
from strix.api.schemas import (
    AssessRequest,
    AssessResponse,
    FindingRemediationUpdate,
    FindingStatusUpdate,
    JobSummaryResponse,
    Page,
    ReportRequest,
)
from strix.core import jobs, store
from strix.core.adapters import PROFILES
from strix.core.auth import EncryptedAuthConfig, create_authenticator_from_dict
from strix.core.findings import to_sarif
from strix.core.queue import get_assessment_worker
from strix.core.redaction import redact_text, sanitize_target
from strix.core.worker import AssessmentQueueFull, WorkerLeaseError
from strix.metrics import record_report
from strix.report_html import render_html_report
from strix.report_pdf import generate_pdf_from_job

router = APIRouter(prefix="/api")

# One queue for the process, selected by STRIX_QUEUE_MODE (in-process or k8s-jobs).
# Use a lazy getter to allow test fixtures to set environment variables first.
_assessment_worker = None


def _get_assessment_worker():
    global _assessment_worker
    if _assessment_worker is None:
        _assessment_worker = get_assessment_worker()
    return _assessment_worker


_ACTIVE_STATES = ("queued", "running")
_RETRYABLE_STATES = ("failed", "partial", "cancelled")
MAX_INLINE_TIMEOUT = 120.0  # wait=true holds a request thread; longer runs must be queued
# A client-chosen deduplication token. Bounded and printable so it can be a
# database key without escaping concerns.
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _idempotency_key(value: str | None) -> str | None:
    """Validated Idempotency-Key header, or 400 when malformed."""
    if value is None:
        return None
    key = value.strip()
    if not key:
        return None
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key must be 1-128 characters of A-Z a-z 0-9 . _ : -",
        )
    return key


async def _existing_submission(key: str, tenant: Tenant) -> dict[str, Any] | None:
    """The job a repeated submission refers to, rendered like a fresh response."""
    existing = await store.find_job_id_by_idempotency(key, tenant=tenant["tenant_id"])
    if existing is None:
        return None
    job = await store.get_job(existing, tenant=tenant_filter(tenant))
    if job is None:
        return None
    return {
        **job,
        **_links(job["id"]),
        "poll_url": f"/api/assess/{job['id']}",
        "cancel_url": f"/api/assess/{job['id']}/cancel",
        "deduplicated": True,
    }


def _links(job_id: str) -> dict[str, str]:
    return {
        "sarif_url": f"/api/assess/{job_id}/sarif",
        "report_url": f"/api/assess/{job_id}/report.html",
    }


async def record_job(job: jobs.Job, tenant: Tenant) -> dict[str, Any]:
    """Persist, audit and chain one finished job (inline and worker paths)."""
    tenant_id = tenant["tenant_id"]
    await store.save_job(job, tenant=tenant_id)
    await audit_async(
        tenant,
        {
            "event": "assessment_job",
            "job": job.id,
            "target": sanitize_target(job.target),
            "profile": job.profile,
            "state": job.state.value,
            "actor": tenant_id,
            "policy": job.policy,
            "findings": len(job.findings),
            "failed_adapters": [run.adapter for run in job.runs if run.state.value != "ok"],
        },
    )
    chain_hash = await deps.audit_chain.append_async(
        {
            "event": "assessment_job",
            "job": job.id,
            "target": sanitize_target(job.target),
            "state": job.state.value,
            "verdict": job.verdict,
            "findings": [finding.category for finding in job.findings],
        }
    )
    return {**job.to_dict(), **_links(job.id), "audit_chain_hash": chain_hash}


def record_job_sync(job: jobs.Job, tenant: Tenant) -> dict[str, Any]:
    """Sync wrapper for record_job (for worker thread callbacks).

    Uses the current thread's event loop if available (worker threads have one),
    otherwise falls back to asyncio.run() for test contexts.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # No event loop in this thread (e.g., tests)
        return asyncio.run(record_job(job, tenant))
    if loop.is_running():
        # If loop is already running (rare in worker thread context),
        # run in a new thread to avoid deadlock. Do not catch RuntimeError
        # from the coroutine itself here: retrying would save a partial job
        # twice and hide the real failure.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, record_job(job, tenant))
            return future.result()
    return loop.run_until_complete(record_job(job, tenant))


@router.post("/assess", response_model=AssessResponse)
async def create_assessment(
    req: AssessRequest,
    tenant: Tenant = Depends(require_auth),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _csrf: bool = Depends(validate_csrf_token),
) -> AssessResponse | JSONResponse:
    """Queue an authorized assessment (202 + job id), or run it inline with ``wait``.

    Scope and profile are validated synchronously: a refused target is an
    immediate 4xx, never a queued job. Acceptance is not success — the caller
    must read the job's own state.

    ``Idempotency-Key`` makes a retried submission safe: a repeat with the same
    key returns the original job (``deduplicated: true``) instead of starting a
    second assessment of the same target.
    """
    key = _idempotency_key(idempotency_key)
    if key is not None:
        prior = await _existing_submission(key, tenant)
        if prior is not None:
            prior_dict = dict(prior)
            prior_dict["deduplicated"] = True
            prior_dict.setdefault("poll_url", f"/api/assess/{prior_dict['id']}")
            prior_dict.setdefault("cancel_url", f"/api/assess/{prior_dict['id']}/cancel")
            status_code = status.HTTP_202_ACCEPTED if prior["state"] in _ACTIVE_STATES else 200
            # Return JSONResponse for correct status code; response_model validates content
            return JSONResponse(status_code=status_code, content=prior_dict)
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    # Managed mode: this tenant's own engagement policy is the authorization
    # (optionally the exact policy named in the request); global mode falls
    # back to the single scope document. Either way the refusal is immediate.
    snapshot = await tenant_scope_async(tenant, req.policy_id)
    check_target_or_raise(target, snapshot)

    # Enforce API key's include_hosts restriction (per-project key scope)
    include_hosts = tenant.get("include_hosts")
    if include_hosts:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        target_host = parsed.hostname or ""
        if target_host:
            target_host = target_host.lower().strip(".")
            allowed = [h.strip().lower().strip(".") for h in include_hosts.split(",") if h.strip()]
            # Support wildcard subdomain matching (e.g., "*.example.com")
            matched = False
            for pattern in allowed:
                if pattern.startswith("*."):
                    # *.example.com covers subdomains only, never the apex
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

    if req.profile not in PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown profile {req.profile!r}; choose from {sorted(PROFILES)}",
        )

    if req.wait and req.timeout > MAX_INLINE_TIMEOUT:
        raise HTTPException(
            status_code=400,
            detail=f"wait=true is limited to {MAX_INLINE_TIMEOUT:.0f}s; queue longer runs and poll",
        )

    actor = tenant["tenant_id"]

    # Build job policy, including encrypted auth config if provided
    job_policy = {}
    if req.auth is not None:
        if not deps_settings.encryption_key:
            raise HTTPException(
                status_code=500,
                detail="Authentication encryption key not configured (STRIX_ENCRYPTION_KEY)",
            )
        # Create authenticator from request config
        auth_config = req.auth.model_dump(exclude_none=True)
        # Ensure principal_id is set
        if "principal_id" not in auth_config or not auth_config["principal_id"]:
            auth_config["principal_id"] = f"auth-{secrets.token_hex(4)}"
        try:
            authenticator = create_authenticator_from_dict(auth_config)
            encrypted_auth = EncryptedAuthConfig.create(authenticator, deps_settings.encryption_key)
            job_policy["encrypted_auth_config"] = {
                "principal_id": encrypted_auth.principal_id,
                "authenticator_type": encrypted_auth.authenticator_type,
                "encrypted_config": encrypted_auth.encrypted_config,
                "created_at": encrypted_auth.created_at,
            }
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid auth configuration: {exc}") from exc

    if req.wait:
        job = jobs.run_assessment(
            target,
            profile=req.profile,
            actor=actor,
            timeout=req.timeout,
            scope_snapshot=snapshot,
            idempotency_key=key,
            policy=job_policy or None,
        )
        try:
            result = await record_job(job, tenant)
            result["deduplicated"] = False
            result.setdefault("poll_url", f"/api/assess/{result['id']}")
            result.setdefault("cancel_url", f"/api/assess/{result['id']}/cancel")
            return AssessResponse(**result)
        except store.JobConflict:
            prior = await _existing_submission(key, tenant) if key else None
            if prior is None:
                raise
            prior_dict = dict(prior)
            prior_dict["deduplicated"] = True
            prior_dict.setdefault("poll_url", f"/api/assess/{prior_dict['id']}")
            prior_dict.setdefault("cancel_url", f"/api/assess/{prior_dict['id']}/cancel")
            return JSONResponse(
                status_code=(status.HTTP_202_ACCEPTED if prior["state"] in _ACTIVE_STATES else 200),
                content=prior_dict,
            )

    # Persist the id first so the job is durable before any work starts, and
    # build the response before submit so this thread never reads a running Job.
    job = jobs.prepare(
        target,
        profile=req.profile,
        actor=actor,
        timeout=req.timeout,
        scope_snapshot=snapshot,
        idempotency_key=key,
        policy=job_policy or None,
    )
    try:
        await store.save_job(job, tenant=actor)
    except store.JobConflict:
        # Two concurrent submissions raced on the same key: the winner owns it.
        prior = await _existing_submission(key, tenant) if key else None
        if prior is None:
            raise
        prior_dict = dict(prior)
        prior_dict["deduplicated"] = True
        prior_dict.setdefault("poll_url", f"/api/assess/{prior_dict['id']}")
        prior_dict.setdefault("cancel_url", f"/api/assess/{prior_dict['id']}/cancel")
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=prior_dict)
    payload = {
        **job.to_dict(),
        **_links(job.id),
        "poll_url": f"/api/assess/{job.id}",
        "cancel_url": f"/api/assess/{job.id}/cancel",
        "deduplicated": False,
    }

    def finish(finished: jobs.Job) -> None:
        record_job_sync(finished, tenant)

    try:
        await _get_assessment_worker().submit(job, on_finish=finish)
    except AssessmentQueueFull as exc:
        job.state = jobs.JobState.FAILED
        job.error = str(exc)
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        await audit_async(
            tenant,
            {
                "event": "assessment_rejected",
                "job": job.id,
                "target": sanitize_target(target),
                "reason": "queue_full",
            },
        )
        raise HTTPException(status_code=503, detail="Assessment queue is full — try again shortly") from None
    except WorkerLeaseError as exc:
        # Another process owns the worker for this database; accepting the job
        # would mean it never runs. Refuse instead of queueing it into a void.
        job.state = jobs.JobState.FAILED
        job.error = "worker unavailable"
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503, detail=f"worker unavailable: {exc}") from None

    await audit_async(
        tenant,
        {
            "event": "assessment_queued",
            "job": job.id,
            "target": sanitize_target(target),
            "profile": req.profile,
            "policy_id": job.policy.get("policy_id"),
            "policy_version": job.policy.get("policy_version"),
        },
    )
    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=payload)


@router.get("/assess", response_model=Page[JobSummaryResponse])
async def list_assessments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    tenant: Tenant = Depends(require_auth),
) -> Page[JobSummaryResponse]:
    rows = await store.list_jobs(tenant=tenant_filter(tenant), limit=page_size, offset=(page - 1) * page_size)
    total = await store.count_jobs(tenant=tenant_filter(tenant))
    items = [
        JobSummaryResponse(
            id=row["id"],
            target=row["target"],
            profile=row["profile"],
            actor=row["actor"],
            state=row["state"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            verdict=row["verdict"],
            findings_count=len(row.get("findings", [])),
            poll_url=f"/api/assess/{row['id']}",
            cancel_url=f"/api/assess/{row['id']}/cancel",
            sarif_url=f"/api/assess/{row['id']}/sarif",
            report_url=f"/api/assess/{row['id']}/report.html",
            audit_chain_hash="",  # Not stored in list view; available on job detail
        )
        for row in rows
    ]
    return Page(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=page * page_size < total,
    )


async def _get_job_or_404(job_id: str, tenant: Tenant) -> dict[str, Any]:
    # 404 rather than 403: never confirm that another tenant's job exists.
    job = await store.get_job(job_id, tenant=tenant_filter(tenant))
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job")
    return job


@router.get("/assess/{job_id}")
async def get_assessment(job_id: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    return await _get_job_or_404(job_id, tenant)


@router.get("/assess/{job_id}/sarif")
async def get_sarif(job_id: str, tenant: Tenant = Depends(require_auth)) -> JSONResponse:
    await _get_job_or_404(job_id, tenant)
    findings = await store.get_findings(job_id, tenant=tenant_filter(tenant))
    return JSONResponse(content=to_sarif(findings), media_type="application/sarif+json")


@router.patch("/assess/{job_id}/findings/{fingerprint}")
async def update_finding_status(
    job_id: str,
    fingerprint: str,
    update: FindingStatusUpdate,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Move a finding through triage/remediation; the transition is audited.

    The finding lifecycle is enforced server-side, so a client cannot skip from
    ``new`` straight to ``closed`` or reopen a closed finding.
    """
    job = await _get_job_or_404(job_id, tenant)
    if job["state"] in _ACTIVE_STATES:
        raise HTTPException(status_code=409, detail="Wait for the assessment to finish before triaging")
    if not re.fullmatch(r"[0-9a-f]{32}", fingerprint):
        raise HTTPException(status_code=404, detail="Unknown finding")
    before = next((f for f in job.get("findings", []) if f["fingerprint"] == fingerprint), None)
    if before is None:
        raise HTTPException(status_code=404, detail="Unknown finding")

    try:
        updated = await store.update_finding_status(
            job_id,
            fingerprint,
            tenant=tenant_filter(tenant),
            to_status=update.status,
            actor=tenant["tenant_id"],
            note=redact_text(update.note) if update.note else "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding")

    await audit_async(
        tenant,
        {
            "event": "finding_status_changed",
            "job": job_id,
            "fingerprint": fingerprint,
            "from": before["status"],
            "to": updated["status"],
            "note": redact_text(update.note) if update.note else "",
        },
    )
    return updated


@router.get("/assess/{job_id}/findings/{fingerprint}/history")
async def finding_history(
    job_id: str,
    fingerprint: str,
    tenant: Tenant = Depends(require_auth),
) -> dict[str, Any]:
    """Immutable event timeline plus current remediation metadata."""
    job = await _get_job_or_404(job_id, tenant)
    if not re.fullmatch(r"[0-9a-f]{32}", fingerprint):
        raise HTTPException(status_code=404, detail="Unknown finding")
    if not any(item["fingerprint"] == fingerprint for item in job.get("findings", [])):
        raise HTTPException(status_code=404, detail="Unknown finding")
    tenant_id = job["tenant"]
    return {
        "job_id": job_id,
        "fingerprint": fingerprint,
        "events": await store.list_finding_events(tenant=tenant_id, job_id=job_id, fingerprint=fingerprint),
        "remediation": await store.get_finding_remediation(
            tenant=tenant_id, job_id=job_id, fingerprint=fingerprint
        )
        or {
            "owner": "",
            "due_at": None,
            "exception_until": None,
            "exception_reason": "",
            "exception_approved_by": "",
        },
    }


@router.patch("/assess/{job_id}/findings/{fingerprint}/remediation")
async def update_finding_remediation(
    job_id: str,
    fingerprint: str,
    update: FindingRemediationUpdate,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Assign an owner/deadline or record a time-boxed risk exception."""
    job = await _get_job_or_404(job_id, tenant)
    if not re.fullmatch(r"[0-9a-f]{32}", fingerprint):
        raise HTTPException(status_code=404, detail="Unknown finding")
    if not any(item["fingerprint"] == fingerprint for item in job.get("findings", [])):
        raise HTTPException(status_code=404, detail="Unknown finding")
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
    updated = await store.set_finding_remediation(
        tenant=job["tenant"],
        job_id=job_id,
        fingerprint=fingerprint,
        owner=update.owner.strip(),
        due_at=update.due_at,
        exception_until=update.exception_until,
        exception_reason=redact_text(update.exception_reason.strip()),
        exception_approved_by=update.exception_approved_by.strip(),
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown finding")
    await audit_async(
        tenant,
        {
            "event": "finding_remediation_updated",
            "job": job_id,
            "fingerprint": fingerprint,
            "owner": updated["owner"],
            "due_at": updated["due_at"],
            "exception_until": updated["exception_until"],
            "exception_approved_by": updated["exception_approved_by"],
        },
    )
    return updated


@router.post("/assess/{job_id}/cancel")
async def cancel_assessment(
    job_id: str,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Cancel a queued or running job the caller owns (administrators excepted)."""
    job = await _get_job_or_404(job_id, tenant)
    if job["state"] not in _ACTIVE_STATES:
        raise HTTPException(status_code=409, detail=f"Job is already {job['state']}")
    # Persist first: another process may own execution, and its in-memory job
    # cannot see this process's event. The durable flag is polled by the owner.
    persisted = await store.request_cancel(job_id, tenant=tenant_filter(tenant))
    signalled = _get_assessment_worker().cancel(job_id)
    if not persisted and not signalled:
        raise HTTPException(status_code=409, detail="Job is not running on this worker")
    await audit_async(
        tenant,
        {"event": "assessment_cancel_requested", "job": job_id, "state": job["state"]},
    )
    return {
        "id": job_id,
        "state": "cancelling",
        "detail": "cancellation signalled; poll the job for its final state",
    }


@router.post("/assess/{job_id}/retry")
async def retry_assessment(
    job_id: str,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> JSONResponse:
    """Queue a fresh job for a failed, partial or cancelled assessment.

    Retrying is a new submission, not a resumption: the target is re-judged
    against the caller's *current* authorization (a revoked policy must not be
    revived by a retry), the stored target is used as persisted — already
    stripped of credentials — and the new job records ``retry_of``
    so the lineage is auditable.
    """
    original = await _get_job_or_404(job_id, tenant)
    if original["state"] not in _RETRYABLE_STATES:
        raise HTTPException(
            status_code=409,
            detail=(f"Job is {original['state']}; only a failed, partial or cancelled job can be retried"),
        )
    target = (original.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=409, detail="Stored target is empty; submit a new assessment")
    snapshot = await tenant_scope_async(tenant)
    check_target_or_raise(target, snapshot)

    actor = tenant["tenant_id"]
    try:
        policy = original.get("policy")
        timeout = float((policy or {}).get("timeout_seconds") or 120.0) if policy is not None else 120.0
    except (TypeError, ValueError, AttributeError):
        timeout = 120.0
    # Preserve encrypted auth config from original job
    retry_policy = {}
    if policy and "encrypted_auth_config" in policy:
        retry_policy["encrypted_auth_config"] = policy["encrypted_auth_config"]
    job = jobs.prepare(
        target,
        profile=original["profile"],
        actor=actor,
        timeout=timeout,
        scope_snapshot=snapshot,
        policy=retry_policy or None,
    )
    job.policy["retry_of"] = job_id
    job.policy["retry_attempt"] = int(original.get("attempts") or 0) + 1
    try:
        await store.save_job(job, tenant=actor)
    except store.JobConflict:
        # Another retry with same idempotency key raced; return the winner
        prior = await _existing_submission(job.idempotency_key, tenant) if job.idempotency_key else None
        if prior is None:
            raise
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=prior)
    payload = {
        **job.to_dict(),
        **_links(job.id),
        "poll_url": f"/api/assess/{job.id}",
        "cancel_url": f"/api/assess/{job.id}/cancel",
        "retry_of": job_id,
    }

    def finish(finished: jobs.Job) -> None:
        record_job_sync(finished, tenant)

    try:
        await _get_assessment_worker().submit(job, on_finish=finish)
    except AssessmentQueueFull as exc:
        job.state = jobs.JobState.FAILED
        job.error = str(exc)
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503, detail="Assessment queue is full — try again shortly") from None
    except WorkerLeaseError as exc:
        job.state = jobs.JobState.FAILED
        job.error = "worker unavailable"
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503, detail=f"worker unavailable: {exc}") from None
    await audit_async(
        tenant,
        {
            "event": "assessment_retried",
            "job": job.id,
            "retry_of": job_id,
            "target": sanitize_target(target),
            "profile": job.profile,
        },
    )
    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=payload)


def _bound_authorization(job: dict[str, Any]) -> dict[str, Any]:
    """Historical authorization metadata captured when the job was prepared.

    Do not substitute today's policy for an older job: a policy may have been
    amended or revoked since the scan, and that must not rewrite the evidence.
    Legacy rows lacking full binding metadata are marked unavailable.
    """
    binding = job.get("policy") or {}
    program = binding.get("scope_program")
    authorized_by = binding.get("scope_authorized_by")
    authorization_ref = binding.get("authorization_ref")
    include = binding.get("scope_include")
    available = (
        isinstance(program, str)
        and bool(program)
        and isinstance(authorized_by, str)
        and bool(authorized_by)
        and isinstance(authorization_ref, str)
        and bool(authorization_ref)
        and isinstance(include, list)
    )
    return {
        "program": program if isinstance(program, str) else "",
        "authorized_by": authorized_by if isinstance(authorized_by, str) else "",
        "authorization_ref": (authorization_ref if isinstance(authorization_ref, str) else ""),
        "scope_include": include if isinstance(include, list) else [],
        "policy_id": binding.get("policy_id"),
        "policy_version": binding.get("policy_version"),
        "available": available,
    }


@router.post("/report")
async def build_report(
    req: ReportRequest,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """Submission-ready evidence bundle for a target's latest finished assessment."""
    target = req.target.strip()
    job = await store.latest_finished_job(target, tenant=tenant_filter(tenant))
    if job is None:
        # Preserve the API's useful 403 for an out-of-scope target, while not
        # making old report retrieval depend on today's active authorization.
        await check_scope_or_raise_async(target, tenant)
        raise HTTPException(
            status_code=404,
            detail="No finished assessment for this target — assess it first",
        )

    authorized = _bound_authorization(job)
    findings = job["findings"]
    by_severity = dict(Counter(finding["severity"] for finding in findings))

    # Seal the bundle in the tamper-evident chain so the report can later be
    # shown to have existed, unchanged, at the moment of submission.
    chain_hash = await deps.audit_chain.append_async(
        {
            "event": "report_generated",
            "target": job["target"],
            "job": job["id"],
            "program": authorized["program"],
            "authorization_ref": authorized["authorization_ref"],
            "findings": [finding["fingerprint"] for finding in findings],
        }
    )
    await audit_async(tenant, {"event": "report_generated", "target": job["target"], "job": job["id"]})

    return {
        "program": authorized["program"],
        "authorized_by": authorized["authorized_by"],
        "authorization_ref": authorized["authorization_ref"],
        "scope_include": authorized["scope_include"],
        "authorization_metadata_available": authorized["available"],
        "policy_id": authorized["policy_id"],
        "policy_version": authorized["policy_version"],
        "target": job["target"],
        "job_id": job["id"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "state": job["state"],
        "verdict": job["verdict"],
        "coverage": job["coverage"],
        "severity_counts": by_severity,
        "findings": findings,
        "summary": (
            f"{len(findings)} finding(s) on {job['target']} under "
            f"{authorized['program']} [{authorized['authorization_ref']}]; "
            f"job {job['id']} {job['state']}"
        ),
        "integrity": {
            "chain_valid": (await deps.audit_chain.verify_async())[0],
            "chain_hash": chain_hash,
        },
    }


@router.post("/assess/{job_id}/triage")
async def triage_assessment(
    job_id: str,
    tenant: Tenant = Depends(require_auth),
    _csrf: bool = Depends(validate_csrf_token),
) -> dict[str, Any]:
    """AI-analyst triage for a finished job's findings (advisory only).

    The analyst can only attach priorities, rationales and next steps to
    fingerprints that exist. It cannot create findings or alter severity,
    status or evidence; without a configured provider the deterministic
    findings are returned unchanged with ``ai_enriched: false``.
    """
    job = await _get_job_or_404(job_id, tenant)
    if job["state"] not in ("completed", "partial"):
        raise HTTPException(status_code=409, detail=f"Job is {job['state']}; triage needs findings")
    provider = analyst.provider_from_env()
    triage = analyst.analyze_findings(job["findings"], provider)
    await audit_async(tenant, {"event": "ai_triage", "job": job_id, "ai_enriched": triage.ai_enriched})
    return {
        **triage.to_dict(),
        "job_id": job_id,
        "findings_count": len(job["findings"]),
    }


@router.get(
    "/assess/{job_id}/report.html",
    response_class=HTMLResponse,
    responses={200: {"content": {"text/html": {}}}},
)
async def get_html_report(job_id: str, tenant: Tenant = Depends(require_auth)) -> HTMLResponse:
    """Self-contained HTML assessment report (evidence pre-redacted)."""
    job = await _get_job_or_404(job_id, tenant)
    findings = await store.get_findings(job_id, tenant=tenant_filter(tenant))
    authorized = _bound_authorization(job)
    report = {
        "target": job["target"],
        "job_id": job["id"],
        "state": job["state"],
        "verdict": job["verdict"],
        "coverage": job["coverage"],
        "severity_counts": dict(Counter(f.severity for f in findings)),
        "findings": [f.to_dict() for f in findings],
        "program": authorized["program"],
        "authorized_by": authorized["authorized_by"],
        "authorization_ref": authorized["authorization_ref"],
        "scope_include": authorized["scope_include"],
        "authorization_metadata_available": authorized["available"],
        "policy_id": authorized["policy_id"],
        "policy_version": authorized["policy_version"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "integrity": {
            "chain_valid": (await deps.audit_chain.verify_cached_async())[0],
            "chain_hash": "",
        },
    }
    record_report("html")
    await audit_async(tenant, {"event": "report_html_generated", "job": job_id})
    return HTMLResponse(render_html_report(report))


@router.get(
    "/assess/{job_id}/report.pdf",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def get_pdf_report(job_id: str, tenant: Tenant = Depends(require_auth)) -> Response:
    """Professional PDF assessment report generated via WeasyPrint."""
    job = await _get_job_or_404(job_id, tenant)
    findings = await store.get_findings(job_id, tenant=tenant_filter(tenant))
    authorized = _bound_authorization(job)

    try:
        pdf_bytes = generate_pdf_from_job(job, [f.to_dict() for f in findings], authorized)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=f"PDF generation unavailable: {exc}") from None

    record_report("pdf")
    await audit_async(tenant, {"event": "report_pdf_generated", "job": job_id})
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="strix-report-{job_id}.pdf"'},
    )
