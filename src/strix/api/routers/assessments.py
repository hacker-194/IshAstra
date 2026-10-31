"""Assessment jobs: create, poll, cancel, SARIF export and evidence reports."""
from __future__ import annotations

import asyncio
import re
import time
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse

from strix import analyst
from strix import metrics as strix_metrics
from strix.api import deps
from strix.api.deps import (
    Tenant,
    audit_async,
    check_scope_or_raise_async,
    check_target_or_raise,
    require_auth,
    tenant_filter,
)
from strix.api.schemas import (
    AssessRequest,
    Page,
    ReportRequest,
)
from strix.core import jobs
from strix.core import store_async as store
from strix.core.adapters import (
    PROFILES,
    Holdings,
    default_holdings,
    hybrid_required,
)
from strix.core.findings import to_sarif
from strix.core.redaction import sanitize_target
from strix.core.worker import AssessmentQueueFull, WorkerLeaseError, assessment_worker
from strix.report_html import render_html_report

router = APIRouter(prefix="/api")

_ACTIVE_STATES = ("queued", "running")
_RETRYABLE_STATES = ("failed", "partial", "cancelled")
MAX_INLINE_TIMEOUT = 120.0   # wait=true holds a request thread; longer runs must be queued
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
    return {**job, **_links(job["id"]), "poll_url": f"/api/assess/{job['id']}",
            "cancel_url": f"/api/assess/{job['id']}/cancel", "deduplicated": True}


def _links(job_id: str) -> dict[str, str]:
    return {"sarif_url": f"/api/assess/{job_id}/sarif",
            "report_url": f"/api/assess/{job_id}/report.html"}


async def record_job(job: jobs.Job, tenant: Tenant) -> dict[str, Any]:
    """Persist, audit and chain one finished job (inline and worker paths)."""
    tenant_id = tenant["tenant_id"]
    await store.save_job(job, tenant=tenant_id)
    await audit_async(tenant, {
        "event": "assessment_job", "job": job.id, "target": sanitize_target(job.target),
        "profile": job.profile, "state": job.state.value, "actor": tenant_id,
        "policy": job.policy, "findings": len(job.findings),
        "failed_adapters": [run.adapter for run in job.runs if run.state.value != "ok"],
    })
    chain_hash = await deps.audit_chain.append_async({
        "event": "assessment_job", "job": job.id, "target": sanitize_target(job.target),
        "state": job.state.value, "verdict": job.verdict,
        "findings": [finding.category for finding in job.findings],
    })
    return {**job.to_dict(), **_links(job.id), "audit_chain_hash": chain_hash}


def record_job_sync(job: jobs.Job, tenant: Tenant) -> dict[str, Any]:
    """Sync wrapper for record_job (for worker thread callbacks)."""
    return asyncio.run(record_job(job, tenant))


@router.post("/assess", response_model=None)  # dict (200) or JSONResponse (202)
async def create_assessment(req: AssessRequest,
                            tenant: Tenant = Depends(require_auth),
                            idempotency_key: str | None = Header(default=None,
                                                                 alias="Idempotency-Key")
                            ) -> dict[str, Any] | JSONResponse:
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
            return JSONResponse(status_code=status.HTTP_202_ACCEPTED
                                if prior["state"] in _ACTIVE_STATES else 200,
                                content=prior)
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    # Managed mode: this tenant's own engagement policy is the authorization
    # (optionally the exact policy named in the request); global mode falls
    # back to the single scope document. Either way the refusal is immediate.
    snapshot = await deps.tenant_scope_async(tenant, req.policy_id)
    check_target_or_raise(target, snapshot)
    if req.profile not in PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown profile {req.profile!r}; choose from {sorted(PROFILES)}")

    if req.profile == "hybrid":
        holdings = Holdings(
                native="native" in (req.hybrid_components or []),
                strix="strix" in (req.hybrid_components or []),
            )
        if not hybrid_required(holdings):
            raise HTTPException(
                status_code=400,
                detail="hybrid assessments require native=true and strix=true in hybrid_components")
    else:
        holdings = default_holdings()

    if req.wait and req.timeout > MAX_INLINE_TIMEOUT:
        raise HTTPException(
            status_code=400,
            detail=f"wait=true is limited to {MAX_INLINE_TIMEOUT:.0f}s; queue longer runs and poll")

    actor = tenant["tenant_id"]
    if req.wait:
        job = jobs.run_assessment(
            target,
            profile=req.profile,
            actor=actor,
            timeout=req.timeout,
            scope_snapshot=snapshot,
            idempotency_key=key,
        )
        try:
            return await record_job(job, tenant)
        except store.JobConflict:
            prior = await _existing_submission(key, tenant) if key else None
            if prior is None:
                raise
            return prior

    # Persist the id first so the job is durable before any work starts, and
    # build the response before submit so this thread never reads a running Job.
    job = jobs.prepare(
        target,
        profile=req.profile,
        actor=actor,
        timeout=req.timeout,
        scope_snapshot=snapshot,
        idempotency_key=key,
    )
    try:
        await store.save_job(job, tenant=actor)
    except store.JobConflict:
        # Two concurrent submissions raced on the same key: the winner owns it.
        prior = await _existing_submission(key, tenant) if key else None
        if prior is None:
            raise
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=prior)
    payload = {**job.to_dict(), **_links(job.id),
               "poll_url": f"/api/assess/{job.id}",
               "cancel_url": f"/api/assess/{job.id}/cancel"}
    def finish(finished: jobs.Job) -> None:
        record_job_sync(finished, tenant)

    try:
        await assessment_worker.submit(job, on_finish=finish)
    except AssessmentQueueFull as exc:
        job.state = jobs.JobState.FAILED
        job.error = str(exc)
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        await audit_async(tenant, {"event": "assessment_rejected", "job": job.id,
                       "target": sanitize_target(target), "reason": "queue_full"})
        raise HTTPException(status_code=503,
                            detail="Assessment queue is full — try again shortly") from None
    except WorkerLeaseError as exc:
        # Another process owns the worker for this database; accepting the job
        # would mean it never runs. Refuse instead of queueing it into a void.
        job.state = jobs.JobState.FAILED
        job.error = "worker unavailable"
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503, detail=str(exc)) from None

    await audit_async(tenant, {"event": "assessment_queued", "job": job.id,
                   "target": sanitize_target(target), "profile": req.profile,
                   "policy_id": job.policy.get("policy_id"),
                   "policy_version": job.policy.get("policy_version")})
    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=payload)


@router.get("/assess/{job_id}/engine-status")
async def get_engine_status(job_id: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Backward-compatible route for existing UIs that polled engine health per job.

    The autonomous engine is no longer tracked as a separate job; it is one
    adapter inside a hybrid assessment. This route returns the engine's
    run-level status for the given job so callers can still display per-engine
    progress without switching to the unified coverage model.
    """
    job = await _get_job_or_404(job_id, tenant)
    runs = job.get("coverage", {}).get("adapters", [])
    agent_run = next((r for r in runs if r["adapter"] == "strix-agent"), None)
    return {
        "job_id": job_id,
        "engine": agent_run["adapter"] if agent_run else None,
        "status": agent_run["state"] if agent_run else "not_run",
        "detail": agent_run["detail"] if agent_run else "",
        "findings": agent_run["findings"] if agent_run else 0,
    }


@router.get("/assess", response_model=Page[dict[str, Any]])
async def list_assessments(page: int = Query(default=1, ge=1),
                           page_size: int = Query(default=20, ge=1, le=100),
                           tenant: Tenant = Depends(require_auth)) -> Page[dict[str, Any]]:
    rows = await store.list_jobs(tenant=tenant_filter(tenant), limit=page_size)
    total = len(rows)  # This is approximate; ideally we'd use a COUNT query
    return Page(
        items=rows,
        total=total,
        page=page,
        page_size=page_size,
        has_next=len(rows) == page_size,
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


@router.post("/assess/{job_id}/cancel")
async def cancel_assessment(job_id: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Cancel a queued or running job the caller owns (administrators excepted)."""
    job = await _get_job_or_404(job_id, tenant)
    if job["state"] not in _ACTIVE_STATES:
        raise HTTPException(status_code=409, detail=f"Job is already {job['state']}")
    if not assessment_worker.cancel(job_id):
        raise HTTPException(status_code=409, detail="Job is not running on this worker")
    await audit_async(tenant, {"event": "assessment_cancel_requested", "job": job_id, "state": job["state"]})
    return {"id": job_id, "state": "cancelling",
            "detail": "cancellation signalled; poll the job for its final state"}


@router.post("/assess/{job_id}/retry")
async def retry_assessment(job_id: str,
                           tenant: Tenant = Depends(require_auth)) -> JSONResponse:
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
            detail=(f"Job is {original['state']}; only a failed, partial or cancelled "
                    "job can be retried"))
    target = (original.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=409, detail="Stored target is empty; submit a new assessment")
    snapshot = await deps.tenant_scope_async(tenant)
    check_target_or_raise(target, snapshot)

    actor = tenant["tenant_id"]
    try:
        timeout = float((original.get("policy") or {}).get("timeout_seconds") or 120.0)
    except (TypeError, ValueError):
        timeout = 120.0
    job = jobs.prepare(target, profile=original["profile"], actor=actor,
                       timeout=timeout, scope_snapshot=snapshot)
    job.policy["retry_of"] = job_id
    job.policy["retry_attempt"] = int(original.get("attempts") or 0) + 1
    await store.save_job(job, tenant=actor)
    payload = {**job.to_dict(), **_links(job.id),
               "poll_url": f"/api/assess/{job.id}",
               "cancel_url": f"/api/assess/{job.id}/cancel",
               "retry_of": job_id}

    def finish(finished: jobs.Job) -> None:
        record_job_sync(finished, tenant)

    try:
        await assessment_worker.submit(job, on_finish=finish)
    except AssessmentQueueFull as exc:
        job.state = jobs.JobState.FAILED
        job.error = str(exc)
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503,
                            detail="Assessment queue is full — try again shortly") from None
    except WorkerLeaseError as exc:
        job.state = jobs.JobState.FAILED
        job.error = "worker unavailable"
        job.finished_at = time.time()
        await store.save_job(job, tenant=actor)
        raise HTTPException(status_code=503, detail=str(exc)) from None
    await audit_async(tenant, {"event": "assessment_retried", "job": job.id, "retry_of": job_id,
                   "target": sanitize_target(target), "profile": job.profile})
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
    available = (isinstance(program, str) and bool(program)
                 and isinstance(authorized_by, str) and bool(authorized_by)
                 and isinstance(authorization_ref, str) and bool(authorization_ref)
                 and isinstance(include, list))
    return {
        "program": program if isinstance(program, str) else "",
        "authorized_by": authorized_by if isinstance(authorized_by, str) else "",
        "authorization_ref": authorization_ref if isinstance(authorization_ref, str) else "",
        "scope_include": include if isinstance(include, list) else [],
        "policy_id": binding.get("policy_id"),
        "policy_version": binding.get("policy_version"),
        "available": available,
    }


@router.post("/report")
async def build_report(req: ReportRequest, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
    """Submission-ready evidence bundle for a target's latest finished assessment."""
    target = req.target.strip()
    job = await store.latest_finished_job(target, tenant=tenant_filter(tenant))
    if job is None:
        # Preserve the API's useful 403 for an out-of-scope target, while not
        # making old report retrieval depend on today's active authorization.
        await check_scope_or_raise_async(target, tenant)
        raise HTTPException(status_code=404,
                            detail="No finished assessment for this target — assess it first")

    authorized = _bound_authorization(job)
    findings = job["findings"]
    by_severity = dict(Counter(finding["severity"] for finding in findings))

    # Seal the bundle in the tamper-evident chain so the report can later be
    # shown to have existed, unchanged, at the moment of submission.
    chain_hash = await deps.audit_chain.append_async({
        "event": "report_generated", "target": job["target"], "job": job["id"],
        "program": authorized["program"], "authorization_ref": authorized["authorization_ref"],
        "findings": [finding["fingerprint"] for finding in findings],
    })
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
        "summary": (f"{len(findings)} finding(s) on {job['target']} under "
                    f"{authorized['program']} [{authorized['authorization_ref']}]; "
                    f"job {job['id']} {job['state']}"),
        "integrity": {"chain_valid": (await deps.audit_chain.verify_async())[0], "chain_hash": chain_hash},
    }


@router.post("/assess/{job_id}/triage")
async def triage_assessment(job_id: str, tenant: Tenant = Depends(require_auth)) -> dict[str, Any]:
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
    return {**triage.to_dict(), "job_id": job_id, "findings_count": len(job["findings"])}


@router.get("/assess/{job_id}/report.html",
            response_class=HTMLResponse,
            responses={200: {"content": {"text/html": {}}}})
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
        "integrity": {"chain_valid": (await deps.audit_chain.verify_cached_async())[0],
                      "chain_hash": ""},
        "engine_status": next(
            (r for r in (job.get("coverage") or {}).get("adapters") or []
             if r["adapter"] == "strix-agent"), None),
    }
    strix_metrics.metrics.inc("strix_reports_total", {"kind": "html"})
    await audit_async(tenant, {"event": "report_html_generated", "job": job_id})
    return HTMLResponse(render_html_report(report))
