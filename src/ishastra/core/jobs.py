"""Assessment job lifecycle and orchestration.

A job records which adapters ran, which were unavailable or failed, and what
each observed: empty findings mean "clean" only when every selected adapter
actually ran, and partial, failed or cancelled jobs are inconclusive.

``prepare`` binds the caller's engagement policy (id and version) into the job;
``execute`` re-validates that binding when work starts, so a policy revoked
after submission stops the job instead of scanning, and every outbound
connection is judged against the bound snapshot rather than another tenant's
authorization.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import ishastra.core.adapters as adapter_module
from ishastra import metrics
from ishastra.core.adapters import (
    AdapterCancelled,
    AdapterError,
    AdapterNotApplicable,
    AdapterTimeout,
)
from ishastra.core.findings import Finding, dedupe
from ishastra.core.redaction import redact, sanitize_target
from ishastra.core.scope import Scope

log = logging.getLogger(__name__)


class RunState(str, Enum):
    OK = "ok"

    PARTIAL = "partial"

    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AdapterRun:
    adapter: str
    state: RunState
    detail: str = ""
    findings: int = 0
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:

        return {
            "adapter": self.adapter,
            "state": self.state.value,
            "detail": redact(self.detail),
            "findings": self.findings,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class Job:
    target: str
    profile: str
    actor: str
    policy: dict[str, Any]
    id: str = field(default_factory=lambda: f"job_{secrets.token_hex(6)}")
    state: JobState = JobState.QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    valid_until: float | None = None
    runs: list[AdapterRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    attempts: int = 0
    worker_id: str = ""
    idempotency_key: str | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    scope_snapshot: Scope | None = field(default=None, repr=False, compare=False)

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def coverage(self) -> dict[str, Any]:
        counts = {state.value: 0 for state in RunState}
        for run in self.runs:
            counts[run.state.value] += 1
        return {
            "total": len(self.runs),
            **counts,
            "adapters": [r.to_dict() for r in self.runs],
        }

    @property
    def verdict(self) -> str:
        """What the job is allowed to claim."""
        if self.state is JobState.COMPLETED:
            return (
                "no findings (complete coverage)" if not self.findings else f"{len(self.findings)} finding(s)"
            )
        if self.state is JobState.PARTIAL:
            if not self.findings:
                return "inconclusive: no findings (partial coverage)"
            return f"{len(self.findings)} finding(s) (partial coverage, inconclusive)"
        if self.state is JobState.FAILED:
            if not self.runs or all(r.state in (RunState.UNAVAILABLE, RunState.REJECTED) for r in self.runs):
                return "no usable coverage"
            return f"failed: {self.error}"
        if self.state is JobState.CANCELLED:
            return "cancelled; do not treat as clean"
        return self.state.value

    def is_clean(self) -> bool:
        """True only when complete coverage with zero findings."""
        return (
            self.state is JobState.COMPLETED
            and not self.findings
            and all(run.state is RunState.OK for run in self.runs)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": sanitize_target(self.target),
            "profile": self.profile,
            "actor": self.actor,
            "policy": self.policy,
            "state": self.state.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "runs": [run.to_dict() for run in self.runs],
            "findings": [f.to_dict() for f in self.findings],
            "error": redact(self.error),
            "attempts": self.attempts,
            "worker": self.worker_id,
            "idempotency_key": self.idempotency_key,
            "coverage": self.coverage(),
            "verdict": self.verdict,
        }


def prepare(
    target: str,
    *,
    profile: str = "web",
    actor: str = "analyst",
    policy: dict[str, Any] | None = None,
    timeout: float = 300.0,
    idempotency_key: str | None = None,
    scope_snapshot: Scope | None = None,
) -> Job:
    """Create a job bound to the current scope snapshot.

    The snapshot is captured now and will be re-validated at execution time.
    """
    from ishastra.core.scope import current as current_scope

    if scope_snapshot is None:
        scope_snapshot = current_scope()
    if scope_snapshot is None:
        raise ValueError("no authorized scope configured — nothing may be scanned")

    job_policy = dict(policy or {})
    job_policy.setdefault("authorization_ref", scope_snapshot.authorization_ref)
    job_policy.setdefault("policy_id", scope_snapshot.policy_id)
    job_policy.setdefault("policy_version", scope_snapshot.policy_version)
    job_policy.setdefault("tenant_id", scope_snapshot.tenant_id)
    job_policy.setdefault("scope_program", scope_snapshot.program)
    job_policy.setdefault("scope_authorized_by", scope_snapshot.authorized_by)
    job_policy.setdefault("scope_include", list(scope_snapshot.include))
    job_policy.setdefault("scope_exclude", list(scope_snapshot.exclude))
    job_policy.setdefault("scope_authorized_networks", list(scope_snapshot.authorized_networks))
    job_policy.setdefault("scope_allowed_ports", list(scope_snapshot.allowed_ports))
    job_policy.setdefault("scope_allow_broad_networks", scope_snapshot.allow_broad_networks)
    job_policy.setdefault("timeout", timeout)

    job = Job(
        target=target,
        profile=profile,
        actor=actor,
        policy=job_policy,
        scope_snapshot=scope_snapshot,
    )
    if idempotency_key:
        job.idempotency_key = idempotency_key
    return job


def prohibited_technique_matches(engagement: dict, adapter: object) -> list[str]:
    """Techniques the engagement forbids that this adapter would use.

    A prohibited entry is matched against the adapter id and the binaries it
    shells out to, so ``prohibited_techniques: [sqlmap]`` blocks the sqlmap
    adapter even though its id is ``sqlmap`` and ``nuclei`` blocks the nuclei
    adapter. Matching is case-insensitive and whitespace-trimmed.
    """
    prohibited = {
        str(item).strip().lower()
        for item in (engagement.get("prohibited_techniques") or [])
        if str(item).strip()
    }
    if not prohibited:
        return []
    labels = {str(getattr(adapter, "id", "")).lower()}
    labels |= {str(requirement).lower() for requirement in getattr(adapter, "requires", ())}
    labels.discard("")
    return sorted(prohibited & labels)


def _set_state(job: Job, state: JobState) -> None:
    """Move the job to ``state`` and record the transition.

    Every state change in ``_execute`` goes through here, so the exported
    lifecycle (jobs_total, transitions, active) cannot drift from the job.
    """
    previous = job.state.value
    job.state = state
    tenant = job.scope_snapshot.tenant_id if job.scope_snapshot else None
    metrics.record_job_state(previous, state.value, tenant)


def execute(job: Job) -> None:
    """Run a prepared job and record its wall-clock duration."""
    started = time.monotonic()
    try:
        _execute(job)
    finally:
        tenant = job.scope_snapshot.tenant_id if job.scope_snapshot else None
        metrics.observe_job_duration(job.profile, tenant or "", time.monotonic() - started)
        for finding in job.findings:
            metrics.record_finding(finding.severity, finding.detector, tenant)


def _execute(job: Job) -> None:
    """Run a prepared job against its bound scope snapshot.

    Re-validates the authorization before any adapter runs. If the bound
    policy has been revoked or narrowed, the job fails instead of scanning
    against another tenant's authorization.
    """
    from ishastra.core.scope import bound as scope_bound
    from ishastra.core.scope import destination as scope_destination
    from ishastra.core.scope import reset_pinned_destination, set_pinned_destination

    if job.scope_snapshot is None:
        _set_state(job, JobState.FAILED)
        job.error = "job has no scope snapshot"
        job.finished_at = time.time()
        return

    _set_state(job, JobState.RUNNING)
    job.started_at = time.time()

    with scope_bound(job.scope_snapshot):
        denial, reason = job.scope_snapshot.check(job.target)
        if denial:
            _set_state(job, JobState.FAILED)
            job.error = f"out_of_scope: {reason}"
            job.finished_at = time.time()
            return

        _, _, pinned = scope_destination(job.target)
        token = set_pinned_destination(pinned) if pinned is not None else None

        def _reset_pin():
            nonlocal token
            if token is not None:
                reset_pinned_destination(token)
                token = None

        try:
            policy_id = job.policy.get("policy_id")
            if policy_id:
                from ishastra.core import policies as policies_module

                policy = policies_module.registry.get(policy_id)
                if policy is None:
                    _set_state(job, JobState.FAILED)
                    job.error = f"authorization policy {policy_id} not found"
                    job.finished_at = time.time()
                    _reset_pin()
                    return
                valid, why = policy.is_valid()
                if not valid:
                    _set_state(job, JobState.FAILED)
                    job.error = redact(why)
                    job.finished_at = time.time()
                    _reset_pin()
                    return

                job_version = job.policy.get("policy_version")
                if job_version is not None and policy.version != job_version:
                    _set_state(job, JobState.FAILED)
                    job.error = (
                        f"authorization policy {policy_id} changed after this job was "
                        f"queued (job bound to v{job_version}, current v{policy.version})"
                    )
                    job.finished_at = time.time()
                    _reset_pin()
                    return

            if job.actor and job.scope_snapshot.tenant_id and job.actor != job.scope_snapshot.tenant_id:
                _set_state(job, JobState.FAILED)
                job.error = (
                    f"actor {job.actor!r} does not belong to this authorization "
                    f"(bound to {job.scope_snapshot.tenant_id!r})"
                )
                job.finished_at = time.time()
                _reset_pin()
                return

            adapters = adapter_module.select(job.profile)
            if not adapters:
                _set_state(job, JobState.FAILED)
                job.error = f"no adapters for profile {job.profile!r}"
                job.finished_at = time.time()
                _reset_pin()
                return

            auth_principal = None
            if job.scope_snapshot.auth and job.scope_snapshot.auth.users:
                auth_principal = job.scope_snapshot.auth.users[0]

            encrypted_auth = job.policy.get("encrypted_auth_config")
            if encrypted_auth:
                try:
                    from ishastra.config import get_settings
                    from ishastra.core.auth import AuthManager, EncryptedAuthConfig

                    settings = get_settings()
                    if not settings.encryption_key:
                        raise ValueError("encryption key not configured")

                    auth_config = EncryptedAuthConfig(
                        authenticator_type=encrypted_auth["authenticator_type"],
                        encrypted_config=encrypted_auth["encrypted_config"],
                        principal_id=encrypted_auth["principal_id"],
                        created_at=encrypted_auth.get("created_at", 0),
                    )

                    auth_manager = AuthManager(encryption_key=settings.encryption_key)
                    auth_manager.add_auth_config(auth_config)

                    auth_result = auth_manager.authenticate(job.target, encrypted_auth["principal_id"])
                    if auth_result.success and auth_result.principal:
                        auth_principal = auth_result.principal
                    else:
                        log.warning("Per-assessment authentication failed: %s", auth_result.error)
                except Exception:
                    log.exception("Failed to set up per-assessment authentication")

            all_findings: list[Finding] = []
            partial = False
            any_adapter_ran = False

            # Rules of Engagement that the gate validates are only real if the
            # runner honours them. Prohibited techniques are matched against an
            # adapter id and the binaries it shells out to ("sqlmap", "nuclei").
            engagement = job.scope_snapshot.rules_of_engagement or {}
            rate_limit_rps: float = float(engagement.get("rate_limit_rps") or 0)

            tenant_for_metrics = job.scope_snapshot.tenant_id if job.scope_snapshot else None
            for adapter in adapters:
                if job.cancelled:
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.CANCELLED,
                            detail="cancelled before execution",
                        )
                    )
                    _set_state(job, JobState.CANCELLED)
                    job.finished_at = time.time()
                    _reset_pin()
                    return

                blocked_by = prohibited_technique_matches(engagement, adapter)
                if blocked_by:
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.REJECTED,
                            detail=("prohibited by rules of engagement: " + ", ".join(blocked_by)),
                        )
                    )
                    partial = True
                    continue

                ok, detail = adapter.available()
                if not ok:
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.UNAVAILABLE,
                            detail=detail,
                        )
                    )
                    continue

                any_adapter_ran = True
                start = time.monotonic()
                try:
                    context: dict[str, Any] = {"auth_principal": auth_principal} if auth_principal else {}
                    if rate_limit_rps:
                        context["rate_limit_rps"] = rate_limit_rps
                    result = adapter.assess(
                        job.target,
                        timeout=job.policy.get("timeout", 300.0),
                        cancel=job._cancel,
                        context=context,
                    )
                except AdapterCancelled:
                    metrics.record_adapter_error(adapter.id, "cancelled", tenant_for_metrics)
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.CANCELLED,
                            detail="cancelled",
                            elapsed_ms=(time.monotonic() - start) * 1000,
                        )
                    )
                    _set_state(job, JobState.CANCELLED)
                    job.finished_at = time.time()
                    _reset_pin()
                    return
                except AdapterTimeout:
                    metrics.record_adapter_error(adapter.id, "timeout", tenant_for_metrics, timeout=True)
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.TIMEOUT,
                            detail="adapter timed out",
                            elapsed_ms=(time.monotonic() - start) * 1000,
                        )
                    )
                    partial = True
                    continue
                except AdapterNotApplicable as exc:
                    metrics.record_adapter_error(adapter.id, "rejected", tenant_for_metrics)
                    any_adapter_ran = True
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.REJECTED,
                            detail=str(exc),
                            elapsed_ms=(time.monotonic() - start) * 1000,
                        )
                    )
                    partial = True
                    continue
                except AdapterError as exc:
                    metrics.record_adapter_error(adapter.id, "failed", tenant_for_metrics)
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.FAILED,
                            detail=str(exc),
                            elapsed_ms=(time.monotonic() - start) * 1000,
                        )
                    )
                    partial = True
                    continue
                except Exception as exc:
                    metrics.record_adapter_error(adapter.id, "crashed", tenant_for_metrics)
                    log.exception("adapter %s crashed", adapter.id)
                    job.runs.append(
                        AdapterRun(
                            adapter=adapter.id,
                            state=RunState.FAILED,
                            detail=f"{type(exc).__name__}: {exc}",
                            elapsed_ms=(time.monotonic() - start) * 1000,
                        )
                    )
                    _set_state(job, JobState.FAILED)
                    job.finished_at = time.time()
                    _reset_pin()
                    return

                elapsed = (time.monotonic() - start) * 1000
                metrics.observe_adapter(adapter.id, tenant_for_metrics, elapsed / 1000)
                run_state = RunState.PARTIAL if result.partial else RunState.OK
                if result.partial:
                    partial = True
                job.runs.append(
                    AdapterRun(
                        adapter=adapter.id,
                        state=run_state,
                        detail="; ".join(result.notes) if result.notes else "",
                        findings=len(result.findings),
                        elapsed_ms=elapsed,
                    )
                )
                all_findings.extend(result.findings)

            job.findings = dedupe(all_findings)
            job.finished_at = time.time()
            if job.state is JobState.RUNNING:
                if not any_adapter_ran:
                    _set_state(job, JobState.FAILED)
                    job.error = "no adapter was able to run"
                else:
                    ran_states = {
                        run.state
                        for run in job.runs
                        if run.state not in (RunState.UNAVAILABLE, RunState.REJECTED)
                    }
                    if not ran_states:
                        _set_state(job, JobState.FAILED)

                        rejected_details = [run.detail for run in job.runs if run.state is RunState.REJECTED]
                        if rejected_details:
                            job.error = redact("; ".join(rejected_details))
                        else:
                            job.error = "no usable coverage"
                    elif all(
                        state in (RunState.FAILED, RunState.TIMEOUT, RunState.CANCELLED)
                        for state in ran_states
                    ):
                        _set_state(job, JobState.FAILED)
                        failed_details = [
                            run.detail
                            for run in job.runs
                            if run.state in (RunState.FAILED, RunState.TIMEOUT, RunState.CANCELLED)
                        ]
                        if failed_details:
                            job.error = redact("; ".join(failed_details))
                        else:
                            job.error = "all adapters failed"
                    elif partial:
                        _set_state(job, JobState.PARTIAL)
                    else:
                        _set_state(job, JobState.COMPLETED)
        finally:
            _reset_pin()


def run_assessment(
    target: str,
    *,
    profile: str = "web",
    actor: str = "analyst",
    policy: dict[str, Any] | None = None,
    timeout: float = 300.0,
    cancel: threading.Event | None = None,
    wait: bool = True,
    scope_snapshot: Scope | None = None,
    idempotency_key: str | None = None,
) -> Job:
    """Prepare and execute an assessment in one call (for tests and simple scripts).

    If ``wait`` is False, returns the prepared job without executing it.
    """
    job = prepare(
        target,
        profile=profile,
        actor=actor,
        policy=policy,
        timeout=timeout,
        idempotency_key=idempotency_key,
        scope_snapshot=scope_snapshot,
    )
    if cancel is not None:
        job._cancel = cancel
    if wait:
        execute(job)
    return job


async def run_exception_expiration_job() -> int:
    """Run one iteration of the exception expiration job.

    Finds all pending/approved exceptions whose until timestamp has passed
    and flips them to 'expired'. Returns the count of expired exceptions.

    This is designed to be called periodically by a scheduler (APScheduler,
    cron, etc.) or run as a background task.
    """
    from ishastra.core.exceptions import expire_exceptions

    return await expire_exceptions()
