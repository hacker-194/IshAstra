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

import strix.core.adapters as adapter_module
from strix.core.adapters import (
    AdapterCancelled,
    AdapterError,
    AdapterNotApplicable,
    AdapterTimeout,
)
from strix.core.findings import Finding, dedupe
from strix.core.redaction import redact, sanitize_target
from strix.core.scope import Scope

log = logging.getLogger(__name__)


class RunState(str, Enum):
    OK = "ok"
    # Ran and reported results, but the adapter itself says its sweep was cut
    # short (deadline, port budget, unanswered hosts). Findings are kept;
    # complete coverage may not be claimed.
    PARTIAL = "partial"
    # Not applicable to this target: no query parameters, no API description,
    # no authorized ports. Not a tool failure, and still not coverage.
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
        # Adapter detail travels into coverage, API responses, reports and the
        # database; tool output can echo credentials, so it is redacted here.
        return {"adapter": self.adapter, "state": self.state.value,
                "detail": redact(self.detail),
                "findings": self.findings, "elapsed_ms": self.elapsed_ms}


@dataclass
class Job:
    target: str
    profile: str
    actor: str
    policy: dict[str, Any]
    id: str = field(default_factory=lambda: f"job_{secrets.token_hex(6)}")
    state: JobState = JobState.QUEUED
    started_at: float | None = None
    finished_at: float | None = None
    runs: list[AdapterRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    # Execution accounting. ``attempts`` counts claims, so a job retried after
    # a crash is distinguishable from one that ran once; ``worker_id`` names the
    # process that claimed it; ``idempotency_key`` deduplicates submissions.
    attempts: int = 0
    worker_id: str = ""
    idempotency_key: str | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    # The validated authorization this job must be judged against. Held in
    # memory only (it may carry in-memory test principals); never serialized.
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
        return {"total": len(self.runs), **counts, "adapters": [r.to_dict() for r in self.runs]}

    @property
    def verdict(self) -> str:
        """What the job is allowed to claim."""
        if self.state is JobState.COMPLETED:
            return ("no findings (complete coverage)" if not self.findings
                    else f"{len(self.findings)} finding(s)")
        if self.state is JobState.PARTIAL:
            if not self.findings:
                return "inconclusive: no findings (partial coverage)"
            return f"{len(self.findings)} finding(s) (partial coverage, inconclusive)"
        if self.state is JobState.FAILED:
            if not self.runs or all(r.state in (RunState.UNAVAILABLE, RunState.REJECTED)
                                  for r in self.runs):
                return "no usable coverage"
            return f"failed: {self.error}"
        if self.state is JobState.CANCELLED:
            return "cancelled; do not treat as clean"
        return self.state.value

    def is_clean(self) -> bool:
        """True only when complete coverage with zero findings."""
        return (self.state is JobState.COMPLETED
                and not self.findings
                and all(run.state is RunState.OK for run in self.runs))

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
    from strix.core.scope import current as current_scope
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


def execute(job: Job) -> None:
    """Run a prepared job against its bound scope snapshot.

    Re-validates the authorization before any adapter runs. If the bound
    policy has been revoked or narrowed, the job fails instead of scanning
    against another tenant's authorization.
    """
    from strix.core.scope import bound as scope_bound

    if job.scope_snapshot is None:
        job.state = JobState.FAILED
        job.error = "job has no scope snapshot"
        job.finished_at = time.time()
        return

    job.state = JobState.RUNNING
    job.started_at = time.time()

    # Bind the job's scope snapshot for this thread
    with scope_bound(job.scope_snapshot):
        # Re-validate the target against the bound scope
        denial, reason = job.scope_snapshot.check(job.target)
        if denial:
            job.state = JobState.FAILED
            job.error = f"out_of_scope: {reason}"
            job.finished_at = time.time()
            return

        # Check if the bound policy has been revoked or expired
        policy_id = job.policy.get("policy_id")
        if policy_id:
            from strix.core import policies as policies_module
            policy = policies_module.registry.get(policy_id)
            if policy is None:
                job.state = JobState.FAILED
                job.error = f"authorization policy {policy_id} not found"
                job.finished_at = time.time()
                return
            valid, why = policy.is_valid()
            if not valid:
                job.state = JobState.FAILED
                job.error = redact(why)
                job.finished_at = time.time()
                return
            # Check version matches (policy was updated after job was prepared)
            job_version = job.policy.get("policy_version")
            if job_version is not None and policy.version != job_version:
                job.state = JobState.FAILED
                job.error = (
                    f"authorization policy {policy_id} changed after this job was "
                    f"queued (job bound to v{job_version}, current v{policy.version})"
                )
                job.finished_at = time.time()
                return

        # Check actor matches the bound scope's tenant (prevents impersonation)
        if job.actor and job.scope_snapshot.tenant_id \
                and job.actor != job.scope_snapshot.tenant_id:
            job.state = JobState.FAILED
            job.error = (
                f"actor {job.actor!r} does not belong to this authorization "
                f"(bound to {job.scope_snapshot.tenant_id!r})"
            )
            job.finished_at = time.time()
            return

        adapters = adapter_module.select(job.profile)
        if not adapters:
            job.state = JobState.FAILED
            job.error = f"no adapters for profile {job.profile!r}"
            job.finished_at = time.time()
            return

        all_findings: list[Finding] = []
        partial = False
        any_adapter_ran = False

        for adapter in adapters:
            if job.cancelled:
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.CANCELLED,
                    detail="cancelled before execution",
                ))
                job.state = JobState.CANCELLED
                job.finished_at = time.time()
                return

            ok, detail = adapter.available()
            if not ok:
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.UNAVAILABLE,
                    detail=detail,
                ))
                continue

            any_adapter_ran = True
            start = time.monotonic()
            try:
                result = adapter.assess(job.target, timeout=job.policy.get("timeout", 300.0),
                                        cancel=job._cancel, context={})
            except AdapterCancelled:
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.CANCELLED,
                    detail="cancelled",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                job.state = JobState.CANCELLED
                job.finished_at = time.time()
                return
            except AdapterTimeout:
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.TIMEOUT,
                    detail="adapter timed out",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                partial = True
                continue
            except AdapterNotApplicable as exc:
                any_adapter_ran = True
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.REJECTED,
                    detail=str(exc),
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                partial = True
                continue
            except AdapterError as exc:
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.FAILED,
                    detail=str(exc),
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                partial = True
                continue
            except Exception as exc:
                log.exception("adapter %s crashed", adapter.id)
                job.runs.append(AdapterRun(
                    adapter=adapter.id,
                    state=RunState.FAILED,
                    detail=f"{type(exc).__name__}: {exc}",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                job.state = JobState.FAILED
                job.finished_at = time.time()
                return

            elapsed = (time.monotonic() - start) * 1000
            run_state = RunState.PARTIAL if result.partial else RunState.OK
            if result.partial:
                partial = True
            job.runs.append(AdapterRun(
                adapter=adapter.id,
                state=run_state,
                detail="; ".join(result.notes) if result.notes else "",
                findings=len(result.findings),
                elapsed_ms=elapsed,
            ))
            all_findings.extend(result.findings)

        job.findings = dedupe(all_findings)
        job.finished_at = time.time()
        if job.state is JobState.RUNNING:
            if not any_adapter_ran:
                job.state = JobState.FAILED
                job.error = "no adapter was able to run"
            else:
                # Check if all adapters that ran were REJECTED or UNAVAILABLE
                # (no usable coverage)
                ran_states = {run.state for run in job.runs
                              if run.state not in (RunState.UNAVAILABLE, RunState.REJECTED)}
                if not ran_states:
                    job.state = JobState.FAILED
                    # Use REJECTED adapter details for error if available
                    rejected_details = [run.detail for run in job.runs
                                        if run.state is RunState.REJECTED]
                    if rejected_details:
                        job.error = redact("; ".join(rejected_details))
                    else:
                        job.error = "no usable coverage"
                elif all(state in (RunState.FAILED, RunState.TIMEOUT, RunState.CANCELLED)
                         for state in ran_states):
                    # All adapters that ran failed/timed out/cancelled - job failed
                    job.state = JobState.FAILED
                    failed_details = [run.detail for run in job.runs
                                      if run.state in (RunState.FAILED, RunState.TIMEOUT, RunState.CANCELLED)]
                    if failed_details:
                        job.error = redact("; ".join(failed_details))
                    else:
                        job.error = "all adapters failed"
                elif partial:
                    job.state = JobState.PARTIAL
                else:
                    job.state = JobState.COMPLETED


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
    job = prepare(target, profile=profile, actor=actor, policy=policy, timeout=timeout,
                  idempotency_key=idempotency_key, scope_snapshot=scope_snapshot)
    if cancel is not None:
        # Use the caller's cancel event
        job._cancel = cancel
    if wait:
        execute(job)
    return job
