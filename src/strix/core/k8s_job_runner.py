"""Kubernetes Job entry point for assessment execution.

Runs inside the assessment Job pod. Executes the assessment and writes
results directly to PostgreSQL. Designed for K8s Jobs mode (STRIX_QUEUE_MODE=k8s-jobs).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any

from strix.core import jobs, store
from strix.core.jobs import JobState
from strix.core.scope import Scope

log = logging.getLogger(__name__)


class K8sJobRunner:
    """Runs a single assessment job in a Kubernetes Job pod."""

    def __init__(self) -> None:
        self.job_id = os.environ.get("STRIX_JOB_ID")
        self.tenant_id = os.environ.get("STRIX_TENANT_ID")
        self.target = os.environ.get("STRIX_TARGET")
        self.profile = os.environ.get("STRIX_PROFILE", "web")
        self.timeout_seconds = float(os.environ.get("STRIX_TIMEOUT_SECONDS", "3600"))
        self.scope_json = os.environ.get("STRIX_SCOPE_JSON")
        self.auth_config_json = os.environ.get("STRIX_AUTH_CONFIG")

        if not all([self.job_id, self.tenant_id, self.target, self.scope_json]):
            raise RuntimeError("Missing required environment variables")

        # Type narrow after validation
        assert self.job_id is not None
        assert self.tenant_id is not None
        assert self.target is not None
        assert self.scope_json is not None

    def _parse_scope(self) -> Scope:
        """Parse scope snapshot from JSON environment variable."""
        data = json.loads(self.scope_json)  # type: ignore[arg-type]
        return Scope(
            authorization_ref=data.get("authorization_ref", ""),
            policy_id=data.get("policy_id", ""),
            policy_version=data.get("policy_version", 0),
            tenant_id=data.get("tenant_id", ""),
            program=data.get("program", ""),
            authorized_by=data.get("authorized_by", ""),
            include=tuple(data.get("include", [])),
            exclude=tuple(data.get("exclude", [])),
            authorized_networks=tuple(data.get("authorized_networks", [])),
            allowed_ports=tuple(data.get("allowed_ports", [])),
            allow_broad_networks=bool(data.get("allow_broad_networks", False)),
        )

    def _build_policy(self) -> dict[str, Any]:
        """Build job policy dict including encrypted auth if provided."""
        policy = {
            "timeout": self.timeout_seconds,
        }
        if self.auth_config_json:
            try:
                policy["encrypted_auth_config"] = json.loads(self.auth_config_json)
            except json.JSONDecodeError:
                log.warning("Failed to parse STRIX_AUTH_CONFIG")
        return policy

    async def run(self) -> int:
        """Execute the assessment and persist results. Returns exit code."""
        log.info("Starting K8s Job assessment: job_id=%s tenant=%s target=%s",
                 self.job_id, self.tenant_id, self.target)

        # Configure store from DATABASE_URL
        db_url = os.environ.get("STRIX_DATABASE_URL")
        if not db_url:
            log.error("STRIX_DATABASE_URL not set")
            return 1
        store.configure(db_url)

        # Build job from environment
        scope_snapshot = self._parse_scope()
        policy = self._build_policy()

        # Type narrow after __init__ validation
        assert self.target is not None
        assert self.tenant_id is not None
        assert self.job_id is not None

        job = jobs.prepare(
            target=self.target,
            profile=self.profile,
            actor=self.tenant_id,
            timeout=self.timeout_seconds,
            scope_snapshot=scope_snapshot,
            policy=policy,
        )
        job.id = self.job_id  # Override with K8s Job ID

        # Scope gate: fail fast if target is out of scope before claiming job
        denial, reason = scope_snapshot.check(self.target)
        if denial:
            log.error("Target %s failed scope gate: %s", self.target, reason)
            job.state = JobState.FAILED
            job.error = f"out_of_scope: {reason}"
            job.finished_at = time.time()
            # Persist failed state so the job isn't retried
            try:
                await store.save_job(job, tenant=self.tenant_id)
            except Exception:
                log.exception("Failed to save failed job %s", job.id)
            return 1

        # Mark job as running in DB
        try:
            claimed = await store.claim_job(job.id, tenant=self.tenant_id, worker=f"k8s-job-{self.job_id}")
            if not claimed:
                existing = await store.get_job(job.id, tenant=self.tenant_id)
                if existing and existing["state"] in ("completed", "partial", "failed", "cancelled"):
                    log.info("Job %s already in terminal state %s", job.id, existing["state"])
                    return 0
                log.error("Job %s was already claimed", job.id)
                return 1
        except Exception:
            log.exception("Failed to claim job %s", job.id)
            return 1

        job.attempts = 1
        job.worker_id = f"k8s-job-{self.job_id}"
        job.state = JobState.RUNNING
        job.started_at = time.time()

        # Execute assessment
        try:
            jobs.execute(job)
        except Exception as exc:
            log.exception("Assessment %s crashed", job.id)
            job.state = JobState.FAILED
            job.error = f"internal error: {type(exc).__name__}"
            job.finished_at = time.time()

        # Persist final state
        try:
            assert self.tenant_id is not None
            await store.save_job(job, tenant=self.tenant_id)
            log.info("Job %s completed with state=%s verdict=%s",
                     job.id, job.state.value, job.verdict)
        except Exception:
            log.exception("Failed to save job %s", job.id)
            return 1

        # Return non-zero for failed/partial jobs (K8s Job will retry if backoffLimit > 0)
        if job.state in (JobState.FAILED, JobState.PARTIAL):
            return 1
        return 0


def main() -> int:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    runner = K8sJobRunner()
    try:
        return asyncio.run(runner.run())
    except KeyboardInterrupt:
        log.info("Interrupted")
        return 130
    except Exception:
        log.exception("Fatal error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
