"""Job dispatch: capability -> gateway -> worker -> signed evidence.

Ordering is the security property here:

1. the token is issued and registered *before* any connection exists;
2. the gateway is bound to this job (``expected_job_id``) and started before
   the worker runs, so a token for another job is refused;
3. the worker receives only the proxy URL and its auth header, never a route;
4. evidence is hashed and signed only after the worker returns;
5. tokens are revoked and the gateway stopped in ``finally``, so a crashed or
   timed-out worker cannot leave an authorized path behind.

The worker itself is injected. A container runner and an in-process lab runner
can both satisfy this contract; this module does not pick one.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import signal
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ishastra.execution.worker_manager import WorkerConfig, WorkerManager
from ishastra.security.authorization.scope import Scope
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import CapabilityToken
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.egress.gateway import EgressGateway
from ishastra.security.signing.service import EvidenceManifest, EvidenceSigningService

EVIDENCE_FILENAME = "evidence.json"

WorkerRunner = Callable[[Path, str, str], "Coroutine[Any, Any, None]"]

# Module-level references for signal handler
_current_worker_manager: WorkerManager | None = None
_current_dispatch_task: asyncio.Task | None = None
_shutdown_event: asyncio.Event | None = None


def _install_signal_handlers(worker_manager: WorkerManager) -> None:
    """Install SIGTERM/SIGINT handlers to cancel worker and cleanup."""
    global _current_worker_manager, _current_dispatch_task, _shutdown_event

    _current_worker_manager = worker_manager
    _shutdown_event = asyncio.Event()

    def _signal_handler(signum=None, frame=None) -> None:
        # Use call_soon_threadsafe to ensure the event loop sees the event
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(_shutdown_event.set)
            if _current_dispatch_task and not _current_dispatch_task.done():
                loop.call_soon_threadsafe(_current_dispatch_task.cancel)
        except RuntimeError:
            # No running loop, fall back to direct set
            if _shutdown_event:
                _shutdown_event.set()
            if _current_dispatch_task and not _current_dispatch_task.done():
                _current_dispatch_task.cancel()

    # Use synchronous signal handlers which work more reliably in subprocesses
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)


async def _wait_for_shutdown() -> None:
    """Wait for shutdown signal."""
    global _shutdown_event
    if _shutdown_event:
        await _shutdown_event.wait()


@dataclass(frozen=True)
class DispatchRequest:
    """Everything the dispatcher needs to run one job."""

    tenant_id: str
    engagement_id: str
    job_id: str
    scope: Scope
    policy_hash: str
    rules_of_engagement_hash: str
    allowed_tools: tuple[str, ...]
    request_budget: int
    bandwidth_limit_mb: int
    pinned_ips: tuple[str, ...]
    workspace: Path


@dataclass(frozen=True)
class DispatchOutcome:
    """Result of a completed dispatch."""

    job_id: str
    token_jti: str
    proxy_url: str
    manifest: EvidenceManifest
    manifest_path: Path
    revoked: bool


def _proxy_authorization(token: CapabilityToken) -> str:
    """Basic ``jti:token`` header, the form a scanner proxy URL can carry."""
    encoded = base64.urlsafe_b64encode(json.dumps(token.to_dict()).encode()).decode().rstrip("=")
    credentials = base64.b64encode(f"{token.jti}:{encoded}".encode()).decode()
    return f"Basic {credentials}"


def _token_from_proxy_authorization(header: str) -> CapabilityToken:
    """Decode the Basic ``jti:token`` header back into a token for the worker."""
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() != "basic" or not credentials:
        raise ValueError("worker runner needs the dispatcher's Basic auth header")
    try:
        decoded = base64.b64decode(credentials + "=" * (-len(credentials) % 4)).decode()
        _, _, raw = decoded.partition(":")
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        return CapabilityToken.from_dict(payload)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"invalid proxy authorization header: {exc}") from None


def container_worker_runner(
    manager: WorkerManager,
    *,
    image: str,
    command: list[str],
    network_mode: str = "ishastra-worker-net",
    working_dir: str = "/workspace",
    environment: dict[str, str] | None = None,
) -> WorkerRunner:
    """Run the dispatcher's worker inside a hardened container.

    The dispatcher's token is recovered from the header it generated and handed
    to the manager, so the container gets the same authorization the in-process
    runner would. A non-zero exit (including "no artifacts") fails the job before
    evidence is signed.
    """

    async def run(workspace: Path, proxy_url: str, auth_header: str) -> None:
        token = _token_from_proxy_authorization(auth_header)
        config = WorkerConfig(
            job_id=token.job_id,
            tenant_id=token.tenant_id,
            engagement_id=token.engagement_id,
            image=image,
            command=list(command),
            environment={
                "ISHASTRA_PROXY_URL": proxy_url,
                "ISHASTRA_PROXY_AUTHORIZATION": auth_header,
                **(environment or {}),
            },
            working_dir=working_dir,
            network_mode=network_mode,
        )
        result = await manager.start_worker(config, token, workspace=workspace)
        if result.exit_code != 0:
            detail = result.error or result.stderr.strip() or "unknown error"
            raise RuntimeError(f"worker container failed: {detail}")

    return run


async def dispatch(
    request: DispatchRequest,
    *,
    issuer: CapabilityIssuer,
    verifier: CapabilityVerifier,
    signing: EvidenceSigningService,
    run_worker: WorkerRunner,
    audit_chain: Any = None,
    listen_host: str = "127.0.0.1",
    worker_manager: WorkerManager | None = None,
) -> DispatchOutcome:
    """Run one job end to end and return its signed evidence.

    Raises whatever ``run_worker`` raises, after revoking the job's tokens and
    stopping the gateway. An empty workspace is an error, never a clean result.

    If ``worker_manager`` is provided, signal handlers are installed to cancel
    the worker on SIGTERM/SIGINT (for subprocess deployments).
    """
    if not request.pinned_ips:
        raise ValueError("dispatch requires pinned_ips: the gateway denies every unpinned target")
    if request.request_budget < 1:
        raise ValueError("request_budget must be at least 1")

    if worker_manager:
        _install_signal_handlers(worker_manager)

    token = await issuer.issue_and_register_token(
        tenant_id=request.tenant_id,
        engagement_id=request.engagement_id,
        job_id=request.job_id,
        scope=request.scope,
        policy_hash=request.policy_hash,
        rules_of_engagement_hash=request.rules_of_engagement_hash,
        allowed_tools=list(request.allowed_tools),
        request_budget=request.request_budget,
        bandwidth_limit_mb=request.bandwidth_limit_mb,
        pinned_ips=list(request.pinned_ips),
    )

    gateway = EgressGateway(
        verifier=verifier,
        audit_chain=audit_chain,
        listen_host=listen_host,
        listen_port=0,
        expected_job_id=request.job_id,
    )
    await gateway.start()
    proxy_url = f"http://{listen_host}:{gateway.listen_port}"
    revoked = False
    worker_task: asyncio.Task[None] = asyncio.create_task(
        run_worker(request.workspace, proxy_url, _proxy_authorization(token))
    )
    shutdown_task: asyncio.Task[None] | None = None
    try:
        global _current_dispatch_task
        _current_dispatch_task = worker_task

        # Wait for either worker to complete or shutdown signal
        if worker_manager:
            shutdown_task = asyncio.create_task(_wait_for_shutdown())
            done, pending = await asyncio.wait(
                [worker_task, shutdown_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # If shutdown was requested, cancel worker
            if shutdown_task in done:
                worker_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await worker_task
                # Cleanup and exit
                if worker_manager:
                    await worker_manager.cancel_worker(request.job_id)
                revoked = (await issuer.revoke_all_for_job(request.job_id, "job cancelled")) > 0
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(gateway.stop(), timeout=5)
                os._exit(0)

            # Worker completed, cancel shutdown waiter
            if shutdown_task in pending:
                shutdown_task.cancel()
            # Check if worker_task raised an exception
            if worker_task.done() and not worker_task.cancelled():
                exc = worker_task.exception()
                if exc is not None:
                    raise exc
        else:
            await worker_task

        manifest = await signing.create_evidence_from_workspace(
            tenant_id=request.tenant_id,
            job_id=request.job_id,
            engagement_id=request.engagement_id,
            workspace_path=str(request.workspace),
            metadata={
                "request_budget": request.request_budget,
                "bandwidth_limit_mb": request.bandwidth_limit_mb,
                "pinned_ips": list(request.pinned_ips),
                "allowed_tools": list(request.allowed_tools),
            },
        )
        manifest_path = request.workspace / EVIDENCE_FILENAME
        manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))
    except asyncio.CancelledError:
        # Signal received - cancel worker and cleanup, then exit cleanly
        if worker_manager:
            await worker_manager.cancel_worker(request.job_id)
        revoked = (await issuer.revoke_all_for_job(request.job_id, "job cancelled")) > 0
        await gateway.stop()
        # Exit cleanly instead of propagating CancelledError (which may hang in subprocess)
        sys.exit(0)
    except Exception:
        revoked = (await issuer.revoke_all_for_job(request.job_id, "job failed")) > 0
        await gateway.stop()
        raise
    else:
        revoked = (await issuer.revoke_all_for_job(request.job_id, "job finished")) > 0
        await gateway.stop()

    return DispatchOutcome(
        job_id=request.job_id,
        token_jti=token.jti,
        proxy_url=proxy_url,
        manifest=manifest,
        manifest_path=manifest_path,
        revoked=revoked,
    )
