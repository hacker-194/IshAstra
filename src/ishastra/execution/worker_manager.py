"""Worker Manager - Disposable container execution with capability injection.

Manages the lifecycle of worker containers:
1. Creates disposable containers (Docker/Podman)
2. Enforces resource limits: CPU, memory, PID, wall-clock timeout
3. Security hardening: non-root, read-only rootfs, no-new-privileges, caps dropped
4. Argument arrays only (no shell interpolation)
5. Workspace collection after exit
6. Worker cleanup on cancel/expiry/completion
7. Capability injection at startup

Called by:
- src/ishastra/control_plane/dispatcher.py (Dispatcher starts workers for jobs)
- src/ishastra/api/routers/assessments.py (API triggers worker execution)
- Tests in tests/unit/test_worker_manager.py

No existing file serves this purpose - new v4.0 worker manager for Phase 2.

Data schemas:
- Reads: CapabilityToken, WorkerConfig, ResourceLimits
- Writes: WorkerResult, job state updates (jobs table), workspace artifacts
- Uses: Docker CLI, capability issuer for token injection

User instruction: "continue with Workstream D" / "proceed with Phase 2 Vertical Slice"
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ishastra.core.store import Database
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import CapabilityToken

log = logging.getLogger(__name__)

WORKER_ROOT = Path("/tmp/ishastra-workers")
CONTAINER_PREFIX = "ishastra-worker-"
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class ResourceLimits:
    """Resource limits for worker containers."""

    cpu_quota: int = 100000      # CPU CFS quota (100000 = 1 CPU)
    cpu_period: int = 100000     # CPU CFS period
    memory_mb: int = 512         # Memory limit in MB
    pids_limit: int = 100        # Max processes
    wall_clock_seconds: int = 300  # Max wall-clock time
    disk_mb: int = 1024          # Disk limit in MB (tmpfs)


@dataclass(frozen=True)
class WorkerConfig:
    """Configuration for a worker container."""

    job_id: str
    tenant_id: str
    engagement_id: str
    image: str
    command: list[str]           # Argument array, no shell
    environment: dict[str, str]  # Env vars (will include capability token)
    working_dir: str = "/workspace"
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    network_mode: str = "ishastra-worker-net"
    readonly_rootfs: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["ALL"])
    security_opt: list[str] = field(default_factory=lambda: ["no-new-privileges:true"])
    user: str = "10001:10001"    # Non-root user

    def __post_init__(self) -> None:
        if not JOB_ID_RE.match(self.job_id) or ".." in self.job_id:
            raise ValueError(f"invalid job_id for a worker: {self.job_id!r}")


@dataclass
class WorkerResult:
    """Result of a worker execution."""

    job_id: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    duration_seconds: float = 0.0
    timed_out: bool = False
    oom_killed: bool = False
    workspace_path: str = ""
    error: str = ""


class WorkerManager:
    """Manages disposable worker containers with capability injection."""

    def __init__(
        self,
        *,
        docker_host: str = "unix:///var/run/docker.sock",
        default_image: str = "ishastra/worker:latest",
        gateway_url: str = "http://127.0.0.1:8080",
        database: Database | None = None,
        issuer: CapabilityIssuer | None = None,
    ):
        """Initialize the worker manager.

        Args:
            docker_host: Docker daemon socket
            default_image: Default worker container image
            gateway_url: Egress gateway URL for workers
            database: Database for job state updates
            issuer: Capability issuer for token generation
        """
        self.docker_host = docker_host
        self.default_image = default_image
        self.gateway_url = gateway_url
        self.database = database
        self.issuer = issuer

        self._active_workers: dict[str, asyncio.subprocess.Process] = {}
        self._worker_configs: dict[str, WorkerConfig] = {}

    async def start_worker(
        self,
        config: WorkerConfig,
        capability_token: CapabilityToken,
        *,
        workspace: Path | None = None,
    ) -> WorkerResult:
        """Start a worker container with the given capability token.

        Args:
            config: Worker configuration
            capability_token: Signed capability token for authorization

        Returns:
            WorkerResult with execution outcome
        """
        env = dict(config.environment)
        env["ISHASTRA_GATEWAY_URL"] = self.gateway_url
        env["ISHASTRA_JOB_ID"] = config.job_id
        env["ISHASTRA_TENANT_ID"] = config.tenant_id
        env["ISHASTRA_ENGAGEMENT_ID"] = config.engagement_id

        job_root = WORKER_ROOT / config.job_id
        job_root.mkdir(parents=True, exist_ok=True)
        workspace = workspace or job_root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        workspace.chmod(0o777)
        env["ISHASTRA_CAPABILITY_TOKEN"] = self._encode_token(capability_token)
        env_file = job_root / ".env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)

        cmd = self._build_docker_command(config, env_file, workspace)

        log.info(
            "starting worker",
            extra={
                "job_id": config.job_id,
                "image": config.image,
                "command": config.command,
                "resource_limits": config.resource_limits.__dict__,
            },
        )

        self._worker_configs[config.job_id] = config

        result = await self._run_container(
            config.job_id,
            cmd,
            config.resource_limits.wall_clock_seconds,
            config.working_dir,
            config.resource_limits.disk_mb,
            workspace=workspace,
        )

        result.workspace_path = str(workspace)

        if self.database:
            await self._update_job_state(config.job_id, result)

        self._worker_configs.pop(config.job_id, None)
        self._active_workers.pop(config.job_id, None)

        return result

    def _encode_token(self, token: CapabilityToken) -> str:
        """Encode token as base64 URL-safe JSON for environment variable."""
        return base64.urlsafe_b64encode(json.dumps(token.to_dict()).encode()).decode()

    def _build_docker_command(
        self,
        config: WorkerConfig,
        env_file: Path,
        workspace: Path,
    ) -> list[str]:
        """Build docker run command with security hardening."""
        cmd = [
            "docker",
            "-H", self.docker_host,
            "run",
            "--name", f"{CONTAINER_PREFIX}{config.job_id}",
            "--network", config.network_mode,
            "--cpus", str(config.resource_limits.cpu_quota / config.resource_limits.cpu_period),
            "--memory", f"{config.resource_limits.memory_mb}m",
            "--memory-swap", f"{config.resource_limits.memory_mb}m",
            "--pids-limit", str(config.resource_limits.pids_limit),
            "--ulimit", "nofile=1024:1024",
        ]

        if config.readonly_rootfs:
            cmd.append("--read-only")

        cmd.extend([
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
            "--mount", f"type=bind,src={workspace},dst={config.working_dir}",
        ])

        for cap in config.drop_capabilities:
            cmd.extend(["--cap-drop", cap])

        for opt in config.security_opt:
            cmd.extend(["--security-opt", opt])

        cmd.extend(["--user", config.user])

        cmd.extend(["--env-file", str(env_file)])

        cmd.extend(["-w", config.working_dir])

        cmd.append(config.image)
        cmd.extend(config.command)

        return cmd

    async def _run_container(
        self,
        job_id: str,
        cmd: list[str],
        timeout_seconds: int,
        working_dir: str = "/workspace",
        disk_mb: int = 1024,
        *,
        workspace: Path | None = None,
    ) -> WorkerResult:
        """Run the container and collect results."""
        result = WorkerResult(job_id=job_id)
        result.started_at = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            self._active_workers[job_id] = proc

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds,
                )
                result.exit_code = proc.returncode
                result.stdout = stdout.decode(errors="replace")
                result.stderr = stderr.decode(errors="replace")
            except TimeoutError:
                proc.kill()
                await proc.wait()
                result.timed_out = True
                result.error = f"Worker exceeded wall-clock timeout of {timeout_seconds}s"
                log.warning("worker timed out", extra={"job_id": job_id})

        except Exception as e:
            result.error = str(e)
            log.error("worker execution failed", extra={"job_id": job_id, "error": str(e)})

        workspace = workspace or WORKER_ROOT / job_id / "workspace"
        await self._remove_container(job_id)

        result.finished_at = time.time()
        result.duration_seconds = result.finished_at - result.started_at

        if result.exit_code == 0 and not self._workspace_has_output(workspace):
            result.exit_code = 1
            result.error = "worker produced no artifacts"
        elif result.exit_code == 0 and self._workspace_bytes(workspace) > disk_mb * 1024 * 1024:
            result.exit_code = 1
            result.error = f"workspace exceeded the {disk_mb} MB disk limit"

        if result.exit_code == 137:  # SIGKILL
            result.oom_killed = True
            result.error = "Worker OOM killed"

        return result

    @staticmethod
    def _workspace_has_output(workspace: Path) -> bool:
        """True when the worker wrote at least one file."""
        return workspace.is_dir() and any(p.is_file() for p in workspace.rglob("*") if p.name != ".env")

    @staticmethod
    def _workspace_bytes(workspace: Path) -> int:
        """Total size of the collected artifacts, in bytes."""
        if not workspace.is_dir():
            return 0
        return sum(p.stat().st_size for p in workspace.rglob("*") if p.is_file())

    async def _remove_container(self, job_id: str) -> None:
        """Remove the worker container; artifacts are already on the host."""
        name = f"{CONTAINER_PREFIX}{job_id}"
        try:
            rm = await asyncio.create_subprocess_exec(
                "docker",
                "-H",
                self.docker_host,
                "rm",
                "-f",
                name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(rm.wait(), timeout=30)
        except Exception as exc:
            log.warning(
                "worker removal failed",
                extra={"job_id": job_id, "error": str(exc)},
            )

    async def cancel_worker(self, job_id: str) -> bool:
        """Cancel a running worker."""
        proc = self._active_workers.get(job_id)
        if not proc:
            return False

        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=10)
            return True
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return True
        except Exception:
            return False

    async def _update_job_state(self, job_id: str, result: WorkerResult) -> None:
        """Update job state in database based on worker result."""
        if not self.database:
            return

        if result.timed_out:
            state = "failed"
            verdict = "timeout"
        elif result.oom_killed:
            state = "failed"
            verdict = "oom"
        elif result.exit_code == 0:
            state = "completed"
            verdict = "clean"
        else:
            state = "completed"
            verdict = "findings"

        sql = """
        UPDATE jobs
        SET state = ?, verdict = ?, finished_at = ?, error = ?
        WHERE id = ?
        """
        async with self.database.transaction() as conn:
            await conn.execute(sql, (state, verdict, result.finished_at, result.error, job_id))

    def get_worker_status(self, job_id: str) -> dict[str, Any] | None:
        """Get status of a running worker."""
        config = self._worker_configs.get(job_id)
        proc = self._active_workers.get(job_id)

        if not config:
            return None

        return {
            "job_id": job_id,
            "running": proc is not None and proc.returncode is None,
            "config": config.__dict__,
        }

    async def cleanup_all(self) -> None:
        """Cancel all running workers (e.g., on shutdown)."""
        for job_id in list(self._active_workers.keys()):
            await self.cancel_worker(job_id)
