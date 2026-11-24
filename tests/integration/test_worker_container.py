"""Real container execution for WorkerManager.

Skipped unless Docker and a worker image with Python are available. The test
image defaults to ``python:3.12-slim`` (no ENTRYPOINT, so the command array is
exactly what runs) and can be overridden with ``ISHASTRA_WORKER_TEST_IMAGE``.
The application images set ENTRYPOINT=["ishastra"], which turns tool arguments
into CLI subcommands; that is correct for them, but wrong for this test.

This exercises what unit tests cannot: a real ``docker run`` with the hardened
argv, the owner-only env file, ``docker cp`` collection, container removal, and
the "empty workspace is a failure" rule.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid

import pytest

from ishastra.execution import worker_manager as wm
from ishastra.execution.worker_manager import ResourceLimits, WorkerConfig, WorkerManager
from ishastra.security.capabilities.token import create_capability_token, new_keypair

IMAGE = os.environ.get("ISHASTRA_WORKER_TEST_IMAGE", "python:3.12-slim")


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    completed = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _docker_ready(), reason=f"docker or worker image {IMAGE} unavailable"),
]


def _token(job_id: str):
    private_key, _ = new_keypair()
    return create_capability_token(
        tenant_id="tenant-container",
        engagement_id="eng-container",
        job_id=job_id,
        targets=["example.com"],
        pinned_ips=["93.184.216.34"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_tools=["nuclei"],
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        request_budget=1,
        bandwidth_limit_mb=1,
        issuer_private_key=private_key,
        ttl_seconds=60,
    )


def _config(job_id: str, command: list[str]) -> WorkerConfig:
    return WorkerConfig(
        job_id=job_id,
        tenant_id="tenant-container",
        engagement_id="eng-container",
        image=IMAGE,
        command=command,
        environment={"TEST_MARKER": "container-run"},
        network_mode="none",
    )


def _container_names() -> str:
    return subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


async def test_container_writes_artifact_and_is_removed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path)
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    manager = WorkerManager(default_image=IMAGE)
    config = _config(
        job_id,
        ["python3", "-c", "open('/workspace/results.json','w').write('{\"ok\": true}')"],
    )

    result = await manager.start_worker(config, _token(job_id))

    assert result.exit_code == 0, result.stderr
    assert result.error == ""
    assert result.timed_out is False
    assert result.oom_killed is False

    artifact = tmp_path / job_id / "workspace" / "results.json"
    assert artifact.is_file(), list((tmp_path / job_id / "workspace").iterdir())
    assert artifact.read_text() == '{"ok": true}'

    env_file = tmp_path / job_id / ".env"
    assert (env_file.stat().st_mode & 0o777) == 0o600
    assert "TEST_MARKER=container-run" in env_file.read_text()

    assert f"{wm.CONTAINER_PREFIX}{job_id}" not in _container_names()


async def test_wall_clock_timeout_is_a_failed_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path)
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    manager = WorkerManager(default_image=IMAGE)
    config = _config(job_id, ["python3", "-c", "import time; time.sleep(30)"])
    config = WorkerConfig(
        **{
            **config.__dict__,
            "resource_limits": ResourceLimits(wall_clock_seconds=2, memory_mb=128),
        }
    )

    started = time.monotonic()
    result = await manager.start_worker(config, _token(job_id))
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert "timeout" in result.error.lower()
    assert elapsed < 20, f"timeout took {elapsed:.1f}s"
    assert f"{wm.CONTAINER_PREFIX}{job_id}" not in _container_names()


async def test_oom_killed_container_is_detected(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path)
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    manager = WorkerManager(default_image=IMAGE)
    config = _config(job_id, ["python3", "-c", "x=bytearray(300*1024*1024)"])
    config = WorkerConfig(
        **{
            **config.__dict__,
            "resource_limits": ResourceLimits(memory_mb=64, wall_clock_seconds=30),
        }
    )

    result = await manager.start_worker(config, _token(job_id))

    assert result.exit_code == 137
    assert result.oom_killed is True
    assert result.error == "Worker OOM killed"
    assert f"{wm.CONTAINER_PREFIX}{job_id}" not in _container_names()


async def test_container_with_no_output_is_a_failure(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path)
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    manager = WorkerManager(default_image=IMAGE)
    config = _config(job_id, ["python3", "-c", "pass"])

    result = await manager.start_worker(config, _token(job_id))

    assert result.exit_code == 1
    assert result.error == "worker produced no artifacts"
    assert not (tmp_path / job_id / "workspace" / "results.json").exists()
    assert f"{wm.CONTAINER_PREFIX}{job_id}" not in _container_names()
