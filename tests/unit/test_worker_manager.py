"""Worker Manager tests: argv hardening and secret placement.

Docker is not available in the test environment, so container execution itself
is NOT tested here. These tests cover the command line and the token delivery
path, which are the parts that can silently leak or grant host access.
"""

from __future__ import annotations

import base64
import json

import pytest

from ishastra.execution import worker_manager as wm
from ishastra.execution.worker_manager import WorkerConfig, WorkerManager, WorkerResult
from ishastra.security.capabilities.token import create_capability_token, new_keypair


def _config(**overrides) -> WorkerConfig:
    values = {
        "job_id": "job-1",
        "tenant_id": "tenant-1",
        "engagement_id": "eng-1",
        "image": "ishastra/worker:latest",
        "command": ["nuclei", "-u", "https://example.com"],
        "environment": {"A": "1"},
    }
    values.update(overrides)
    return WorkerConfig(**values)


def _token():
    private, _ = new_keypair()
    return create_capability_token(
        tenant_id="tenant-1",
        engagement_id="eng-1",
        job_id="job-1",
        targets=["example.com"],
        pinned_ips=["93.184.216.34"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_tools=["nuclei"],
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        request_budget=10,
        bandwidth_limit_mb=10,
        issuer_private_key=private,
        ttl_seconds=60,
    )


def test_command_mounts_only_the_controlled_workspace(tmp_path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    env_file = tmp_path / ".env"
    cmd = WorkerManager()._build_docker_command(_config(), env_file, workspace)

    assert cmd.count("--mount") == 1
    mount = next(arg for arg in cmd if arg.startswith("type=bind,"))
    assert f"src={workspace}" in mount
    assert "dst=/workspace" in mount
    assert "-v" not in cmd
    assert "--rm" not in cmd
    assert cmd[cmd.index("--env-file") + 1] == str(env_file)
    assert "ISHASTRA_CAPABILITY_TOKEN" not in " ".join(cmd)
    assert "127.0.0.1" not in " ".join(cmd)


def test_command_carries_the_security_baseline(tmp_path) -> None:
    cmd = WorkerManager()._build_docker_command(_config(), tmp_path / ".env", tmp_path / "ws")
    joined = " ".join(cmd)

    assert "--read-only" in cmd
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges:true" in joined
    assert "--pids-limit 100" in joined
    assert "--memory 512m" in joined
    assert "--user 10001:10001" in joined
    assert "--network ishastra-worker-net" in joined
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=100m" in joined
    assert "dst=/workspace" in joined


async def test_token_is_delivered_in_an_owner_only_env_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path)
    manager = WorkerManager()
    captured: dict[str, list[str]] = {}

    async def fake_run(job_id, cmd, timeout_seconds, working_dir="/workspace", disk_mb=1024, **kwargs):
        captured["cmd"] = cmd
        return WorkerResult(job_id=job_id, exit_code=0)

    monkeypatch.setattr(manager, "_run_container", fake_run)

    token = _token()
    await manager.start_worker(_config(), token)

    env_file = tmp_path / "job-1" / ".env"
    assert env_file.exists()
    assert (env_file.stat().st_mode & 0o777) == 0o600

    content = env_file.read_text()
    assert "ISHASTRA_CAPABILITY_TOKEN=" in content
    encoded = next(
        line.split("=", 1)[1]
        for line in content.splitlines()
        if line.startswith("ISHASTRA_CAPABILITY_TOKEN=")
    )
    decoded = json.loads(base64.urlsafe_b64decode(encoded))
    assert decoded["jti"] == token.jti
    assert token.jti not in " ".join(captured["cmd"])


def test_invalid_job_id_is_rejected(tmp_path) -> None:
    for bad in ("../escape", "a/b", ".hidden", "x" * 65):
        with pytest.raises(ValueError, match="invalid job_id"):
            _config(job_id=bad)


def test_empty_workspace_is_not_output(tmp_path) -> None:
    assert WorkerManager._workspace_has_output(tmp_path) is False
    (tmp_path / ".env").write_text("A=1")
    assert WorkerManager._workspace_has_output(tmp_path) is False

    (tmp_path / "results.json").write_text("{}")
    assert WorkerManager._workspace_has_output(tmp_path) is True


async def test_sentinel_config_is_required() -> None:
    from ishastra.integrations.connectors.sentinel import SentinelConfig, SentinelConnector

    with pytest.raises(ValueError):
        SentinelConnector(None)
    connector = SentinelConnector(SentinelConfig(workspace_id="w", shared_key="a2V5"))
    assert connector.config.workspace_id == "w"
