"""Dispatcher + WorkerManager: a job executed in a real hardened container.

The container runs through the real gateway with the dispatcher's token, writes
an artifact into the job workspace, and the dispatcher signs the evidence after
the container exits. ``--network host`` is used only because the gateway binds
127.0.0.1 in this lab; production uses the worker network with a gateway sidecar.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ishastra.control_plane.dispatcher import (
    DispatchRequest,
    container_worker_runner,
    dispatch,
)
from ishastra.core import store
from ishastra.execution import worker_manager as wm
from ishastra.execution.worker_manager import WorkerManager
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import new_keypair
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.signing.service import EvidenceSigningService

IMAGE = os.environ.get("ISHASTRA_WORKER_TEST_IMAGE", "python:3.12-slim")

WORKER_SCRIPT = (
    "import os,socket;"
    "u=os.environ['ISHASTRA_PROXY_URL'];"
    "h,p=u.split('//',1)[1].rsplit(':',1);"
    "s=socket.create_connection((h,int(p)),5);"
    "req='CONNECT 127.0.0.1:%s HTTP/1.1\\r\\nProxy-Authorization: %s\\r\\n\\r\\n'"
    "%(os.environ['TARGET_PORT'],os.environ['ISHASTRA_PROXY_AUTHORIZATION']);"
    "s.sendall(req.encode());r=s.recv(200);"
    "assert b'200' in r,r;"
    "open('/workspace/results.json','w').write('{\"connected\":true}')"
)


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True).returncode == 0
    )


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _docker_ready(), reason=f"docker or worker image {IMAGE} unavailable"),
]


@pytest.fixture
async def echo_server() -> Any:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port: int = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


@pytest.fixture
async def parts() -> Any:
    db = await store.get_database()
    private_key, _ = new_keypair()
    config = CapabilityIssuer.create_config(signing_key_private=private_key, database=db)
    issuer = CapabilityIssuer(config)
    await issuer.initialize()
    return {
        "issuer": issuer,
        "verifier": CapabilityVerifier.from_issuer_config(config, database=db, require_job_running=False),
        "signing": EvidenceSigningService.create_service(),
    }


def _request(workspace: Path, echo_port: int) -> DispatchRequest:
    return DispatchRequest(
        tenant_id="tenant-container",
        engagement_id="eng-container",
        job_id=f"job-{os.urandom(4).hex()}",
        scope=configure(
            program="Container Dispatch",
            authorized_by="Test",
            authorization_ref="DISPATCH-C-1",
            include=["127.0.0.1"],
            allowed_ports=[echo_port],
        ),
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        allowed_tools=("nuclei",),
        request_budget=5,
        bandwidth_limit_mb=5,
        pinned_ips=("127.0.0.1",),
        workspace=workspace,
    )


async def test_dispatch_runs_the_worker_in_a_container(
    parts: dict[str, Any], echo_server: int, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path / "workers")
    workspace = tmp_path / "evidence"
    workspace.mkdir()
    manager = WorkerManager(default_image=IMAGE)
    runner = container_worker_runner(
        manager,
        image=IMAGE,
        command=["python3", "-c", WORKER_SCRIPT],
        network_mode="host",
        environment={"TARGET_PORT": str(echo_server)},
    )

    outcome = await dispatch(
        _request(workspace, echo_server),
        issuer=parts["issuer"],
        verifier=parts["verifier"],
        signing=parts["signing"],
        run_worker=runner,
        worker_manager=manager,
    )

    assert outcome.revoked is True
    assert (workspace / "results.json").is_file()
    assert [a.path for a in outcome.manifest.artifacts] == ["results.json"]
    ok, reason = parts["signing"].verify_evidence(outcome.manifest)
    assert ok, reason


async def test_failed_container_produces_no_evidence(
    parts: dict[str, Any], echo_server: int, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path / "workers")
    workspace = tmp_path / "evidence"
    workspace.mkdir()
    manager = WorkerManager(default_image=IMAGE)
    runner = container_worker_runner(
        manager,
        image=IMAGE,
        command=["python3", "-c", "pass"],
        network_mode="host",
        environment={"TARGET_PORT": str(echo_server)},
    )

    with pytest.raises(RuntimeError, match="worker container failed"):
        await dispatch(
            _request(workspace, echo_server),
            issuer=parts["issuer"],
            verifier=parts["verifier"],
            signing=parts["signing"],
            run_worker=runner,
            worker_manager=manager,
        )

    assert not (workspace / "evidence.json").exists()
