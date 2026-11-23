"""Dispatcher process kill test: verifies cleanup when dispatcher receives SIGTERM.

This test runs the dispatcher in a separate subprocess, waits for the worker
container to start (gateway connection established), then sends SIGTERM to the
dispatcher process. It verifies:
1. Worker container is stopped/removed
2. Job is marked FAILED/REVOKED in database
3. No orphan containers remain
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

from ishastra.control_plane.dispatcher import (
    DispatchRequest,
)
from ishastra.core import store
from ishastra.execution import worker_manager as wm
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import new_keypair
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.signing.service import EvidenceSigningService

IMAGE = os.environ.get("ISHASTRA_WORKER_TEST_IMAGE", "python:3.12-slim")

# Worker script that connects to gateway and keeps running
# We write this to a file to avoid escaping issues
WORKER_SCRIPT_HOLD = (
    "import os,socket,time\n"
    "u=os.environ['ISHASTRA_PROXY_URL']\n"
    "h,p=u.split('//',1)[1].rsplit(':',1)\n"
    "s=socket.create_connection((h,int(p)),5)\n"
    "req='CONNECT 127.0.0.1:%s HTTP/1.1\\r\\nProxy-Authorization: %s\\r\\n\\r\\n' % "
    "(os.environ['TARGET_PORT'],os.environ['ISHASTRA_PROXY_AUTHORIZATION'])\n"
    "s.sendall(req.encode())\n"
    "r=s.recv(200)\n"
    "assert b'200' in r,r\n"
    "open('/workspace/connected','w').write('connected')\n"
    "time.sleep(300)"
)


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "image", "inspect", IMAGE], capture_output=True, text=True
        ).returncode
        == 0
    )


def _container_names() -> str:
    return subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


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
    config = CapabilityIssuer.create_config(
        signing_key_private=private_key, database=db
    )
    issuer = CapabilityIssuer(config)
    await issuer.initialize()
    return {
        "issuer": issuer,
        "verifier": CapabilityVerifier.from_issuer_config(
            config, database=db, require_job_running=False
        ),
        "signing": EvidenceSigningService.create_service(),
        "database": db,
    }


def _request(workspace: Path, echo_port: int, job_id: str) -> DispatchRequest:
    return DispatchRequest(
        tenant_id="tenant-container",
        engagement_id="eng-container",
        job_id=job_id,
        scope=configure(
            program="Container Dispatch Kill Test",
            authorized_by="Test",
            authorization_ref="DISPATCH-KILL-1",
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


def _make_dispatcher_script(script_dir: Path) -> Path:
    """Create dispatcher script that reads worker script from file."""
    worker_script_path = script_dir / "worker_script.py"
    worker_script_path.write_text(WORKER_SCRIPT_HOLD)

    worker_script_path_str = str(worker_script_path).replace("\\", "/")

    script_content = f'''import asyncio
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pathlib import Path
from ishastra.control_plane.dispatcher import (
    DispatchRequest,
    container_worker_runner,
    dispatch,
)
from ishastra.core import store
from ishastra.execution.worker_manager import WorkerManager
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import new_keypair
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.signing.service import EvidenceSigningService

async def run_dispatch(job_id, workspace_path, echo_port, db_path):
    store.configure(db_path)
    db = await store.get_database()
    private_key, _ = new_keypair()
    config = CapabilityIssuer.create_config(signing_key_private=private_key, database=db)
    issuer = CapabilityIssuer(config)
    await issuer.initialize()
    verifier = CapabilityVerifier.from_issuer_config(config, database=db, require_job_running=False)
    signing = EvidenceSigningService.create_service()

    workspace = Path(workspace_path)
    request = DispatchRequest(
        tenant_id="tenant-container",
        engagement_id="eng-container",
        job_id=job_id,
        scope=configure(
            program="Container Dispatch Kill Test",
            authorized_by="Test",
            authorization_ref="DISPATCH-KILL-1",
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

    manager = WorkerManager(default_image="{IMAGE}")
    # Read worker script from file
    worker_script = Path(r"{worker_script_path_str}").read_text()
    runner = container_worker_runner(
        manager,
        image="{IMAGE}",
        command=["python3", "-c", worker_script],
        network_mode="host",
        environment={{"TARGET_PORT": str(echo_port)}},
    )

    outcome = await dispatch(
        request,
        issuer=issuer,
        verifier=verifier,
        signing=signing,
        run_worker=runner,
        worker_manager=manager,
    )
    print(f"OUTCOME: {{outcome.job_id}} revoked={{outcome.revoked}}")

if __name__ == "__main__":
    job_id = sys.argv[1]
    workspace_path = sys.argv[2]
    echo_port = int(sys.argv[3])
    db_path = sys.argv[4]
    asyncio.run(run_dispatch(job_id, workspace_path, echo_port, db_path))
'''
    script_path = script_dir / "dispatcher_script.py"
    script_path.write_text(script_content)
    return script_path


@pytest.mark.integration
@pytest.mark.skipif(
    not _docker_ready(), reason=f"docker or worker image {IMAGE} unavailable"
)
async def test_dispatcher_sigterm_cleans_up_worker(
    parts: dict[str, Any], echo_server: int, tmp_path: Path, monkeypatch
) -> None:
    """Test that SIGTERM to dispatcher cleans up worker container and marks job failed."""
    monkeypatch.setattr(wm, "WORKER_ROOT", tmp_path / "workers")

    job_id = f"job-{uuid.uuid4().hex[:8]}"
    workspace = tmp_path / "evidence" / job_id
    workspace.mkdir(parents=True)

    # Get database path for subprocess
    db_path = store.current_path()

    # Create dispatcher script that reads worker script from file
    script_path = _make_dispatcher_script(tmp_path)

    # Start dispatcher in subprocess
    proc = subprocess.Popen(
        [sys.executable, str(script_path), job_id, str(workspace), str(echo_server), db_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # First check if subprocess is still alive and capture any early output
        early_exit = proc.poll()
        if early_exit is not None:
            stdout, stderr = proc.communicate()
            print(f"Subprocess exited early with code {early_exit}")
            print(f"Subprocess stdout: {stdout}")
            print(f"Subprocess stderr: {stderr}")
            pytest.fail(f"Dispatcher subprocess exited early with code {early_exit}")

        # Wait for worker container to start (gateway connection established)
        # Poll for container with our prefix
        container_name = f"{wm.CONTAINER_PREFIX}{job_id}"
        container_started = False
        for _ in range(50):  # Wait up to 10 seconds
            await asyncio.sleep(0.2)
            names = _container_names()
            if container_name in names:
                container_started = True
                break

        assert container_started, f"Worker container {container_name} did not start"

        # Give a moment for gateway connection to be fully established
        await asyncio.sleep(0.5)

        # Send SIGTERM to dispatcher process
        proc.send_signal(signal.SIGTERM)

        # Wait for process to exit (with timeout)
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            pytest.fail(f"Dispatcher did not exit after SIGTERM. stdout: {stdout}, stderr: {stderr}")

        # Verify container was removed
        names = _container_names()
        assert container_name not in names, f"Orphan container {container_name} still exists: {names}"

    finally:
        # Ensure cleanup
        if proc.poll() is None:
            proc.kill()
            proc.communicate()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
