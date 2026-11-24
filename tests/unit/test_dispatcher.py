"""Dispatcher tests: one job through the real gateway, ending in signed evidence.

The worker is an in-process function that speaks CONNECT to the gateway; the
target is a loopback echo server. No Docker, no public host.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from ishastra.control_plane.dispatcher import (
    EVIDENCE_FILENAME,
    DispatchRequest,
    dispatch,
)
from ishastra.core import store
from ishastra.security.authorization.scope import configure
from ishastra.security.capabilities.issuer import CapabilityIssuer
from ishastra.security.capabilities.token import new_keypair
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.signing.service import EvidenceSigningService, verify_evidence_file

TENANT = "tenant-dispatch"
ENGAGEMENT = "eng-dispatch"
JOB = "job-dispatch"


@pytest.fixture
async def echo_server() -> Any:
    """Authorized lab target: echoes whatever the worker sends."""

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
        "db": db,
    }


def _request(workspace: Path, echo_port: int, **overrides: Any) -> DispatchRequest:
    values: dict[str, Any] = {
        "tenant_id": TENANT,
        "engagement_id": ENGAGEMENT,
        "job_id": JOB,
        "scope": configure(
            program="Dispatch Test",
            authorized_by="Test",
            authorization_ref="DISPATCH-001",
            include=["127.0.0.1"],
            allowed_ports=[echo_port],
        ),
        "policy_hash": "a" * 64,
        "rules_of_engagement_hash": "b" * 64,
        "allowed_tools": ("nuclei",),
        "request_budget": 10,
        "bandwidth_limit_mb": 10,
        "pinned_ips": ("127.0.0.1",),
        "workspace": workspace,
    }
    values.update(overrides)
    return DispatchRequest(**values)


def _worker(echo_port: int, *, payload: bytes = b"ping") -> Any:
    async def run(workspace: Path, proxy_url: str, auth: str) -> None:
        host, port = proxy_url.removeprefix("http://").rsplit(":", 1)
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.write(
            (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo_port}\r\n"
                f"Proxy-Authorization: {auth}\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), 5)
        assert status.startswith(b"HTTP/1.1 200"), status
        while True:
            line = await asyncio.wait_for(reader.readline(), 5)
            if line in (b"\r\n", b""):
                break
        writer.write(payload)
        await writer.drain()
        echoed = await asyncio.wait_for(reader.readexactly(len(payload)), 5)
        assert echoed == payload
        (workspace / "results.json").write_text(json.dumps({"echoed": len(echoed)}))
        writer.close()
        await writer.wait_closed()

    return run


async def test_job_runs_through_gateway_and_yields_signed_evidence(
    parts: dict[str, Any], echo_server: int, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    outcome = await dispatch(
        _request(workspace, echo_server),
        issuer=parts["issuer"],
        verifier=parts["verifier"],
        signing=parts["signing"],
        run_worker=_worker(echo_server),
    )

    assert outcome.job_id == JOB
    assert outcome.revoked is True
    assert outcome.manifest_path == workspace / EVIDENCE_FILENAME
    assert outcome.manifest_path.is_file()

    ok, reason = parts["signing"].verify_evidence(outcome.manifest)
    assert ok, reason
    assert [a.path for a in outcome.manifest.artifacts] == ["results.json"]

    assert await parts["issuer"].is_revoked(outcome.token_jti) is True

    public_key = parts["signing"].get_verification_keys()[outcome.manifest.key_id]
    public_path = tmp_path / "evidence.pub"
    public_path.write_text(public_key)
    ok, reason = verify_evidence_file(outcome.manifest_path, public_path, artifacts_dir=workspace)
    assert ok, reason


async def test_gateway_stops_after_dispatch(parts: dict[str, Any], echo_server: int, tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outcome = await dispatch(
        _request(workspace, echo_server),
        issuer=parts["issuer"],
        verifier=parts["verifier"],
        signing=parts["signing"],
        run_worker=_worker(echo_server),
    )

    host, port = outcome.proxy_url.removeprefix("http://").rsplit(":", 1)
    with pytest.raises(OSError):
        await asyncio.open_connection(host, int(port))


async def test_worker_failure_still_revokes_and_stops(
    parts: dict[str, Any], echo_server: int, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    async def failing(workspace: Path, proxy_url: str, auth: str) -> None:
        raise RuntimeError("scanner crashed")

    with pytest.raises(RuntimeError, match="scanner crashed"):
        await dispatch(
            _request(workspace, echo_server),
            issuer=parts["issuer"],
            verifier=parts["verifier"],
            signing=parts["signing"],
            run_worker=failing,
        )

    assert not (workspace / EVIDENCE_FILENAME).exists()
    assert await parts["issuer"].revoke_all_for_job(JOB, "job finished") == 0


async def test_empty_workspace_is_an_error_not_clean_evidence(
    parts: dict[str, Any], echo_server: int, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    async def writes_nothing(workspace: Path, proxy_url: str, auth: str) -> None:
        (workspace / "empty").mkdir(exist_ok=True)

    with pytest.raises(ValueError, match="no files"):
        await dispatch(
            _request(workspace, echo_server),
            issuer=parts["issuer"],
            verifier=parts["verifier"],
            signing=parts["signing"],
            run_worker=writes_nothing,
        )
    assert await parts["issuer"].revoke_all_for_job(JOB, "job finished") == 0


async def test_dispatch_without_pinned_ips_is_refused(
    parts: dict[str, Any], echo_server: int, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    with pytest.raises(ValueError, match="pinned_ips"):
        await dispatch(
            _request(workspace, echo_server, pinned_ips=()),
            issuer=parts["issuer"],
            verifier=parts["verifier"],
            signing=parts["signing"],
            run_worker=_worker(echo_server),
        )


async def test_request_budget_must_be_positive(
    parts: dict[str, Any], echo_server: int, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    with pytest.raises(ValueError, match="request_budget"):
        await dispatch(
            _request(workspace, echo_server, request_budget=0),
            issuer=parts["issuer"],
            verifier=parts["verifier"],
            signing=parts["signing"],
            run_worker=_worker(echo_server),
        )
