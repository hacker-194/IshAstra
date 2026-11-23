"""Egress gateway tests: every check in the CONNECT decision flow.

The "lab target" is an echo server on 127.0.0.1 - no container or public host
is involved. Anything that needs Docker or nftables is not tested here and is
listed as UNVERIFIED in docs/architecture/EGRESS_ENFORCEMENT.md.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import time
from typing import Any

import pytest

from ishastra.audit import AuditChain
from ishastra.core import store
from ishastra.security.capabilities.revocation import RevocationList
from ishastra.security.capabilities.token import (
    CapabilityToken,
    create_capability_token,
    fingerprint,
    new_keypair,
    public_key,
)
from ishastra.security.capabilities.verifier import CapabilityVerifier
from ishastra.security.egress.gateway import EgressGateway

TENANT = "tenant-1"
ENGAGEMENT = "eng-1"
JOB = "job-1"


@pytest.fixture
async def echo_server() -> Any:
    """A loopback TCP echo server standing in for the authorized target."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


@pytest.fixture
async def env() -> Any:
    """Database, capability key, revocation list and audit chain."""
    db = await store.get_database()
    private_key, pub = new_keypair()
    return {
        "db": db,
        "private_key": private_key,
        "keys": {fingerprint(pub): pub},
        "revocation": RevocationList(db),
        "chain": AuditChain(persistent=True),
    }


@pytest.fixture
async def gateway_factory(env: dict[str, Any]) -> Any:
    """Build and start gateways; stop every one at the end of the test."""
    started: list[EgressGateway] = []

    async def make(
        *,
        require_job_running: bool = False,
        expected_token: CapabilityToken | None = None,
        expected_job_id: str | None = None,
    ) -> EgressGateway:
        verifier = CapabilityVerifier(
            verification_keys=env["keys"],
            revocation=env["revocation"],
            database=env["db"],
            require_job_running=require_job_running,
        )
        gateway = EgressGateway(
            verifier=verifier,
            database=env["db"],
            audit_chain=env["chain"],
            listen_host="127.0.0.1",
            listen_port=0,
            expected_token=expected_token,
            expected_job_id=expected_job_id,
        )
        await gateway.start()
        started.append(gateway)
        return gateway

    yield make
    for gateway in started:
        await gateway.stop()


def make_token(
    private_key: str,
    echo_port: int,
    *,
    targets: tuple[str, ...] = ("127.0.0.1",),
    pinned: tuple[str, ...] = ("127.0.0.1",),
    ports: tuple[int, ...] | None = None,
    protocols: tuple[str, ...] = ("https",),
    budget: int = 10,
    job_id: str = JOB,
    ttl: int = 60,
) -> CapabilityToken:
    return create_capability_token(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        job_id=job_id,
        targets=list(targets),
        pinned_ips=list(pinned),
        allowed_ports=list(ports if ports is not None else (echo_port,)),
        allowed_protocols=list(protocols),
        allowed_tools=["nuclei"],
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        request_budget=budget,
        bandwidth_limit_mb=10,
        issuer_private_key=private_key,
        ttl_seconds=ttl,
    )


def _auth(token: CapabilityToken, scheme: str = "bearer") -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(token.to_dict()).encode()).decode()
    encoded = encoded.rstrip("=")
    if scheme == "basic":
        credentials = base64.b64encode(f"{token.jti}:{encoded}".encode()).decode()
        return f"Basic {credentials}"
    return f"Bearer {encoded}"


async def _connect(
    gateway: EgressGateway,
    token: CapabilityToken,
    host: str,
    port: int,
    scheme: str = "bearer",
) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(gateway.listen_host, gateway.listen_port)
    request = (
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Proxy-Authorization: {_auth(token, scheme)}\r\n\r\n"
    )
    writer.write(request.encode())
    await writer.drain()

    status = await asyncio.wait_for(reader.readline(), 5)
    while True:
        line = await asyncio.wait_for(reader.readline(), 5)
        if line in (b"\r\n", b""):
            break
    return status, reader, writer


async def _insert_job(db: Any, state: str) -> None:
    async with db.transaction() as conn:
        await conn.execute(
            "INSERT OR REPLACE INTO jobs "
            "(id, tenant, target, profile, actor, policy, state, verdict, coverage, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (JOB, TENANT, "127.0.0.1", "web", "tester", "policy", state, "allow", "{}", time.time()),
        )


async def _chain_receipts(db: Any) -> list[dict[str, Any]]:
    """Read every sealed entry from the persistent audit chain."""
    async with db.transaction() as conn:
        cursor = await conn.execute("SELECT data FROM audit_chain ORDER BY sequence")
        rows = await cursor.fetchall()
    return [json.loads(row["data"]) for row in rows]


async def test_allowed_connection_relays_bytes_both_ways(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server)

    status, reader, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 200"), status

    writer.write(b"ping")
    await writer.drain()
    assert await asyncio.wait_for(reader.readexactly(4), 5) == b"ping"

    writer.write(b"pong")
    await writer.drain()
    assert await asyncio.wait_for(reader.readexactly(4), 5) == b"pong"

    writer.close()
    await writer.wait_closed()

    ok, error = await env["chain"].verify_async()
    assert ok, error
    receipts = [
        e for e in await _chain_receipts(env["db"]) if e.get("token_jti") == token.jti
    ]
    assert receipts and receipts[-1]["decision"] == "allowed"


async def test_host_outside_scope_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, targets=("example.com",))

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_port_outside_scope_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, ports=(443,))

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_protocol_outside_scope_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, protocols=("tcp",))

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_expired_token_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    private_key = env["private_key"]
    token = CapabilityToken(
        jti="expired-jti",
        iat=1.0,
        exp=2.0,
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        job_id=JOB,
        targets=("127.0.0.1",),
        pinned_ips=("127.0.0.1",),
        allowed_ports=(echo_server,),
        allowed_protocols=("https",),
        allowed_tools=("nuclei",),
        policy_hash="a" * 64,
        rules_of_engagement_hash="b" * 64,
        request_budget=5,
        bandwidth_limit_mb=1,
        issuer=fingerprint(public_key(private_key)),
    ).sign(private_key)

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_token_signed_by_unknown_key_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    other_private, _ = new_keypair()
    token = make_token(other_private, echo_server)

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_revoked_token_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server)
    assert await env["revocation"].revoke(token.jti, "cancelled", "kid")

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_job_must_be_running(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory(require_job_running=True)
    token = make_token(env["private_key"], echo_server)

    await _insert_job(env["db"], "queued")
    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()

    await _insert_job(env["db"], "running")
    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 200"), status
    writer.close()
    await writer.wait_closed()


async def test_request_budget_is_enforced(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, budget=1)

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 200")
    writer.close()
    await writer.wait_closed()

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_mixed_dns_answers_are_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int, monkeypatch: Any
) -> None:
    async def fake_resolve(host: str, port: int | None = None) -> list[str]:
        return ["127.0.0.1", "127.0.0.2"]

    monkeypatch.setattr("ishastra.security.egress.gateway.resolve", fake_resolve)

    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server)
    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_token_without_pinned_ips_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, pinned=())

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_basic_proxy_auth_is_accepted(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server)

    status, reader, writer = await _connect(
        gateway, token, "127.0.0.1", echo_server, scheme="basic"
    )
    assert status.startswith(b"HTTP/1.1 200"), status
    writer.write(b"ok")
    await writer.drain()
    assert await asyncio.wait_for(reader.readexactly(2), 5) == b"ok"
    writer.close()
    await writer.wait_closed()


async def test_wrong_audience_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    base = make_token(env["private_key"], echo_server)
    token = dataclasses.replace(
        base, audience="some-other-service", signature=""
    ).sign(env["private_key"])

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_unknown_token_version_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    base = make_token(env["private_key"], echo_server)
    token = dataclasses.replace(
        base, version="ishastra-capability/0", signature=""
    ).sign(env["private_key"])

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_token_for_another_job_is_denied(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory(expected_job_id="job-2")
    token = make_token(env["private_key"], echo_server, job_id="job-1")

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()


async def test_denied_connection_is_audited(
    env: dict[str, Any], gateway_factory: Any, echo_server: int
) -> None:
    gateway = await gateway_factory()
    token = make_token(env["private_key"], echo_server, targets=("example.com",))

    status, _, writer = await _connect(gateway, token, "127.0.0.1", echo_server)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()

    ok, error = await env["chain"].verify_async()
    assert ok, error
    receipts = [
        e for e in await _chain_receipts(env["db"]) if e.get("token_jti") == token.jti
    ]
    assert receipts and receipts[-1]["decision"] == "denied"
    assert "approved target" in receipts[-1]["reason"]


async def test_redirect_hop_is_authorized_again(
    env: dict[str, Any], gateway_factory: Any
) -> None:
    """A redirect target is a new CONNECT and must pass authorization itself."""

    async def redirect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            writer.write(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: http://127.0.0.2:8080/\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(redirect, "127.0.0.1", 0)
    port: int = server.sockets[0].getsockname()[1]
    gateway = await gateway_factory()
    token = make_token(
        env["private_key"], port, targets=("127.0.0.1",), pinned=("127.0.0.1",)
    )

    try:
        status, reader, writer = await _connect(gateway, token, "127.0.0.1", port)
        assert status.startswith(b"HTTP/1.1 200"), status
        writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"302" in head and b"Location: http://127.0.0.2:" in head
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

    status, _, writer = await _connect(gateway, token, "127.0.0.2", port)
    assert status.startswith(b"HTTP/1.1 403")
    writer.close()
    await writer.wait_closed()

    receipts = [
        e for e in await _chain_receipts(env["db"]) if e.get("token_jti") == token.jti
    ]
    assert [r["decision"] for r in receipts] == ["allowed", "denied"]


async def test_ipv6_loopback_pinning(
    env: dict[str, Any], gateway_factory: Any
) -> None:
    """IPv6 targets are pinned and matched with the same rules as IPv4."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    try:
        server = await asyncio.start_server(echo, "::1", 0)
    except OSError:
        pytest.skip("IPv6 loopback is unavailable on this host")

    port: int = server.sockets[0].getsockname()[1]
    gateway = await gateway_factory()
    token = make_token(
        env["private_key"],
        port,
        targets=("::1",),
        pinned=("::1",),
        ports=(port,),
    )
    try:
        status, reader, writer = await _connect(gateway, token, "::1", port)
        assert status.startswith(b"HTTP/1.1 200"), status
        writer.write(b"v6")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(2), 5) == b"v6"
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
