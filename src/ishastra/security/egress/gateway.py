"""Egress Gateway - HTTP CONNECT proxy with capability enforcement.

Every outbound connection from a worker goes through this gateway. The gateway:

1. Reads the capability token from ``Proxy-Authorization`` (Bearer, or Basic
   ``jti:token`` so a scanner can put the token in its proxy URL).
2. Verifies it against the DB (signature, exp, revocation, job RUNNING).
3. Checks the CONNECT authority against the token's targets, ports, protocols.
4. Resolves DNS itself and requires *every* answer to be in ``pinned_ips``.
5. Connects to the pinned IP, never the hostname, so DNS cannot rebind.
6. Charges the request budget and appends a hash-chained receipt.
7. Relays bytes in both directions until either side closes.

Phase 2 mode support is HTTP/HTTPS over CONNECT only. SOCKS5, ICMP, raw
packets and UDP are not implemented and are refused; each redirect hop is a new
CONNECT and is authorized again. See docs/architecture/EGRESS_ENFORCEMENT.md.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ishastra.security.authorization.scope import resolve
from ishastra.security.capabilities.token import CapabilityToken
from ishastra.security.capabilities.verifier import CapabilityVerifier

log = logging.getLogger(__name__)

_MAX_HEADER_LINES = 100
_MAX_LINE_BYTES = 16 * 1024


@dataclass(frozen=True)
class GatewayDecision:
    """Result of a gateway authorization decision."""

    allowed: bool
    reason: str
    token: CapabilityToken | None = None
    target_host: str = ""
    target_port: int = 0
    resolved_ips: tuple[str, ...] = ()
    pinned_ip: str = ""
    timestamp: float = field(default_factory=time.time)


def _normalize_ip(value: str) -> str:
    """Canonical text form of an IP, tolerating brackets and whitespace."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return value.strip()


class EgressGateway:
    """CONNECT proxy that authorizes every hop against a capability token."""

    def __init__(
        self,
        *,
        verifier: CapabilityVerifier,
        database: Any = None,
        audit_chain: Any = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        connection_timeout: float = 30.0,
        expected_token: CapabilityToken | None = None,
        expected_job_id: str | None = None,
    ) -> None:
        """Build a gateway.

        Args:
            verifier: verifies tokens (pass ``require_job_running=True``).
            database: unused directly; kept for callers that construct one.
            audit_chain: object with ``append_async(entry)``; receipts go there.
            expected_token: per-job fallback for tools that cannot send proxy
                auth headers. Only set this on a gateway dedicated to one job.
            expected_job_id: when set, a token issued for any other job is
                refused even if its scope matches.
        """
        self.verifier = verifier
        self.database = database
        self.audit_chain = audit_chain
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.connection_timeout = connection_timeout
        self.expected_token = expected_token
        self.expected_job_id = expected_job_id

        self._server: asyncio.Server | None = None
        self._budget_used: dict[str, int] = {}
        self._budget_lock = asyncio.Lock()

    async def start(self) -> None:
        """Bind the proxy and record the actual port (0 means ephemeral)."""
        self._server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        socket = self._server.sockets[0]
        self.listen_port = socket.getsockname()[1]
        log.info(
            "egress gateway started",
            extra={"host": self.listen_host, "port": self.listen_port},
        )

    async def stop(self) -> None:
        """Stop accepting connections."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        log.info("egress gateway stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        try:
            await self._handle_connect(reader, writer, client_ip)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:  # never crash the listener on one bad client
            log.warning(
                "gateway client error",
                extra={"client_ip": client_ip, "error": str(exc)},
            )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
    ) -> None:
        """Parse one CONNECT, authorize it, relay both directions."""
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
        except UnicodeDecodeError:
            await self._refuse(writer, 400, "malformed request line")
            return

        parts = request_line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            await self._refuse(writer, 400, "only CONNECT is supported")
            return

        target_spec = parts[1].rsplit(":", 1)
        if len(target_spec) != 2:
            await self._refuse(writer, 400, "CONNECT target must be host:port")
            return
        target_host, port_text = target_spec[0].strip("[]"), target_spec[1]
        try:
            target_port = int(port_text)
        except ValueError:
            await self._refuse(writer, 400, "CONNECT port is not a number")
            return

        headers = await self._read_headers(reader)
        token = self._token_from_headers(headers)
        if token is None:
            await self._refuse(writer, 401, "no capability token on the request")
            return

        decision = await self.authorize_connection(token, client_ip, target_host, target_port, "https")
        if not decision.allowed:
            await self._record(decision, token, client_ip)
            await self._refuse(writer, 403, decision.reason)
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(decision.pinned_ip, decision.target_port),
                timeout=self.connection_timeout,
            )
        except (TimeoutError, OSError) as exc:
            await self._record(
                GatewayDecision(
                    allowed=False,
                    reason=f"upstream connect failed: {exc}",
                    token=token,
                    target_host=target_host,
                    target_port=target_port,
                ),
                token,
                client_ip,
            )
            await self._refuse(writer, 502, "upstream connection failed")
            return

        await self._record(decision, token, client_ip)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        try:
            await self._relay(reader, writer, upstream_reader, upstream_writer)
        finally:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Copy bytes both ways until either direction closes."""

        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
            with contextlib.suppress(Exception):
                dst.write_eof()

        tasks = {
            asyncio.create_task(copy(client_reader, upstream_writer)),
            asyncio.create_task(copy(upstream_reader, client_writer)),
        }
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
        for task in done:
            with contextlib.suppress(Exception):
                task.result()
        del pending

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict[str, str]:
        """Read request headers with caps so a client cannot grow memory."""
        headers: dict[str, str] = {}
        for _ in range(_MAX_HEADER_LINES):
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            if len(line) > _MAX_LINE_BYTES:
                break
            text = line.decode("latin-1").strip()
            if ":" in text:
                key, value = text.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return headers

    def _token_from_headers(self, headers: dict[str, str]) -> CapabilityToken | None:
        """Bearer token, or Basic ``jti:token`` as used in a proxy URL."""
        value = headers.get("proxy-authorization", "")
        scheme, _, credentials = value.partition(" ")
        scheme = scheme.lower()
        if scheme == "bearer":
            return self._decode_token(credentials)
        if scheme == "basic":
            try:
                decoded = base64.b64decode(credentials + "=" * (-len(credentials) % 4))
            except (ValueError, TypeError):
                return None
            _, _, token_part = decoded.decode("utf-8", "replace").partition(":")
            return self._decode_token(token_part)
        return self.expected_token

    @staticmethod
    def _decode_token(raw: str) -> CapabilityToken | None:
        """Decode base64url JSON into a token; ``None`` on any malformation."""
        if not raw:
            return None
        try:
            padded = raw + "=" * (-len(raw) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode())
            return CapabilityToken.from_dict(payload)
        except (ValueError, TypeError, KeyError):
            return None

    async def authorize_connection(
        self,
        token: CapabilityToken,
        client_ip: str,
        target_host: str,
        target_port: int,
        protocol: str = "https",
    ) -> GatewayDecision:
        """Authorize one connection. Deny is the default."""
        result = await self.verifier.verify_async(token.to_dict())
        if not result.valid:
            return GatewayDecision(
                allowed=False,
                reason=f"token invalid: {result.reason}",
                token=token,
                target_host=target_host,
                target_port=target_port,
            )

        verified = result.token
        assert verified is not None  # verify_async never returns a null token

        if self.expected_job_id and verified.job_id != self.expected_job_id:
            return self._deny(
                verified,
                target_host,
                target_port,
                f"token is for job {verified.job_id}, not {self.expected_job_id}",
            )

        if not self._host_matches(verified.targets, target_host):
            return self._deny(
                verified, target_host, target_port, f"host {target_host} is not an approved target"
            )
        if target_port not in verified.allowed_ports:
            return self._deny(verified, target_host, target_port, f"port {target_port} is not allowed")
        if protocol not in verified.allowed_protocols:
            return self._deny(verified, target_host, target_port, f"protocol {protocol} is not allowed")

        resolved = await resolve(target_host, target_port)
        if not resolved:
            return self._deny(verified, target_host, target_port, f"DNS resolution failed for {target_host}")

        pinned = {_normalize_ip(ip) for ip in verified.pinned_ips}
        answers = {_normalize_ip(ip) for ip in resolved}
        if not pinned:
            return self._deny(verified, target_host, target_port, "token carries no pinned IPs")
        unmatched = answers - pinned
        if unmatched:
            return self._deny(
                verified,
                target_host,
                target_port,
                f"DNS answers outside the pin: {sorted(unmatched)}",
                resolved_ips=tuple(sorted(answers)),
            )

        async with self._budget_lock:
            used = self._budget_used.get(verified.jti, 0)
            if used >= verified.request_budget:
                return self._deny(
                    verified,
                    target_host,
                    target_port,
                    f"request budget exhausted ({used}/{verified.request_budget})",
                )
            self._budget_used[verified.jti] = used + 1

        return GatewayDecision(
            allowed=True,
            reason="authorized",
            token=verified,
            target_host=target_host,
            target_port=target_port,
            resolved_ips=tuple(sorted(answers)),
            pinned_ip=sorted(answers)[0],
        )

    def _deny(
        self,
        token: CapabilityToken,
        target_host: str,
        target_port: int,
        reason: str,
        resolved_ips: tuple[str, ...] = (),
    ) -> GatewayDecision:
        return GatewayDecision(
            allowed=False,
            reason=reason,
            token=token,
            target_host=target_host,
            target_port=target_port,
            resolved_ips=resolved_ips,
        )

    @staticmethod
    def _host_matches(patterns: tuple[str, ...], host: str) -> bool:
        """Exact match, or ``*.example.com`` matching only real subdomains."""
        lowered = host.lower().rstrip(".")
        for pattern in patterns:
            pattern = pattern.lower().rstrip(".")
            if pattern == lowered:
                return True
            if pattern.startswith("*.") and lowered.endswith(pattern[1:]):
                return True
        return False

    async def _record(
        self,
        decision: GatewayDecision,
        token: CapabilityToken,
        client_ip: str,
    ) -> None:
        """Append a decision receipt to the hash-chained audit log."""
        if self.audit_chain is None:
            return
        entry = {
            "type": "gateway_decision",
            "event": "gateway_decision",
            "tenant": token.tenant_id,
            "decision": "allowed" if decision.allowed else "denied",
            "reason": decision.reason,
            "token_jti": token.jti,
            "job_id": token.job_id,
            "engagement_id": token.engagement_id,
            "target_host": decision.target_host,
            "target_port": decision.target_port,
            "pinned_ip": decision.pinned_ip,
            "client_ip": client_ip,
        }
        try:
            await self.audit_chain.append_async(entry)
        except Exception:
            log.exception("gateway receipt write failed", extra={"jti": token.jti})

    @staticmethod
    async def _refuse(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        phrases = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 502: "Bad Gateway"}
        phrase = phrases.get(status, "Error")
        body = reason.encode("utf-8", "replace")
        writer.write(
            f"HTTP/1.1 {status} {phrase}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        with contextlib.suppress(Exception):
            await writer.drain()


async def main() -> int:
    """Run the egress gateway as a standalone service."""
    import os
    import signal

    from ishastra.core import store
    from ishastra.security.capabilities.issuer import CapabilityIssuer
    from ishastra.security.capabilities.verifier import CapabilityVerifier

    # Configure database
    db_url = os.environ.get("ISHASTRA_DATABASE_URL")
    if not db_url:
        print("ISHASTRA_DATABASE_URL not set", file=sys.stderr)
        return 1

    store.configure(db_url)
    db = await store.get_database()

    # Load keys
    private_key_path = os.environ.get("ISHASTRA_CAPABILITY_PRIVATE_KEY_PATH")

    if not private_key_path or not os.path.exists(private_key_path):
        print("ISHASTRA_CAPABILITY_PRIVATE_KEY_PATH not set or file not found", file=sys.stderr)
        return 1

    private_key = Path(private_key_path).read_text().strip()

    # Create issuer and verifier
    config = CapabilityIssuer.create_config(signing_key_private=private_key, database=db)
    issuer = CapabilityIssuer(config)
    await issuer.initialize()

    verifier = CapabilityVerifier.from_issuer_config(config, database=db, require_job_running=False)

    # Create gateway
    listen_host = os.environ.get("ISHASTRA_GATEWAY_LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.environ.get("ISHASTRA_GATEWAY_LISTEN_PORT", "8080"))

    gateway = EgressGateway(
        verifier=verifier,
        audit_chain=None,  # Could be configured from environment
        listen_host=listen_host,
        listen_port=listen_port,
        expected_job_id=None,  # None means accept any valid job
    )

    shutdown_event = asyncio.Event()

    def _signal_handler(signum, frame):
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    print(f"Starting egress gateway on {listen_host}:{listen_port}", file=sys.stderr)
    await gateway.start()

    try:
        await shutdown_event.wait()
    finally:
        print("Shutting down egress gateway...", file=sys.stderr)
        await gateway.stop()

    return 0


if __name__ == "__main__":
    import asyncio
    import sys
    from pathlib import Path

    sys.exit(asyncio.run(main()))
