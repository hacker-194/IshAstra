"""Test fixtures: an explicit authorized scope, and a loopback HTTP target."""
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlparse

import pytest

from strix.core import scope, store, store_async

TEST_SCOPE = {
    "program": "strix test suite",
    "authorized_by": "pytest",
    "authorization_ref": "local-tests",
    "include": ["evil.com", "example.com", "*.example.com", "127.0.0.1"],
    # Hermetic tests talk to a loopback server through the real gate:
    # loopback is allowed only because the fixture scope explicitly
    # authorizes the network (production default is still deny).
    "authorized_networks": ["127.0.0.0/8", "::1/128"],
}


@pytest.fixture(autouse=True)
def authorized_scope(monkeypatch):
    """Every test uses an explicit scope and deterministic DNS for test domains."""
    import ipaddress

    real_resolve = scope.resolve
    real_resolve_sync = scope.resolve_sync

    async def deterministic_resolve(host, port=None):
        # The suite must not depend on public DNS or make incidental network
        # lookups. Tests for DNS rebinding explicitly replace this resolver.
        try:
            return [str(ipaddress.ip_address(host.split("%")[0]))]
        except ValueError:
            pass
        normalized = host.lower().rstrip(".")
        if len(normalized) > 253:
            # Call the real async resolve for malformed labels
            return await real_resolve(host, port)
        if (normalized in {"example.com", "evil.com", "victim.example.net", "app.example"}
                or normalized.endswith(".example.com")):
            return ["93.184.216.34"]
        return await real_resolve(host, port)

    def deterministic_resolve_sync(host, port=None):
        # Synchronous version for the sync code path (scope.destination -> _authorize)
        try:
            return [str(ipaddress.ip_address(host.split("%")[0]))]
        except ValueError:
            pass
        normalized = host.lower().rstrip(".")
        if len(normalized) > 253:
            return real_resolve_sync(host, port)
        if (normalized in {"example.com", "evil.com", "victim.example.net", "app.example"}
                or normalized.endswith(".example.com")):
            return ["93.184.216.34"]
        return real_resolve_sync(host, port)

    monkeypatch.setattr(scope, "resolve", deterministic_resolve)
    monkeypatch.setattr(scope, "resolve_sync", deterministic_resolve_sync)
    scope.configure(**TEST_SCOPE)
    yield


@pytest.fixture(autouse=True)
def hermetic_network(monkeypatch):
    """Tests may only open sockets to loopback.

    The fixture scope authorizes public-looking names (example.com, evil.com)
    with a faked DNS answer, so a code path that wrongly believes such a host is
    in scope would silently reach the real network. Refuse that here: a
    non-loopback connect becomes a loud failure instead of a flaky test.
    """
    import ipaddress
    import socket

    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        try:
            allowed = ipaddress.ip_address(str(host).split("%")[0]).is_loopback
        except ValueError:
            allowed = False
        if not allowed:
            raise AssertionError(
                f"test attempted a non-loopback connection to {host!r}; "
                "stub the transport instead of reaching the network")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield


@pytest.fixture(autouse=True)
def temp_database(tmp_path):
    """Each test gets its own SQLite file, so tests never share persisted state."""
    db_path = tmp_path / "strix.db"
    store.configure(db_path)
    store_async.configure(db_path)
    from strix.api.security import api_keys
    api_keys.reset()
    yield


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """Rate-limit buckets are process state; isolate them per test."""
    from strix.api import deps
    from strix.api.security import rate_limiter

    rate_limiter.reset()
    deps.monitor.set_targets([])
    yield
    rate_limiter.reset()


class Reflector(BaseHTTPRequestHandler):
    """Echoes the q parameter, redirects /redirect, ignores every other parameter."""

    hits: list[str] = []

    def do_GET(self):
        parsed = urlparse(self.path)
        type(self).hits.append(parsed.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
            return
        if parsed.path == "/hostile-redirect":  # a Location no URL parser accepts
            self.send_response(302)
            self.send_header("Location", "http://[::1")
            self.end_headers()
            return
        payload = dict(parse_qsl(parsed.query)).get("q", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@dataclass
class LocalTarget:
    url: str
    hits: list[str] = field(default_factory=list)


@pytest.fixture
def local_target(monkeypatch):
    """A loopback server, reached through the real scope gate.

    The fixture scope (TEST_SCOPE) explicitly authorizes 127.0.0.0/8, which is
    exactly how an internal engagement is authorized in production — no gate is
    stubbed out, so probe and adapter tests exercise the full validation path.
    """
    Reflector.hits = []
    server = HTTPServer(("127.0.0.1", 0), Reflector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield LocalTarget(f"http://127.0.0.1:{server.server_port}", Reflector.hits)
    finally:
        server.shutdown()
        server.server_close()
