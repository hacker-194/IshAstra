"""Test fixtures: an explicit authorized scope, and a loopback HTTP target."""

import asyncio
import os
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from strix.core import scope, store

TEST_SCOPE = {
    "program": "strix test suite",
    "authorized_by": "pytest",
    "authorization_ref": "local-tests",
    "include": ["evil.com", "example.com", "*.example.com", "127.0.0.1"],
    "authorized_networks": ["127.0.0.0/8", "::1/128"],
}


def create_test_app():
    """Create a fresh app instance with test configuration.

    Uses STRIX_TEST_MODE=1 to disable rate limiters at app construction time,
    avoiding fragile middleware patching.
    """
    os.environ.setdefault("STRIX_SCOPE_FILE", "")
    os.environ.setdefault("STRIX_API_KEY", "test-key-" + "x" * 32)
    os.environ.setdefault("STRIX_AUDIT_HMAC_KEY", "test-hmac-" + "x" * 32)
    os.environ.setdefault("STRIX_REDIS_URL", "redis://localhost:6379/15")
    os.environ.setdefault("STRIX_REDIS_REQUIRED", "0")
    os.environ.setdefault("STRIX_WEBHOOK_SECRET", "test-webhook-secret")
    os.environ.setdefault("STRIX_SCOPE_MODE", "auto")
    os.environ.setdefault("STRIX_RETENTION_DAYS", "0")
    os.environ.setdefault("STRIX_DEBUG", "1")
    # Skip Redis initialization in tests to avoid connection attempts
    os.environ.setdefault("STRIX_SKIP_REDIS_INIT", "1")
    # Test mode: disable rate limiters entirely at construction time
    os.environ.setdefault("STRIX_TEST_MODE", "1")

    import importlib

    import strix.api.dependencies

    # `strix.core.worker` is deliberately NOT reloaded: reloading rebinds its
    # exception classes, so an AssessmentQueueFull raised by a worker built after
    # the reload no longer matches the class a test imported at collection time.
    strix.api.dependencies = importlib.reload(strix.api.dependencies)
    # Reset cached settings on the RELOADED module so get_settings() picks up the test STRIX_DB
    strix.api.dependencies.reset_settings()

    # Reload deps module which caches settings at import time
    import strix.api.deps
    strix.api.deps = importlib.reload(strix.api.deps)

    # Now import app AFTER patching
    import strix.api.app

    strix.api.app = importlib.reload(strix.api.app)
    from strix.api.app import create_app

    return create_app()


def create_test_app_with_overrides(overrides: dict = None):
    """Create a test app with dependency overrides for isolated unit tests.

    Usage:
        app = create_test_app_with_overrides({
            deps.get_http_client: override_http_client,
            deps.get_redis: override_redis,
            deps.get_current_tenant: override_current_tenant,
        })

    This pattern avoids hitting real DB/Redis and allows mocking services.
    """
    app = create_test_app()
    if overrides:
        for dep, override in overrides.items():
            app.dependency_overrides[dep] = override
    return app


# Test overrides to avoid real Redis/HTTP connections
async def _override_get_redis():
    """Mock Redis that fails fast, triggering in-memory fallback."""
    from unittest.mock import AsyncMock

    mock = AsyncMock()
    mock.ping.side_effect = Exception("Test Redis unavailable")
    mock.eval.side_effect = Exception("Test Redis unavailable")
    return mock


@pytest.fixture
def client(authorized_scope, temp_database, fresh_rate_limits, async_temp_database):
    """TestClient fixture with test configuration applied before app creation.

    Uses STRIX_TEST_MODE=1 to disable rate limiters at construction time,
    avoiding fragile middleware patching. Only Redis/DB dependency overrides
    are needed for tests that need them.
    """
    from strix.api.dependencies import get_redis, monitor
    from strix.core import scope as scope_mod

    app = create_test_app_with_overrides(
        {
            get_redis: _override_get_redis,
        }
    )

    # Ensure async store uses the same temp database as sync store
    # (create_test_app lifespan calls store.configure which syncs both,
    # but do it explicitly here for reliability)
    import os
    db_path = os.environ.get("STRIX_DB")
    if db_path and db_path != ":memory:":
        store.configure(db_path)

    monitor.set_targets([])

    with TestClient(app) as client:
        scope_mod.configure(**TEST_SCOPE)
        yield client


@pytest.fixture
async def async_test_client(authorized_scope, async_temp_database, fresh_rate_limits):
    """Async test client using httpx AsyncClient with ASGITransport."""
    from strix.api.dependencies import get_redis

    app = create_test_app_with_overrides(
        {
            get_redis: _override_get_redis,
        }
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        from strix.core import scope as scope_mod

        scope_mod.configure(**TEST_SCOPE)
        yield client


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
        if normalized in {
            "example.com",
            "evil.com",
            "victim.example.net",
            "app.example",
        } or normalized.endswith(".example.com"):
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
        if normalized in {
            "example.com",
            "evil.com",
            "victim.example.net",
            "app.example",
        } or normalized.endswith(".example.com"):
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
                "stub the transport instead of reaching the network"
            )
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield


@pytest.fixture(autouse=True)
def temp_database(tmp_path):
    """Each test gets its own SQLite file, so tests never share persisted state."""
    db_path = tmp_path / "strix.db"
    store.configure(db_path)
    # Set STRIX_DB env var so Settings.from_env() picks up the test database
    import os

    old_strix_db = os.environ.get("STRIX_DB")
    os.environ["STRIX_DB"] = str(db_path)
    # Reset cached settings to pick up the new database path
    from strix.api.dependencies import reset_settings
    reset_settings()
    from strix.api.security import api_keys

    api_keys.reset()
    try:
        yield
    finally:
        if old_strix_db is not None:
            os.environ["STRIX_DB"] = old_strix_db
        else:
            os.environ.pop("STRIX_DB", None)


# Async fixture for async tests - runs in the test's event loop
@pytest_asyncio.fixture(autouse=True)
async def async_temp_database(tmp_path):
    """Async fixture to configure async store for the test's event loop."""
    db_path = tmp_path / "strix.db"
    # Ensure fresh database file
    if db_path.exists():
        db_path.unlink()
    for suffix in ("-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink()
    store.configure(db_path)

    yield


@pytest.fixture(autouse=True)
def close_store_pool(temp_database):
    """Close pooled DB connections before their event loop disappears.

    aiosqlite's connection threads are non-daemon: a connection left in the
    process-wide pool after the test loop closes keeps pytest alive at exit and
    logs "Event loop is closed" from its worker thread.
    """
    yield
    asyncio.run(store.close_db_pool())


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    """Rate-limit buckets are process state; isolate them per test."""
    from strix.api import deps

    # Import at runtime to get the current module instance (after reloads)
    from strix.api.security import rate_limiter as _rate_limiter

    _rate_limiter.reset()
    deps.monitor.set_targets([])
    yield
    # Re-import at teardown in case module was reloaded
    from strix.api.security import rate_limiter as _rate_limiter2

    _rate_limiter2.reset()


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
