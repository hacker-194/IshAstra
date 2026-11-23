"""Pytest configuration and fixtures for Ishastra.

This module provides fixtures for:
- Unit tests (mocked, fast, no external dependencies)
- Integration tests (against test targets like httpbin, juice-shop)
- E2E tests (against running Ishastra API)
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ["ISHASTRA_RATE_LIMIT_DISABLED"] = "1"
os.environ["ISHASTRA_SKIP_REDIS_INIT"] = "1"
os.environ["ISHASTRA_DB"] = str(Path(tempfile.gettempdir()) / "ishastra-test.db")
os.environ["ISHASTRA_SCOPE_FILE"] = str(Path(tempfile.gettempdir()) / "scope.json")
os.environ["ISHASTRA_API_KEY"] = "test-key-12345678901234567890123456789012"
os.environ["ISHASTRA_ENCRYPTION_KEY"] = "i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ="
os.environ["ISHASTRA_AUDIT_HMAC_KEY"] = "dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw=="
os.environ["ISHASTRA_WORKERS"] = "1"


def pytest_sessionfinish() -> None:
    """Close the store pool so aiosqlite's non-daemon thread cannot block exit."""
    import asyncio
    import contextlib

    from ishastra.core import store

    with contextlib.suppress(Exception):
        asyncio.run(store.close_db_pool())


@pytest_asyncio.fixture(autouse=True, scope="function")
async def reset_store_per_test():
    """Reset the database store between each test to prevent connection leaks."""
    from ishastra.core import store
    from ishastra.core.store import _database

    yield

    await store.close_database()
    if _database is not None and hasattr(_database, "discard_sync"):
        _database.discard_sync()


HTTPBIN_URL = os.environ.get("ISHASTRA_HTTPBIN_URL", "https://httpbin.org")
JUICE_SHOP_URL = os.environ.get("ISHASTRA_JUICE_SHOP_URL", "http://localhost:3000")
ISHASTRA_API_URL = os.environ.get("ISHASTRA_API_URL", "http://localhost:8000")


@pytest.fixture
def temp_db() -> Generator[str, None, None]:
    """Create a temporary SQLite database for testing."""
    import tempfile

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield db_path

    Path(db_path).unlink(missing_ok=True)
    Path(db_path + "-shm").unlink(missing_ok=True)
    Path(db_path + "-wal").unlink(missing_ok=True)


@pytest.fixture(scope="session")
def scope_file() -> Generator[str, None, None]:
    """Create a minimal scope.json for testing."""
    scope_content = """{
  "program": "Test Program",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-001",
  "include": ["example.com", "*.example.com", "httpbin.org", "*.httpbin.org"],
  "exclude": ["admin.example.com"],
  "authorized_networks": ["0.0.0.0/0", "::/0"],
  "allowed_ports": [80, 443, 8080],
  "allow_broad_networks": true,
  "auth": {
    "users": [
      {
        "id": "test-user-1",
        "cookies": [{"name": "sessionid", "value": "test-session-123"}],
        "headers": {},
        "bearer": ""
      },
      {
        "id": "test-user-2",
        "cookies": [{"name": "sessionid", "value": "test-session-456"}],
        "headers": {},
        "bearer": ""
      }
    ]
  },
  "collab": {
    "host": "127.0.0.1",
    "port": 0
  }
}"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(scope_content)
        scope_path = f.name
    yield scope_path
    Path(scope_path).unlink(missing_ok=True)


@pytest.fixture(scope="session")
def scope_file_no_auth() -> Generator[str, None, None]:
    """Create a scope.json without auth users for testing adapter unavailability."""
    scope_content = """{
  "program": "Test Program No Auth",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-002",
  "include": ["example.com", "*.example.com"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [],
  "allow_broad_networks": false
}"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(scope_content)
        scope_path = f.name
    yield scope_path
    Path(scope_path).unlink(missing_ok=True)


@pytest.fixture(scope="session")
def scope_file_broad_network() -> Generator[str, None, None]:
    """Create a scope.json allowing broad networks."""
    scope_content = """{
  "program": "Test Program Broad",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-003",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": ["0.0.0.0/0"],
  "allowed_ports": [80, 443],
  "allow_broad_networks": true
}"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(scope_content)
        scope_path = f.name
    yield scope_path
    Path(scope_path).unlink(missing_ok=True)


@pytest_asyncio.fixture
async def store_with_scope(temp_db: str, scope_file: str):
    """Initialize store with test scope."""
    from ishastra.core import scope, store

    store.configure(temp_db)

    await store.get_database()

    scope.load(scope_file)
    yield store
    await store.close_db_pool()


@pytest_asyncio.fixture
async def store_with_scope_no_auth(temp_db: str, scope_file_no_auth: str):
    """Initialize store with test scope (no auth users)."""
    from ishastra.core import scope, store

    store.configure(temp_db)
    await store.get_database()
    scope.load(scope_file_no_auth)
    yield store
    await store.close_db_pool()


@pytest_asyncio.fixture
async def store_with_broad_scope(temp_db: str, scope_file_broad_network: str):
    """Initialize store with broad network scope."""
    from ishastra.core import scope, store

    store.configure(temp_db)
    await store.get_database()
    scope.load(scope_file_broad_network)
    yield store
    await store.close_db_pool()


@pytest_asyncio.fixture
async def app_with_db(temp_db: str, scope_file: str):
    """Create test app with configured database and scope."""

    from ishastra.api.deps import reset_settings
    from ishastra.api.security import api_keys

    reset_settings()
    api_keys.reset()

    os.environ["ISHASTRA_DB"] = temp_db
    from ishastra.core import scope, store

    store.configure(temp_db)
    scope.load(scope_file)
    from ishastra.api.app import create_app

    app = create_app()

    from ishastra.api import app as app_module
    from ishastra.api import deps
    from ishastra.api.app import _bootstrap_admin_key_async
    from ishastra.api.deps import init_http_client
    from ishastra.core import policies

    async def bootstrap():
        await init_http_client()
        await api_keys.load_async()
        await policies.registry.load_async()
        await deps.audit_log.load_async()
        await deps.monitor.load_async()
        await _bootstrap_admin_key_async()

        app_module._scheduler = await deps.create_scheduler(
            audit_chain=deps.audit_chain,
            monitor=deps.monitor,
            settings=deps.settings,
            job_timeout=300.0,
            scope_mode=deps.settings.scope_mode,
        )
        await app_module._scheduler.start()

    await bootstrap()
    yield app

    if app_module._scheduler is not None:
        await app_module._scheduler.stop()
        app_module._scheduler = None


@pytest_asyncio.fixture
async def client(app_with_db) -> AsyncGenerator[AsyncClient, None]:
    """Create test client without auth."""
    transport = ASGITransport(app=app_with_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def auth_client(app_with_db) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with API key auth."""
    transport = ASGITransport(app=app_with_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.headers["Authorization"] = "Bearer test-key-12345678901234567890123456789012"
        yield client


@pytest.fixture
def httpbin_target() -> str:
    """Target URL for httpbin integration tests."""
    return f"{HTTPBIN_URL}/get"


@pytest.fixture
def httpbin_post_target() -> str:
    """Target URL for httpbin POST tests."""
    return f"{HTTPBIN_URL}/post"


@pytest.fixture
def httpbin_redirect_target() -> str:
    """Target URL for httpbin redirect tests."""
    return f"{HTTPBIN_URL}/redirect/3"


@pytest.fixture
def juice_shop_target() -> str:
    """Target URL for juice-shop integration tests (if running)."""
    return JUICE_SHOP_URL


@pytest.fixture
def test_targets() -> dict[str, str]:
    """Dictionary of available test targets for integration tests."""
    return {
        "httpbin": HTTPBIN_URL,
        "httpbin_post": f"{HTTPBIN_URL}/post",
        "httpbin_redirect": f"{HTTPBIN_URL}/redirect/3",
        "juice_shop": JUICE_SHOP_URL,
    }


@pytest.fixture
def sample_findings() -> list[dict[str, Any]]:
    """Sample findings for testing dedupe, SARIF, etc."""
    from ishastra.core.findings import Finding

    return [
        Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing Content-Security-Policy header",
            severity="low",
            confidence="medium",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence="HTTP 200 response carries no Content-Security-Policy header",
            location="https://example.com/",
            cwe="CWE-693",
            verification="observed",
        ),
        Finding(
            asset="https://example.com/",
            category="missing_hsts",
            title="Missing Strict-Transport-Security header",
            severity="low",
            confidence="medium",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence="HTTPS response 200 carries no Strict-Transport-Security header",
            location="https://example.com/",
            cwe="CWE-319",
            verification="observed",
        ),
        Finding(
            asset="https://example.com/page?id=1",
            category="sqli",
            title="Potential SQL injection indicator in request target",
            severity="info",
            confidence="low",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence=(
                "request-target signature matched; this is an indicator only "
                "and does not establish that the server is vulnerable"
            ),
            location="https://example.com/page?id=1",
            cwe="CWE-89",
            verification="unverified",
        ),
    ]


@pytest.fixture
def mock_adapter_context() -> dict[str, Any]:
    """Mock context for adapter tests."""
    return {
        "auth_principal": None,
        "discovered_urls": [],
        "crawl_pages": [],
    }


@pytest.fixture
def encryption_key() -> str:
    """Valid base64-encoded 32-byte encryption key for testing."""
    return "i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ="


@pytest.fixture
def wrong_encryption_key() -> str:
    """Different base64-encoded 32-byte key for negative testing."""
    return "Y5vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="


@pytest.fixture
def cancel_event() -> Generator[Any, None, None]:
    """Threading.Event for cancellation testing."""
    import threading

    yield threading.Event()


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset module-level singletons between tests for isolation."""
    yield

    from ishastra.core import scope

    scope._active_scope = None
    scope._bound_scope = None
    scope._pinned_destinations = {}


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (require external services)"
    )
    config.addinivalue_line("markers", "e2e: marks tests as end-to-end API tests")
    config.addinivalue_line("markers", "slow: marks tests as slow (>5s)")
    config.addinivalue_line("markers", "auth: marks tests as requiring authentication setup")
    config.addinivalue_line("markers", "scope: marks tests as requiring scope configuration")
    config.addinivalue_line("markers", "external: marks tests requiring external tools (nmap, nuclei)")
    config.addinivalue_line("markers", "asyncio: marks tests as async")


def pytest_collection_modifyitems(config, items):
    """Automatically add markers based on test location/name."""
    for item in items:
        if "asyncio" in item.keywords:
            item.add_marker(pytest.mark.asyncio)

        is_unit_path = "unit" in str(item.fspath)
        is_not_integration_e2e = "integration" not in str(item.fspath) and "e2e" not in str(item.fspath)
        no_integration_e2e_kw = "integration" not in item.keywords and "e2e" not in item.keywords
        if (is_unit_path or is_not_integration_e2e) and no_integration_e2e_kw:
            item.add_marker(pytest.mark.unit)

        if "integration" in str(item.fspath) or "integration" in item.name:
            item.add_marker(pytest.mark.integration)

        if "e2e" in str(item.fspath) or "e2e" in item.name:
            item.add_marker(pytest.mark.e2e)
