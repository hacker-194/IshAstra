"""Playwright E2E test configuration and fixtures."""

import os
import tempfile

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)

os.environ.setdefault("ISHASTRA_RATE_LIMIT_DISABLED", "1")
os.environ.setdefault("ISHASTRA_SKIP_REDIS_INIT", "1")
os.environ.setdefault("ISHASTRA_DB", _db_path)
os.environ.setdefault("ISHASTRA_SCOPE_FILE", "/tmp/scope.json")
os.environ.setdefault("ISHASTRA_API_KEY", "test-key-12345678901234567890123456789012")
os.environ.setdefault("ISHASTRA_ENCRYPTION_KEY", "i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ=")
os.environ.setdefault("ISHASTRA_AUDIT_HMAC_KEY", "dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==")
os.environ.setdefault("ISHASTRA_WORKERS", "1")


@pytest.fixture(scope="session")
def base_url() -> str:
    """Base URL for the Ishastra API."""
    return os.environ.get("ISHASTRA_E2E_BASE_URL", "http://localhost:8000")


def pytest_collection_modifyitems(config, items) -> None:
    """Skip e2e tests unless a live API is configured.

    The e2e job in CI sets ISHASTRA_E2E_BASE_URL. Without it (the normal test
    jobs) Playwright has no server to talk to, and its sync event loop leaks
    into the async tests that run afterwards.
    """
    if os.environ.get("ISHASTRA_E2E_BASE_URL"):
        return
    skip = pytest.mark.skip(reason="ISHASTRA_E2E_BASE_URL not set; e2e tests need a running API")
    for item in items:
        if "tests/e2e" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture
def api_key() -> str:
    """Test API key."""
    return "test-key-12345678901234567890123456789012"


@pytest.fixture
def auth_headers(api_key: str) -> dict:
    """Authorization headers for API requests."""
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture(scope="session", autouse=True)
def cleanup_db():
    """Cleanup the temporary database after all tests."""
    yield
    from pathlib import Path

    Path(_db_path).unlink(missing_ok=True)
    Path(_db_path + "-shm").unlink(missing_ok=True)
    Path(_db_path + "-wal").unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def reset_store_per_test():
    """Override the async store reset that tests/conftest.py installs.

    The Playwright sync API runs its own event loop, so an autouse async fixture
    makes pytest-asyncio call Runner.run() from inside a running loop and every
    e2e test errors during setup. These tests drive a live server over HTTP and
    never touch the in-process store.
    """
    yield
