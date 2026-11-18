"""Playwright E2E test configuration and fixtures."""

import os
import tempfile

import pytest

# Ensure test environment - use RATE_LIMIT_DISABLED instead of TEST_MODE to allow worker
# Use file-based SQLite DB so worker thread can share the database
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)

os.environ.setdefault("STRIX_RATE_LIMIT_DISABLED", "1")
os.environ.setdefault("STRIX_SKIP_REDIS_INIT", "1")
os.environ.setdefault("STRIX_DB", _db_path)
os.environ.setdefault("STRIX_SCOPE_FILE", "/tmp/scope.json")
os.environ.setdefault("STRIX_API_KEY", "test-key-12345678901234567890123456789012")
os.environ.setdefault("STRIX_ENCRYPTION_KEY", "i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ=")
os.environ.setdefault("STRIX_AUDIT_HMAC_KEY", "dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==")
os.environ.setdefault("STRIX_WORKERS", "1")


@pytest.fixture(scope="session")
def base_url() -> str:
    """Base URL for the Strix API."""
    return os.environ.get("STRIX_E2E_BASE_URL", "http://localhost:8000")


def pytest_collection_modifyitems(config, items) -> None:
    """Skip e2e tests unless a live API is configured.

    The e2e job in CI sets STRIX_E2E_BASE_URL. Without it (the normal test
    jobs) Playwright has no server to talk to, and its sync event loop leaks
    into the async tests that run afterwards.
    """
    if os.environ.get("STRIX_E2E_BASE_URL"):
        return
    skip = pytest.mark.skip(reason="STRIX_E2E_BASE_URL not set; e2e tests need a running API")
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
