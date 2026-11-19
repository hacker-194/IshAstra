"""Fail-closed checks for STRIX_ENV=production."""

from __future__ import annotations

import base64

import pytest

from strix.config import Settings

ENCRYPTION_KEY = base64.b64encode(bytes(range(32))).decode()


def test_production_requires_bootstrap_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.delenv("STRIX_API_KEY", raising=False)
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.setenv("STRIX_ENCRYPTION_KEY", ENCRYPTION_KEY)
    with pytest.raises(ValueError, match="STRIX_API_KEY"):
        Settings.from_env()


def test_production_requires_audit_hmac_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.delenv("STRIX_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("STRIX_ENCRYPTION_KEY", ENCRYPTION_KEY)
    with pytest.raises(ValueError, match="STRIX_AUDIT_HMAC_KEY"):
        Settings.from_env()


def test_production_requires_encryption_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.delenv("STRIX_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError, match="STRIX_ENCRYPTION_KEY"):
        Settings.from_env()


def test_production_rejects_invalid_encryption_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.setenv("STRIX_ENCRYPTION_KEY", "not-a-valid-key-material")
    with pytest.raises(ValueError, match="base64-encoded 32-byte"):
        Settings.from_env()


def test_production_forces_docs_off(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.setenv("STRIX_ENCRYPTION_KEY", ENCRYPTION_KEY)
    monkeypatch.delenv("STRIX_DISABLE_DOCS", raising=False)
    monkeypatch.delenv("STRIX_DEBUG", raising=False)
    monkeypatch.delenv("STRIX_RATE_LIMIT_DISABLED", raising=False)
    settings = Settings.from_env()
    assert settings.environment == "production"
    assert settings.disable_docs is True


@pytest.mark.parametrize(
    ("name", "value"),
    [("STRIX_DEBUG", "1"), ("STRIX_RATE_LIMIT_DISABLED", "1")],
)
def test_production_rejects_debug_or_disabled_rate_limits(monkeypatch, name, value):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.setenv("STRIX_ENCRYPTION_KEY", ENCRYPTION_KEY)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        Settings.from_env()


def test_development_allows_missing_optional_secrets(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "development")
    monkeypatch.delenv("STRIX_API_KEY", raising=False)
    monkeypatch.delenv("STRIX_AUDIT_HMAC_KEY", raising=False)
    settings = Settings.from_env()
    assert settings.environment == "development"
    assert settings.disable_docs is False
