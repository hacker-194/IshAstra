"""Fail-closed checks for STRIX_ENV=production."""

from __future__ import annotations

import pytest

from strix.config import Settings


def test_production_requires_bootstrap_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.delenv("STRIX_API_KEY", raising=False)
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    with pytest.raises(ValueError, match="STRIX_API_KEY"):
        Settings.from_env()


def test_production_requires_audit_hmac_key(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.delenv("STRIX_AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(ValueError, match="STRIX_AUDIT_HMAC_KEY"):
        Settings.from_env()


def test_production_forces_docs_off(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "production")
    monkeypatch.setenv("STRIX_API_KEY", "production-api-key-1234567890")
    monkeypatch.setenv("STRIX_AUDIT_HMAC_KEY", "production-audit-key-1234567890")
    monkeypatch.delenv("STRIX_DISABLE_DOCS", raising=False)
    settings = Settings.from_env()
    assert settings.environment == "production"
    assert settings.disable_docs is True


def test_development_allows_missing_optional_secrets(monkeypatch):
    monkeypatch.setenv("STRIX_ENV", "development")
    monkeypatch.delenv("STRIX_API_KEY", raising=False)
    monkeypatch.delenv("STRIX_AUDIT_HMAC_KEY", raising=False)
    settings = Settings.from_env()
    assert settings.environment == "development"
    assert settings.disable_docs is False
