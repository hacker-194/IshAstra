"""Tests for the fail-closed production preflight."""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

from scripts.production_preflight import Check, run_checks


def _fixture(tmp_path: Path, **overrides: str) -> tuple[dict[str, str], Path, Path]:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "program": "preflight-test",
                "authorized_by": "test",
                "include": ["example.com"],
                "authorized_networks": [],
            }
        )
    )
    backups = tmp_path / "backups"
    backups.mkdir()
    values = {
        "ISHASTRA_ENV": "production",
        "ISHASTRA_API_KEY": secrets.token_urlsafe(32),
        "ISHASTRA_AUDIT_HMAC_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "ISHASTRA_ENCRYPTION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "ISHASTRA_DATABASE_URL": "postgresql://user:pass@127.0.0.1:1/ishastra",
        "ISHASTRA_QUEUE_MODE": "postgres",
        "ISHASTRA_GATEWAY_URL": "http://gateway:8080",
        "ISHASTRA_TRUSTED_PROXIES": "127.0.0.1",
        "ISHASTRA_RETENTION_DAYS": "90",
    }
    values.update(overrides)
    return values, scope, backups


def _check(checks: list[Check], name: str) -> Check:
    return next(check for check in checks if check.name == name)


def test_supported_profile_passes(tmp_path: Path) -> None:
    values, scope, backups = _fixture(tmp_path)
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert [check for check in checks if check.level == "FAIL"] == []


def test_sqlite_is_rejected_for_production(tmp_path: Path) -> None:
    values, scope, backups = _fixture(
        tmp_path, ISHASTRA_DATABASE_URL="", ISHASTRA_DB=str(tmp_path / "pilot.db")
    )
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert _check(checks, "database backend").level == "FAIL"


def test_inprocess_queue_is_rejected(tmp_path: Path) -> None:
    values, scope, backups = _fixture(tmp_path, ISHASTRA_QUEUE_MODE="inprocess")
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert _check(checks, "durable queue").level == "FAIL"


def test_missing_gateway_is_rejected(tmp_path: Path) -> None:
    values, scope, backups = _fixture(tmp_path, ISHASTRA_GATEWAY_URL="")
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert _check(checks, "egress gateway configured").level == "FAIL"


def test_placeholder_secret_is_rejected(tmp_path: Path) -> None:
    values, scope, backups = _fixture(tmp_path, ISHASTRA_API_KEY="change-me-change-me-change-me")
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert _check(checks, "configuration accepted").level == "FAIL"


def test_incomplete_scope_is_rejected(tmp_path: Path) -> None:
    values, scope, backups = _fixture(tmp_path)
    scope.write_text(json.dumps({"program": "only-a-program"}))
    checks = run_checks(values=values, scope_file=scope, backup_dir=backups, skip_db=True)
    assert _check(checks, "scope document valid").level == "FAIL"


def test_missing_backup_directory_is_rejected(tmp_path: Path) -> None:
    values, scope, _ = _fixture(tmp_path)
    checks = run_checks(
        values=values, scope_file=scope, backup_dir=tmp_path / "does-not-exist", skip_db=True
    )
    assert _check(checks, "backup directory exists").level == "FAIL"


def test_sqlite_pilot_downgrades_to_warning(tmp_path: Path) -> None:
    values, scope, backups = _fixture(
        tmp_path, ISHASTRA_DATABASE_URL="", ISHASTRA_DB=str(tmp_path / "pilot.db"),
        ISHASTRA_QUEUE_MODE="inprocess",
    )
    checks = run_checks(
        values=values, scope_file=scope, backup_dir=backups, skip_db=True, allow_sqlite=True
    )
    assert _check(checks, "database backend").level == "WARN"
    assert _check(checks, "durable queue").level == "WARN"
