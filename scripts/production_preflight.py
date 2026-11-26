#!/usr/bin/env python3
"""Fail-closed production preflight for the supported single-tenant profile.

The API validates secrets at startup but cannot see the deployment around it:
whether the database is reachable, whether RLS is active, whether the queue is
durable, whether a gateway is configured, and whether backups have somewhere to
go. This script checks those before a release is allowed to go live.

It reuses ``Settings.from_env()`` so the preflight cannot drift from the
application's own validation. Secret values are never printed.

Exit status 0 only when no check fails. Warnings are printed but do not fail
the run. Use ``--allow-sqlite`` only for a single-operator pilot.

Usage:
    python3 scripts/production_preflight.py --env-file /etc/ishastra/ishastra.env \
        --scope-file /etc/ishastra/scope.json --backup-dir /backups
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ishastra.config import Settings  # noqa: E402

DURABLE_QUEUE_MODES = frozenset({"postgres", "redis-streams"})
POSTGRES_PREFIXES = ("postgres://", "postgresql://")


@dataclass(frozen=True)
class Check:
    """One preflight result. ``level`` is PASS, WARN or FAIL."""

    level: str
    name: str
    detail: str = ""


def load_env_file(path: Path) -> dict[str, str]:
    """Read a KEY=VALUE file without expanding or executing anything."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


@contextmanager
def _patched_env(values: dict[str, str]) -> Iterator[None]:
    """Apply ``values`` as the only ISHASTRA_* variables, then restore."""
    previous = {key: value for key, value in os.environ.items() if key.startswith("ISHASTRA_")}
    for key in previous:
        os.environ.pop(key, None)
    os.environ.update({k: v for k, v in values.items() if k.startswith("ISHASTRA_")})
    try:
        yield
    finally:
        for key in [key for key in os.environ if key.startswith("ISHASTRA_")]:
            os.environ.pop(key, None)
        os.environ.update(previous)


def _scope_check(path: Path) -> tuple[bool, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    document = data.get("document", data) if isinstance(data, dict) else {}
    program = document.get("program") if isinstance(document, dict) else None
    authorized_by = document.get("authorized_by") if isinstance(document, dict) else None
    include = document.get("include") if isinstance(document, dict) else None
    networks = document.get("authorized_networks") if isinstance(document, dict) else None
    complete = bool(program and authorized_by and (include or networks))
    return complete, f"program={program or 'missing'}"


def _probe_database(dsn: str) -> list[Check]:
    try:
        import asyncpg
    except ImportError:
        return [
            Check(
                "FAIL",
                "database driver available",
                "asyncpg is not installed (pip install 'ishastra[postgres]')",
            )
        ]

    async def _run() -> tuple[object, object, object]:
        conn = await asyncpg.connect(dsn, timeout=8)
        try:
            role = await conn.fetchrow(
                "SELECT current_user AS name, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            rls = await conn.fetchrow(
                "SELECT relrowsecurity FROM pg_class WHERE relname = 'jobs' AND relkind = 'r'"
            )
            owner = await conn.fetchval(
                "SELECT tableowner FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename = 'jobs'"
            )
            return role, rls, owner
        finally:
            await conn.close()

    try:
        role, rls, owner = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - report the failure class, never the DSN
        return [Check("FAIL", "database reachable", type(exc).__name__)]

    checks = [Check("PASS", "database reachable")]
    role_name = None
    if role is None:
        checks.append(Check("FAIL", "database role exists", "current role not found in pg_roles"))
    else:
        role_name = str(role["name"])
        checks.append(
            Check(
                "PASS" if not role["rolsuper"] else "FAIL",
                "application role is not superuser",
                role_name,
            )
        )
        checks.append(
            Check(
                "PASS" if not role["rolbypassrls"] else "FAIL",
                "application role cannot bypass RLS",
                role_name,
            )
        )
    if rls is None:
        checks.append(
            Check("FAIL", "schema migrated", "table 'jobs' not found; run alembic upgrade head")
        )
    else:
        checks.append(
            Check(
                "PASS" if rls["relrowsecurity"] else "FAIL",
                "row-level security enabled on jobs",
            )
        )
        owns_tables = role_name is not None and owner == role_name
        checks.append(
            Check(
                "PASS" if not owns_tables else "FAIL",
                "application role does not own tables",
                f"owner={owner}",
            )
        )
    return checks


def run_checks(
    *,
    values: dict[str, str],
    scope_file: Path,
    backup_dir: Path | None,
    allow_sqlite: bool = False,
    allow_staging: bool = False,
    skip_db: bool = False,
    tls_declared: bool = False,
    no_external_tools: bool = False,
) -> list[Check]:
    """Return every preflight result. Nothing is printed and no secret leaks."""
    checks: list[Check] = []
    with _patched_env(values):
        try:
            settings: Settings | None = Settings.from_env()
            checks.append(Check("PASS", "configuration accepted"))
        except Exception as exc:  # noqa: BLE001 - startup validation is the source of truth
            settings = None
            checks.append(Check("FAIL", "configuration accepted", str(exc)))

    environment = (values.get("ISHASTRA_ENV") or "development").strip().lower()
    checks.append(
        Check(
            "PASS" if environment == "production" or allow_staging else "FAIL",
            "environment is production",
            environment,
        )
    )

    if settings is not None:
        missing = [
            name
            for name, value in (
                ("ISHASTRA_API_KEY", settings.api_key),
                ("ISHASTRA_AUDIT_HMAC_KEY", settings.audit_hmac_key),
                ("ISHASTRA_ENCRYPTION_KEY", settings.encryption_key),
            )
            if not value
        ]
        checks.append(
            Check(
                "PASS" if not missing else "FAIL",
                "credentials configured",
                ", ".join(missing) if missing else "api key, audit key, encryption key",
            )
        )

    queue_mode = (
        values.get("ISHASTRA_QUEUE_MODE") or ("postgres" if environment == "production" else "inprocess")
    ).strip().lower()
    if queue_mode in DURABLE_QUEUE_MODES:
        checks.append(Check("PASS", "durable queue", queue_mode))
    else:
        checks.append(
            Check(
                "WARN" if allow_sqlite else "FAIL",
                "durable queue",
                f"{queue_mode} does not survive a restart",
            )
        )

    if settings is not None:
        dsn = settings.database_url or settings.db_path
    else:
        dsn = (values.get("ISHASTRA_DATABASE_URL") or values.get("ISHASTRA_DB") or "").strip()
    is_postgres = dsn.startswith(POSTGRES_PREFIXES)
    checks.append(
        Check(
            "PASS" if is_postgres else ("WARN" if allow_sqlite else "FAIL"),
            "database backend",
            "PostgreSQL" if is_postgres else "SQLite is single-writer; use --allow-sqlite only for a pilot",
        )
    )

    gateway = (values.get("ISHASTRA_GATEWAY_URL") or "").strip()
    checks.append(
        Check(
            "PASS" if gateway or no_external_tools else "FAIL",
            "egress gateway configured",
            "" if gateway else "external tools refuse to run without a gateway URL",
        )
    )

    scope_path = Path(scope_file)
    if not scope_path.is_file():
        checks.append(Check("FAIL", "scope document present", str(scope_path)))
    else:
        try:
            valid, detail = _scope_check(scope_path)
            checks.append(Check("PASS" if valid else "FAIL", "scope document valid", detail))
        except (OSError, json.JSONDecodeError) as exc:
            checks.append(Check("FAIL", "scope document valid", type(exc).__name__))

    proxies = (values.get("ISHASTRA_TRUSTED_PROXIES") or "").strip()
    checks.append(
        Check(
            "PASS" if proxies or tls_declared else "FAIL",
            "TLS termination declared",
            "set ISHASTRA_TRUSTED_PROXIES or pass --tls-enabled",
        )
    )

    if backup_dir is None:
        checks.append(
            Check("FAIL", "backup directory configured", "pass --backup-dir or set ISHASTRA_BACKUP_DIR")
        )
    else:
        path = Path(backup_dir)
        if not path.is_dir():
            checks.append(Check("FAIL", "backup directory exists", str(path)))
        elif not os.access(path, os.W_OK):
            checks.append(Check("FAIL", "backup directory writable", str(path)))
        else:
            free = shutil.disk_usage(path).free
            checks.append(
                Check(
                    "PASS" if free > 1 << 30 else "WARN",
                    "backup volume has headroom",
                    f"{free // (1 << 30)} GiB free",
                )
            )

    if settings is not None:
        checks.append(
            Check(
                "PASS" if settings.retention_days > 0 else "WARN",
                "retention configured",
                f"{settings.retention_days} days",
            )
        )

    if is_postgres and not skip_db:
        checks.extend(_probe_database(dsn))
    else:
        checks.append(Check("WARN", "database checks skipped", "--skip-db or SQLite backend"))

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed production preflight")
    parser.add_argument("--env-file", default=None, help="Environment file (default: .env.production)")
    parser.add_argument("--scope-file", default=None, help="Scope document (default: config/scope.json)")
    parser.add_argument("--backup-dir", default=None, help="Writable backup directory")
    parser.add_argument("--allow-sqlite", action="store_true", help="Allow SQLite/in-process for a pilot")
    parser.add_argument("--allow-staging", action="store_true", help="Accept ISHASTRA_ENV=staging")
    parser.add_argument("--skip-db", action="store_true", help="Skip database connectivity and RLS checks")
    parser.add_argument("--tls-enabled", action="store_true", help="TLS is terminated by a proxy")
    parser.add_argument(
        "--no-external-tools",
        action="store_true",
        help="Do not require an egress gateway (no external scanners will run)",
    )
    parser.add_argument("env_file_pos", nargs="?", default=None)
    parser.add_argument("scope_file_pos", nargs="?", default=None)
    args = parser.parse_args(argv)

    env_path = Path(args.env_file or args.env_file_pos or ".env.production")
    if not env_path.is_file():
        print(f"FAIL  environment file  {env_path}")
        print("\nNOT READY: 1 check(s) failed")
        return 1

    values = load_env_file(env_path)
    scope_path = Path(args.scope_file or args.scope_file_pos or "config/scope.json")
    backup = Path(args.backup_dir or values.get("ISHASTRA_BACKUP_DIR") or "") if (
        args.backup_dir or values.get("ISHASTRA_BACKUP_DIR")
    ) else None

    checks = run_checks(
        values=values,
        scope_file=scope_path,
        backup_dir=backup,
        allow_sqlite=args.allow_sqlite,
        allow_staging=args.allow_staging,
        skip_db=args.skip_db,
        tls_declared=args.tls_enabled,
        no_external_tools=args.no_external_tools,
    )

    width = max(len(check.name) for check in checks)
    for check in checks:
        print(f"{check.level:<4}  {check.name.ljust(width)}  {check.detail}".rstrip())

    failed = [check for check in checks if check.level == "FAIL"]
    warnings = [check for check in checks if check.level == "WARN"]
    print()
    if failed:
        print(f"NOT READY: {len(failed)} check(s) failed")
        return 1
    suffix = f", {len(warnings)} warning(s)" if warnings else ""
    print(f"READY: {len(checks) - len(warnings)} checks passed{suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
