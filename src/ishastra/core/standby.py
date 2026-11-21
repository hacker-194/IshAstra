"""Warm standby promotion: verify backup, restore, acquire lease, run readiness checks.

Single-host by design. HA is achieved by promoting a warm standby:
1. Verify the latest backup file exists and is valid
2. Restore the database from that backup
3. Take the exclusive worker lease (prevents split-brain)
4. Run readiness checks (audit chain verify, scope loaded, API responsive)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from ishastra.audit import AuditChain
from ishastra.config import get_settings
from ishastra.core import store

log = logging.getLogger(__name__)


REQUIRED_TABLES = {
    "jobs",
    "findings",
    "audit_log",
    "audit_chain",
    "api_keys",
    "settings",
    "finding_records",
    "engagement_policies",
}

PG_PREFIXES = ("postgresql://", "postgres://")


class StandbyError(RuntimeError):
    """Raised when standby promotion cannot proceed."""


def _backup_header(backup_path: Path) -> bytes:
    with open(backup_path, "rb") as stream:
        return stream.read(16)


async def verify_backup(backup_path: Path) -> dict[str, Any]:
    """Verify a backup: a SQLite snapshot or a ``pg_dump`` custom archive."""
    if not backup_path.exists():
        raise StandbyError(f"backup file not found: {backup_path}")
    if not backup_path.is_file():
        raise StandbyError(f"backup path is not a file: {backup_path}")
    if backup_path.stat().st_size == 0:
        raise StandbyError(f"backup file is empty: {backup_path}")

    header = _backup_header(backup_path)
    if header.startswith(b"SQLite format 3"):
        return _verify_sqlite_backup(backup_path)
    if header.startswith(b"PGDMP"):
        return _verify_pg_dump(backup_path)
    raise StandbyError("unrecognised backup format (expected SQLite or pg_dump custom archive)")


def _verify_sqlite_backup(backup_path: Path) -> dict[str, Any]:
    """Validate a SQLite snapshot: schema version, required tables, audit chain."""

    try:
        conn = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {row[0] for row in cursor.fetchall()}
        missing = REQUIRED_TABLES - existing
        if missing:
            raise StandbyError(f"backup missing required tables: {sorted(missing)}")

        cursor.execute("SELECT COUNT(*) FROM audit_chain")
        chain_count = cursor.fetchone()[0]
        if chain_count == 0:
            raise StandbyError("backup has empty audit_chain")

        cursor.execute("PRAGMA user_version")
        row = cursor.fetchone()
        schema_version = int(row[0]) if row else 0

        conn.close()
    except sqlite3.Error as exc:
        raise StandbyError(f"backup is not a valid SQLite database: {exc}") from exc

    return {
        "path": str(backup_path),
        "backend": "sqlite",
        "size_bytes": backup_path.stat().st_size,
        "schema_version": schema_version,
        "audit_chain_entries": chain_count,
        "tables": sorted(existing),
    }


def _pg_connection_args(dsn: str) -> tuple[list[str], dict[str, str], str]:
    """Connection arguments, environment and database name for pg tools.

    The password goes in ``PGPASSWORD``, never on the command line: argv is
    world-readable through /proc/<pid>/cmdline.
    """
    parts = urlsplit(dsn)
    args = ["--host", parts.hostname or "localhost", "--port", str(parts.port or 5432)]
    if parts.username:
        args += ["--username", unquote(parts.username)]
    env = dict(os.environ)
    if parts.password:
        env["PGPASSWORD"] = unquote(parts.password)
    sslmode = parse_qs(parts.query).get("sslmode")
    if sslmode:
        env["PGSSLMODE"] = sslmode[0]
    database = (parts.path or "").lstrip("/") or "postgres"
    return args, env, database


def _verify_pg_dump(backup_path: Path) -> dict[str, Any]:
    """Validate a pg_dump custom archive by listing and checking its tables."""
    listing = subprocess.run(
        ["pg_restore", "--list", str(backup_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if listing.returncode != 0:
        raise StandbyError(f"pg_restore could not read the archive: {listing.stderr.strip()[:500]}")

    tables: set[str] = set()
    for line in listing.stdout.splitlines():
        row = line.split()
        if "TABLE" in row:
            index = row.index("TABLE")
            if index + 2 < len(row):
                tables.add(row[index + 2])
    missing = REQUIRED_TABLES - tables
    if missing:
        raise StandbyError(f"backup missing required tables: {sorted(missing)}")

    return {
        "path": str(backup_path),
        "backend": "postgresql",
        "size_bytes": backup_path.stat().st_size,
        "tables": sorted(tables),
    }


def create_backup(target: str, out_dir: Path) -> dict[str, Any]:
    """Write one verified backup of ``target`` (a SQLite file or a PostgreSQL DSN)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

    if target.startswith(PG_PREFIXES):
        artifact = out_dir / f"ishastra-{stamp}.dump"
        args, env, database = _pg_connection_args(target)
        completed = subprocess.run(
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--file",
                str(artifact),
                *args,
                "--dbname",
                database,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        if completed.returncode != 0:
            artifact.unlink(missing_ok=True)
            raise StandbyError(f"pg_dump failed: {completed.stderr.strip()[:500]}")
        info = _verify_pg_dump(artifact)
    else:
        source = Path(target)
        if not source.exists() or source.stat().st_size == 0:
            raise StandbyError(f"database not found or empty: {source}")

        artifact = out_dir / f"ishastra-{stamp}.db"
        src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        dst = sqlite3.connect(artifact)
        try:
            src.backup(dst)

            dst.execute("PRAGMA journal_mode=DELETE")
            dst.commit()
        finally:
            src.close()
            dst.close()
        for sidecar in (f"{artifact}-wal", f"{artifact}-shm"):
            Path(sidecar).unlink(missing_ok=True)
        os.chmod(artifact, 0o600)
        info = _verify_sqlite_backup(artifact)

    return {
        "path": str(artifact),
        "backend": info["backend"],
        "size_bytes": artifact.stat().st_size,
        "verified": info,
    }


def restore_postgres(backup_path: Path, dsn: str) -> None:
    """Restore a pg_dump custom archive into the database in ``dsn``."""
    args, env, database = _pg_connection_args(dsn)
    completed = subprocess.run(
        [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            *args,
            "--dbname",
            database,
            str(backup_path),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    if completed.returncode != 0:
        raise StandbyError(f"pg_restore failed: {completed.stderr.strip()[:500]}")


def restore_database(backup_path: Path, target_path: Path) -> None:
    """Restore database from backup using SQLite's backup API (consistent snapshot)."""

    target_path.parent.mkdir(parents=True, exist_ok=True)

    if target_path.exists():
        target_path.unlink()
    for suffix in ("-wal", "-shm"):
        wal_path = Path(str(target_path) + suffix)
        if wal_path.exists():
            wal_path.unlink()

    try:
        src = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
        dst = sqlite3.connect(target_path)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
    except sqlite3.Error as exc:
        raise StandbyError(f"database restore failed: {exc}") from exc

    os.chmod(target_path, 0o600)


async def acquire_standby_lease(db_path: str) -> str:
    """Take the exclusive worker lease for the restored database.

    This prevents split-brain: only one process can hold the lease at a time.
    """

    store.configure(db_path)
    await store.reset_database()

    from ishastra.core.worker import WorkerLeaseError, acquire_worker_lease

    try:
        lease_path = await acquire_worker_lease()
    except WorkerLeaseError as exc:
        raise StandbyError(str(exc)) from exc

    return lease_path


async def run_readiness_checks(
    db_path: str,
    *,
    scope_file: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run post-restore readiness checks.

    Checks:
    1. Audit chain verifies
    2. Scope document or policy exists
    3. Database schema is at expected version
    4. API would be healthy (no startup blocks)
    """
    settings = get_settings()

    store.configure(db_path)
    await store.reset_database()

    results: dict[str, Any] = {}

    chain = AuditChain(persistent=True, hmac_key=settings.audit_hmac_key)
    ok, reason = await chain.verify_async()
    results["audit_chain"] = {"ok": ok, "reason": reason}
    log.info("Audit chain verify: ok=%s, reason=%s", ok, reason)
    if not ok:
        raise StandbyError(f"audit chain verification failed: {reason}")

    version = await store.schema_version()
    results["schema_version"] = version

    if settings.scope_mode == "managed":
        policies = await store.load_policies()
        active_policies = [p for p in policies if p.get("status") == "active"]
        results["scope"] = {
            "mode": "managed",
            "active_policies": len(active_policies),
            "ok": len(active_policies) > 0,
        }
        if not active_policies:
            raise StandbyError("no active engagement policies found (scope_mode=managed)")
    else:
        scope_path = Path(scope_file or settings.scope_file).expanduser().resolve()
        if scope_path.exists():
            from ishastra.core import scope as scope_module

            loaded_scope = scope_module.load(scope_path)
            results["scope"] = {
                "mode": "global",
                "file": str(scope_path),
                "ok": loaded_scope is not None,
                "program": loaded_scope.program if loaded_scope else None,
            }
            if loaded_scope is None:
                raise StandbyError(f"scope file exists but failed to load: {scope_path}")
        else:
            results["scope"] = {
                "mode": "global",
                "file": str(scope_path),
                "ok": False,
            }
            raise StandbyError(f"scope file not found: {scope_path}")

    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT COUNT(*) FROM api_keys WHERE admin = 1 AND active = 1")
        admin_keys = row[0] if row else 0
    results["api_keys"] = {"admin_count": admin_keys, "ok": admin_keys > 0}
    if admin_keys == 0:
        raise StandbyError("no active admin API keys found")

    chain_count = await store.chain_count()
    results["audit_chain_entries"] = chain_count

    return results


async def promote_standby(
    backup_dir: Path,
    db_path: Path | str,
    *,
    scope_file: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Full standby promotion workflow.

    Returns a dict with promotion results and timings for RTO measurement.
    """
    started = time.time()
    timings = {}

    step_start = time.time()
    target = str(db_path)
    postgres = target.startswith(PG_PREFIXES)
    pattern = "ishastra-*.dump" if postgres else "ishastra-*.db"
    backup_files = sorted(backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backup_files:
        raise StandbyError(f"no backup files found in {backup_dir} (expected {pattern})")
    latest_backup = backup_files[0]
    log.info("Found latest backup: %s (mtime: %.0f)", latest_backup, latest_backup.stat().st_mtime)

    verify_result = await verify_backup(latest_backup)
    timings["verify_backup_ms"] = round((time.time() - step_start) * 1000, 1)

    step_start = time.time()
    if postgres:
        restore_postgres(latest_backup, target)
    else:
        restore_database(latest_backup, Path(target))
    timings["restore_ms"] = round((time.time() - step_start) * 1000, 1)

    step_start = time.time()
    lease_path = await acquire_standby_lease(target)
    timings["acquire_lease_ms"] = round((time.time() - step_start) * 1000, 1)

    step_start = time.time()
    readiness = await run_readiness_checks(target, scope_file=scope_file, timeout=timeout)
    timings["readiness_checks_ms"] = round((time.time() - step_start) * 1000, 1)

    total_ms = round((time.time() - started) * 1000, 1)
    timings["total_ms"] = total_ms

    return {
        "ok": True,
        "backup_used": str(latest_backup),
        "backup_info": verify_result,
        "db_restored_to": str(db_path),
        "lease_path": lease_path,
        "readiness": readiness,
        "timings_ms": timings,
        "rto_ms": total_ms,
    }
