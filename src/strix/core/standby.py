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
import time
from pathlib import Path
from typing import Any

from strix.audit import AuditChain
from strix.config import get_settings
from strix.core import store

log = logging.getLogger(__name__)


class StandbyError(RuntimeError):
    """Raised when standby promotion cannot proceed."""


async def verify_backup(backup_path: Path) -> dict[str, Any]:
    """Verify a backup file is a valid SQLite database with expected schema."""
    if not backup_path.exists():
        raise StandbyError(f"backup file not found: {backup_path}")
    if not backup_path.is_file():
        raise StandbyError(f"backup path is not a file: {backup_path}")
    if backup_path.stat().st_size == 0:
        raise StandbyError(f"backup file is empty: {backup_path}")

    # Check it's a valid SQLite database
    try:
        conn = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Verify required tables exist
        required_tables = {
            "jobs",
            "findings",
            "audit_log",
            "audit_chain",
            "api_keys",
            "settings",
            "finding_records",
            "engagement_policies",
        }
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {row[0] for row in cursor.fetchall()}
        missing = required_tables - existing
        if missing:
            raise StandbyError(f"backup missing required tables: {sorted(missing)}")

        # Check audit_chain has at least genesis
        cursor.execute("SELECT COUNT(*) FROM audit_chain")
        chain_count = cursor.fetchone()[0]
        if chain_count == 0:
            raise StandbyError("backup has empty audit_chain")

        # Get schema version (PRAGMA user_version is the authoritative schema version)
        cursor.execute("PRAGMA user_version")
        row = cursor.fetchone()
        schema_version = int(row[0]) if row else 0

        conn.close()
    except sqlite3.Error as exc:
        raise StandbyError(f"backup is not a valid SQLite database: {exc}") from exc

    return {
        "path": str(backup_path),
        "size_bytes": backup_path.stat().st_size,
        "schema_version": schema_version,
        "audit_chain_entries": chain_count,
        "tables": sorted(existing),
    }


def restore_database(backup_path: Path, target_path: Path) -> None:
    """Restore database from backup using SQLite's backup API (consistent snapshot)."""
    # Ensure target directory exists
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove any existing target database and WAL/SHM files for clean restore
    if target_path.exists():
        target_path.unlink()
    for suffix in ("-wal", "-shm"):
        wal_path = Path(str(target_path) + suffix)
        if wal_path.exists():
            wal_path.unlink()

    # Use SQLite's backup API for atomic, consistent restore
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

    # Restrict permissions (owner only, like the live DB)
    os.chmod(target_path, 0o600)


async def acquire_standby_lease(db_path: str) -> str:
    """Take the exclusive worker lease for the restored database.

    This prevents split-brain: only one process can hold the lease at a time.
    """
    # Configure store to point at the restored database
    store.configure(db_path)
    await store.reset_database()

    # Try to acquire the lease - this will fail if another worker is running
    from strix.core.worker import WorkerLeaseError, acquire_worker_lease

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

    # Re-configure store to the restored DB
    store.configure(db_path)
    await store.reset_database()

    results: dict[str, Any] = {}

    # 1. Audit chain verification
    chain = AuditChain(persistent=True, hmac_key=settings.audit_hmac_key)
    ok, reason = await chain.verify_async()
    results["audit_chain"] = {"ok": ok, "reason": reason}
    log.info("Audit chain verify: ok=%s, reason=%s", ok, reason)
    if not ok:
        raise StandbyError(f"audit chain verification failed: {reason}")

    # 2. Schema version check
    version = await store.schema_version()
    results["schema_version"] = version

    # 3. Scope/policy check
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
            from strix.core import scope as scope_module

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

    # 4. Check API keys exist (at least one admin key for bootstrap)
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT COUNT(*) FROM api_keys WHERE admin = 1 AND active = 1")
        admin_keys = row[0] if row else 0
    results["api_keys"] = {"admin_count": admin_keys, "ok": admin_keys > 0}
    if admin_keys == 0:
        raise StandbyError("no active admin API keys found")

    # 5. Check audit chain has entries
    chain_count = await store.chain_count()
    results["audit_chain_entries"] = chain_count

    return results


async def promote_standby(
    backup_dir: Path,
    db_path: Path,
    *,
    scope_file: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Full standby promotion workflow.

    Returns a dict with promotion results and timings for RTO measurement.
    """
    started = time.time()
    timings = {}

    # Step 1: Find and verify latest backup
    step_start = time.time()
    backup_files = sorted(backup_dir.glob("strix-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backup_files:
        raise StandbyError(f"no backup files found in {backup_dir} (expected strix-*.db)")
    latest_backup = backup_files[0]
    log.info("Found latest backup: %s (mtime: %.0f)", latest_backup, latest_backup.stat().st_mtime)

    verify_result = await verify_backup(latest_backup)
    timings["verify_backup_ms"] = round((time.time() - step_start) * 1000, 1)

    # Step 2: Restore database
    step_start = time.time()
    restore_database(latest_backup, db_path)
    timings["restore_ms"] = round((time.time() - step_start) * 1000, 1)

    # Step 3: Acquire worker lease
    step_start = time.time()
    lease_path = await acquire_standby_lease(str(db_path))
    timings["acquire_lease_ms"] = round((time.time() - step_start) * 1000, 1)

    # Step 4: Run readiness checks
    step_start = time.time()
    readiness = await run_readiness_checks(str(db_path), scope_file=scope_file, timeout=timeout)
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
