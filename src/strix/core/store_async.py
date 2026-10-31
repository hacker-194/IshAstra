"""Async SQLite persistence for assessment jobs and findings.

This module mirrors the synchronous `store.py` API but uses `aiosqlite` for
non-blocking database operations. All functions are async and must be awaited.

Migration notes:
- Uses the same schema and migrations as `store.py`
- For migration operations, opens a dedicated connection
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from strix.core.findings import Finding, dedupe, redact
from strix.core.redaction import sanitize_target
from strix.core.store import MIGRATIONS, TERMINAL_STATES, JobConflict

log = logging.getLogger(__name__)

_path = "strix.db"


def configure(path: str | Path) -> None:
    """Set the database file path (same as sync version)."""
    global _path
    _path = str(path)
    # Reset pool so it's recreated with the new path
    from strix.api.dependencies import reset_db_pool
    reset_db_pool()


def current_path() -> str:
    return _path


async def migrate_async(connection: aiosqlite.Connection) -> int:
    """Apply pending migrations. Returns the resulting schema version."""
    row = await connection.execute("PRAGMA user_version")
    version_row = await row.fetchone()
    version = version_row[0] if version_row else 0
    for target, script in MIGRATIONS:
        if target <= version:
            continue
        await connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in script.split(";"):
                if statement.strip():
                    await connection.execute(statement)
            await connection.execute(f"PRAGMA user_version = {int(target)}")
            await connection.execute("COMMIT")
        except aiosqlite.Error:
            await connection.execute("ROLLBACK")
            raise
        version = target
    return version


def _restrict_permissions(path: str) -> None:
    """The database holds key hashes, findings and the audit trail: owner only."""
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):
            os.chmod(path + suffix, 0o600)


@asynccontextmanager
async def get_db_async() -> AsyncIterator[aiosqlite.Connection]:
    """Get a database connection from the pool (initialized on first use)."""
    from strix.api.dependencies import get_db_pool
    pool = await get_db_pool()
    db = await pool.get()
    try:
        yield db
    finally:
        await pool.put(db)


async def schema_version() -> int:
    async with get_db_async() as db:
        row = await db.execute("PRAGMA user_version")
        version_row = await row.fetchone()
        return version_row[0] if version_row else 0


# ---------------------------------------------------------------------------
# Jobs and findings
# ---------------------------------------------------------------------------
async def save_job(job: Any, *, tenant: str) -> None:
    """Persist a job and its findings in one transaction (async version)."""
    rows = []
    for finding in dedupe(job.findings):
        data = finding.to_dict()
        rows.append((
            job.id, tenant, data["fingerprint"], data["asset"], data["category"],
            data["title"], data["severity"], data["confidence"], data["verification"],
            data["status"], data["detector"], data["detector_version"],
            data["location"], data["evidence"], data["description"],
            data["remediation"], data["cwe"], json.dumps(data["sources"]),
        ))

    stored_target = sanitize_target(job.target)
    stored_error = redact(job.error)
    state, verdict = job.state.value, job.verdict
    finished_at = job.finished_at

    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            existing = await db.execute(
                "SELECT state, verdict, error, finished_at FROM jobs WHERE id = ?",
                (job.id,))
            existing_row = await existing.fetchone()
            if (existing_row is not None and existing_row["state"] in TERMINAL_STATES
                    and state not in TERMINAL_STATES):
                state, verdict = existing_row["state"], existing_row["verdict"]
                stored_error, finished_at = existing_row["error"], existing_row["finished_at"]
            try:
                await db.execute(
                    """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                         verdict, error, started_at, finished_at, coverage,
                                         created_at, attempts, worker, idempotency_key)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT (id) DO UPDATE SET
                         state = excluded.state, verdict = excluded.verdict,
                         error = excluded.error, finished_at = excluded.finished_at,
                         coverage = excluded.coverage,
                         attempts = excluded.attempts, worker = excluded.worker,
                         started_at = COALESCE(jobs.started_at, excluded.started_at)""",
                    (job.id, tenant, stored_target, job.profile, job.actor,
                     json.dumps(job.policy), state, verdict, stored_error,
                     job.started_at, finished_at, json.dumps(job.coverage()),
                     time.time(), int(getattr(job, "attempts", 0) or 0),
                     str(getattr(job, "worker_id", "") or ""),
                     getattr(job, "idempotency_key", None) or None),
                )
            except aiosqlite.IntegrityError as exc:
                raise JobConflict(f"idempotency key already used by another job: {exc}") from None
            await db.execute("DELETE FROM findings WHERE job_id = ?", (job.id,))
            await db.executemany(
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


def _job_row_to_dict(row: aiosqlite.Row, findings: list[dict[str, Any]]) -> dict[str, Any]:
    finished, started = row["finished_at"], row["started_at"]
    return {
        "id": row["id"],
        "target": row["target"],
        "profile": row["profile"],
        "actor": row["actor"],
        "policy": json.loads(row["policy"]),
        "state": row["state"],
        "verdict": row["verdict"],
        "clean": row["state"] == "completed" and not findings,
        "started_at": started,
        "finished_at": finished,
        "duration_ms": round((finished - started) * 1000, 1) if started and finished else None,
        "coverage": json.loads(row["coverage"]),
        "findings": findings,
        "error": row["error"],
        "tenant": row["tenant"],
        "attempts": row["attempts"],
        "worker": row["worker"],
        "idempotency_key": row["idempotency_key"],
    }


def _finding_row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return {
        "fingerprint": row["fingerprint"],
        "asset": row["asset"],
        "category": row["category"],
        "title": row["title"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "verification": row["verification"],
        "status": row["status"],
        "detector": row["detector"],
        "detector_version": row["detector_version"],
        "location": row["location"],
        "evidence": row["evidence"],
        "description": row["description"],
        "remediation": row["remediation"],
        "cwe": row["cwe"],
        "sources": json.loads(row["sources"]),
    }


async def get_job(job_id: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Load a job. ``tenant=None`` is reserved for administrators."""
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        else:
            cursor = await db.execute(
                "SELECT * FROM jobs WHERE id = ? AND tenant = ?", (job_id, tenant))
        row = await cursor.fetchone()
        if row is None:
            return None
        findings_cursor = await db.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", (job_id,))
        findings = await findings_cursor.fetchall()
        return _job_row_to_dict(row, [_finding_row_to_dict(item) for item in findings])


async def latest_finished_job(target: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Most recent job for ``target`` that produced a result (with its findings)."""
    target = sanitize_target(target)
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute(
                "SELECT id FROM jobs WHERE target = ? AND state IN ('completed', 'partial') "
                "ORDER BY created_at DESC LIMIT 1", (target,))
        else:
            cursor = await db.execute(
                "SELECT id FROM jobs WHERE target = ? AND tenant = ? "
                "AND state IN ('completed', 'partial') ORDER BY created_at DESC LIMIT 1",
                (target, tenant))
        row = await cursor.fetchone()
    return await get_job(row["id"], tenant=tenant) if row else None


async def list_jobs(*, tenant: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Recent job summaries (no findings payload)."""
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
        else:
            cursor = await db.execute(
                "SELECT * FROM jobs WHERE tenant = ? ORDER BY created_at DESC LIMIT ?",
                (tenant, limit))
        rows = await cursor.fetchall()
        return [_job_row_to_dict(row, []) for row in rows]


async def fail_interrupted(*, created_before: float | None = None) -> int:
    """Mark jobs a previous process left queued/running as failed."""
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            cutoff = "AND created_at < ?" if created_before is not None else ""
            params = (time.time(),) if created_before is None else (time.time(), created_before)
            cursor = await db.execute(
                f"""UPDATE jobs
                   SET state = 'failed',
                       verdict = 'failed -- no usable coverage',
                       error = 'interrupted by process restart',
                       finished_at = ?
                   WHERE state IN ('queued', 'running') {cutoff}""",
                params,
            )
            await db.execute("COMMIT")
            return cursor.rowcount
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def mark_running(job_id: str, *, tenant: str, worker: str,
                       now: float | None = None) -> bool:
    """Claim a queued job for one worker. False when another claim won."""
    stamp = time.time() if now is None else now
    async with get_db_async() as db:
        cursor = await db.execute(
            """UPDATE jobs
               SET state = 'running', worker = ?,
                   started_at = COALESCE(started_at, ?),
                   attempts = attempts + 1
               WHERE id = ? AND tenant = ? AND state = 'queued'""",
            (worker, stamp, job_id, tenant),
        )
        await db.commit()
        return cursor.rowcount == 1


async def claim_job(job_id: str, *, tenant: str, worker: str,
                    now: float | None = None) -> bool:
    """Single-execution claim: True when this caller may run the job."""
    if await mark_running(job_id, tenant=tenant, worker=worker, now=now):
        return True
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT 1 FROM jobs WHERE id = ? AND tenant = ?", (job_id, tenant))
        row = await cursor.fetchone()
        return row is None


async def find_job_id_by_idempotency(idempotency_key: str, *, tenant: str) -> str | None:
    """The job that already owns ``idempotency_key`` for this tenant, if any."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT id FROM jobs WHERE tenant = ? AND idempotency_key = ?",
            (tenant, idempotency_key))
        row = await cursor.fetchone()
        return row["id"] if row else None


async def count_jobs(*, tenant: str) -> int:
    """How many jobs a tenant owns — counted in SQL, never across tenants."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM jobs WHERE tenant = ?", (tenant,))
        row = await cursor.fetchone()
        assert row is not None
        return int(row[0])


async def count_findings(*, tenant: str) -> int:
    """How many findings a tenant owns — scoped in SQL."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM findings WHERE tenant = ?", (tenant,))
        row = await cursor.fetchone()
        assert row is not None
        return int(row[0])


async def jobs_by_state(*, tenant: str | None = None) -> dict[str, int]:
    """Jobs grouped by state — aggregate SQL, optionally scoped to a tenant."""
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state")
        else:
            cursor = await db.execute(
                "SELECT state, COUNT(*) AS n FROM jobs WHERE tenant = ? GROUP BY state",
                (tenant,))
        rows = await cursor.fetchall()
    return {str(row["state"]): int(row["n"]) for row in rows}


async def findings_by_severity(*, tenant: str | None = None) -> dict[str, int]:
    """Findings grouped by severity — aggregate SQL, optionally scoped to a tenant."""
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        else:
            cursor = await db.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE tenant = ? GROUP BY severity",
                (tenant,))
        rows = await cursor.fetchall()
    return {str(row["severity"]): int(row["n"]) for row in rows}


async def get_findings(job_id: str, *, tenant: str | None = None) -> list[Finding]:
    """Rehydrate findings for report generation (SARIF)."""
    async with get_db_async() as db:
        if tenant is None:
            cursor = await db.execute(
                "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", (job_id,))
        else:
            cursor = await db.execute(
                "SELECT * FROM findings WHERE job_id = ? AND tenant = ? ORDER BY rowid",
                (job_id, tenant))
        rows = await cursor.fetchall()

    findings = []
    for row in rows:
        data = _finding_row_to_dict(row)
        findings.append(Finding(
            asset=data["asset"], category=data["category"], title=data["title"],
            severity=data["severity"], confidence=data["confidence"],
            detector=data["detector"], detector_version=data["detector_version"],
            evidence=redact(data["evidence"]), location=data["location"],
            description=data["description"], remediation=data["remediation"],
            cwe=data["cwe"], verification=data["verification"], status=data["status"],
            sources=tuple(data["sources"]),
        ))
    return findings


# ---------------------------------------------------------------------------
# API keys (hashes only — a raw key is never stored)
# ---------------------------------------------------------------------------
async def save_api_key(*, tenant_id: str, key_hash: str, tier: str, admin: bool,
                       active: bool, created_at: float, expires_at: float | None = None,
                       last_used: float | None = None, rotated_at: float | None = None) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at, "
                "expires_at, last_used, rotated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET "
                "key_hash = excluded.key_hash, tier = excluded.tier, admin = excluded.admin, "
                "active = excluded.active, created_at = excluded.created_at, "
                "expires_at = excluded.expires_at, last_used = excluded.last_used, "
                "rotated_at = excluded.rotated_at",
                (tenant_id, key_hash, tier, int(admin), int(active), created_at,
                 expires_at, last_used, rotated_at))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def load_api_keys() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT * FROM api_keys")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Audit trail and hash chain
# ---------------------------------------------------------------------------
async def append_audit(entry: dict[str, Any]) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
                (entry.get("tenant"), entry.get("event"), entry.get("timestamp", time.time()),
                 json.dumps(entry, sort_keys=True)))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def recent_audit(limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` entries, returned oldest-first."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT data FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
    return [json.loads(row["data"]) for row in reversed(list(rows))]


async def chain_tip() -> tuple[int, str] | None:
    """(sequence, hash) of the last sealed entry, or None for an empty chain."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT sequence, hash FROM audit_chain ORDER BY sequence DESC LIMIT 1")
        row = await cursor.fetchone()
    return (row["sequence"], row["hash"]) if row else None


async def chain_insert(sequence: int, previous_hash: str, digest: str, data: dict[str, Any]) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                (sequence, previous_hash, digest, json.dumps(data, sort_keys=True)))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def chain_rows() -> AsyncIterator[dict[str, Any]]:
    """Stream the whole chain in order without loading it into memory."""
    async with get_db_async() as db:
        cursor = await db.execute(
            "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence")
        async for row in cursor:
            yield dict(row)


async def chain_count() -> int:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT COUNT(*) FROM audit_chain")
        row = await cursor.fetchone()
        assert row is not None
        return row[0]


# ---------------------------------------------------------------------------
# Retention (opt-in via STRIX_RETENTION_DAYS; 0 keeps everything forever)
# ---------------------------------------------------------------------------
async def prune_finished_jobs(older_than: float) -> int:
    """Delete terminal-state jobs finished before the cutoff epoch."""
    async with get_db_async() as db:
        cursor = await db.execute(
            f"""DELETE FROM jobs
                WHERE state IN ({', '.join(repr(s) for s in TERMINAL_STATES)})
                  AND finished_at IS NOT NULL AND finished_at < ?""",
            (older_than,))
        return cursor.rowcount


async def prune_audit_log(older_than: float) -> int:
    """Delete plain audit-log entries older than the cutoff epoch."""
    async with get_db_async() as db:
        cursor = await db.execute("DELETE FROM audit_log WHERE ts < ?", (older_than,))
        return cursor.rowcount


async def _connect_direct() -> aiosqlite.Connection:
    """Open a direct database connection (not from pool) for VACUUM operations.

    VACUUM requires exclusive access to the database, which is impossible when
    the connection pool has other connections open. This mirrors the sync
    store.connect() behavior.
    """
    from strix.config import Settings
    from strix.core.store_async import _restrict_permissions, current_path, migrate_async
    settings = Settings.from_env()
    db_path = current_path() or settings.db_path
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA busy_timeout = 10000")
    await db.execute("PRAGMA foreign_keys = ON")
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA synchronous = NORMAL")
    await migrate_async(db)
    _restrict_permissions(db_path)
    return db


async def vacuum() -> None:
    """Reclaim file space after bulk retention deletes (WAL is checkpointed).

    Uses a direct connection (not from pool) because VACUUM requires
    exclusive access to the database.
    """
    db = await _connect_direct()
    try:
        await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await db.execute("VACUUM")
    finally:
        await db.close()


async def _close_pool() -> None:
    """Close all connections in the database pool for the current event loop."""
    from strix.api.dependencies import close_db_pool
    await close_db_pool()


async def prune_and_vacuum(older_than: float) -> dict[str, int]:
    """Prune finished jobs and audit log, then vacuum.

    Uses a direct connection (not from pool) because VACUUM requires
    exclusive access to the database. Closes the pool first since VACUUM
    requires no other connections to the database file.
    """
    # Close the pool so VACUUM can get exclusive access
    await _close_pool()

    db = await _connect_direct()
    try:
        cursor = await db.execute(
            f"""DELETE FROM jobs
                WHERE state IN ({', '.join(repr(s) for s in TERMINAL_STATES)})
                  AND finished_at IS NOT NULL AND finished_at < ?""",
            (older_than,))
        jobs = cursor.rowcount
        cursor = await db.execute("DELETE FROM audit_log WHERE ts < ?", (older_than,))
        audit_entries = cursor.rowcount
        # In autocommit mode (isolation_level=None), the DELETEs are already committed.
        # VACUUM requires the transaction to be committed and no other connections open.

        if jobs or audit_entries:
            await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await db.execute("VACUUM")
    finally:
        await db.close()
    return {"jobs": jobs, "audit_entries": audit_entries}


# ---------------------------------------------------------------------------
# Monitor config
# ---------------------------------------------------------------------------
async def save_monitor_config(targets: list[str], interval_seconds: int) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO settings (key, value) VALUES ('monitor_targets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps(targets),))
            await db.execute(
                "INSERT INTO settings (key, value) VALUES ('monitor_interval', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(interval_seconds),))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def load_monitor_config() -> tuple[list[str], int | None]:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT value FROM settings WHERE key = 'monitor_targets'")
        row = await cursor.fetchone()
        targets = json.loads(row["value"]) if row else []
        cursor = await db.execute("SELECT value FROM settings WHERE key = 'monitor_interval'")
        row = await cursor.fetchone()
        interval = int(row["value"]) if row else None
        return targets, interval


async def save_monitor_baseline(target: str, fingerprints: list[str] | set[str]) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO monitor_baseline (target, fingerprints, updated_at) "
                "VALUES (?, ?, ?) ON CONFLICT(target) DO UPDATE SET "
                "fingerprints = excluded.fingerprints, updated_at = excluded.updated_at",
                (target, json.dumps(list(fingerprints)), time.time()))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def load_monitor_baseline() -> dict[str, set[str]]:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT target, fingerprints FROM monitor_baseline")
        rows = await cursor.fetchall()
        return {row["target"]: set(json.loads(row["fingerprints"])) for row in rows}


async def delete_monitor_baseline(target: str) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute("DELETE FROM monitor_baseline WHERE target = ?", (target,))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


# ---------------------------------------------------------------------------
# Engagement policies
# ---------------------------------------------------------------------------
async def save_policy(policy: dict[str, Any]) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                """INSERT INTO engagement_policies (policy_id, tenant_id, program, authorized_by,
                    authorization_ref, include, exclude, authorized_networks, allowed_ports,
                    allow_broad_networks, status, version, created_at, updated_at,
                    effective_at, expires_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(policy_id) DO UPDATE SET
                    -- tenant_id is IMMUTABLE: never update it on conflict.
                    -- This prevents a policy from being moved between tenants.
                    program = excluded.program,
                    authorized_by = excluded.authorized_by, authorization_ref = excluded.authorization_ref,
                    include = excluded.include, exclude = excluded.exclude,
                    authorized_networks = excluded.authorized_networks,
                    allowed_ports = excluded.allowed_ports,
                    allow_broad_networks = excluded.allow_broad_networks, status = excluded.status,
                    version = excluded.version, created_at = excluded.created_at,
                    updated_at = excluded.updated_at, effective_at = excluded.effective_at,
                    expires_at = excluded.expires_at, created_by = excluded.created_by""",
                (policy["policy_id"], policy["tenant_id"], policy["program"],
                 policy["authorized_by"], policy["authorization_ref"],
                 json.dumps(policy["include"]), json.dumps(policy["exclude"]),
                 json.dumps(policy["authorized_networks"]), json.dumps(policy["allowed_ports"]),
                 int(policy["allow_broad_networks"]), policy["status"], policy["version"],
                 policy["created_at"], policy["updated_at"],
                 policy.get("effective_at"), policy.get("expires_at"),
                 policy.get("created_by", "")))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def load_policies() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT * FROM engagement_policies")
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            row_dict = dict(row)
            # Parse JSON fields
            for field in ("include", "exclude", "authorized_networks", "allowed_ports"):
                if row_dict.get(field):
                    row_dict[field] = json.loads(row_dict[field])
            result.append(row_dict)
        return result


# ---------------------------------------------------------------------------
# Webhook sinks
# ---------------------------------------------------------------------------
async def save_webhook_sink(name: str, url: str) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute(
                "INSERT INTO webhook_sinks (name, url, added_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET url = excluded.url",
                (name, url, time.time()))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def delete_webhook_sink(name: str) -> None:
    async with get_db_async() as db:
        await db.execute("BEGIN IMMEDIATE")
        try:
            await db.execute("DELETE FROM webhook_sinks WHERE name = ?", (name,))
            await db.execute("COMMIT")
        except aiosqlite.Error:
            await db.execute("ROLLBACK")
            raise


async def load_webhook_sinks() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        cursor = await db.execute("SELECT * FROM webhook_sinks")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
