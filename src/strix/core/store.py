"""Unified SQLite/PostgreSQL persistence for assessment jobs and findings.

This module provides both async (primary) and sync (wrapper) APIs.
Async functions are the canonical implementation; sync wrappers delegate to them.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import json
import logging
import os
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

try:
    import asyncpg
except Exception:  # pragma: no cover - asyncpg is optional (PostgreSQL)
    asyncpg = None

from strix.core.findings import (
    Finding,
    allowed_transitions,
    dedupe,
    redact,
    validate_transition,
)
from strix.core.redaction import sanitize_target

log = logging.getLogger(__name__)

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        tenant      TEXT NOT NULL,
        project     TEXT NOT NULL DEFAULT 'default',
        target      TEXT NOT NULL,
        profile     TEXT NOT NULL,
        actor       TEXT NOT NULL,
        policy      TEXT NOT NULL,
        state       TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        error       TEXT NOT NULL DEFAULT '',
        started_at  REAL,
        finished_at REAL,
        coverage    TEXT NOT NULL,
        created_at  REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS jobs_by_tenant ON jobs (tenant, created_at DESC);
    CREATE TABLE IF NOT EXISTS findings (
        job_id           TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
        tenant           TEXT NOT NULL,
        fingerprint      TEXT NOT NULL,
        asset            TEXT NOT NULL,
        category         TEXT NOT NULL,
        title            TEXT NOT NULL,
        severity         TEXT NOT NULL,
        confidence       TEXT NOT NULL,
        verification     TEXT NOT NULL,
        status           TEXT NOT NULL,
        detector         TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        location         TEXT NOT NULL DEFAULT '',
        evidence         TEXT NOT NULL,
        description      TEXT NOT NULL DEFAULT '',
        remediation      TEXT NOT NULL DEFAULT '',
        cwe              TEXT NOT NULL DEFAULT '',
        cvss_score       TEXT NOT NULL DEFAULT '0.0',
        business_impact  TEXT NOT NULL DEFAULT 'low',
        asset_criticality TEXT NOT NULL DEFAULT 'medium',
        risk_rating      TEXT NOT NULL DEFAULT 'low',
        exploit_available INTEGER NOT NULL DEFAULT 0,
        user_impact      TEXT NOT NULL DEFAULT 'none',
        compliance_refs  TEXT NOT NULL DEFAULT '[]',
        remediation_status TEXT NOT NULL DEFAULT 'pending',
        discovered_date  TEXT NOT NULL DEFAULT '1970-01-01',
        reported_date    TEXT NOT NULL DEFAULT '1970-01-01',
        resolved_date    TEXT NOT NULL DEFAULT '1970-01-01',
        sources          TEXT NOT NULL,
        PRIMARY KEY (job_id, fingerprint)
    );
    CREATE INDEX IF NOT EXISTS findings_by_tenant ON findings (tenant, category);
    """,
    ),
    (
        2,
        """
    CREATE TABLE IF NOT EXISTS api_keys (
        tenant_id  TEXT PRIMARY KEY,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      INTEGER NOT NULL,
        active     INTEGER NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT,
        event  TEXT,
        ts     REAL NOT NULL,
        data   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_log_by_tenant ON audit_log (tenant, id);
    CREATE TABLE IF NOT EXISTS audit_chain (
        sequence      INTEGER PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    );
    """,
    ),
    (
        3,
        """
    CREATE TABLE IF NOT EXISTS monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    ),
    (
        4,
        """
    ALTER TABLE api_keys ADD COLUMN expires_at REAL;
    ALTER TABLE api_keys ADD COLUMN last_used REAL;
    ALTER TABLE api_keys ADD COLUMN rotated_at REAL;
    """,
    ),
    (
        5,
        """
    CREATE TABLE IF NOT EXISTS engagement_policies (
        policy_id      TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        project        TEXT NOT NULL DEFAULT 'default',
        program        TEXT NOT NULL,
        authorized_by  TEXT NOT NULL,
        authorization_ref TEXT NOT NULL,
        include        TEXT NOT NULL,
        exclude        TEXT NOT NULL,
        authorized_networks TEXT NOT NULL,
        allowed_ports  TEXT NOT NULL,
        allow_broad_networks INTEGER NOT NULL DEFAULT 0,
        status         TEXT NOT NULL,
        version        INTEGER NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL,
        effective_at   REAL,
        expires_at     REAL,
        created_by     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS policies_by_tenant ON engagement_policies (tenant_id, project, status);
    CREATE TABLE IF NOT EXISTS webhook_sinks (
        name    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        added_at REAL NOT NULL
    );
    """,
    ),
    (
        6,
        """
    ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE jobs ADD COLUMN worker TEXT NOT NULL DEFAULT '';
    ALTER TABLE jobs ADD COLUMN idempotency_key TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency ON jobs (tenant, project, idempotency_key)
        WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs (state, created_at)
    """,
    ),
    (
        7,
        """
    CREATE TABLE IF NOT EXISTS monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   REAL NOT NULL
    )
    """,
    ),
    (
        8,
        """
    ALTER TABLE api_keys ADD COLUMN ai_enabled INTEGER NOT NULL DEFAULT 0;
    """,
    ),
    (
        9,
        """
    -- Add project column and unique constraint for multi-project support
    ALTER TABLE api_keys ADD COLUMN project TEXT NOT NULL DEFAULT 'default';
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project ON api_keys (tenant_id, project);
    """,
    ),
]

# PostgreSQL migrations — same schema versions, PG-native syntax.
# SERIAL = auto-increment integer; TIMESTAMPTZ = timezone-aware timestamp;
# UUID = native UUID; JSONB = binary JSON; GENERATED ALWAYS AS IDENTITY = PG 10+ identity.
MIGRATIONS_PG: list[tuple[int, str]] = [
    (
        9,
        """
    -- Mirrors the SQLite schema. IDs, JSON payloads and epoch timestamps stay
    -- TEXT/TEXT/DOUBLE PRECISION because that is what the query layer binds;
    -- PostgreSQL-native UUID/TIMESTAMPTZ/JSONB columns rejected those values.
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        tenant      TEXT NOT NULL,
        project     TEXT NOT NULL DEFAULT 'default',
        target      TEXT NOT NULL,
        profile     TEXT NOT NULL,
        actor       TEXT NOT NULL,
        policy      TEXT NOT NULL,
        state       TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        error       TEXT NOT NULL DEFAULT '',
        started_at  DOUBLE PRECISION,
        finished_at DOUBLE PRECISION,
        coverage    TEXT NOT NULL,
        created_at  DOUBLE PRECISION NOT NULL,
        attempts    INTEGER NOT NULL DEFAULT 0,
        worker      TEXT NOT NULL DEFAULT '',
        idempotency_key TEXT
    );
    CREATE INDEX IF NOT EXISTS jobs_by_tenant ON jobs (tenant, created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency
        ON jobs (tenant, project, idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs (state, created_at);

    CREATE TABLE IF NOT EXISTS findings (
        job_id           TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
        tenant           TEXT NOT NULL,
        fingerprint      TEXT NOT NULL,
        asset            TEXT NOT NULL,
        category         TEXT NOT NULL,
        title            TEXT NOT NULL,
        severity         TEXT NOT NULL,
        confidence       TEXT NOT NULL,
        verification     TEXT NOT NULL,
        status           TEXT NOT NULL,
        detector         TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        location         TEXT NOT NULL DEFAULT '',
        evidence         TEXT NOT NULL,
        description      TEXT NOT NULL DEFAULT '',
        remediation      TEXT NOT NULL DEFAULT '',
        cwe              TEXT NOT NULL DEFAULT '',
        cvss_score       TEXT NOT NULL DEFAULT '0.0',
        business_impact  TEXT NOT NULL DEFAULT 'low',
        asset_criticality TEXT NOT NULL DEFAULT 'medium',
        risk_rating      TEXT NOT NULL DEFAULT 'low',
        exploit_available BOOLEAN NOT NULL DEFAULT false,
        user_impact      TEXT NOT NULL DEFAULT 'none',
        compliance_refs  TEXT NOT NULL DEFAULT '[]',
        remediation_status TEXT NOT NULL DEFAULT 'pending',
        discovered_date  TEXT NOT NULL DEFAULT '1970-01-01',
        reported_date    TEXT NOT NULL DEFAULT '1970-01-01',
        resolved_date    TEXT NOT NULL DEFAULT '1970-01-01',
        sources          TEXT NOT NULL,
        PRIMARY KEY (job_id, fingerprint)
    );
    CREATE INDEX IF NOT EXISTS findings_by_tenant ON findings (tenant, category);

    CREATE TABLE IF NOT EXISTS api_keys (
        tenant_id  TEXT NOT NULL,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      BOOLEAN NOT NULL,
        active     BOOLEAN NOT NULL,
        project    TEXT NOT NULL DEFAULT 'default',
        created_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION,
        last_used  DOUBLE PRECISION,
        rotated_at DOUBLE PRECISION,
        ai_enabled BOOLEAN NOT NULL DEFAULT false,
        PRIMARY KEY (tenant_id, project)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id     BIGSERIAL PRIMARY KEY,
        tenant TEXT,
        event  TEXT,
        ts     DOUBLE PRECISION NOT NULL,
        data   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_log_by_tenant ON audit_log (tenant, id);

    CREATE TABLE IF NOT EXISTS audit_chain (
        sequence      BIGINT PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS engagement_policies (
        policy_id      TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        project        TEXT NOT NULL DEFAULT 'default',
        program        TEXT NOT NULL,
        authorized_by  TEXT NOT NULL,
        authorization_ref TEXT NOT NULL,
        include        TEXT NOT NULL,
        exclude        TEXT NOT NULL,
        authorized_networks TEXT NOT NULL,
        allowed_ports  TEXT NOT NULL,
        allow_broad_networks BOOLEAN NOT NULL DEFAULT false,
        status         TEXT NOT NULL,
        version        INTEGER NOT NULL,
        created_at     DOUBLE PRECISION NOT NULL,
        updated_at     DOUBLE PRECISION NOT NULL,
        effective_at   DOUBLE PRECISION,
        expires_at     DOUBLE PRECISION,
        created_by     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS policies_by_tenant
        ON engagement_policies (tenant_id, project, status);

    CREATE TABLE IF NOT EXISTS webhook_sinks (
        name     TEXT PRIMARY KEY,
        url      TEXT NOT NULL,
        added_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   DOUBLE PRECISION NOT NULL
    );
    """,
    ),
]


TERMINAL_STATES = ("completed", "partial", "failed", "cancelled")


class JobConflict(RuntimeError):
    """An idempotency key was already used by another job."""


_path: str = "strix.db"
_db_type: str | None = None
_pool: Any = None


def configure(path: str | Path) -> None:
    """Set the database file path or DSN. Resets the connection pool."""
    global _path, _db_type, _pool
    # Release connections from the previous database. Without this the
    # aiosqlite worker threads (non-daemon) outlive the reconfigure: they leak
    # one thread per test/restart and keep the interpreter from exiting.
    if _pool is not None and hasattr(_pool, "discard_sync"):
        _pool.discard_sync()
    _path = str(path)
    _db_type = None  # Reset type detection on reconfigure
    _pool = None  # Pool will be recreated on next get_db_async()


def current_path() -> str:
    return _path


def _detect_db_type(path_or_dsn: str) -> str:
    """Detect database type from path or DSN."""
    if path_or_dsn.startswith(("postgresql://", "postgres://")):
        return "postgresql"
    return "sqlite"


def _get_db_type() -> str:
    """Get cached database type, detecting on first call."""
    global _db_type
    if _db_type is None:
        _db_type = _detect_db_type(_path)
    return _db_type


_migrated: set[str] = set()


def _restrict_permissions(path: str) -> None:
    """The database holds key hashes, findings and the audit trail: owner only."""
    if path.startswith(("postgresql://", "postgres://")):
        return  # No file permissions for PostgreSQL
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):  # not every sidecar exists yet
            os.chmod(path + suffix, 0o600)


async def _close_connections(connections: list[Any]) -> None:
    for conn in connections:
        with contextlib.suppress(Exception):
            await conn.close()


async def _create_pool() -> Any:
    """Create a connection pool for the configured database."""
    global _pool
    db_type = _get_db_type()

    if db_type == "postgresql":
        if asyncpg is None:
            raise RuntimeError("asyncpg is required for PostgreSQL support")
        pool = await asyncpg.create_pool(_path, min_size=1, max_size=10)
        async with pool.acquire() as conn:
            await _migrate_pg(conn, _path)
        _restrict_permissions(_path)
        _pool = pool
        return _pool

    # SQLite - use aiosqlite pool
    # aiosqlite doesn't have a built-in pool, so we simulate one with a deque
    # of connections. Bookkeeping uses a threading lock, not an asyncio.Lock:
    # the pool is process-wide and is leased by several event loops (uvicorn,
    # worker threads, the DB bridge), and an asyncio.Lock bound to one loop
    # deadlocks every other loop. aiosqlite binds each query to the loop that
    # issued it, so a connection may be leased by any loop.
    from collections import deque

    class SimplePool:
        def __init__(self, path: str, max_size: int = 10):
            self.path = path
            self.max_size = max_size
            self._pool: deque[aiosqlite.Connection] = deque()
            self._in_use = 0
            self._lock = threading.Lock()

        async def _connect(self) -> aiosqlite.Connection:
            conn = await aiosqlite.connect(self.path)
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA busy_timeout = 10000")
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute("PRAGMA journal_mode = WAL")
            await conn.execute("PRAGMA synchronous = NORMAL")
            return conn

        async def get(self) -> aiosqlite.Connection:
            while True:
                create = False
                with self._lock:
                    if self._pool:
                        self._in_use += 1
                        return self._pool.popleft()
                    if self._in_use < self.max_size:
                        self._in_use += 1
                        create = True
                if create:
                    try:
                        return await self._connect()
                    except Exception:
                        with self._lock:
                            self._in_use = max(0, self._in_use - 1)
                        raise
                # ponytail: polling wait instead of a cross-loop condition;
                # fine for the default pool of 10. Upgrade to a waiter queue
                # if pool contention ever shows up in profiles.
                await asyncio.sleep(0.01)

        async def put(self, conn: aiosqlite.Connection) -> None:
            with self._lock:
                self._in_use = max(0, self._in_use - 1)
                self._pool.append(conn)

        async def close(self) -> None:
            with self._lock:
                conns = list(self._pool)
                self._pool.clear()
                self._in_use = 0
            await _close_connections(conns)

        def discard_sync(self) -> None:
            """Close idle connections without requiring a live event loop."""
            with self._lock:
                conns = list(self._pool)
                self._pool.clear()
                self._in_use = 0
            if not conns:
                return
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                asyncio.run(_close_connections(conns))
            else:
                # Cannot await from a running loop; stop the worker threads
                # without blocking. They are non-daemon, so this matters for
                # interpreter exit.
                for conn in conns:
                    with contextlib.suppress(Exception):
                        conn.stop()

    pool = SimplePool(_path)
    if _path not in _migrated:
        conn = await pool.get()
        try:
            await migrate_async(conn)
        except Exception:
            await pool.close()
            raise
        finally:
            await pool.put(conn)
        _migrated.add(_path)
    _restrict_permissions(_path)
    _pool = pool
    return _pool


def _discard_pool_at_exit() -> None:
    global _pool
    pool = _pool
    if pool is not None and hasattr(pool, "discard_sync"):
        pool.discard_sync()


atexit.register(_discard_pool_at_exit)


async def get_db_pool() -> Any:
    """Get or create the connection pool."""
    global _pool
    if _pool is None:
        _pool = await _create_pool()
    return _pool


async def close_db_pool() -> None:
    """Close the connection pool."""
    global _pool
    if _pool is not None:
        if hasattr(_pool, "close"):
            await _pool.close()
        _pool = None


async def reset_db_pool() -> None:
    """Reset the connection pool (used after configure)."""
    await close_db_pool()
    await get_db_pool()


def _is_asyncpg(conn: Any) -> bool:
    """Check if connection is asyncpg (PostgreSQL)."""
    return asyncpg is not None and isinstance(conn, asyncpg.Connection)


def _is_aiosqlite(conn: Any) -> bool:
    """Check if connection is aiosqlite (SQLite)."""
    return isinstance(conn, aiosqlite.Connection)


def _adapt_placeholders(sql: str, is_pg: bool) -> str:
    """Convert SQLite ? placeholders to PostgreSQL $1, $2, ... if needed."""
    if not is_pg:
        return sql
    parts = sql.split("?")
    if len(parts) == 1:
        return sql
    result = []
    for i, part in enumerate(parts):
        result.append(part)
        if i < len(parts) - 1:
            result.append(f"${i + 1}")
    return "".join(result)


async def _execute(conn: Any, sql: str, *params: Any) -> Any:
    """Execute a SQL statement (works with both aiosqlite and asyncpg)."""
    is_pg = _is_asyncpg(conn)
    if is_pg and sql.lstrip().upper().startswith("BEGIN IMMEDIATE"):
        # SQLite's write-lock hint is not PostgreSQL syntax. asyncpg exposes the
        # same transaction semantics through plain BEGIN/COMMIT statements.
        sql = "BEGIN"
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        status = await conn.execute(sql, *params)
        last = status.rsplit(" ", 1)[-1]
        from types import SimpleNamespace

        return SimpleNamespace(rowcount=int(last) if last.isdigit() else 0)
    return await conn.execute(sql, params)


async def _fetchone(conn: Any, sql: str, *params: Any) -> Any:
    """Fetch one row (works with both aiosqlite and asyncpg)."""
    is_pg = _is_asyncpg(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        return await conn.fetchrow(sql, *params)
    cursor = await conn.execute(sql, params)
    return await cursor.fetchone()


async def _fetchall(conn: Any, sql: str, *params: Any) -> list[Any]:
    """Fetch all rows (works with both aiosqlite and asyncpg)."""
    is_pg = _is_asyncpg(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        return await conn.fetch(sql, *params)
    cursor = await conn.execute(sql, params)
    return await cursor.fetchall()


async def _executemany(conn: Any, sql: str, params_list: list[tuple]) -> None:
    """Execute many statements (works with both aiosqlite and asyncpg)."""
    is_pg = _is_asyncpg(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        await conn.executemany(sql, params_list)
    else:
        await conn.executemany(sql, params_list)


@asynccontextmanager
async def get_db_async() -> AsyncIterator[Any]:
    """Get a database connection from the pool (initialized on first use)."""
    pool = await get_db_pool()
    if _get_db_type() == "postgresql":
        # asyncpg pools lease with acquire()/release(), not get()/put().
        async with pool.acquire() as db:
            yield db
        return
    db = await pool.get()
    try:
        yield db
    finally:
        await pool.put(db)


async def migrate_async(connection: aiosqlite.Connection, path: str | None = None) -> int:
    """Apply pending SQLite migrations. Returns the resulting schema version."""
    cursor = await connection.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    version = int(row[0]) if row else 0
    for target, script in MIGRATIONS:
        if target <= version:
            continue
        await connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in script.split(";"):
                stmt = "\n".join(
                    line
                    for line in statement.splitlines()
                    if not line.strip().startswith("--")
                ).strip()
                if stmt:
                    await connection.execute(stmt)
            await connection.execute(f"PRAGMA user_version = {int(target)}")
            await connection.commit()
        except Exception:
            await connection.rollback()
            raise
        version = target
    return version


async def _migrate_pg(conn: asyncpg.Connection, dsn: str) -> None:
    """Apply PostgreSQL migrations. Bootstrap settings first: every step records
    its version there, but the schema migrations only create it at step 3."""
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    row = await conn.fetchrow(
        "SELECT COALESCE(value::int, 0) FROM settings WHERE key = 'schema_version'"
    )
    version = row[0] if row else 0
    for target, script in MIGRATIONS_PG:
        if target <= version:
            continue
        async with conn.transaction():
            try:
                for statement in script.split(";"):
                    # A comment-only chunk has no status message, which asyncpg
                    # cannot decode; drop leading SQL comments first.
                    stmt = "\n".join(
                        line
                        for line in statement.splitlines()
                        if not line.strip().startswith("--")
                    ).strip()
                    if not stmt:
                        continue
                    await conn.execute(stmt)
                await conn.execute(
                    "INSERT INTO settings (key, value) VALUES ('schema_version', $1) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    str(target),  # settings.value is TEXT; asyncpg is strict
                )
            except Exception:
                raise
            version = target


async def schema_version() -> int:
    async with get_db_async() as db:
        if _is_asyncpg(db):
            row = await db.fetchrow(
                "SELECT COALESCE(value::int, 0) FROM settings WHERE key = 'schema_version'"
            )
            return row[0] if row else 0
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
        rows.append(
            (
                job.id,
                tenant,
                data["fingerprint"],
                data["asset"],
                data["category"],
                data["title"],
                data["severity"],
                data["confidence"],
                data["verification"],
                data["status"],
                data["detector"],
                data["detector_version"],
                data["location"],
                data["evidence"],
                data["description"],
                data["remediation"],
                data["cwe"],
                json.dumps(data["sources"]),
            )
        )

    stored_target = sanitize_target(job.target)
    stored_error = redact(job.error)
    state, verdict = job.state.value, job.verdict
    finished_at = job.finished_at

    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            existing = await _fetchone(
                db,
                "SELECT state, verdict, error, finished_at FROM jobs WHERE id = ?",
                job.id,
            )
            if (
                existing is not None
                and existing["state"] in TERMINAL_STATES
                and state not in TERMINAL_STATES
            ):
                state, verdict = existing["state"], existing["verdict"]
                stored_error, finished_at = existing["error"], existing["finished_at"]
            try:
                await _execute(
                    db,
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
                    job.id,
                    tenant,
                    stored_target,
                    job.profile,
                    job.actor,
                    json.dumps(job.policy),
                    state,
                    verdict,
                    stored_error,
                    job.started_at,
                    finished_at,
                    json.dumps(job.coverage()),
                    time.time(),
                    int(getattr(job, "attempts", 0) or 0),
                    str(getattr(job, "worker_id", "") or ""),
                    getattr(job, "idempotency_key", None) or None,
                )
            except (aiosqlite.IntegrityError, Exception) as exc:
                if "unique constraint" in str(exc).lower() or "duplicate key" in str(exc).lower():
                    raise JobConflict(
                        f"idempotency key already used by another job: {exc}"
                    ) from None
                raise
            await _execute(db, "DELETE FROM findings WHERE job_id = ?", job.id)
            await _executemany(
                db,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


def _job_row_to_dict(
    row: Any, findings: list[dict[str, Any]]
) -> dict[str, Any]:
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
        "duration_ms": (
            round((finished - started) * 1000, 1) if started and finished else None
        ),
        "coverage": json.loads(row["coverage"]),
        "findings": findings,
        "error": row["error"],
        "tenant": row["tenant"],
        "attempts": row["attempts"],
        "worker": row["worker"],
        "idempotency_key": row["idempotency_key"],
    }


def _json_list(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, (list, tuple)) else []


def _finding_row_to_dict(row: Any) -> dict[str, Any]:
    status = row["status"]
    return {
        "fingerprint": row["fingerprint"],
        "asset": row["asset"],
        "category": row["category"],
        "title": row["title"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "verification": row["verification"],
        "status": status,
        "allowed_transitions": list(allowed_transitions(status)),
        "detector": row["detector"],
        "detector_version": row["detector_version"],
        "location": row["location"],
        "evidence": row["evidence"],
        "description": row["description"],
        "remediation": row["remediation"],
        "cwe": row["cwe"],
        "cvss_score": row["cvss_score"],
        "business_impact": row["business_impact"],
        "asset_criticality": row["asset_criticality"],
        "risk_rating": row["risk_rating"],
        "exploit_available": bool(row["exploit_available"]),
        "user_impact": row["user_impact"],
        "compliance_refs": _json_list(row["compliance_refs"]),
        "remediation_status": row["remediation_status"],
        "discovered_date": row["discovered_date"],
        "reported_date": row["reported_date"],
        "resolved_date": row["resolved_date"],
        "sources": _json_list(row["sources"]),
    }


async def get_job(job_id: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Load a job. ``tenant=None`` is reserved for administrators."""
    async with get_db_async() as db:
        if tenant is None:
            row = await _fetchone(db, "SELECT * FROM jobs WHERE id = ?", job_id)
        else:
            row = await _fetchone(
                db, "SELECT * FROM jobs WHERE id = ? AND tenant = ?", job_id, tenant
            )
        if row is None:
            return None
        findings = await _fetchall(
            db, "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", job_id
        )
        return _job_row_to_dict(row, [_finding_row_to_dict(item) for item in findings])


async def latest_finished_job(
    target: str, *, tenant: str | None = None
) -> dict[str, Any] | None:
    """Most recent job for ``target`` that produced a result (with its findings)."""
    target = sanitize_target(target)
    async with get_db_async() as db:
        if tenant is None:
            row = await _fetchone(
                db,
                "SELECT id FROM jobs WHERE target = ? AND state IN ('completed', 'partial') "
                "ORDER BY created_at DESC LIMIT 1",
                target,
            )
        else:
            row = await _fetchone(
                db,
                "SELECT id FROM jobs WHERE target = ? AND tenant = ? "
                "AND state IN ('completed', 'partial') ORDER BY created_at DESC LIMIT 1",
                target,
                tenant,
            )
    return await get_job(row["id"], tenant=tenant) if row else None


async def list_jobs(
    *, tenant: str | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Recent job summaries (no findings payload)."""
    async with get_db_async() as db:
        if tenant is None:
            rows = await _fetchall(
                db, "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", limit
            )
        else:
            rows = await _fetchall(
                db, "SELECT * FROM jobs WHERE tenant = ? ORDER BY created_at DESC LIMIT ?", tenant, limit
            )
        return [_job_row_to_dict(row, []) for row in rows]


async def fail_interrupted(*, created_before: float | None = None) -> int:
    """Mark jobs a previous process left queued/running as failed."""
    for attempt in range(3):
        try:
            async with get_db_async() as db:
                await _execute(db, "BEGIN IMMEDIATE")
                try:
                    if created_before is not None:
                        cursor = await _execute(
                            db,
                            """UPDATE jobs
                               SET state = 'failed',
                                   verdict = 'failed -- no usable coverage',
                                   error = 'interrupted by process restart',
                                   finished_at = ?
                               WHERE state IN ('queued', 'running') AND created_at < ?""",
                            time.time(),
                            created_before,
                        )
                    else:
                        cursor = await _execute(
                            db,
                            """UPDATE jobs
                               SET state = 'failed',
                                   verdict = 'failed -- no usable coverage',
                                   error = 'interrupted by process restart',
                                   finished_at = ?
                               WHERE state IN ('queued', 'running')""",
                            time.time(),
                        )
                    await _execute(db, "COMMIT")
                    return cursor.rowcount
                except (aiosqlite.Error, Exception):
                    await _execute(db, "ROLLBACK")
                    raise
        except aiosqlite.OperationalError as e:
            if "database is locked" in str(e) and attempt < 2:
                await asyncio.sleep(0.1 * (attempt + 1))
                continue
            raise
    return 0


async def mark_running(
    job_id: str, *, tenant: str, worker: str, now: float | None = None
) -> bool:
    """Claim a queued job for one worker. False when another claim won."""
    stamp = time.time() if now is None else now
    async with get_db_async() as db:
        cursor = await _execute(
            db,
            """UPDATE jobs
               SET state = 'running', worker = ?,
                   started_at = COALESCE(started_at, ?),
                   attempts = attempts + 1
               WHERE id = ? AND tenant = ? AND state = 'queued'""",
            worker,
            stamp,
            job_id,
            tenant,
        )
        await _execute(db, "COMMIT")
        return cursor.rowcount == 1


async def claim_job(
    job_id: str, *, tenant: str, worker: str, now: float | None = None
) -> bool:
    """Single-execution claim: True when this caller may run the job."""
    if await mark_running(job_id, tenant=tenant, worker=worker, now=now):
        return True
    async with get_db_async() as db:
        row = await _fetchone(db, "SELECT 1 FROM jobs WHERE id = ? AND tenant = ?", job_id, tenant)
        return row is None


async def find_job_id_by_idempotency(
    idempotency_key: str, *, tenant: str
) -> str | None:
    """The job that already owns ``idempotency_key`` for this tenant, if any."""
    async with get_db_async() as db:
        row = await _fetchone(
            db, "SELECT id FROM jobs WHERE tenant = ? AND idempotency_key = ?", tenant, idempotency_key
        )
        return row["id"] if row else None


async def count_jobs(*, tenant: str | None = None) -> int:
    """Total job count for a tenant (or all tenants if None)."""
    async with get_db_async() as db:
        if tenant is None:
            row = await _fetchone(db, "SELECT COUNT(*) FROM jobs")
        else:
            row = await _fetchone(db, "SELECT COUNT(*) FROM jobs WHERE tenant = ?", tenant)
        return row[0] if row else 0


async def count_findings(*, tenant: str) -> int:
    """How many findings a tenant owns — scoped in SQL."""
    async with get_db_async() as db:
        row = await _fetchone(db, "SELECT COUNT(*) FROM findings WHERE tenant = ?", tenant)
        if row is None:
            raise RuntimeError("COUNT(*) query returned no row")
        return int(row[0])


async def jobs_by_state(*, tenant: str | None = None) -> dict[str, int]:
    """Jobs grouped by state — aggregate SQL, optionally scoped to a tenant."""
    async with get_db_async() as db:
        if tenant is None:
            rows = await _fetchall(db, "SELECT state, COUNT(*) AS n FROM jobs GROUP BY state")
        else:
            rows = await _fetchall(
                db, "SELECT state, COUNT(*) AS n FROM jobs WHERE tenant = ? GROUP BY state", tenant
            )
    return {str(row["state"]): int(row["n"]) for row in rows}


async def findings_by_severity(*, tenant: str | None = None) -> dict[str, int]:
    """Findings grouped by severity — aggregate SQL, optionally scoped to a tenant."""
    async with get_db_async() as db:
        if tenant is None:
            rows = await _fetchall(db, "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        else:
            rows = await _fetchall(
                db, "SELECT severity, COUNT(*) AS n FROM findings WHERE tenant = ? GROUP BY severity", tenant
            )
    return {str(row["severity"]): int(row["n"]) for row in rows}


async def get_findings(job_id: str, *, tenant: str | None = None) -> list[Finding]:
    """Rehydrate findings for report generation (SARIF)."""
    async with get_db_async() as db:
        if tenant is None:
            rows = await _fetchall(db, "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", job_id)
        else:
            rows = await _fetchall(
                db, "SELECT * FROM findings WHERE job_id = ? AND tenant = ? ORDER BY rowid", job_id, tenant
            )

    findings = []
    for row in rows:
        data = _finding_row_to_dict(row)
        findings.append(
            Finding(
                asset=data["asset"],
                category=data["category"],
                title=data["title"],
                severity=data["severity"],
                confidence=data["confidence"],
                detector=data["detector"],
                detector_version=data["detector_version"],
                evidence=redact(data["evidence"]),
                location=data["location"],
                description=data["description"],
                remediation=data["remediation"],
                cwe=data["cwe"],
                verification=data["verification"],
                status=data["status"],
                cvss_score=data["cvss_score"],
                business_impact=data["business_impact"],
                asset_criticality=data["asset_criticality"],
                risk_rating=data["risk_rating"],
                exploit_available=data["exploit_available"],
                user_impact=data["user_impact"],
                compliance_refs=tuple(data["compliance_refs"]),
                remediation_status=data["remediation_status"],
                discovered_date=data["discovered_date"],
                reported_date=data["reported_date"],
                resolved_date=data["resolved_date"],
                sources=tuple(data["sources"]),
            )
        )
    return findings


_REMEDIATION_BY_STATUS = {
    "new": "pending",
    "triaged": "pending",
    "in_progress": "in_progress",
    "fix_verified": "fix_verified",
    "closed": "closed",
    "reopened": "in_progress",
    "deferred": "pending",
}


async def update_finding_status(
    job_id: str,
    fingerprint: str,
    *,
    tenant: str | None,
    to_status: str,
) -> dict[str, Any] | None:
    """Move one finding through its lifecycle, enforcing the transition table.

    Returns the updated finding, or None when the job/finding is not visible to
    this tenant. Raises ValueError for an invalid transition.
    """
    from datetime import UTC, datetime

    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            where = "job_id = ? AND fingerprint = ?"
            params: list[Any] = [job_id, fingerprint]
            if tenant is not None:
                where += " AND tenant = ?"
                params.append(tenant)
            row = await _fetchone(db, f"SELECT * FROM findings WHERE {where}", *params)
            if row is None:
                await _execute(db, "ROLLBACK")
                return None

            from_status = row["status"]
            validate_transition(from_status, to_status)
            resolved_date = (
                row["resolved_date"]
                if to_status != "closed"
                else datetime.now(UTC).date().isoformat()
            )
            if to_status == "reopened":
                resolved_date = ""
            await _execute(
                db,
                "UPDATE findings SET status = ?, remediation_status = ?, "
                "resolved_date = ? WHERE " + where,
                to_status,
                _REMEDIATION_BY_STATUS[to_status],
                resolved_date,
                *params,
            )
            updated = await _fetchone(
                db, f"SELECT * FROM findings WHERE {where}", *params
            )
            await _execute(db, "COMMIT")
        except Exception:
            await _execute(db, "ROLLBACK")
            raise
    return _finding_row_to_dict(updated) if updated is not None else None


# ---------------------------------------------------------------------------
# API keys (hashes only — a raw key is never stored)
# ---------------------------------------------------------------------------
async def save_api_key(
    *,
    tenant_id: str,
    key_hash: str,
    tier: str,
    admin: bool,
    active: bool,
    created_at: float,
    expires_at: float | None = None,
    last_used: float | None = None,
    rotated_at: float | None = None,
    ai_enabled: bool = False,
    project: str = "default",
) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, project, created_at, "
                "expires_at, last_used, rotated_at, ai_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, project) DO UPDATE SET "
                "key_hash = excluded.key_hash, tier = excluded.tier, admin = excluded.admin, "
                "active = excluded.active, created_at = excluded.created_at, "
                "expires_at = excluded.expires_at, last_used = excluded.last_used, "
                "rotated_at = excluded.rotated_at, ai_enabled = excluded.ai_enabled",
                tenant_id,
                key_hash,
                tier,
                bool(admin),
                bool(active),
                project,
                created_at,
                expires_at,
                last_used,
                rotated_at,
                bool(ai_enabled),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def load_api_keys() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        rows = await _fetchall(db, "SELECT * FROM api_keys")
        return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Audit trail and hash chain
# ---------------------------------------------------------------------------
async def append_audit(entry: dict[str, Any]) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
                entry.get("tenant"),
                entry.get("event"),
                entry.get("timestamp", time.time()),
                json.dumps(entry, sort_keys=True),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def recent_audit(limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` entries, returned oldest-first."""
    async with get_db_async() as db:
        rows = await _fetchall(db, "SELECT data FROM audit_log ORDER BY id DESC LIMIT ?", limit)
    return [json.loads(row["data"]) for row in reversed(list(rows))]


async def chain_tip() -> tuple[int, str] | None:
    """(sequence, hash) of the last sealed entry, or None for an empty chain."""
    async with get_db_async() as db:
        row = await _fetchone(
            db, "SELECT sequence, hash FROM audit_chain ORDER BY sequence DESC LIMIT 1"
        )
    return (row["sequence"], row["hash"]) if row else None


async def chain_insert(
    sequence: int, previous_hash: str, digest: str, data: dict[str, Any]
) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                sequence,
                previous_hash,
                digest,
                json.dumps(data, sort_keys=True),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def chain_rows() -> AsyncIterator[dict[str, Any]]:
    """Stream the whole chain in order without loading it into memory."""
    async with get_db_async() as db:
        if _is_asyncpg(db):
            async with db.transaction():
                async for row in db.cursor(
                    "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
                ):
                    yield dict(row)
        else:
            cursor = await db.execute(
                "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
            )
            async for row in cursor:
                yield dict(row)


async def chain_count() -> int:
    async with get_db_async() as db:
        row = await _fetchone(db, "SELECT COUNT(*) FROM audit_chain")
        if row is None:
            raise RuntimeError("COUNT(*) query returned no row")
        return row[0]


# ---------------------------------------------------------------------------
# Retention (opt-in via STRIX_RETENTION_DAYS; 0 keeps everything forever)
# ---------------------------------------------------------------------------
async def prune_finished_jobs(older_than: float) -> int:
    """Delete terminal-state jobs finished before the cutoff epoch."""
    async with get_db_async() as db:
        placeholders = ", ".join("?" for _ in TERMINAL_STATES)
        params = tuple(TERMINAL_STATES) + (older_than,)
        cursor = await _execute(
            db,
            f"""DELETE FROM jobs
                WHERE state IN ({placeholders})
                  AND finished_at IS NOT NULL AND finished_at < ?""",
            *params,
        )
        return cursor.rowcount


async def prune_audit_log(older_than: float) -> int:
    """Delete plain audit-log entries older than the cutoff epoch."""
    async with get_db_async() as db:
        cursor = await _execute(db, "DELETE FROM audit_log WHERE ts < ?", older_than)
        return cursor.rowcount


async def _connect_direct() -> Any:
    """Open a direct database connection (not from pool) for VACUUM operations.

    VACUUM requires exclusive access to the database, which is impossible when
    the request pool has other connections open.
    """
    from strix.config import Settings
    from strix.core.store import (
        _detect_db_type,
        _restrict_permissions,
        current_path,
        migrate_async,
    )

    settings = Settings.from_env()
    db_path = current_path() or settings.db_path
    db_type = _detect_db_type(db_path)

    if db_type == "postgresql":
        if asyncpg is None:
            raise RuntimeError("asyncpg is required for PostgreSQL support")
        conn = await asyncpg.connect(db_path)
        await _migrate_pg(conn, db_path)
        _restrict_permissions(db_path)
        return conn

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
        if _is_asyncpg(db):
            await db.execute("VACUUM")
        else:
            await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await db.execute("VACUUM")
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Monitor config
# ---------------------------------------------------------------------------
async def save_monitor_config(targets: list[str], interval_seconds: int) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO settings (key, value) VALUES ('monitor_targets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                json.dumps(targets),
            )
            await _execute(
                db,
                "INSERT INTO settings (key, value) VALUES ('monitor_interval', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                str(interval_seconds),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def load_monitor_config() -> tuple[list[str], int | None]:
    async with get_db_async() as db:
        row = await _fetchone(db, "SELECT value FROM settings WHERE key = 'monitor_targets'")
        targets = json.loads(row["value"]) if row else []
        row = await _fetchone(db, "SELECT value FROM settings WHERE key = 'monitor_interval'")
        interval = int(row["value"]) if row else None
        return targets, interval


async def save_monitor_baseline(
    target: str, fingerprints: list[str] | set[str]
) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO monitor_baseline (target, fingerprints, updated_at) "
                "VALUES (?, ?, ?) ON CONFLICT(target) DO UPDATE SET "
                "fingerprints = excluded.fingerprints, updated_at = excluded.updated_at",
                target,
                json.dumps(list(fingerprints)),
                time.time(),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def load_monitor_baseline() -> dict[str, set[str]]:
    async with get_db_async() as db:
        rows = await _fetchall(db, "SELECT target, fingerprints FROM monitor_baseline")
        return {row["target"]: set(json.loads(row["fingerprints"])) for row in rows}


async def delete_monitor_baseline(target: str) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(db, "DELETE FROM monitor_baseline WHERE target = ?", target)
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


# ---------------------------------------------------------------------------
# Engagement policies
# ---------------------------------------------------------------------------
async def save_policy(policy: dict[str, Any]) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
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
                policy["policy_id"],
                policy["tenant_id"],
                policy["program"],
                policy["authorized_by"],
                policy["authorization_ref"],
                json.dumps(policy["include"]),
                json.dumps(policy["exclude"]),
                json.dumps(policy["authorized_networks"]),
                json.dumps(policy["allowed_ports"]),
                bool(policy["allow_broad_networks"]),
                policy["status"],
                policy["version"],
                policy["created_at"],
                policy["updated_at"],
                policy.get("effective_at"),
                policy.get("expires_at"),
                policy.get("created_by", ""),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def load_policies() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        rows = await _fetchall(db, "SELECT * FROM engagement_policies")
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
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(
                db,
                "INSERT INTO webhook_sinks (name, url, added_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET url = excluded.url",
                name,
                url,
                time.time(),
            )
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def delete_webhook_sink(name: str) -> None:
    async with get_db_async() as db:
        await _execute(db, "BEGIN IMMEDIATE")
        try:
            await _execute(db, "DELETE FROM webhook_sinks WHERE name = ?", name)
            await _execute(db, "COMMIT")
        except (aiosqlite.Error, Exception):
            await _execute(db, "ROLLBACK")
            raise


async def load_webhook_sinks() -> list[dict[str, Any]]:
    async with get_db_async() as db:
        rows = await _fetchall(db, "SELECT * FROM webhook_sinks")
        return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Sync wrappers for CLI/retention use
# ---------------------------------------------------------------------------

_sync_bridge_lock = threading.Lock()


def _run_async(coro):
    """Run one store operation from sync code, on a private pool.

    A throwaway ``asyncio.run()`` loop must not leave connections in the
    process-wide pool: aiosqlite's connection thread is non-daemon, so a single
    leaked connection keeps the interpreter alive forever (a CLI that appears to
    hang and has to be force-quit). The private pool is discarded before
    returning, and the server's pool is left untouched.
    """
    global _pool
    with _sync_bridge_lock:
        saved = _pool
        _pool = None
        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(coro)
            # Called from inside a running loop: use a nested loop in a thread.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, coro)
                return future.result()
        finally:
            private = _pool
            _pool = saved
            if private is not None and hasattr(private, "discard_sync"):
                private.discard_sync()


# Direct SQLite connection for CLI and migration helpers


def reset_audit_chain_sync() -> int:
    """Clear the sealed audit chain on explicit operator request."""
    async def _reset():
        async with get_db_async() as db:
            await _execute(db, "BEGIN IMMEDIATE")
            try:
                cursor = await _execute(db, "DELETE FROM audit_chain")
                await _execute(db, "COMMIT")
                return int(cursor.rowcount)
            except Exception:
                await _execute(db, "ROLLBACK")
                raise
    return _run_async(_reset())
