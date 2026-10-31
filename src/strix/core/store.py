"""SQLite persistence for assessment jobs and findings.

A single file-backed database: jobs and their findings survive a restart, are
filtered by tenant in SQL rather than in Python, and are migrated forward by a
versioned schema. Evidence is redacted on the way in, so the database never
holds a raw credential.
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from strix.core.findings import Finding, dedupe, redact
from strix.core.redaction import sanitize_target

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
    CREATE TABLE jobs (
        id          TEXT PRIMARY KEY,
        tenant      TEXT NOT NULL,
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
    CREATE INDEX jobs_by_tenant ON jobs (tenant, created_at DESC);
    CREATE TABLE findings (
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
        sources          TEXT NOT NULL,
        PRIMARY KEY (job_id, fingerprint)
    );
    CREATE INDEX findings_by_tenant ON findings (tenant, category);
    """),
    (2, """
    CREATE TABLE api_keys (
        tenant_id  TEXT PRIMARY KEY,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      INTEGER NOT NULL,
        active     INTEGER NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE audit_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT,
        event  TEXT,
        ts     REAL NOT NULL,
        data   TEXT NOT NULL
    );
    CREATE INDEX audit_log_by_tenant ON audit_log (tenant, id);
    CREATE TABLE audit_chain (
        sequence      INTEGER PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    );
    """),
    (3, """
    CREATE TABLE monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at REAL NOT NULL
    );
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """),
    (4, """
    ALTER TABLE api_keys ADD COLUMN expires_at REAL;
    ALTER TABLE api_keys ADD COLUMN last_used REAL;
    ALTER TABLE api_keys ADD COLUMN rotated_at REAL;
    """),
    (5, """
    CREATE TABLE engagement_policies (
        policy_id      TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
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
    CREATE INDEX policies_by_tenant ON engagement_policies (tenant_id, status);
    CREATE TABLE webhook_sinks (
        name    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        added_at REAL NOT NULL
    );
    """),
    (6, """
    ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE jobs ADD COLUMN worker TEXT NOT NULL DEFAULT '';
    ALTER TABLE jobs ADD COLUMN idempotency_key TEXT;
    CREATE UNIQUE INDEX jobs_idempotency ON jobs (tenant, idempotency_key)
        WHERE idempotency_key IS NOT NULL;
    CREATE INDEX jobs_by_state ON jobs (state, created_at)
    """),
    (7, """
    CREATE TABLE monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   REAL NOT NULL
    )
    """),
]

# A finished job stays finished: a late write from a crashed/hung worker must
# not resurrect it as queued or running (that is how a job gets executed twice
# and how a cancelled scan reappears as live).
TERMINAL_STATES = ("completed", "partial", "failed", "cancelled")


class JobConflict(RuntimeError):
    """Two jobs tried to claim the same idempotency key; the caller must re-read."""

_path = "strix.db"


def configure(path: str | Path) -> None:
    global _path
    _path = str(path)


def current_path() -> str:
    return _path


_migrated: set[str] = set()
_setup_lock = threading.Lock()


def connect() -> sqlite3.Connection:
    """Open the database; the schema is migrated once per file per process.

    First-time setup is serialized: request and worker threads can all open a
    brand-new database at the same moment, and each must not try to create the
    schema. ``busy_timeout`` makes lock contention wait instead of failing, and
    ``synchronous=NORMAL`` is the documented durable-enough pairing for WAL.
    """
    connection = sqlite3.connect(_path, timeout=10.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA foreign_keys = ON")
    if _path not in _migrated:
        with _setup_lock:
            if _path not in _migrated:      # another thread may have finished first
                try:
                    connection.execute("PRAGMA journal_mode = WAL")  # persistent in the file
                    migrate(connection)
                except BaseException:
                    connection.close()
                    raise
                _migrated.add(_path)
                _restrict_permissions(_path)
    connection.execute("PRAGMA synchronous = NORMAL")   # per-connection setting
    return connection


def _restrict_permissions(path: str) -> None:
    """The database holds key hashes, findings and the audit trail: owner only."""
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):  # not every sidecar exists yet
            os.chmod(path + suffix, 0o600)


def migrate(connection: sqlite3.Connection) -> int:
    """Apply pending migrations. Returns the resulting schema version."""
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    for target, script in MIGRATIONS:
        if target <= version:
            continue
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in script.split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {int(target)}")
            connection.execute("COMMIT")
        except sqlite3.Error:
            connection.execute("ROLLBACK")
            raise
        version = target
    return version


def schema_version() -> int:
    connection = connect()
    try:
        return connection.execute("PRAGMA user_version").fetchone()[0]
    finally:
        connection.close()


def save_job(job: Any, *, tenant: str) -> None:
    """Persist a job and its findings in one transaction.

    Two guarantees that the raw upsert did not have:

    * a terminal state is sticky — a late ``running``/``queued`` write from a
      crashed or hung execution cannot undo a completed, partial, failed or
      cancelled row (which would let the job be picked up and run again);
    * ``created_at`` and the first ``started_at`` are preserved across updates,
      so duration and ordering stay truthful.

    Raises :class:`JobConflict` when the job's idempotency key is already owned
    by a different job id.
    """
    rows = []
    for finding in dedupe(job.findings):   # one row per fingerprint, even if unsaved input repeats it
        data = finding.to_dict()          # already redacted
        rows.append((
            job.id, tenant, data["fingerprint"], data["asset"], data["category"],
            data["title"], data["severity"], data["confidence"], data["verification"],
            data["status"], data["detector"], data["detector_version"],
            data["location"], data["evidence"], data["description"],
            data["remediation"], data["cwe"], json.dumps(data["sources"]),
        ))

    # The target and error are sanitized on the way in: the database never
    # holds credentials that happened to sit in a URL or an exception message.
    # The in-memory job keeps its original target so the assessment itself is
    # unaffected; only what is stored (and therefore served back) is sanitized.
    stored_target = sanitize_target(job.target)
    stored_error = redact(job.error)
    state, verdict = job.state.value, job.verdict
    finished_at = job.finished_at
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT state, verdict, error, finished_at FROM jobs WHERE id = ?",
            (job.id,)).fetchone()
        if (existing is not None and existing["state"] in TERMINAL_STATES
                and state not in TERMINAL_STATES):
            state, verdict = existing["state"], existing["verdict"]
            stored_error, finished_at = existing["error"], existing["finished_at"]
        try:
            connection.execute(
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
        except sqlite3.IntegrityError as exc:
            raise JobConflict(f"idempotency key already used by another job: {exc}") from None
        connection.execute("DELETE FROM findings WHERE job_id = ?", (job.id,))
        connection.executemany(
            """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                     severity, confidence, verification, status, detector,
                                     detector_version, location, evidence, description,
                                     remediation, cwe, sources)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        connection.execute("COMMIT")
    except sqlite3.Error:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _job_row_to_dict(row: sqlite3.Row, findings: list[dict[str, Any]]) -> dict[str, Any]:
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
        # Lifecycle metadata: which execution claimed the job, how many
        # attempts it took, and whether it was a deduplicated submission.
        "attempts": row["attempts"],
        "worker": row["worker"],
        "idempotency_key": row["idempotency_key"],
    }


def _finding_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
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


def get_job(job_id: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Load a job. ``tenant=None`` is reserved for administrators."""
    connection = connect()
    try:
        if tenant is None:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM jobs WHERE id = ? AND tenant = ?", (job_id, tenant)).fetchone()
        if row is None:
            return None
        findings = connection.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", (job_id,)).fetchall()
        return _job_row_to_dict(row, [_finding_row_to_dict(item) for item in findings])
    finally:
        connection.close()


def latest_finished_job(target: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Most recent job for ``target`` that produced a result (with its findings).

    The lookup key is sanitized exactly the way :func:`save_job` sanitized the
    stored target, so a caller quoting the raw URL still finds its job.
    """
    target = sanitize_target(target)
    connection = connect()
    try:
        if tenant is None:
            row = connection.execute(
                "SELECT id FROM jobs WHERE target = ? AND state IN ('completed', 'partial') "
                "ORDER BY created_at DESC LIMIT 1", (target,)).fetchone()
        else:
            row = connection.execute(
                "SELECT id FROM jobs WHERE target = ? AND tenant = ? "
                "AND state IN ('completed', 'partial') ORDER BY created_at DESC LIMIT 1",
                (target, tenant)).fetchone()
    finally:
        connection.close()
    return get_job(row["id"], tenant=tenant) if row else None


def list_jobs(*, tenant: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Recent job summaries (no findings payload)."""
    connection = connect()
    try:
        if tenant is None:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM jobs WHERE tenant = ? ORDER BY created_at DESC LIMIT ?",
                (tenant, limit)).fetchall()
        return [_job_row_to_dict(row, []) for row in rows]
    finally:
        connection.close()


def fail_interrupted(*, created_before: float | None = None) -> int:
    """Mark jobs a previous process left queued/running as failed.

    Called at worker startup: an interrupted job must never be reported as
    completed (or left looking live) after a restart. Returns the row count.

    ``created_before`` keeps the sweep from eating work this process has just
    accepted: the worker passes its own start time, so a job row written a
    moment before the first claim (the API persists queued jobs) is not mistaken
    for the remains of a dead process. ``None`` sweeps every non-terminal row.
    """
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cutoff = "AND created_at < ?" if created_before is not None else ""
        params = (time.time(),) if created_before is None else (time.time(), created_before)
        cursor = connection.execute(
            f"""UPDATE jobs
               SET state = 'failed',
                   verdict = 'failed — no usable coverage',
                   error = 'interrupted by process restart',
                   finished_at = ?
               WHERE state IN ('queued', 'running') {cutoff}""",
            params,
        )
        connection.execute("COMMIT")
        return cursor.rowcount
    except sqlite3.Error:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def mark_running(job_id: str, *, tenant: str, worker: str,
                 now: float | None = None) -> bool:
    """Claim a queued job for one worker. False when another claim won.

    The queued -> running transition is a single conditional UPDATE, so two
    workers (or a worker and a stale retry) can never both execute the same
    job: exactly one sees ``rowcount == 1``.
    """
    stamp = time.time() if now is None else now
    connection = connect()
    try:
        cursor = connection.execute(
            """UPDATE jobs
               SET state = 'running', worker = ?,
                   started_at = COALESCE(started_at, ?),
                   attempts = attempts + 1
               WHERE id = ? AND tenant = ? AND state = 'queued'""",
            (worker, stamp, job_id, tenant),
        )
        return cursor.rowcount == 1
    finally:
        connection.close()


def claim_job(job_id: str, *, tenant: str, worker: str,
              now: float | None = None) -> bool:
    """Single-execution claim: True when this caller may run the job.

    A persisted ``queued`` row is claimed atomically (see :func:`mark_running`).
    A job that was never persisted (direct use of :class:`AssessmentWorker` in
    tests, or an inline run) has no row to contend for, and the in-memory queue
    is its only claim — that case returns True rather than deadlocking the job.
    """
    if mark_running(job_id, tenant=tenant, worker=worker, now=now):
        return True
    connection = connect()
    try:
        row = connection.execute(
            "SELECT 1 FROM jobs WHERE id = ? AND tenant = ?", (job_id, tenant)).fetchone()
        return row is None
    finally:
        connection.close()


def find_job_id_by_idempotency(idempotency_key: str, *, tenant: str) -> str | None:
    """The job that already owns ``idempotency_key`` for this tenant, if any."""
    connection = connect()
    try:
        row = connection.execute(
            "SELECT id FROM jobs WHERE tenant = ? AND idempotency_key = ?",
            (tenant, idempotency_key)).fetchone()
        return row["id"] if row else None
    finally:
        connection.close()


def count_jobs(*, tenant: str) -> int:
    """How many jobs a tenant owns — counted in SQL, never across tenants."""
    connection = connect()
    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE tenant = ?", (tenant,)).fetchone()
        return int(row[0])
    finally:
        connection.close()


def count_findings(*, tenant: str) -> int:
    """How many findings a tenant owns — scoped in SQL."""
    connection = connect()
    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE tenant = ?", (tenant,)).fetchone()
        return int(row[0])
    finally:
        connection.close()


def get_findings(job_id: str, *, tenant: str | None = None) -> list[Finding]:
    """Rehydrate findings for report generation (SARIF)."""
    connection = connect()
    try:
        if tenant is None:
            rows = connection.execute(
                "SELECT * FROM findings WHERE job_id = ? ORDER BY rowid", (job_id,)).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM findings WHERE job_id = ? AND tenant = ? ORDER BY rowid",
                (job_id, tenant)).fetchall()
    finally:
        connection.close()

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
def save_api_key(*, tenant_id: str, key_hash: str, tier: str, admin: bool,
                 active: bool, created_at: float, expires_at: float | None = None,
                 last_used: float | None = None, rotated_at: float | None = None) -> None:
    connection = connect()
    try:
        connection.execute(
            "INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at, "
            "expires_at, last_used, rotated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id) DO UPDATE SET "
            "key_hash = excluded.key_hash, tier = excluded.tier, admin = excluded.admin, "
            "active = excluded.active, created_at = excluded.created_at, "
            "expires_at = excluded.expires_at, last_used = excluded.last_used, "
            "rotated_at = excluded.rotated_at",
            (tenant_id, key_hash, tier, int(admin), int(active), created_at,
             expires_at, last_used, rotated_at))
    finally:
        connection.close()


def load_api_keys() -> list[dict[str, Any]]:
    connection = connect()
    try:
        return [dict(row) for row in connection.execute("SELECT * FROM api_keys")]
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Audit trail and hash chain
# ---------------------------------------------------------------------------
def append_audit(entry: dict[str, Any]) -> None:
    connection = connect()
    try:
        connection.execute(
            "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
            (entry.get("tenant"), entry.get("event"), entry.get("timestamp", time.time()),
             json.dumps(entry, sort_keys=True)))
    finally:
        connection.close()


def recent_audit(limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` entries, returned oldest-first."""
    connection = connect()
    try:
        rows = connection.execute(
            "SELECT data FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        connection.close()
    return [json.loads(row["data"]) for row in reversed(rows)]


def chain_tip() -> tuple[int, str] | None:
    """(sequence, hash) of the last sealed entry, or None for an empty chain."""
    connection = connect()
    try:
        row = connection.execute(
            "SELECT sequence, hash FROM audit_chain ORDER BY sequence DESC LIMIT 1").fetchone()
    finally:
        connection.close()
    return (row["sequence"], row["hash"]) if row else None


def chain_insert(sequence: int, previous_hash: str, digest: str, data: dict[str, Any]) -> None:
    connection = connect()
    try:
        connection.execute(
            "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
            (sequence, previous_hash, digest, json.dumps(data, sort_keys=True)))
    finally:
        connection.close()


def chain_rows() -> Iterator[sqlite3.Row]:
    """Stream the whole chain in order without loading it into memory."""
    connection = connect()
    try:
        yield from connection.execute(
            "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence")
    finally:
        connection.close()


def chain_count() -> int:
    connection = connect()
    try:
        return connection.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Retention (opt-in via STRIX_RETENTION_DAYS; 0 keeps everything forever)
# ---------------------------------------------------------------------------
def prune_finished_jobs(older_than: float) -> int:
    """Delete terminal-state jobs finished before the cutoff epoch.

    Findings cascade through the foreign key. Queued/running rows are never
    touched: retention must not delete work that is still live or about to run.
    """
    connection = connect()
    try:
        cursor = connection.execute(
            f"""DELETE FROM jobs
                WHERE state IN ({', '.join(repr(s) for s in TERMINAL_STATES)})
                  AND finished_at IS NOT NULL AND finished_at < ?""",
            (older_than,))
        return cursor.rowcount
    finally:
        connection.close()


def prune_audit_log(older_than: float) -> int:
    """Delete plain audit-log entries older than the cutoff epoch.

    The ``audit_chain`` table is intentionally never pruned: it is the
    tamper-evident record, and removing old links would break verification
    from genesis. It only grows with sealed security events (key rotations,
    denials, policy changes), which is slow.
    """
    connection = connect()
    try:
        cursor = connection.execute("DELETE FROM audit_log WHERE ts < ?", (older_than,))
        return cursor.rowcount
    finally:
        connection.close()


def vacuum() -> None:
    """Reclaim file space after bulk retention deletes (WAL is checkpointed)."""
    connection = connect()
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Monitor configuration
# ---------------------------------------------------------------------------
def save_monitor_config(targets: list[str], interval_seconds: int) -> None:
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM monitor_targets")
        connection.executemany("INSERT INTO monitor_targets (target, added_at) VALUES (?, ?)",
                               [(target, time.time()) for target in dict.fromkeys(targets)])
        connection.execute(
            "INSERT INTO settings (key, value) VALUES ('monitor_interval', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(interval_seconds),))
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def load_monitor_config() -> tuple[list[str], int | None]:
    """(targets in the order they were added, interval or None if never set)."""
    connection = connect()
    try:
        targets = [row["target"] for row in connection.execute(
            "SELECT target FROM monitor_targets ORDER BY added_at, rowid")]
        row = connection.execute(
            "SELECT value FROM settings WHERE key = 'monitor_interval'").fetchone()
    finally:
        connection.close()
    return targets, (int(row["value"]) if row else None)


# ---------------------------------------------------------------------------
# Monitor baselines
# ---------------------------------------------------------------------------
def save_monitor_baseline(target: str, fingerprints: list[str] | set[str]) -> None:
    """Persist one target's last-seen finding fingerprints.

    Without this, a restart re-baselines every target and the first cycle is
    silent: a critical finding that appeared while the process was down would
    never alert. Only fingerprints (hashes) are stored, never evidence.
    """
    connection = connect()
    try:
        connection.execute(
            """INSERT INTO monitor_baseline (target, fingerprints, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(target) DO UPDATE SET
                   fingerprints = excluded.fingerprints,
                   updated_at = excluded.updated_at""",
            (sanitize_target(target), json.dumps(sorted(set(fingerprints))), time.time()))
    finally:
        connection.close()


def load_monitor_baseline() -> dict[str, set[str]]:
    """Every persisted baseline, keyed by the stored (sanitized) target."""
    connection = connect()
    try:
        rows = connection.execute(
            "SELECT target, fingerprints FROM monitor_baseline").fetchall()
    finally:
        connection.close()
    baseline: dict[str, set[str]] = {}
    for row in rows:
        try:
            stored = json.loads(row["fingerprints"])
        except json.JSONDecodeError:
            continue
        if isinstance(stored, list):
            baseline[row["target"]] = {str(item) for item in stored}
    return baseline


def delete_monitor_baseline(target: str) -> None:
    connection = connect()
    try:
        connection.execute("DELETE FROM monitor_baseline WHERE target = ?",
                           (sanitize_target(target),))
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Engagement authorization policies
# ---------------------------------------------------------------------------
_POLICY_COLUMNS = ("policy_id", "tenant_id", "program", "authorized_by",
                   "authorization_ref", "include", "exclude", "authorized_networks",
                   "allowed_ports", "allow_broad_networks", "status", "version",
                   "created_at", "updated_at", "effective_at", "expires_at",
                   "created_by")


def save_policy(policy: dict[str, Any]) -> None:
    """Insert or replace one engagement policy row (fields pre-validated)."""
    row = dict(policy)
    for column in ("include", "exclude", "authorized_networks", "allowed_ports"):
        row[column] = json.dumps(row[column])
    row["allow_broad_networks"] = int(bool(row["allow_broad_networks"]))
    connection = connect()
    try:
        connection.execute(
            f"""INSERT INTO engagement_policies ({', '.join(_POLICY_COLUMNS)})
                VALUES ({', '.join('?' for _ in _POLICY_COLUMNS)})
                ON CONFLICT(policy_id) DO UPDATE SET
                    {', '.join(f'{column} = excluded.{column}'
                               for column in _POLICY_COLUMNS[1:])}""",
            tuple(row[column] for column in _POLICY_COLUMNS))
    finally:
        connection.close()


def load_policies() -> list[dict[str, Any]]:
    """Every stored policy, newest first; list columns are decoded."""
    connection = connect()
    try:
        rows = connection.execute(
            f"SELECT {', '.join(_POLICY_COLUMNS)} FROM engagement_policies "
            "ORDER BY created_at DESC").fetchall()
    finally:
        connection.close()
    policies = []
    for row in rows:
        item = dict(row)
        for column in ("include", "exclude", "authorized_networks", "allowed_ports"):
            item[column] = json.loads(item[column])
        item["allow_broad_networks"] = bool(item["allow_broad_networks"])
        policies.append(item)
    return policies


# ---------------------------------------------------------------------------
# Webhook sinks (alert destinations survive a restart)
# ---------------------------------------------------------------------------
def save_webhook_sink(name: str, url: str) -> None:
    """Persist an alert sink. The URL is operator-supplied configuration: it is
    stored so delivery survives a restart, and is never exposed through the API
    (only the sink name is)."""
    connection = connect()
    try:
        connection.execute(
            "INSERT INTO webhook_sinks (name, url, added_at) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET url = excluded.url",
            (name, url, time.time()))
    finally:
        connection.close()


def delete_webhook_sink(name: str) -> None:
    """Delete a persisted alert sink, e.g. when an unsafe legacy URL is found."""
    connection = connect()
    try:
        connection.execute("DELETE FROM webhook_sinks WHERE name = ?", (name,))
    finally:
        connection.close()


def load_webhook_sinks() -> list[dict[str, Any]]:
    connection = connect()
    try:
        return [dict(row) for row in connection.execute(
            "SELECT name, url, added_at FROM webhook_sinks ORDER BY added_at, rowid")]
    finally:
        connection.close()
