"""Capability token revocation list with database persistence."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ishastra.core.store import Database

log = logging.getLogger(__name__)


REVOCATION_TABLE_SQLITE = """
CREATE TABLE IF NOT EXISTS capability_revocations (
    jti          TEXT PRIMARY KEY,
    key_id       TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    revoked_at   REAL NOT NULL,
    revoked_by   TEXT NOT NULL DEFAULT '',
    job_id       TEXT,
    engagement_id TEXT,
    tenant_id    TEXT
);
CREATE INDEX IF NOT EXISTS revocations_by_job ON capability_revocations (job_id);
CREATE INDEX IF NOT EXISTS revocations_by_engagement ON capability_revocations (engagement_id);
CREATE INDEX IF NOT EXISTS revocations_by_tenant ON capability_revocations (tenant_id);
CREATE INDEX IF NOT EXISTS revocations_by_key ON capability_revocations (key_id);
"""

REVOCATION_TABLE_PG = """
CREATE TABLE IF NOT EXISTS capability_revocations (
    jti            TEXT PRIMARY KEY,
    key_id         TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    revoked_at     DOUBLE PRECISION NOT NULL,
    revoked_by     TEXT NOT NULL DEFAULT '',
    job_id         TEXT,
    engagement_id  TEXT,
    tenant_id      TEXT
);
CREATE INDEX IF NOT EXISTS revocations_by_job ON capability_revocations (job_id);
CREATE INDEX IF NOT EXISTS revocations_by_engagement ON capability_revocations (engagement_id);
CREATE INDEX IF NOT EXISTS revocations_by_tenant ON capability_revocations (tenant_id);
CREATE INDEX IF NOT EXISTS revocations_by_key ON capability_revocations (key_id);
"""

TOKEN_REGISTRY_SQLITE = """
CREATE TABLE IF NOT EXISTS capability_tokens (
    jti            TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    engagement_id  TEXT NOT NULL,
    job_id         TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    issued_at      REAL NOT NULL,
    expires_at     REAL NOT NULL,
    policy_hash    TEXT NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_by_job ON capability_tokens (job_id);
CREATE INDEX IF NOT EXISTS tokens_by_engagement ON capability_tokens (engagement_id);
CREATE INDEX IF NOT EXISTS tokens_by_tenant ON capability_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS tokens_by_key ON capability_tokens (key_id);
"""

TOKEN_REGISTRY_PG = """
CREATE TABLE IF NOT EXISTS capability_tokens (
    jti            TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    engagement_id  TEXT NOT NULL,
    job_id         TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    issued_at      DOUBLE PRECISION NOT NULL,
    expires_at     DOUBLE PRECISION NOT NULL,
    policy_hash    TEXT NOT NULL,
    revoked        BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS tokens_by_job ON capability_tokens (job_id);
CREATE INDEX IF NOT EXISTS tokens_by_engagement ON capability_tokens (engagement_id);
CREATE INDEX IF NOT EXISTS tokens_by_tenant ON capability_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS tokens_by_key ON capability_tokens (key_id);
"""


@dataclass(frozen=True)
class RevocationEntry:
    """A revoked capability token entry."""

    jti: str
    key_id: str
    reason: str
    revoked_at: float
    revoked_by: str
    job_id: str | None = None
    engagement_id: str | None = None
    tenant_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "jti": self.jti,
            "key_id": self.key_id,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "job_id": self.job_id,
            "engagement_id": self.engagement_id,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_row(cls, row: Any) -> RevocationEntry:
        columns = row.keys()
        return cls(
            jti=row["jti"],
            key_id=row["key_id"],
            reason=row["reason"],
            revoked_at=row["revoked_at"],
            revoked_by=row["revoked_by"],
            job_id=row["job_id"] if "job_id" in columns else None,
            engagement_id=row["engagement_id"] if "engagement_id" in columns else None,
            tenant_id=row["tenant_id"] if "tenant_id" in columns else None,
        )


class RevocationList:
    """Database-backed revocation list for capability tokens.

    Provides O(1) revocation checks via indexed JTI lookup.
    Supports bulk revocation by job/engagement/tenant via token registry.
    """

    def __init__(self, database: Database):
        self.db = database
        self._cache: dict[str, bool] = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_time = 0.0

    async def _run_ddl(self, sql: str) -> None:
        """Execute a DDL script one statement at a time (aiosqlite limit)."""
        async with self.db.transaction() as conn:
            for statement in sql.split(";"):
                if statement.strip():
                    await conn.execute(statement)

    async def initialize(self) -> None:
        """Create the revocation table if it doesn't exist."""
        sql = REVOCATION_TABLE_PG if self.db.is_postgresql() else REVOCATION_TABLE_SQLITE
        await self._run_ddl(sql)

    async def initialize_token_registry(self) -> None:
        """Create the token registry table if it doesn't exist."""
        sql = TOKEN_REGISTRY_PG if self.db.is_postgresql() else TOKEN_REGISTRY_SQLITE
        await self._run_ddl(sql)

    def _sql(self, sql: str) -> str:
        """Convert SQLite placeholders for PostgreSQL (asyncpg needs $n)."""
        if not self.db.is_postgresql():
            return sql
        parts = sql.split("?")
        if len(parts) == 1:
            return sql
        return "".join(
            part + (f"${i + 1}" if i < len(parts) - 1 else "")
            for i, part in enumerate(parts)
        )

    async def _run(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> Any:
        if self.db.is_postgresql():
            return await conn.execute(self._sql(sql), *params)
        return await conn.execute(sql, params)

    async def _one(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> Any:
        if self.db.is_postgresql():
            return await conn.fetchrow(self._sql(sql), *params)
        cursor = await conn.execute(sql, params)
        return await cursor.fetchone()

    async def _all(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        if self.db.is_postgresql():
            return list(await conn.fetch(self._sql(sql), *params))
        cursor = await conn.execute(sql, params)
        return list(await cursor.fetchall())

    async def _inserted(self, conn: Any, sql: str, params: tuple[Any, ...]) -> bool:
        """True when an INSERT ... ON CONFLICT DO NOTHING inserted a row."""
        if self.db.is_postgresql():
            return await self._one(conn, sql + " RETURNING jti", params) is not None
        cursor = await self._run(conn, sql, params)
        return bool(getattr(cursor, "rowcount", 0))

    async def _deleted_count(self, conn: Any, sql: str, params: tuple[Any, ...]) -> int:
        if self.db.is_postgresql():
            return len(await self._all(conn, sql + " RETURNING jti", params))
        cursor = await self._run(conn, sql, params)
        return int(getattr(cursor, "rowcount", 0) or 0)

    def _maybe_refresh_cache(self) -> None:
        """Refresh cache if TTL expired."""
        if time.time() - self._cache_time > self._cache_ttl:
            self._cache.clear()
            self._cache_time = time.time()

    async def register_token(
        self,
        jti: str,
        tenant_id: str,
        engagement_id: str,
        job_id: str,
        key_id: str,
        iat: float,
        exp: float,
        policy_hash: str,
    ) -> None:
        """Register an issued token for bulk revocation tracking."""
        sql = """
        INSERT INTO capability_tokens
            (jti, tenant_id, engagement_id, job_id, key_id, issued_at, expires_at, policy_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO UPDATE SET
            tenant_id=excluded.tenant_id,
            engagement_id=excluded.engagement_id,
            job_id=excluded.job_id,
            key_id=excluded.key_id,
            issued_at=excluded.issued_at,
            expires_at=excluded.expires_at,
            policy_hash=excluded.policy_hash
        """
        async with self.db.transaction() as conn:
            await self._run(
                conn,
                sql,
                (jti, tenant_id, engagement_id, job_id, key_id, iat, exp, policy_hash),
            )

    async def revoke(
        self,
        jti: str,
        reason: str = "",
        key_id: str = "",
        job_id: str | None = None,
        engagement_id: str | None = None,
        tenant_id: str | None = None,
        revoked_by: str = "system",
    ) -> bool:
        """Revoke a token by JTI.

        Returns True if newly revoked, False if already revoked.
        """
        now = time.time()
        self._maybe_refresh_cache()

        if jti in self._cache:
            return False

        sql = """
        INSERT INTO capability_revocations
            (jti, key_id, reason, revoked_at, revoked_by, job_id, engagement_id, tenant_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO NOTHING
        """
        params = (jti, key_id, reason, now, revoked_by, job_id, engagement_id, tenant_id)
        async with self.db.transaction() as conn:
            if await self._inserted(conn, sql, params):
                self._cache[jti] = True
                log.info("revoked capability token", extra={"jti": jti, "key_id": key_id, "reason": reason})
                return True

        self._cache[jti] = True
        return False

    async def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI is revoked (with caching)."""
        self._maybe_refresh_cache()

        if jti in self._cache:
            return self._cache[jti]

        sql = "SELECT 1 FROM capability_revocations WHERE jti = ?"
        async with self.db.read_transaction() as conn:
            row = await self._one(conn, sql, (jti,))
            result = row is not None
            self._cache[jti] = result
            return result

    async def revoke_by_job(
        self,
        job_id: str,
        reason: str = "",
        key_id: str = "",
        revoked_by: str = "system",
    ) -> int:
        """Revoke all tokens for a job. Returns count revoked."""
        now = time.time()
        self._maybe_refresh_cache()

        sql_select = "SELECT jti FROM capability_tokens WHERE job_id = ? AND revoked = 0"
        async with self.db.transaction() as conn:
            jti_rows = await self._all(conn, sql_select, (job_id,))
            jtis = [row["jti"] for row in jti_rows]

        if not jtis:
            return 0

        sql_insert = """
        INSERT INTO capability_revocations (jti, key_id, reason, revoked_at, revoked_by, job_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO NOTHING
        """  # noqa: E501
        revoked_count = 0
        async with self.db.transaction() as conn:
            for jti in jtis:
                inserted = await self._inserted(
                    conn, sql_insert, (jti, key_id, reason, now, revoked_by, job_id)
                )
                if inserted:
                    revoked_count += 1
                    self._cache[jti] = True

        sql_update = "UPDATE capability_tokens SET revoked = 1 WHERE job_id = ?"
        async with self.db.transaction() as conn:
            await self._run(conn, sql_update, (job_id,))

        log.info("revoked tokens for job", extra={"job_id": job_id, "count": revoked_count})
        return revoked_count

    async def revoke_by_engagement(
        self,
        engagement_id: str,
        reason: str = "",
        key_id: str = "",
        revoked_by: str = "system",
    ) -> int:
        """Revoke all tokens for an engagement. Returns count revoked."""
        now = time.time()
        self._maybe_refresh_cache()

        sql_select = "SELECT jti FROM capability_tokens WHERE engagement_id = ? AND revoked = 0"
        async with self.db.transaction() as conn:
            jti_rows = await self._all(conn, sql_select, (engagement_id,))
            jtis = [row["jti"] for row in jti_rows]

        if not jtis:
            return 0

        sql_insert = """
        INSERT INTO capability_revocations (jti, key_id, reason, revoked_at, revoked_by, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO NOTHING
        """
        revoked_count = 0
        async with self.db.transaction() as conn:
            for jti in jtis:
                inserted = await self._inserted(
                    conn, sql_insert, (jti, key_id, reason, now, revoked_by, engagement_id)
                )
                if inserted:
                    revoked_count += 1
                    self._cache[jti] = True

        sql_update = "UPDATE capability_tokens SET revoked = 1 WHERE engagement_id = ?"
        async with self.db.transaction() as conn:
            await self._run(conn, sql_update, (engagement_id,))

        log.info(
            "revoked tokens for engagement",
            extra={"engagement_id": engagement_id, "count": revoked_count},
        )
        return revoked_count

    async def revoke_by_tenant(
        self,
        tenant_id: str,
        reason: str = "",
        key_id: str = "",
        revoked_by: str = "system",
    ) -> int:
        """Revoke all tokens for a tenant. Returns count revoked."""
        now = time.time()
        self._maybe_refresh_cache()

        sql_select = "SELECT jti FROM capability_tokens WHERE tenant_id = ? AND revoked = 0"
        async with self.db.transaction() as conn:
            jti_rows = await self._all(conn, sql_select, (tenant_id,))
            jtis = [row["jti"] for row in jti_rows]

        if not jtis:
            return 0

        sql_insert = """
        INSERT INTO capability_revocations (jti, key_id, reason, revoked_at, revoked_by, tenant_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO NOTHING
        """
        revoked_count = 0
        async with self.db.transaction() as conn:
            for jti in jtis:
                inserted = await self._inserted(
                    conn, sql_insert, (jti, key_id, reason, now, revoked_by, tenant_id)
                )
                if inserted:
                    revoked_count += 1
                    self._cache[jti] = True

        sql_update = "UPDATE capability_tokens SET revoked = 1 WHERE tenant_id = ?"
        async with self.db.transaction() as conn:
            await self._run(conn, sql_update, (tenant_id,))

        log.info("revoked tokens for tenant", extra={"tenant_id": tenant_id, "count": revoked_count})
        return revoked_count

    async def get_revoked_for_job(self, job_id: str) -> list[RevocationEntry]:
        """Get all revoked tokens for a job."""
        sql = "SELECT * FROM capability_revocations WHERE job_id = ? ORDER BY revoked_at DESC"
        async with self.db.read_transaction() as conn:
            rows = await self._all(conn, sql, (job_id,))
            return [RevocationEntry.from_row(row) for row in rows]

    async def cleanup_expired(self, max_age_seconds: int = 86400 * 30) -> int:
        """Remove revocation entries older than max_age_seconds.

        Returns count of removed entries.
        """
        cutoff = time.time() - max_age_seconds
        sql = "DELETE FROM capability_revocations WHERE revoked_at < ?"
        async with self.db.transaction() as conn:
            return await self._deleted_count(conn, sql, (cutoff,))
