"""Migration 28: enable Row-Level Security on every tenant-scoped table.

The SQL now lives in ``strix.core.pg_rls`` and is applied by the store's own
PostgreSQL migration chain (``store.PostgreSQLDatabase._migrate_pg``), so a
deployment cannot skip it. This module stays only as the historical entry
point: running it applies whatever is still pending.
"""

from __future__ import annotations

import asyncio

from strix.core import store
from strix.core.pg_rls import RLS_SCHEMA_VERSION, apply_rls, build_sql

SQLITE_MIGRATION_28 = ""


async def run_migrations(db_path: str) -> None:
    """Bring the configured database up to the current schema version."""
    store.configure(db_path)
    db = await store.get_database()
    version = await db.schema_version()
    print(f"Current schema version: {version}")

    if not db.is_postgresql():
        print("RLS is PostgreSQL-only; SQLite keeps application-level filtering")
        return

    if version >= RLS_SCHEMA_VERSION:
        print(f"RLS already applied (schema version {version})")
        return

    async with db.transaction() as conn:
        await apply_rls(conn)
        await conn.execute(
            "INSERT INTO settings (key, value) VALUES ('schema_version', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            str(RLS_SCHEMA_VERSION),
        )
    print(f"RLS applied; schema version now {await db.schema_version()}")


__all__ = ["PG_MIGRATION_SQL", "RLS_SCHEMA_VERSION", "apply_rls", "run_migrations"]

PG_MIGRATION_SQL = build_sql(
    {
        "jobs",
        "findings",
        "api_keys",
        "audit_log",
        "audit_chain",
        "engagement_policies",
        "webhook_sinks",
        "monitor_targets",
        "monitor_baseline",
        "assessment_schedules",
        "evidence_packs",
        "assets",
        "finding_events",
        "finding_remediation",
        "finding_records",
        "tenant_users",
        "organizations",
        "org_memberships",
        "teams",
        "memberships",
        "compliance_schedules",
        "compliance_reports",
        "compliance_exports",
        "mssp_partners",
        "mssp_customers",
        "mssp_usage_records",
        "mssp_invitations",
    }
)


if __name__ == "__main__":
    import os

    asyncio.run(run_migrations(os.environ.get("STRIX_DATABASE_URL") or os.environ.get("STRIX_DB", "strix.db")))
