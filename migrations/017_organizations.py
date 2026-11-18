"""Migration 17: Create organizations and org_memberships tables.

This migration adds the organization layer on top of tenants.
Organizations group multiple tenants under a single administrative umbrella.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import asyncio

from strix.core.store import configure, get_database

SQLITE_MIGRATION_17 = """
CREATE TABLE IF NOT EXISTS organizations (
    org_id         TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    admin_key_hash TEXT NOT NULL UNIQUE,
    tier           TEXT NOT NULL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS org_memberships (
    org_id     TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    role       TEXT NOT NULL,
    joined_at  REAL NOT NULL,
    PRIMARY KEY (org_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);
"""

SQLITE_MIGRATION_18 = """
ALTER TABLE api_keys ADD COLUMN org_id TEXT;
CREATE INDEX IF NOT EXISTS api_keys_by_org ON api_keys (org_id);
"""


async def run_migrations(db_path: str) -> None:
    """Run the organization migrations."""
    configure(db_path)
    db = await get_database()

    # Check current version
    version = await db.schema_version()
    print(f"Current schema version: {version}")

    if version >= 18:
        print("Migrations already applied (version >= 18)")
        return

    # Apply migration 17
    if version < 17:
        print("Applying migration 17: organizations and org_memberships tables")
        async with db.transaction() as conn:
            for statement in SQLITE_MIGRATION_17.split(";"):
                stmt = "\n".join(
                    line for line in statement.splitlines() if not line.strip().startswith("--")
                ).strip()
                if stmt:
                    await conn.execute(stmt)
            await conn.execute("PRAGMA user_version = 17")
            await conn.commit()
        print("Migration 17 applied")

    # Apply migration 18
    if version < 18:
        print("Applying migration 18: add org_id to api_keys")
        async with db.transaction() as conn:
            for statement in SQLITE_MIGRATION_18.split(";"):
                stmt = "\n".join(
                    line for line in statement.splitlines() if not line.strip().startswith("--")
                ).strip()
                if stmt:
                    await conn.execute(stmt)
            await conn.execute("PRAGMA user_version = 18")
            await conn.commit()
        print("Migration 18 applied")

    # Verify
    final_version = await db.schema_version()
    print(f"Final schema version: {final_version}")


if __name__ == "__main__":
    import os

    db_path = os.environ.get("STRIX_DB_PATH", "strix.db")
    asyncio.run(run_migrations(db_path))
