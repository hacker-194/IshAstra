#!/usr/bin/env python3
"""Migration script: Assign existing tenants to a default organization.

This script creates a default organization for each existing tenant that doesn't
already belong to one, and adds the tenant as an org_admin member.

Run this after applying the organization hierarchy migrations (versions 21-23).

Usage:
    python scripts/migrate_add_org.py [--db-path PATH] [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from strix.core import store
from strix.core.organizations import (
    add_member,
    create_org,
)


async def migrate_tenants_to_orgs(db_path: str, dry_run: bool = False) -> int:
    """Migrate existing tenants to default organizations.

    Returns the number of tenants migrated.
    """
    store.configure(db_path)
    db = await store.get_database()

    # Load all existing tenants (api_keys)
    async with db.transaction() as conn:
        rows = await store._fetchall(
            conn,
            "SELECT tenant_id, tier, admin, active, created_at FROM api_keys WHERE active = 1",
        )

    migrated = 0
    for row in rows:
        tenant_id = row["tenant_id"]
        tier = row["tier"]

        # Check if tenant already has an org membership (new memberships table)
        async with db.transaction() as conn:
            existing = await store._fetchone(
                conn,
                "SELECT org_id FROM memberships WHERE user_id = ? AND team_id IS NULL",
                tenant_id,
            )

        if existing:
            print(f"Skipping {tenant_id}: already in organization {existing['org_id']}")
            continue

        # Create a default organization for this tenant
        org_name = f"{tenant_id}-org"
        org_slug = tenant_id.lower().replace("_", "-").replace(".", "-")

        if dry_run:
            print(f"[DRY RUN] Would create org '{org_name}' (slug: {org_slug}) for tenant {tenant_id}")
            migrated += 1
            continue

        try:
            org = await create_org(
                name=org_name,
                slug=org_slug,
                tier=tier,
                settings={},
            )
            print(f"Created organization {org.org_id} ({org.name}) for tenant {tenant_id}")

            # Add tenant as org_admin
            await add_member(
                org_id=org.org_id,
                user_id=tenant_id,
                role="org_admin",
                status="active",
            )
            print(f"  Added {tenant_id} as org_admin to {org.org_id}")

            migrated += 1

        except Exception as e:
            print(f"ERROR migrating {tenant_id}: {e}", file=sys.stderr)

    return migrated


async def main():
    parser = argparse.ArgumentParser(description="Migrate existing tenants to organizations")
    parser.add_argument(
        "--db-path",
        default="strix.db",
        help="Path to SQLite database (default: strix.db)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    args = parser.parse_args()

    db_path = args.db_path
    if not Path(db_path).exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Migrating tenants to organizations (db: {db_path})...")
    if args.dry_run:
        print("DRY RUN MODE - no changes will be made")

    count = await migrate_tenants_to_orgs(db_path, args.dry_run)
    print(f"\nMigrated {count} tenant(s) to organizations.")

    await store.close_database()


if __name__ == "__main__":
    asyncio.run(main())
