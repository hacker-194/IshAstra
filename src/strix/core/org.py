"""Organization model and management.

An organization groups multiple tenants under a single administrative umbrella.
Org-level admin keys can manage all tenants within the organization.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

from strix.core import store


@dataclass(frozen=True)
class Organization:
    """An organization containing multiple tenants."""

    org_id: str
    name: str
    admin_key_hash: str
    tier: str
    created_at: float
    updated_at: float


# Valid organization tiers (matching tenant tiers)
ORG_TIER_ORDER = {"standard": 0, "elevated": 1, "unlimited": 2}


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def create_organization(
    *,
    name: str,
    tier: str = "standard",
    admin_key: str | None = None,
) -> tuple[str, str]:
    """Create a new organization.

    Returns (org_id, raw_admin_key). The raw key is shown only once.
    """
    if tier not in ORG_TIER_ORDER:
        raise ValueError(f"Invalid tier. Must be one of: {list(ORG_TIER_ORDER)}")

    org_id = f"org_{secrets.token_hex(8)}"
    raw_admin_key = admin_key or f"strix_org_{secrets.token_urlsafe(32)}"
    admin_key_hash = _hash_key(raw_admin_key)
    now = time.time()

    db = await store.get_database()
    async with db.transaction() as conn:
        await store._execute(
            conn,
            """INSERT INTO organizations (org_id, name, admin_key_hash, tier, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            org_id,
            name,
            admin_key_hash,
            tier,
            now,
            now,
        )

    return org_id, raw_admin_key


async def get_organization(org_id: str) -> Organization | None:
    """Load an organization by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM organizations WHERE org_id = ?", org_id)
    if row is None:
        return None
    return Organization(
        org_id=row["org_id"],
        name=row["name"],
        admin_key_hash=row["admin_key_hash"],
        tier=row["tier"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def validate_org_admin_key(api_key: str) -> Organization | None:
    """Validate an organization admin key and return the org."""
    if not api_key:
        return None
    digest = _hash_key(api_key)
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(
            conn,
            "SELECT * FROM organizations WHERE admin_key_hash = ?",
            digest,
        )
    if row is None:
        return None
    if not secrets.compare_digest(digest, row["admin_key_hash"]):
        return None
    return Organization(
        org_id=row["org_id"],
        name=row["name"],
        admin_key_hash=row["admin_key_hash"],
        tier=row["tier"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def list_organizations() -> list[dict[str, Any]]:
    """List all organizations (for global admins)."""
    db = await store.get_database()
    async with db.transaction() as conn:
        rows = await store._fetchall(conn, "SELECT * FROM organizations ORDER BY created_at DESC")
    return [
        {
            "org_id": row["org_id"],
            "name": row["name"],
            "tier": row["tier"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


async def add_tenant_to_org(org_id: str, tenant_id: str, role: str = "member") -> None:
    """Add a tenant to an organization."""
    if role not in ("member", "admin"):
        raise ValueError("role must be 'member' or 'admin'")

    org = await get_organization(org_id)
    if org is None:
        raise ValueError(f"Organization {org_id} not found")

    db = await store.get_database()
    async with db.transaction() as conn:
        # Check if tenant exists
        tenant_row = await store._fetchone(
            conn, "SELECT tenant_id FROM api_keys WHERE tenant_id = ?", tenant_id
        )
        if tenant_row is None:
            raise ValueError(f"Tenant {tenant_id} not found")

        # Check if already a member
        existing = await store._fetchone(
            conn,
            "SELECT 1 FROM org_memberships WHERE org_id = ? AND tenant_id = ?",
            org_id,
            tenant_id,
        )
        if existing:
            raise ValueError(f"Tenant {tenant_id} is already a member of organization {org_id}")

        await store._execute(
            conn,
            """INSERT INTO org_memberships (org_id, tenant_id, role, joined_at)
               VALUES (?, ?, ?, ?)""",
            org_id,
            tenant_id,
            role,
            time.time(),
        )


async def remove_tenant_from_org(org_id: str, tenant_id: str) -> bool:
    """Remove a tenant from an organization. Returns True if removed."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "DELETE FROM org_memberships WHERE org_id = ? AND tenant_id = ?",
            org_id,
            tenant_id,
        )
    return cursor.rowcount > 0


async def get_org_tenants(org_id: str) -> list[dict[str, Any]]:
    """List all tenants in an organization."""
    db = await store.get_database()
    async with db.transaction() as conn:
        rows = await store._fetchall(
            conn,
            """SELECT ak.tenant_id, ak.tier, ak.admin, ak.active, ak.scope, om.role, om.joined_at
               FROM api_keys ak
               JOIN org_memberships om ON om.tenant_id = ak.tenant_id
               WHERE om.org_id = ?
               ORDER BY om.joined_at""",
            org_id,
        )
    return [
        {
            "tenant_id": row["tenant_id"],
            "tier": row["tier"],
            "admin": bool(row["admin"]),
            "active": bool(row["active"]),
            "scope": row["scope"],
            "org_role": row["role"],
            "joined_at": row["joined_at"],
        }
        for row in rows
    ]


async def get_tenant_org(tenant_id: str) -> str | None:
    """Get the organization ID for a tenant, if any."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT org_id FROM org_memberships WHERE tenant_id = ?", tenant_id)
    return row["org_id"] if row else None


async def update_org_tier(org_id: str, tier: str) -> None:
    """Update an organization's tier (org admin only)."""
    if tier not in ORG_TIER_ORDER:
        raise ValueError(f"Invalid tier. Must be one of: {list(ORG_TIER_ORDER)}")

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE organizations SET tier = ?, updated_at = ? WHERE org_id = ?",
            tier,
            time.time(),
            org_id,
        )
    if cursor.rowcount == 0:
        raise ValueError(f"Organization {org_id} not found")


async def rotate_org_admin_key(org_id: str) -> str:
    """Rotate the organization admin key. Returns new raw key."""
    raw_key = f"strix_org_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    now = time.time()

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE organizations SET admin_key_hash = ?, updated_at = ? WHERE org_id = ?",
            key_hash,
            now,
            org_id,
        )
    if cursor.rowcount == 0:
        raise ValueError(f"Organization {org_id} not found")

    return raw_key


async def migrate_tenant_to_org(tenant_id: str, org_name: str | None = None) -> tuple[str, str]:
    """Migrate an existing tenant to a new single-tenant organization.

    Returns (org_id, org_admin_key).
    """
    # Check if tenant already has an org
    existing_org = await get_tenant_org(tenant_id)
    if existing_org:
        raise ValueError(f"Tenant {tenant_id} already belongs to organization {existing_org}")

    name = org_name or f"{tenant_id}-org"
    org_id, admin_key = await create_organization(name=name, tier="standard")
    await add_tenant_to_org(org_id, tenant_id, role="admin")
    return org_id, admin_key
