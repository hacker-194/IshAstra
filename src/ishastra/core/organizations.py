"""Organization hierarchy models: organizations, teams, and memberships.

This module provides the data models and store functions for a three-level hierarchy:
- Organization: top-level container (id, name, slug, settings, created_at)
- Team: belongs to an organization (id, org_id, name, slug, role_mappings, created_at)
- Membership: links users to orgs/teams with roles (id, org_id, team_id, user_id, role, status, joined_at)

Role definitions:
- org_admin: full org access, can manage teams and members
- org_member: basic org access, can view org resources
- team_lead: can manage team members and team resources
- team_member: can access team resources
- viewer: read-only access to assigned resources
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from ishastra.core import store

ROLE_ORDER = {
    "viewer": 0,
    "team_member": 10,
    "org_member": 20,
    "team_lead": 30,
    "org_admin": 40,
}

VALID_ROLES = frozenset(ROLE_ORDER.keys())


VALID_STATUSES = frozenset({"active", "pending", "suspended", "removed"})


def role_rank(role: str) -> int:
    """Get numeric rank for a role (higher = more permissions)."""
    return ROLE_ORDER.get(role, -1)


def can_manage_role(actor_role: str, target_role: str) -> bool:
    """Check if actor_role can manage target_role."""
    return role_rank(actor_role) > role_rank(target_role)


def _slugify(value: str) -> str:
    """Convert a string to a URL-safe slug."""
    import re

    slug = value.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[-\s]+", "-", slug)
    return slug[:64]


def _generate_id(prefix: str) -> str:
    """Generate a prefixed random ID."""
    return f"{prefix}_{secrets.token_hex(8)}"


@dataclass(frozen=True)
class Organization:
    """An organization containing teams and members."""

    org_id: str
    name: str
    slug: str
    settings: dict[str, Any]
    tier: str
    created_at: float
    updated_at: float

    @classmethod
    def from_row(cls, row: Any) -> Organization:
        return cls(
            org_id=row["org_id"],
            name=row["name"],
            slug=row["slug"],
            settings=json.loads(row["settings"]) if row["settings"] else {},
            tier=row["tier"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "name": self.name,
            "slug": self.slug,
            "settings": self.settings,
            "tier": self.tier,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class Team:
    """A team within an organization."""

    team_id: str
    org_id: str
    name: str
    slug: str
    role_mappings: dict[str, str]
    created_at: float

    @classmethod
    def from_row(cls, row: Any) -> Team:
        return cls(
            team_id=row["team_id"],
            org_id=row["org_id"],
            name=row["name"],
            slug=row["slug"],
            role_mappings=json.loads(row["role_mappings"]) if row["role_mappings"] else {},
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "org_id": self.org_id,
            "name": self.name,
            "slug": self.slug,
            "role_mappings": self.role_mappings,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class Membership:
    """A user's membership in an organization and/or team."""

    membership_id: str
    org_id: str
    team_id: str | None
    user_id: str
    role: str
    status: str
    joined_at: float

    @classmethod
    def from_row(cls, row: Any) -> Membership:
        return cls(
            membership_id=row["membership_id"],
            org_id=row["org_id"],
            team_id=row["team_id"] if row["team_id"] else None,
            user_id=row["user_id"],
            role=row["role"],
            status=row["status"],
            joined_at=row["joined_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "membership_id": self.membership_id,
            "org_id": self.org_id,
            "team_id": self.team_id,
            "user_id": self.user_id,
            "role": self.role,
            "status": self.status,
            "joined_at": self.joined_at,
        }


MIGRATIONS_ORG_HIERARCHY: list[tuple[int, str]] = [
    (
        21,
        """
    -- Migration 21: Enhanced organizations table with slug and settings
    CREATE TABLE IF NOT EXISTS organizations_v2 (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL UNIQUE,
        settings       TEXT NOT NULL DEFAULT '{}',
        tier           TEXT NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS organizations_by_slug ON organizations_v2 (slug);

    -- Migration existing data if organizations table exists
    INSERT INTO organizations_v2 (org_id, name, slug, settings, tier, created_at, updated_at)
    SELECT org_id, name, LOWER(REPLACE(name, ' ', '-')), '{}', tier, created_at, updated_at
    FROM organizations WHERE NOT EXISTS (SELECT 1 FROM organizations_v2 WHERE org_id = organizations.org_id);

    DROP TABLE IF EXISTS organizations;
    ALTER TABLE organizations_v2 RENAME TO organizations;
    """,
    ),
    (
        22,
        """
    -- Migration 22: Teams table
    CREATE TABLE IF NOT EXISTS teams (
        team_id        TEXT PRIMARY KEY,
        org_id         TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL,
        role_mappings  TEXT NOT NULL DEFAULT '{}',
        created_at     REAL NOT NULL,
        UNIQUE(org_id, slug)
    );
    CREATE INDEX IF NOT EXISTS teams_by_org ON teams (org_id);
    """,
    ),
    (
        23,
        """
    -- Migration 23: Memberships table (org and team level)
    CREATE TABLE IF NOT EXISTS memberships (
        membership_id  TEXT PRIMARY KEY,
        org_id         TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        team_id        TEXT REFERENCES teams (team_id) ON DELETE SET NULL,
        user_id        TEXT NOT NULL,
        role           TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'active',
        joined_at      REAL NOT NULL,
        UNIQUE(org_id, team_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS memberships_by_org ON memberships (org_id);
    CREATE INDEX IF NOT EXISTS memberships_by_team ON memberships (team_id);
    CREATE INDEX IF NOT EXISTS memberships_by_user ON memberships (user_id);
    """,
    ),
]


MIGRATIONS_ORG_HIERARCHY_PG: list[tuple[int, str]] = [
    (
        21,
        """
    CREATE TABLE IF NOT EXISTS organizations_v2 (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL UNIQUE,
        settings       TEXT NOT NULL DEFAULT '{}',
        tier           TEXT NOT NULL,
        created_at     DOUBLE PRECISION NOT NULL,
        updated_at     DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS organizations_by_slug ON organizations_v2 (slug);

    INSERT INTO organizations_v2 (org_id, name, slug, settings, tier, created_at, updated_at)
    SELECT org_id, name, LOWER(REPLACE(name, ' ', '-')), '{}', tier, created_at, updated_at
    FROM organizations WHERE NOT EXISTS (SELECT 1 FROM organizations_v2 WHERE org_id = organizations.org_id);

    DROP TABLE IF EXISTS organizations;
    ALTER TABLE organizations_v2 RENAME TO organizations;
    """,
    ),
    (
        22,
        """
    CREATE TABLE IF NOT EXISTS teams (
        team_id        TEXT PRIMARY KEY,
        org_id         TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL,
        role_mappings  TEXT NOT NULL DEFAULT '{}',
        created_at     DOUBLE PRECISION NOT NULL,
        UNIQUE(org_id, slug)
    );
    CREATE INDEX IF NOT EXISTS teams_by_org ON teams (org_id);
    """,
    ),
    (
        23,
        """
    CREATE TABLE IF NOT EXISTS memberships (
        membership_id  TEXT PRIMARY KEY,
        org_id         TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        team_id        TEXT REFERENCES teams (team_id) ON DELETE SET NULL,
        user_id        TEXT NOT NULL,
        role           TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'active',
        joined_at      DOUBLE PRECISION NOT NULL,
        UNIQUE(org_id, team_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS memberships_by_org ON memberships (org_id);
    CREATE INDEX IF NOT EXISTS memberships_by_team ON memberships (team_id);
    CREATE INDEX IF NOT EXISTS memberships_by_user ON memberships (user_id);
    """,
    ),
]


async def create_org(
    *,
    name: str,
    slug: str | None = None,
    settings: dict[str, Any] | None = None,
) -> Organization:
    """Create a new organization. All organizations are free/unlimited."""
    final_slug = slug or _slugify(name)
    if len(final_slug) > 64:
        raise ValueError("Slug too long (max 64 characters)")

    org_id = _generate_id("org")
    now = time.time()
    settings_json = json.dumps(settings or {})
    tier = "free"  # Only tier - all features unlimited

    db = await store.get_database()
    async with db.transaction() as conn:
        existing = await store._fetchone(conn, "SELECT 1 FROM organizations WHERE slug = ?", final_slug)
        if existing:
            raise ValueError(f"Organization with slug '{final_slug}' already exists")

        await store._execute(
            conn,
            """INSERT INTO organizations (org_id, name, slug, settings, tier, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            org_id,
            name,
            final_slug,
            settings_json,
            tier,
            now,
            now,
        )

    return Organization(
        org_id=org_id,
        name=name,
        slug=final_slug,
        settings=settings or {},
        tier=tier,
        created_at=now,
        updated_at=now,
    )


async def get_org(org_id: str) -> Organization | None:
    """Load an organization by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM organizations WHERE org_id = ?", org_id)
    if row is None:
        return None
    return Organization.from_row(row)


async def get_org_by_slug(slug: str) -> Organization | None:
    """Load an organization by slug."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM organizations WHERE slug = ?", slug)
    if row is None:
        return None
    return Organization.from_row(row)


async def list_orgs(*, limit: int = 50, offset: int = 0) -> list[Organization]:
    """List all organizations."""
    db = await store.get_database()
    async with db.transaction() as conn:
        rows = await store._fetchall(
            conn, "SELECT * FROM organizations ORDER BY created_at DESC LIMIT ? OFFSET ?", limit, offset
        )
    return [Organization.from_row(row) for row in rows]


async def update_org(
    org_id: str,
    *,
    name: str | None = None,
    slug: str | None = None,
    settings: dict[str, Any] | None = None,
) -> Organization | None:
    """Update an organization. Tier is fixed to 'free' (all features unlimited)."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM organizations WHERE org_id = ?", org_id)
        if row is None:
            return None

        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if slug is not None:
            if len(slug) > 64:
                raise ValueError("Slug too long (max 64 characters)")
            existing = await store._fetchone(
                conn, "SELECT 1 FROM organizations WHERE slug = ? AND org_id != ?", slug, org_id
            )
            if existing:
                raise ValueError(f"Organization with slug '{slug}' already exists")
            updates.append("slug = ?")
            params.append(slug)
        if settings is not None:
            updates.append("settings = ?")
            params.append(json.dumps(settings))

        if not updates:
            return Organization.from_row(row)

        updates.append("updated_at = ?")
        params.append(str(time.time()))
        params.append(org_id)

        await store._execute(conn, f"UPDATE organizations SET {', '.join(updates)} WHERE org_id = ?", *params)

        updated = await store._fetchone(conn, "SELECT * FROM organizations WHERE org_id = ?", org_id)
    return Organization.from_row(updated) if updated else None


async def delete_org(org_id: str) -> bool:
    """Delete an organization (cascades to teams and memberships)."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(conn, "DELETE FROM organizations WHERE org_id = ?", org_id)
    return cursor.rowcount > 0


async def create_team(
    *,
    org_id: str,
    name: str,
    slug: str | None = None,
    role_mappings: dict[str, str] | None = None,
) -> Team:
    """Create a new team within an organization."""
    org = await get_org(org_id)
    if org is None:
        raise ValueError(f"Organization {org_id} not found")

    final_slug = slug or _slugify(name)
    if len(final_slug) > 64:
        raise ValueError("Slug too long (max 64 characters)")

    team_id = _generate_id("team")
    now = time.time()
    role_mappings_json = json.dumps(role_mappings or {})

    db = await store.get_database()
    async with db.transaction() as conn:
        existing = await store._fetchone(
            conn, "SELECT 1 FROM teams WHERE org_id = ? AND slug = ?", org_id, final_slug
        )
        if existing:
            raise ValueError(f"Team with slug '{final_slug}' already exists in this organization")

        await store._execute(
            conn,
            """INSERT INTO teams (team_id, org_id, name, slug, role_mappings, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            team_id,
            org_id,
            name,
            final_slug,
            role_mappings_json,
            now,
        )

    return Team(
        team_id=team_id,
        org_id=org_id,
        name=name,
        slug=final_slug,
        role_mappings=role_mappings or {},
        created_at=now,
    )


async def get_team(team_id: str) -> Team | None:
    """Load a team by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM teams WHERE team_id = ?", team_id)
    if row is None:
        return None
    return Team.from_row(row)


async def get_team_by_slug(org_id: str, slug: str) -> Team | None:
    """Load a team by org ID and slug."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM teams WHERE org_id = ? AND slug = ?", org_id, slug)
    if row is None:
        return None
    return Team.from_row(row)


async def list_teams(org_id: str, *, limit: int = 50, offset: int = 0) -> list[Team]:
    """List teams in an organization."""
    db = await store.get_database()
    async with db.transaction() as conn:
        rows = await store._fetchall(
            conn,
            "SELECT * FROM teams WHERE org_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            org_id,
            limit,
            offset,
        )
    return [Team.from_row(row) for row in rows]


async def update_team(
    team_id: str,
    *,
    name: str | None = None,
    slug: str | None = None,
    role_mappings: dict[str, str] | None = None,
) -> Team | None:
    """Update a team."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM teams WHERE team_id = ?", team_id)
        if row is None:
            return None

        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if slug is not None:
            if len(slug) > 64:
                raise ValueError("Slug too long (max 64 characters)")
            existing = await store._fetchone(
                conn,
                "SELECT 1 FROM teams WHERE org_id = ? AND slug = ? AND team_id != ?",
                row["org_id"],
                slug,
                team_id,
            )
            if existing:
                raise ValueError(f"Team with slug '{slug}' already exists in this organization")
            updates.append("slug = ?")
            params.append(slug)
        if role_mappings is not None:
            updates.append("role_mappings = ?")
            params.append(json.dumps(role_mappings))

        if not updates:
            return Team.from_row(row)

        params.append(team_id)
        await store._execute(conn, f"UPDATE teams SET {', '.join(updates)} WHERE team_id = ?", *params)

        updated = await store._fetchone(conn, "SELECT * FROM teams WHERE team_id = ?", team_id)
    return Team.from_row(updated) if updated else None


async def delete_team(team_id: str) -> bool:
    """Delete a team (cascades to memberships)."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(conn, "DELETE FROM teams WHERE team_id = ?", team_id)
    return cursor.rowcount > 0


async def add_member(
    *,
    org_id: str,
    user_id: str,
    role: str = "org_member",
    team_id: str | None = None,
    status: str = "active",
) -> Membership:
    """Add a member to an organization (and optionally a team)."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role. Must be one of: {sorted(VALID_ROLES)}")
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status. Must be one of: {sorted(VALID_STATUSES)}")

    org = await get_org(org_id)
    if org is None:
        raise ValueError(f"Organization {org_id} not found")

    if team_id is not None:
        team = await get_team(team_id)
        if team is None or team.org_id != org_id:
            raise ValueError(f"Team {team_id} not found in organization {org_id}")

    membership_id = _generate_id("mem")
    now = time.time()

    db = await store.get_database()
    async with db.transaction() as conn:
        if team_id is not None:
            existing = await store._fetchone(
                conn,
                "SELECT 1 FROM memberships WHERE org_id = ? AND team_id = ? AND user_id = ?",
                org_id,
                team_id,
                user_id,
            )
        else:
            existing = await store._fetchone(
                conn,
                "SELECT 1 FROM memberships WHERE org_id = ? AND team_id IS NULL AND user_id = ?",
                org_id,
                user_id,
            )
        if existing:
            raise ValueError(f"User {user_id} is already a member of this org/team")

        await store._execute(
            conn,
            """INSERT INTO memberships (membership_id, org_id, team_id, user_id, role, status, joined_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            membership_id,
            org_id,
            team_id,
            user_id,
            role,
            status,
            now,
        )

    return Membership(
        membership_id=membership_id,
        org_id=org_id,
        team_id=team_id,
        user_id=user_id,
        role=role,
        status=status,
        joined_at=now,
    )


async def get_membership(membership_id: str) -> Membership | None:
    """Load a membership by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM memberships WHERE membership_id = ?", membership_id)
    if row is None:
        return None
    return Membership.from_row(row)


async def get_user_memberships(user_id: str, org_id: str | None = None) -> list[Membership]:
    """Get all memberships for a user, optionally filtered by org."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if org_id is not None:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM memberships WHERE user_id = ? AND org_id = ? ORDER BY joined_at",
                user_id,
                org_id,
            )
        else:
            rows = await store._fetchall(
                conn, "SELECT * FROM memberships WHERE user_id = ? ORDER BY joined_at", user_id
            )
    return [Membership.from_row(row) for row in rows]


async def get_org_memberships(org_id: str, team_id: str | None = None) -> list[Membership]:
    """Get all memberships in an organization, optionally filtered by team."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if team_id is not None:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM memberships WHERE org_id = ? AND team_id = ? ORDER BY joined_at",
                org_id,
                team_id,
            )
        else:
            rows = await store._fetchall(
                conn, "SELECT * FROM memberships WHERE org_id = ? ORDER BY joined_at", org_id
            )
    return [Membership.from_row(row) for row in rows]


async def update_member_role(
    membership_id: str,
    *,
    role: str,
    actor_role: str | None = None,
) -> Membership | None:
    """Update a member's role. Optionally validate actor can manage target role."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role. Must be one of: {sorted(VALID_ROLES)}")

    if actor_role is not None and not can_manage_role(actor_role, role):
        raise ValueError(f"Role {actor_role} cannot assign role {role}")

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE memberships SET role = ? WHERE membership_id = ?",
            role,
            membership_id,
        )
        if cursor.rowcount == 0:
            return None
        row = await store._fetchone(conn, "SELECT * FROM memberships WHERE membership_id = ?", membership_id)
    return Membership.from_row(row) if row else None


async def update_member_status(
    membership_id: str,
    *,
    status: str,
) -> Membership | None:
    """Update a member's status."""
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status. Must be one of: {sorted(VALID_STATUSES)}")

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE memberships SET status = ? WHERE membership_id = ?",
            status,
            membership_id,
        )
        if cursor.rowcount == 0:
            return None
        row = await store._fetchone(conn, "SELECT * FROM memberships WHERE membership_id = ?", membership_id)
    return Membership.from_row(row) if row else None


async def remove_member(membership_id: str) -> bool:
    """Remove a member (soft delete by setting status to 'removed')."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE memberships SET status = 'removed' WHERE membership_id = ?",
            membership_id,
        )
    return cursor.rowcount > 0


async def delete_membership(membership_id: str) -> bool:
    """Permanently delete a membership record."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(conn, "DELETE FROM memberships WHERE membership_id = ?", membership_id)
    return cursor.rowcount > 0


async def get_user_org_role(user_id: str, org_id: str) -> str | None:
    """Get the highest role a user has in an organization (across all teams)."""
    memberships = await get_user_memberships(user_id, org_id)
    if not memberships:
        return None

    return max(
        (m.role for m in memberships if m.status == "active"),
        key=role_rank,
        default=None,
    )


async def get_user_team_role(user_id: str, team_id: str) -> str | None:
    """Get a user's role in a specific team."""
    memberships = await get_user_memberships(user_id)
    for m in memberships:
        if m.team_id == team_id and m.status == "active":
            return m.role
    return None


async def user_has_org_access(user_id: str, org_id: str, min_role: str = "viewer") -> bool:
    """Check if user has at least min_role in organization."""
    user_role = await get_user_org_role(user_id, org_id)
    if user_role is None:
        return False
    return role_rank(user_role) >= role_rank(min_role)


async def user_has_team_access(user_id: str, team_id: str, min_role: str = "viewer") -> bool:
    """Check if user has at least min_role in team."""
    user_role = await get_user_team_role(user_id, team_id)
    if user_role is None:
        return False
    return role_rank(user_role) >= role_rank(min_role)


async def run_org_hierarchy_migrations(db_path: str | None = None) -> int:
    """Apply organization hierarchy migrations (versions 21-23).

    Returns the final schema version.
    """
    if db_path:
        store.configure(db_path)
    db = await store.get_database()

    version = await db.schema_version()
    print(f"Current schema version: {version}")

    migrations_to_apply = [(v, sql) for v, sql in MIGRATIONS_ORG_HIERARCHY if v > version]

    for target, script in migrations_to_apply:
        print(f"Applying migration {target}...")
        async with db.transaction() as conn:
            try:
                for statement in script.split(";"):
                    stmt = "\n".join(
                        line for line in statement.splitlines() if not line.strip().startswith("--")
                    ).strip()
                    if stmt:
                        await conn.execute(stmt)

                if db.is_postgresql():
                    await conn.execute(
                        "INSERT INTO settings (key, value) VALUES ('schema_version', $1) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                        str(target),
                    )
                else:
                    await conn.execute(f"PRAGMA user_version = {int(target)}")
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        version = target
        print(f"Migration {target} applied")

    final_version = await db.schema_version()
    print(f"Final schema version: {final_version}")
    return final_version


if __name__ == "__main__":
    import asyncio
    import os

    db_path = os.environ.get("ISHASTRA_DB_PATH", "ishastra.db")
    asyncio.run(run_org_hierarchy_migrations(db_path))
