"""Project-scoped API key extensions for multi-project tenant isolation.

Extends the existing api_keys schema with project-level scoping, allowing keys
to be restricted to specific projects within a tenant. Integrates with existing
auth.py validate_api_key() and rate limiting.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from strix.core.store import (
    _execute,
    _fetchall,
    _fetchone,
    get_database,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectKey:
    """Project-scoped API key record."""

    tenant_id: str
    key_hash: str
    tier: str
    admin: bool
    active: bool
    scope: str  # read | write
    scope_type: str  # tenant | project
    project_id: str | None
    allowed_projects: list[str]
    resource_filters: dict[str, Any]
    created_at: float
    expires_at: float | None
    last_used: float | None
    rotated_at: float | None
    ai_enabled: bool
    include_hosts: str | None


def _row_to_project_key(row: Any) -> ProjectKey:
    """Convert a database row to ProjectKey."""

    # sqlite3.Row doesn't have .get(), use dict-style access with fallback
    def get(key: str, default=None):
        try:
            return row[key]
        except KeyError:
            return default

    return ProjectKey(
        tenant_id=row["tenant_id"],
        key_hash=row["key_hash"],
        tier=row["tier"],
        admin=bool(row["admin"]),
        active=bool(row["active"]),
        scope=get("scope") or "write",
        scope_type=get("scope_type") or "tenant",
        project_id=get("project_id"),
        allowed_projects=json.loads(row["allowed_projects"]) if get("allowed_projects") else [],
        resource_filters=json.loads(row["resource_filters"]) if get("resource_filters") else {},
        created_at=row["created_at"],
        expires_at=get("expires_at"),
        last_used=get("last_used"),
        rotated_at=get("rotated_at"),
        ai_enabled=bool(get("ai_enabled", False)),
        include_hosts=get("include_hosts"),
    )


# ---------------------------------------------------------------------------
# Core store functions
# ---------------------------------------------------------------------------


async def save_project_key(
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
    scope: str = "write",
    scope_type: str = "tenant",
    project_id: str | None = None,
    allowed_projects: list[str] | None = None,
    resource_filters: dict[str, Any] | None = None,
    include_hosts: str | None = None,
) -> None:
    """Persist a project-scoped API key."""
    db = await get_database()
    async with db.transaction() as conn:
        # Use project_id as the project column value to avoid unique constraint
        # violation on (tenant_id, project) from migration 9
        project_col = project_id if project_id is not None else "default"
        await _execute(
            conn,
            """INSERT INTO api_keys (
                tenant_id, key_hash, tier, admin, active, scope, scope_type,
                project, project_id, allowed_projects, resource_filters,
                created_at, expires_at, last_used, rotated_at, ai_enabled, include_hosts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, project_id) DO UPDATE SET
                key_hash = excluded.key_hash,
                tier = excluded.tier,
                admin = excluded.admin,
                active = excluded.active,
                scope = excluded.scope,
                scope_type = excluded.scope_type,
                project = excluded.project,
                allowed_projects = excluded.allowed_projects,
                resource_filters = excluded.resource_filters,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                last_used = excluded.last_used,
                rotated_at = excluded.rotated_at,
                ai_enabled = excluded.ai_enabled,
                include_hosts = excluded.include_hosts""",
            tenant_id,
            key_hash,
            tier,
            bool(admin),
            bool(active),
            scope,
            scope_type,
            project_col,
            project_id,
            json.dumps(allowed_projects or []),
            json.dumps(resource_filters or {}),
            created_at,
            expires_at,
            last_used,
            rotated_at,
            bool(ai_enabled),
            include_hosts,
        )


async def load_project_keys(tenant_id: str | None = None) -> list[ProjectKey]:
    """Load all project keys, optionally filtered by tenant."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant_id:
            rows = await _fetchall(conn, "SELECT * FROM api_keys WHERE tenant_id = ?", tenant_id)
        else:
            rows = await _fetchall(conn, "SELECT * FROM api_keys")
        return [_row_to_project_key(row) for row in rows]


async def get_project_key(tenant_id: str, project_id: str | None = None) -> ProjectKey | None:
    """Get a specific project key by tenant and project."""
    db = await get_database()
    async with db.transaction() as conn:
        if project_id is None:
            row = await _fetchone(
                conn,
                "SELECT * FROM api_keys WHERE tenant_id = ? AND project_id IS NULL",
                tenant_id,
            )
        else:
            row = await _fetchone(
                conn,
                "SELECT * FROM api_keys WHERE tenant_id = ? AND project_id = ?",
                tenant_id,
                project_id,
            )
        return _row_to_project_key(row) if row else None


async def list_project_keys(tenant_id: str) -> list[ProjectKey]:
    """List all project keys for a tenant (including tenant-scoped and project-scoped)."""
    return await load_project_keys(tenant_id)


async def deactivate_project_key(tenant_id: str, project_id: str | None = None) -> bool:
    """Deactivate a project key."""
    db = await get_database()
    async with db.transaction() as conn:
        if project_id is None:
            cursor = await _execute(
                conn,
                "UPDATE api_keys SET active = ? WHERE tenant_id = ? AND project_id IS NULL AND active = ?",
                False,
                tenant_id,
                True,
            )
        else:
            cursor = await _execute(
                conn,
                "UPDATE api_keys SET active = ? WHERE tenant_id = ? AND project_id = ? AND active = ?",
                False,
                tenant_id,
                project_id,
                True,
            )
        return bool(cursor.rowcount)


# ---------------------------------------------------------------------------
# Key lifecycle functions
# ---------------------------------------------------------------------------


async def create_project_key(
    *,
    tenant_id: str,
    tier: str = "standard",
    admin: bool = False,
    ttl_days: int | None = None,
    scope: str = "write",
    scope_type: str = "tenant",
    project_id: str | None = None,
    allowed_projects: list[str] | None = None,
    resource_filters: dict[str, Any] | None = None,
    include_hosts: str | None = None,
) -> tuple[str, ProjectKey]:
    """Create a new project-scoped API key.

    Returns (raw_key, ProjectKey). The raw key is shown only once.
    """
    if scope not in ("read", "write"):
        raise ValueError("scope must be 'read' or 'write'")
    if scope_type not in ("tenant", "project"):
        raise ValueError("scope_type must be 'tenant' or 'project'")
    if scope_type == "project" and not project_id:
        raise ValueError("project_id required when scope_type is 'project'")
    if ttl_days is not None and (ttl_days < 1 or ttl_days > 3650):
        raise ValueError("ttl_days must be between 1 and 3650")

    raw_key = f"strix_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = time.time()
    expires_at = now + ttl_days * 86400.0 if ttl_days is not None else None

    record = ProjectKey(
        tenant_id=tenant_id,
        key_hash=key_hash,
        tier=tier,
        admin=admin,
        active=True,
        scope=scope,
        scope_type=scope_type,
        project_id=project_id,
        allowed_projects=allowed_projects or [],
        resource_filters=resource_filters or {},
        created_at=now,
        expires_at=expires_at,
        last_used=None,
        rotated_at=now,
        ai_enabled=False,
        include_hosts=include_hosts,
    )

    await save_project_key(
        tenant_id=tenant_id,
        key_hash=key_hash,
        tier=tier,
        admin=admin,
        active=True,
        created_at=now,
        expires_at=expires_at,
        last_used=None,
        rotated_at=now,
        ai_enabled=False,
        scope=scope,
        scope_type=scope_type,
        project_id=project_id,
        allowed_projects=allowed_projects,
        resource_filters=resource_filters,
        include_hosts=include_hosts,
    )

    return raw_key, record


async def validate_project_key(api_key: str | None) -> ProjectKey | None:
    """Validate an API key and return the ProjectKey if valid.

    This replaces the in-memory validation in security.py with a database-backed
    version that supports project scoping.
    """
    if not api_key:
        return None

    digest = hashlib.sha256(api_key.encode()).hexdigest()
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1",
            digest,
        )
        if not row:
            return None

        # Check expiration - sqlite3.Row.__contains__ checks indices, not names
        expires_at = row["expires_at"] if "expires_at" in row.keys() else None  # noqa: SIM118
        if expires_at is not None and time.time() >= float(expires_at):
            await _execute(
                conn,
                "UPDATE api_keys SET active = 0 WHERE key_hash = ?",
                digest,
            )
            return None

        # Update last_used
        now = time.time()
        await _execute(
            conn,
            "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
            now,
            digest,
        )

        # Fetch updated row to get the new last_used value
        row = await _fetchone(
            conn,
            "SELECT * FROM api_keys WHERE key_hash = ?",
            digest,
        )

        return _row_to_project_key(row) if row else None


async def rotate_project_key(
    tenant_id: str,
    *,
    project_id: str | None = None,
    ttl_days: int | None = None,
) -> tuple[str, ProjectKey] | None:
    """Rotate a project key, preserving its scope configuration.

    Since the schema only allows one key per tenant (PK on tenant_id),
    this updates the existing key in place with a new hash.
    """
    existing = await get_project_key(tenant_id, project_id)
    if not existing or not existing.active:
        return None

    now = time.time()
    if existing.expires_at is not None and now >= float(existing.expires_at):
        return None

    new_expires_at = (now + ttl_days * 86400.0) if ttl_days is not None else existing.expires_at
    raw_key = f"strix_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    new_record = ProjectKey(
        tenant_id=existing.tenant_id,
        key_hash=key_hash,
        tier=existing.tier,
        admin=existing.admin,
        active=True,
        scope=existing.scope,
        scope_type=existing.scope_type,
        project_id=existing.project_id,
        allowed_projects=existing.allowed_projects,
        resource_filters=existing.resource_filters,
        created_at=now,
        expires_at=new_expires_at,
        last_used=None,
        rotated_at=now,
        ai_enabled=existing.ai_enabled,
        include_hosts=existing.include_hosts,
    )

    # Update existing key in place (schema only allows one key per tenant)
    db = await get_database()
    async with db.transaction() as conn:
        project_col = existing.project_id if existing.project_id is not None else "default"
        await _execute(
            conn,
            """UPDATE api_keys SET
                key_hash = ?, tier = ?, admin = ?, active = ?,
                scope = ?, scope_type = ?, project = ?, project_id = ?,
                allowed_projects = ?, resource_filters = ?,
                created_at = ?, expires_at = ?, last_used = ?, rotated_at = ?,
                ai_enabled = ?, include_hosts = ?
             WHERE tenant_id = ? AND (project_id = ? OR (project_id IS NULL AND ? IS NULL))""",
            key_hash,
            existing.tier,
            bool(existing.admin),
            True,
            existing.scope,
            existing.scope_type,
            project_col,
            existing.project_id,
            json.dumps(existing.allowed_projects or []),
            json.dumps(existing.resource_filters or {}),
            now,
            new_expires_at,
            None,
            now,
            bool(existing.ai_enabled),
            existing.include_hosts,
            existing.tenant_id,
            existing.project_id,
            existing.project_id,
        )

    return raw_key, new_record


# ---------------------------------------------------------------------------
# Authorization: check_key_scope
# ---------------------------------------------------------------------------


def check_key_scope(
    key: ProjectKey,
    required_project: str | None = None,
    required_action: str = "read",
) -> bool:
    """Check if a key has the required scope for a project/action.

    Args:
        key: The validated ProjectKey
        required_project: Project ID being accessed (None for tenant-level)
        required_action: 'read' or 'write'

    Returns:
        True if the key is authorized for the action on the project
    """
    if not key.active:
        return False

    # Check action scope
    if required_action == "write" and key.scope == "read":
        return False

    # Tenant-scoped keys have access to all projects in the tenant
    if key.scope_type == "tenant":
        return True

    # Project-scoped keys: check project_id or allowed_projects
    if key.scope_type == "project":
        if key.project_id and key.project_id == required_project:
            return True
        return bool(required_project and required_project in key.allowed_projects)

    return False


async def authorize_request(
    api_key: str,
    required_project: str | None = None,
    required_action: str = "read",
) -> ProjectKey | None:
    """Full authorization: validate key and check scope in one call."""
    key = await validate_project_key(api_key)
    if not key:
        return None
    if not check_key_scope(key, required_project, required_action):
        return None
    return key


# ---------------------------------------------------------------------------
# Project-scoped rate limiting
# ---------------------------------------------------------------------------


async def get_project_rate_limit_key(
    key: ProjectKey,
    route_class: str,
) -> str:
    """Generate rate limit bucket key for a project-scoped key.

    Format: {route_class}:{scope_type}:{tenant_id}:{project_id or 'tenant'}
    """
    if key.scope_type == "project" and key.project_id:
        return f"{route_class}:project:{key.tenant_id}:{key.project_id}"
    return f"{route_class}:tenant:{key.tenant_id}"


# ---------------------------------------------------------------------------
# Integration with existing auth.py validate_api_key()
# ---------------------------------------------------------------------------


async def validate_api_key_with_scopes(api_key: str | None) -> dict[str, Any] | None:
    """Extended validate_api_key that returns project scope info.

    Compatible with the existing API in security.py but includes
    project-scoped fields.
    """
    key = await validate_project_key(api_key)
    if not key:
        return None

    expires_at = key.expires_at
    if expires_at is not None and time.time() >= float(expires_at):
        return None

    return {
        "tenant_id": key.tenant_id,
        "tier": key.tier,
        "admin": key.admin,
        "global_admin": key.admin,
        "role": "admin" if key.admin else "analyst",
        "scope": key.scope,
        "scope_type": key.scope_type,
        "project_id": key.project_id,
        "allowed_projects": key.allowed_projects,
        "resource_filters": key.resource_filters,
        "include_hosts": key.include_hosts,
        "record": {
            "key_hash": key.key_hash,
            "tier": key.tier,
            "admin": key.admin,
            "active": key.active,
            "scope": key.scope,
            "scope_type": key.scope_type,
            "project_id": key.project_id,
            "allowed_projects": key.allowed_projects,
            "resource_filters": key.resource_filters,
            "created_at": key.created_at,
            "last_used": key.last_used,
            "expires_at": key.expires_at,
            "rotated_at": key.rotated_at,
            "ai_enabled": key.ai_enabled,
            "include_hosts": key.include_hosts,
        },
    }
