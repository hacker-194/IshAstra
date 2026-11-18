"""Tenant model and management with organization support."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from strix.core import store


@dataclass(frozen=True)
class Tenant:
    """A tenant (customer) in the system."""

    tenant_id: str
    org_id: str | None
    name: str
    tier: str
    admin: bool
    active: bool
    scope: str
    created_at: float


async def list_tenants(org_id: str | None = None) -> list[dict[str, Any]]:
    """List all tenants, optionally filtered by organization."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if org_id:
            rows = await store._fetchall(
                conn,
                """SELECT ak.*, om.org_id, om.role as org_role
                   FROM api_keys ak
                   JOIN org_memberships om ON om.tenant_id = ak.tenant_id
                   WHERE om.org_id = ?
                   ORDER BY ak.created_at DESC""",
                org_id,
            )
        else:
            rows = await store._fetchall(
                conn,
                """SELECT ak.*, om.org_id, om.role as org_role
                   FROM api_keys ak
                   LEFT JOIN org_memberships om ON om.tenant_id = ak.tenant_id
                   ORDER BY ak.created_at DESC""",
            )

    return [
        {
            "tenant_id": row["tenant_id"],
            "org_id": row["org_id"],
            "org_role": row["org_role"],
            "tier": row["tier"],
            "admin": bool(row["admin"]),
            "active": bool(row["active"]),
            "scope": row.get("scope") or "write",
            "created_at": row["created_at"],
        }
        for row in rows
    ]


async def create_tenant(
    tenant_id: str,
    tier: str = "standard",
    admin: bool = False,
    scope: str = "write",
) -> str:
    """Create a new tenant API key. Returns raw key."""
    from strix.api.security import api_keys

    return await api_keys.register_async(tenant_id, tier, admin=admin, scope=scope)
