"""PostgreSQL Row-Level Security (RLS) migration.

SQLite keeps using application-level tenant filtering; on PostgreSQL RLS is the
second line of defence behind it, so a query that forgets its tenant predicate
still cannot read another tenant's rows.

Everything here is idempotent: policies are dropped and recreated, indexes use
IF NOT EXISTS, and the store only calls this when ``schema_version < 28``.

The tenant is carried in the session setting ``app.current_tenant``; the
bypass helpers are SECURITY DEFINER so they can read the membership tables
without recursing back through RLS.
"""

from __future__ import annotations

from typing import Any

RLS_SCHEMA_VERSION = 28


TENANT_COLUMNS: dict[str, str] = {
    "jobs": "tenant",
    "findings": "tenant",
    "api_keys": "tenant_id",
    "audit_log": "tenant",
    "engagement_policies": "tenant_id",
    "evidence_packs": "tenant",
    "assets": "tenant",
    "finding_events": "tenant",
    "finding_remediation": "tenant",
    "finding_records": "tenant",
    "tenant_users": "tenant_id",
    "org_memberships": "tenant_id",
    "compliance_schedules": "tenant",
    "compliance_reports": "tenant",
    "compliance_exports": "tenant",
}


AUTHENTICATED_TABLES: tuple[str, ...] = (
    "audit_chain",
    "webhook_sinks",
    "monitor_targets",
    "monitor_baseline",
    "assessment_schedules",
)


ORG_SCOPED_TABLES: dict[str, str] = {
    "organizations": "org_id",
    "teams": "org_id",
    "memberships": "org_id",
}

FUNCTIONS_SQL = """
CREATE OR REPLACE FUNCTION set_app_current_tenant(tenant_id TEXT) RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', tenant_id, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION current_app_tenant() RETURNS TEXT AS $$
BEGIN
    RETURN current_setting('app.current_tenant', true);
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION is_global_admin() RETURNS BOOLEAN AS $$
DECLARE
    current_tenant TEXT := current_app_tenant();
    is_admin BOOLEAN := false;
BEGIN
    IF current_tenant IS NULL OR current_tenant = '' THEN
        RETURN false;
    END IF;

    SELECT admin INTO is_admin
    FROM api_keys
    WHERE tenant_id = current_tenant
      AND active = true
    LIMIT 1;

    RETURN COALESCE(is_admin, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

CREATE OR REPLACE FUNCTION is_org_admin() RETURNS BOOLEAN AS $$
DECLARE
    current_tenant TEXT := current_app_tenant();
    admin_in_org BOOLEAN := false;
BEGIN
    IF current_tenant IS NULL OR current_tenant = '' THEN
        RETURN false;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM org_memberships om
        JOIN api_keys ak ON ak.tenant_id = om.tenant_id
        WHERE om.tenant_id = current_tenant
          AND ak.active = true
          AND om.role IN ('admin', 'owner')
    ) INTO admin_in_org;

    RETURN COALESCE(admin_in_org, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

CREATE OR REPLACE FUNCTION rls_bypass_tenant(target_tenant TEXT) RETURNS BOOLEAN AS $$
BEGIN
    IF is_global_admin() THEN
        RETURN true;
    END IF;

    IF is_org_admin() THEN
        RETURN true;
    END IF;

    RETURN target_tenant = current_app_tenant();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
"""

GRANTS_SQL = """
GRANT EXECUTE ON FUNCTION set_app_current_tenant(TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION current_app_tenant() TO PUBLIC;
GRANT EXECUTE ON FUNCTION is_global_admin() TO PUBLIC;
GRANT EXECUTE ON FUNCTION is_org_admin() TO PUBLIC;
GRANT EXECUTE ON FUNCTION rls_bypass_tenant(TEXT) TO PUBLIC;
"""


def build_sql(existing_tables: set[str]) -> str:
    """Build the idempotent RLS migration for the tables that exist."""
    parts: list[str] = [FUNCTIONS_SQL]

    for table, column in TENANT_COLUMNS.items():
        if table not in existing_tables:
            continue
        parts.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        parts.append(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};")
        parts.append(
            f"CREATE POLICY {table}_tenant_isolation ON {table} "
            f"USING (rls_bypass_tenant({column})) "
            f"WITH CHECK (rls_bypass_tenant({column}));"
        )
        parts.append(f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant_rls ON {table} ({column});")

    for table in AUTHENTICATED_TABLES:
        if table not in existing_tables:
            continue
        parts.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        parts.append(f"DROP POLICY IF EXISTS {table}_isolation ON {table};")
        parts.append(
            f"CREATE POLICY {table}_isolation ON {table} "
            f"USING (current_app_tenant() IS NOT NULL) "
            f"WITH CHECK (current_app_tenant() IS NOT NULL);"
        )

    for table, column in ORG_SCOPED_TABLES.items():
        if table not in existing_tables:
            continue

        check = (
            "is_global_admin() OR EXISTS ("
            f"SELECT 1 FROM org_memberships om WHERE om.{column} = {table}.{column} "
            "AND rls_bypass_tenant(om.tenant_id))"
        )
        parts.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        parts.append(f"DROP POLICY IF EXISTS {table}_isolation ON {table};")
        parts.append(f"CREATE POLICY {table}_isolation ON {table} USING ({check}) WITH CHECK ({check});")

    parts.append(GRANTS_SQL)
    return "\n".join(parts)


async def apply_rls(conn: Any) -> None:
    """Create the RLS helpers, policies and indexes for the tables present."""
    rows = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    existing = {row["tablename"] for row in rows}
    if not existing:
        return
    await conn.execute(build_sql(existing))
