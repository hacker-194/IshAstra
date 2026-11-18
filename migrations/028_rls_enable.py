"""Migration 28: Enable Row-Level Security (RLS) on all tenant-scoped tables.

This migration enables RLS and creates policies using current_setting('app.current_tenant').
Cross-tenant access (admin, org-level, MSSP) is handled via bypass functions.

PostgreSQL only - SQLite continues to use application-level tenant filtering.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import asyncio

from strix.core.store import configure, get_database

# SQLite migration - no-op since SQLite doesn't support RLS
SQLITE_MIGRATION_28 = ""

# PostgreSQL migration - RLS enable + policies
PG_MIGRATION_28 = """
-- Migration 28: Enable RLS on all tenant-scoped tables (PostgreSQL)
-- This migration creates the RLS policies and supporting functions

-- 1. Create the tenant context setting function
CREATE OR REPLACE FUNCTION set_app_current_tenant(tenant_id TEXT) RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', tenant_id, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Create the current tenant getter (returns NULL if not set)
CREATE OR REPLACE FUNCTION current_app_tenant() RETURNS TEXT AS $$
BEGIN
    RETURN current_setting('app.current_tenant', true);
END;
$$ LANGUAGE plpgsql STABLE;

-- 3. Create admin bypass check - returns true if current user is admin
CREATE OR REPLACE FUNCTION is_global_admin() RETURNS BOOLEAN AS $$
DECLARE
    current_tenant TEXT := current_app_tenant();
    is_admin BOOLEAN := false;
BEGIN
    IF current_tenant IS NULL THEN
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

-- 4. Create org_admin bypass check - returns true if current user is org admin
CREATE OR REPLACE FUNCTION is_org_admin() RETURNS BOOLEAN AS $$
DECLARE
    current_tenant TEXT := current_app_tenant();
    is_org_admin BOOLEAN := false;
BEGIN
    IF current_tenant IS NULL THEN
        RETURN false;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM org_memberships om
        JOIN api_keys ak ON ak.tenant_id = om.tenant_id
        WHERE om.tenant_id = current_tenant
          AND ak.active = true
          AND om.role IN ('admin', 'owner')
    ) INTO is_org_admin;

    RETURN COALESCE(is_org_admin, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- 5. Create MSSP partner bypass check
CREATE OR REPLACE FUNCTION is_mssp_partner_for_tenant(target_tenant TEXT) RETURNS BOOLEAN AS $$
DECLARE
    current_tenant TEXT := current_app_tenant();
    is_partner BOOLEAN := false;
BEGIN
    IF current_tenant IS NULL THEN
        RETURN false;
    END IF;

    -- Check if current tenant is an MSSP partner managing the target tenant
    SELECT EXISTS (
        SELECT 1 FROM mssp_customers mc
        JOIN mssp_partners mp ON mp.partner_id = mc.partner_id
        WHERE mc.tenant_id = target_tenant
          AND mp.status = 'active'
          AND mc.status IN ('active', 'trial')
    ) INTO is_partner;

    RETURN COALESCE(is_partner, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- 6. Create the combined bypass function for cross-tenant access
CREATE OR REPLACE FUNCTION rls_bypass_tenant(target_tenant TEXT) RETURNS BOOLEAN AS $$
BEGIN
    -- Global admins can access all tenants
    IF is_global_admin() THEN
        RETURN true;
    END IF;

    -- Org admins can access tenants in their organization
    IF is_org_admin() THEN
        RETURN true;
    END IF;

    -- MSSP partners can access their customers
    IF is_mssp_partner_for_tenant(target_tenant) THEN
        RETURN true;
    END IF;

    -- Same tenant (normal case)
    RETURN target_tenant = current_app_tenant();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- 7. Enable RLS on all tenant-scoped tables
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagement_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_sinks ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitor_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitor_baseline ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_packs ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_remediation ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_partners ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_invitations ENABLE ROW LEVEL SECURITY;

-- 8. Create RLS policies for each table

-- jobs: tenant column
CREATE POLICY jobs_tenant_isolation ON jobs
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- findings: tenant column
CREATE POLICY findings_tenant_isolation ON findings
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- api_keys: tenant_id column
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (rls_bypass_tenant(tenant_id))
    WITH CHECK (rls_bypass_tenant(tenant_id));

-- audit_log: tenant column
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- audit_chain: no tenant column (global), but restrict inserts to authenticated users
CREATE POLICY audit_chain_isolation ON audit_chain
    USING (current_app_tenant() IS NOT NULL)
    WITH CHECK (current_app_tenant() IS NOT NULL);

-- engagement_policies: tenant_id column
CREATE POLICY engagement_policies_tenant_isolation ON engagement_policies
    USING (rls_bypass_tenant(tenant_id))
    WITH CHECK (rls_bypass_tenant(tenant_id));

-- webhook_sinks: no tenant column (global config)
CREATE POLICY webhook_sinks_isolation ON webhook_sinks
    USING (current_app_tenant() IS NOT NULL)
    WITH CHECK (current_app_tenant() IS NOT NULL);

-- monitor_targets: no tenant column (global config)
CREATE POLICY monitor_targets_isolation ON monitor_targets
    USING (current_app_tenant() IS NOT NULL)
    WITH CHECK (current_app_tenant() IS NOT NULL);

-- monitor_baseline: no tenant column (global config)
CREATE POLICY monitor_baseline_isolation ON monitor_baseline
    USING (current_app_tenant() IS NOT NULL)
    WITH CHECK (current_app_tenant() IS NOT NULL);

-- assessment_schedules: no tenant column (global)
CREATE POLICY assessment_schedules_isolation ON assessment_schedules
    USING (current_app_tenant() IS NOT NULL)
    WITH CHECK (current_app_tenant() IS NOT NULL);

-- evidence_packs: tenant column
CREATE POLICY evidence_packs_tenant_isolation ON evidence_packs
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- assets: tenant column
CREATE POLICY assets_tenant_isolation ON assets
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- finding_events: tenant column
CREATE POLICY finding_events_tenant_isolation ON finding_events
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- finding_remediation: tenant column
CREATE POLICY finding_remediation_tenant_isolation ON finding_remediation
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- finding_records: tenant column
CREATE POLICY finding_records_tenant_isolation ON finding_records
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- tenant_users: tenant_id column
CREATE POLICY tenant_users_tenant_isolation ON tenant_users
    USING (rls_bypass_tenant(tenant_id))
    WITH CHECK (rls_bypass_tenant(tenant_id));

-- organizations: org_id is the primary key, but we restrict by org_memberships
CREATE POLICY organizations_isolation ON organizations
    USING (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = organizations.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = organizations.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    );

-- org_memberships: tenant_id column
CREATE POLICY org_memberships_tenant_isolation ON org_memberships
    USING (rls_bypass_tenant(tenant_id))
    WITH CHECK (rls_bypass_tenant(tenant_id));

-- teams: org_id, restrict via org_memberships
CREATE POLICY teams_isolation ON teams
    USING (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = teams.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = teams.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    );

-- memberships: org_id, restrict via org_memberships
CREATE POLICY memberships_isolation ON memberships
    USING (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = memberships.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM org_memberships om
            WHERE om.org_id = memberships.org_id
              AND rls_bypass_tenant(om.tenant_id)
        )
    );

-- compliance_schedules: tenant column
CREATE POLICY compliance_schedules_tenant_isolation ON compliance_schedules
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- compliance_reports: tenant column
CREATE POLICY compliance_reports_tenant_isolation ON compliance_reports
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- compliance_exports: tenant column
CREATE POLICY compliance_exports_tenant_isolation ON compliance_exports
    USING (rls_bypass_tenant(tenant))
    WITH CHECK (rls_bypass_tenant(tenant));

-- mssp_partners: partner admin key isolation
CREATE POLICY mssp_partners_isolation ON mssp_partners
    USING (
        admin_key_hash = current_setting('app.current_mssp_key_hash', true)
        OR is_global_admin()
    )
    WITH CHECK (
        admin_key_hash = current_setting('app.current_mssp_key_hash', true)
        OR is_global_admin()
    );

-- mssp_customers: partner isolation via mssp_partners
CREATE POLICY mssp_customers_isolation ON mssp_customers
    USING (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_customers.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin()
                   OR is_mssp_partner_for_tenant(mssp_customers.tenant_id))
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_customers.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin()
                   OR is_mssp_partner_for_tenant(mssp_customers.tenant_id))
        )
    );

-- mssp_usage_records: partner isolation
CREATE POLICY mssp_usage_records_isolation ON mssp_usage_records
    USING (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_usage_records.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin()
                   OR is_mssp_partner_for_tenant(
                       (SELECT tenant_id FROM mssp_customers WHERE customer_id = mssp_usage_records.customer_id)
                   ))
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_usage_records.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin()
                   OR is_mssp_partner_for_tenant(
                       (SELECT tenant_id FROM mssp_customers WHERE customer_id = mssp_usage_records.customer_id)
                   ))
        )
    );

-- mssp_invitations: partner isolation
CREATE POLICY mssp_invitations_isolation ON mssp_invitations
    USING (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_invitations.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin())
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM mssp_partners mp
            WHERE mp.partner_id = mssp_invitations.partner_id
              AND (mp.admin_key_hash = current_setting('app.current_mssp_key_hash', true)
                   OR is_global_admin())
        )
    );

-- 9. Create policy indexes for performance
-- These indexes support the RLS policy conditions
CREATE INDEX IF NOT EXISTS idx_jobs_tenant_rls ON jobs (tenant);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_rls ON findings (tenant);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_rls ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_rls ON audit_log (tenant);
CREATE INDEX IF NOT EXISTS idx_engagement_policies_tenant_rls ON engagement_policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_tenant_rls ON evidence_packs (tenant);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_rls ON assets (tenant);
CREATE INDEX IF NOT EXISTS idx_finding_events_tenant_rls ON finding_events (tenant);
CREATE INDEX IF NOT EXISTS idx_finding_remediation_tenant_rls ON finding_remediation (tenant);
CREATE INDEX IF NOT EXISTS idx_finding_records_tenant_rls ON finding_records (tenant);
CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_rls ON tenant_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_org_memberships_tenant_rls ON org_memberships (tenant_id);
CREATE INDEX IF NOT EXISTS idx_compliance_schedules_tenant_rls ON compliance_schedules (tenant);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_tenant_rls ON compliance_reports (tenant);
CREATE INDEX IF NOT EXISTS idx_compliance_exports_tenant_rls ON compliance_exports (tenant);

-- 10. Force query planner to consider RLS (helps with plan caching)
-- This ensures RLS policies are evaluated before joins
ALTER TABLE jobs SET (enable_rowsecurity = on);
ALTER TABLE findings SET (enable_rowsecurity = on);
ALTER TABLE api_keys SET (enable_rowsecurity = on);
ALTER TABLE audit_log SET (enable_rowsecurity = on);
ALTER TABLE audit_chain SET (enable_rowsecurity = on);
ALTER TABLE engagement_policies SET (enable_rowsecurity = on);
ALTER TABLE webhook_sinks SET (enable_rowsecurity = on);
ALTER TABLE monitor_targets SET (enable_rowsecurity = on);
ALTER TABLE monitor_baseline SET (enable_rowsecurity = on);
ALTER TABLE assessment_schedules SET (enable_rowsecurity = on);
ALTER TABLE evidence_packs SET (enable_rowsecurity = on);
ALTER TABLE assets SET (enable_rowsecurity = on);
ALTER TABLE finding_events SET (enable_rowsecurity = on);
ALTER TABLE finding_remediation SET (enable_rowsecurity = on);
ALTER TABLE finding_records SET (enable_rowsecurity = on);
ALTER TABLE tenant_users SET (enable_rowsecurity = on);
ALTER TABLE organizations SET (enable_rowsecurity = on);
ALTER TABLE org_memberships SET (enable_rowsecurity = on);
ALTER TABLE teams SET (enable_rowsecurity = on);
ALTER TABLE memberships SET (enable_rowsecurity = on);
ALTER TABLE compliance_schedules SET (enable_rowsecurity = on);
ALTER TABLE compliance_reports SET (enable_rowsecurity = on);
ALTER TABLE compliance_exports SET (enable_rowsecurity = on);
ALTER TABLE mssp_partners SET (enable_rowsecurity = on);
ALTER TABLE mssp_customers SET (enable_rowsecurity = on);
ALTER TABLE mssp_usage_records SET (enable_rowsecurity = on);
ALTER TABLE mssp_invitations SET (enable_rowsecurity = on);

-- 11. Grant execute permissions on RLS functions to the application role
GRANT EXECUTE ON FUNCTION set_app_current_tenant(TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION current_app_tenant() TO PUBLIC;
GRANT EXECUTE ON FUNCTION is_global_admin() TO PUBLIC;
GRANT EXECUTE ON FUNCTION is_org_admin() TO PUBLIC;
GRANT EXECUTE ON FUNCTION is_mssp_partner_for_tenant(TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION rls_bypass_tenant(TEXT) TO PUBLIC;
"""


async def run_migrations(db_path: str) -> None:
    """Run the RLS migration (PostgreSQL only)."""
    configure(db_path)
    db = await get_database()

    # Check current version
    version = await db.schema_version()
    print(f"Current schema version: {version}")

    if version >= 28:
        print("Migration 28 already applied (version >= 28)")
        return

    # Only apply on PostgreSQL
    if not db.is_postgresql():
        print("RLS migration is PostgreSQL-only; skipping on SQLite")
        # Still bump version to prevent re-running
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO settings (key, value) VALUES ('schema_version', '28') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        print("Schema version bumped to 28 (no-op on SQLite)")
        return

    print("Applying migration 28: Enable RLS on all tenant-scoped tables")
    async with db.transaction() as conn:
        for statement in PG_MIGRATION_28.split(";"):
            stmt = "\n".join(
                line for line in statement.splitlines() if not line.strip().startswith("--")
            ).strip()
            if stmt:
                await conn.execute(stmt)
        await conn.execute(
            "INSERT INTO settings (key, value) VALUES ('schema_version', '28') "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        )
    print("Migration 28 applied")

    # Verify
    final_version = await db.schema_version()
    print(f"Final schema version: {final_version}")


if __name__ == "__main__":
    import os

    db_path = os.environ.get("STRIX_DB_PATH", "strix.db")
    asyncio.run(run_migrations(db_path))