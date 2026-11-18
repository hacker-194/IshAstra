"""Test plan for RLS (Row-Level Security) verification.

This test suite verifies that RLS policies correctly isolate tenant data
and allow appropriate cross-tenant access for admins, org admins, and MSSP partners.
"""

from collections.abc import AsyncGenerator

import pytest

# Note: These tests require PostgreSQL with RLS enabled
# They should be run against a test PostgreSQL instance


class TestRLSPolicies:
    """Tests for RLS policy enforcement."""

    @pytest.fixture
    async def pg_pool(self) -> AsyncGenerator:
        """Create a PostgreSQL connection pool for testing.

        Requires a test database with RLS migration applied.
        """
        import os

        import asyncpg

        dsn = os.environ.get("STRIX_TEST_PG_DSN", "postgresql://postgres:postgres@localhost:5432/strix_test")
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)

        # Apply RLS migration
        async with pool.acquire():
            # Run migration 28 SQL here
            pass

        yield pool
        await pool.close()

    @pytest.fixture
    async def tenant_a(self, pg_pool) -> str:
        """Create tenant A and return tenant_id."""
        async with pg_pool.acquire() as conn:
            tenant_id = "tenant_a_test"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (tenant_id) DO UPDATE SET
                       key_hash = EXCLUDED.key_hash""",
                tenant_id,
                "hash_a",
                "free",
                False,
                True,
                1234567890.0,
            )
            return tenant_id

    @pytest.fixture
    async def tenant_b(self, pg_pool) -> str:
        """Create tenant B and return tenant_id."""
        async with pg_pool.acquire() as conn:
            tenant_id = "tenant_b_test"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (tenant_id) DO UPDATE SET
                       key_hash = EXCLUDED.key_hash""",
                tenant_id,
                "hash_b",
                "free",
                False,
                True,
                1234567890.0,
            )
            return tenant_id

    @pytest.fixture
    async def admin_tenant(self, pg_pool) -> str:
        """Create admin tenant and return tenant_id."""
        async with pg_pool.acquire() as conn:
            tenant_id = "admin_test"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (tenant_id) DO UPDATE SET
                       key_hash = EXCLUDED.key_hash""",
                tenant_id,
                "hash_admin",
                "enterprise",
                True,
                True,
                1234567890.0,
            )
            return tenant_id

    async def test_tenant_isolation_jobs(self, pg_pool, tenant_a, tenant_b):
        """Test that tenants can only see their own jobs."""
        async with pg_pool.acquire() as conn:
            # Insert job for tenant A
            await conn.execute("""SELECT set_app_current_tenant($1)""", tenant_a)
            await conn.execute(
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                "job_a1",
                tenant_a,
                "example.com",
                "web",
                "tester",
                "{}",
                "completed",
                "clean",
                1234567890.0,
            )

            # Insert job for tenant B
            await conn.execute("""SELECT set_app_current_tenant($1)""", tenant_b)
            await conn.execute(
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                "job_b1",
                tenant_b,
                "example.org",
                "web",
                "tester",
                "{}",
                "completed",
                "clean",
                1234567890.0,
            )

            # Query as tenant A - should only see tenant A's job
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            jobs_a = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs_a) == 1
            assert jobs_a[0]["tenant"] == tenant_a

            # Query as tenant B - should only see tenant B's job
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            jobs_b = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs_b) == 1
            assert jobs_b[0]["tenant"] == tenant_b

    async def test_tenant_isolation_findings(self, pg_pool, tenant_a, tenant_b):
        """Test that tenants can only see their own findings."""
        async with pg_pool.acquire() as conn:
            # Insert finding for tenant A
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await conn.execute(
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title, severity,
                       confidence, verification, status, detector, detector_version, evidence, sources)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)""",
                "job_a1",
                tenant_a,
                "fp_a1",
                "example.com",
                "xss",
                "XSS found",
                "high",
                "confirmed",
                "verified",
                "open",
                "scanner",
                "1.0",
                "evidence",
                "[]",
            )

            # Insert finding for tenant B
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            await conn.execute(
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title, severity,
                       confidence, verification, status, detector, detector_version, evidence, sources)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)""",
                "job_b1",
                tenant_b,
                "fp_b1",
                "example.org",
                "sqli",
                "SQLi found",
                "critical",
                "confirmed",
                "verified",
                "open",
                "scanner",
                "1.0",
                "evidence",
                "[]",
            )

            # Query as tenant A
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            findings_a = await conn.fetch("SELECT * FROM findings")
            assert len(findings_a) == 1
            assert findings_a[0]["tenant"] == tenant_a

            # Query as tenant B
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            findings_b = await conn.fetch("SELECT * FROM findings")
            assert len(findings_b) == 1
            assert findings_b[0]["tenant"] == tenant_b

    async def test_admin_bypass(self, pg_pool, admin_tenant, tenant_a):
        """Test that global admin can see all tenant data."""
        async with pg_pool.acquire() as conn:
            # Insert data for tenant A
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await conn.execute(
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                "job_a1",
                tenant_a,
                "example.com",
                "web",
                "tester",
                "{}",
                "completed",
                "clean",
                1234567890.0,
            )

            # Query as admin - should see all jobs
            await conn.execute("SELECT set_app_current_tenant($1)", admin_tenant)
            jobs = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs) >= 1  # At least the tenant A job

            # Should be able to query specific tenant's data
            jobs_a = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", tenant_a)
            assert len(jobs_a) == 1

    async def test_cross_tenant_insert_blocked(self, pg_pool, tenant_a, tenant_b):
        """Test that tenants cannot insert data for other tenants."""
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)

            # Try to insert a job for tenant B - should fail due to WITH CHECK policy
            with pytest.raises(Exception) as exc_info:
                await conn.execute(
                    """INSERT INTO jobs
                       (id, tenant, target, profile, actor, policy, state, verdict, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                    "job_bad",
                    tenant_b,
                    "example.com",
                    "web",
                    "tester",
                    "{}",
                    "completed",
                    "clean",
                    1234567890.0,
                )
            # Should raise a policy violation error
            assert "policy" in str(exc_info.value).lower() or "rls" in str(exc_info.value).lower()

    async def test_rls_functions_exist(self, pg_pool):
        """Test that all RLS helper functions are created."""
        async with pg_pool.acquire() as conn:
            functions = await conn.fetch("""
                SELECT proname FROM pg_proc
                WHERE proname IN (
                    'set_app_current_tenant', 'current_app_tenant',
                    'is_global_admin', 'is_org_admin',
                    'is_mssp_partner_for_tenant', 'rls_bypass_tenant'
                )
            """)
            func_names = [f["proname"] for f in functions]
            assert "set_app_current_tenant" in func_names
            assert "current_app_tenant" in func_names
            assert "is_global_admin" in func_names
            assert "is_org_admin" in func_names
            assert "is_mssp_partner_for_tenant" in func_names
            assert "rls_bypass_tenant" in func_names

    async def test_policies_exist(self, pg_pool):
        """Test that RLS policies are created on all tenant-scoped tables."""
        async with pg_pool.acquire() as conn:
            policies = await conn.fetch("""
                SELECT polname, polrelid::regclass as table_name
                FROM pg_policy
                WHERE polname LIKE '%_isolation' OR polname LIKE '%_tenant_isolation'
                ORDER BY table_name
            """)
            # Should have policies on all tenant-scoped tables
            table_names = {p["table_name"] for p in policies}
            expected_tables = {
                "jobs",
                "findings",
                "api_keys",
                "audit_log",
                "engagement_policies",
                "evidence_packs",
                "assets",
                "finding_events",
                "finding_remediation",
                "finding_records",
                "tenant_users",
                "org_memberships",
                "compliance_schedules",
                "compliance_reports",
                "compliance_exports",
            }
            for table in expected_tables:
                assert table in table_names, f"Missing policy on {table}"

    async def test_rls_enabled_on_tables(self, pg_pool):
        """Test that RLS is enabled on all tenant-scoped tables."""
        async with pg_pool.acquire() as conn:
            tables = await conn.fetch("""
                SELECT relname, relrowsecurity
                FROM pg_class
                WHERE relname IN (
                    'jobs', 'findings', 'api_keys', 'audit_log', 'audit_chain',
                    'engagement_policies', 'webhook_sinks', 'monitor_targets',
                    'monitor_baseline', 'assessment_schedules', 'evidence_packs',
                    'assets', 'finding_events', 'finding_remediation', 'finding_records',
                    'tenant_users', 'organizations', 'org_memberships', 'teams',
                    'memberships', 'compliance_schedules', 'compliance_reports',
                    'compliance_exports', 'mssp_partners', 'mssp_customers',
                    'mssp_usage_records', 'mssp_invitations'
                )
                AND relkind = 'r'
            """)
            for table in tables:
                assert table["relrowsecurity"] is True, f"RLS not enabled on {table['relname']}"

    async def test_policy_indexes_exist(self, pg_pool):
        """Test that policy indexes are created for performance."""
        async with pg_pool.acquire() as conn:
            indexes = await conn.fetch("""
                SELECT indexrelid::regclass as index_name
                FROM pg_index
                WHERE indexrelid::regclass::text LIKE 'idx_%_rls'
            """)
            index_names = {i["index_name"] for i in indexes}
            expected_indexes = {
                "idx_jobs_tenant_rls",
                "idx_findings_tenant_rls",
                "idx_api_keys_tenant_rls",
                "idx_audit_log_tenant_rls",
                "idx_engagement_policies_tenant_rls",
                "idx_evidence_packs_tenant_rls",
                "idx_assets_tenant_rls",
                "idx_finding_events_tenant_rls",
                "idx_finding_remediation_tenant_rls",
                "idx_finding_records_tenant_rls",
                "idx_tenant_users_tenant_rls",
                "idx_org_memberships_tenant_rls",
                "idx_compliance_schedules_tenant_rls",
                "idx_compliance_reports_tenant_rls",
                "idx_compliance_exports_tenant_rls",
            }
            for idx in expected_indexes:
                assert idx in index_names, f"Missing index {idx}"

    async def test_mssp_partner_isolation(self, pg_pool):
        """Test MSSP partner can only see their customers."""
        async with pg_pool.acquire() as conn:
            # Create MSSP partner
            partner_id = "mssp_test"
            await conn.execute(
                """INSERT INTO mssp_partners (partner_id, name, slug, tier, status, admin_key_hash,
                       contact_email, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                partner_id,
                "Test MSSP",
                "test-mssp",
                "authorized",
                "active",
                "partner_key_hash",
                "partner@example.com",
                1234567890.0,
                1234567890.0,
            )

            # Create customer for partner
            customer_tenant = "customer_tenant"
            await conn.execute(
                """INSERT INTO mssp_customers (customer_id, partner_id, tenant_id, name, status, tier,
                       created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                "cust_1",
                partner_id,
                customer_tenant,
                "Customer Corp",
                "active",
                "pro",
                1234567890.0,
                1234567890.0,
            )

            # Create another tenant not managed by this partner
            other_tenant = "other_tenant"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                other_tenant,
                "other_hash",
                "free",
                False,
                True,
                1234567890.0,
            )

            # Set MSSP partner context
            await conn.execute("SELECT set_app_current_tenant($1)", partner_id)
            await conn.execute("SELECT set_config('app.current_mssp_key_hash', 'partner_key_hash', false)")

            # Should see customer
            customers = await conn.fetch("SELECT * FROM mssp_customers WHERE tenant_id = $1", customer_tenant)
            assert len(customers) == 1

            # Should NOT see other tenant's data
            # (This depends on the specific query - RLS on mssp_customers is partner-scoped)

    async def test_org_admin_access(self, pg_pool):
        """Test org admin can access all tenants in their organization."""
        async with pg_pool.acquire() as conn:
            # Create organization
            org_id = "org_test"
            await conn.execute(
                """INSERT INTO organizations (org_id, name, slug, tier, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                org_id,
                "Test Org",
                "test-org",
                "enterprise",
                1234567890.0,
                1234567890.0,
            )

            # Create admin tenant (org admin)
            admin_tenant = "admin_tenant"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                admin_tenant,
                "admin_hash",
                "enterprise",
                False,
                True,
                1234567890.0,
            )

            # Create member tenant
            member_tenant = "member_tenant"
            await conn.execute(
                """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                member_tenant,
                "member_hash",
                "pro",
                False,
                True,
                1234567890.0,
            )

            # Link both to organization
            await conn.execute(
                """INSERT INTO org_memberships (org_id, tenant_id, role, joined_at)
                   VALUES ($1, $2, $3, $4)""",
                org_id,
                admin_tenant,
                "admin",
                1234567890.0,
            )
            await conn.execute(
                """INSERT INTO org_memberships (org_id, tenant_id, role, joined_at)
                   VALUES ($1, $2, $3, $4)""",
                org_id,
                member_tenant,
                "member",
                1234567890.0,
            )

            # Insert job for member tenant
            await conn.execute("SELECT set_app_current_tenant($1)", member_tenant)
            await conn.execute(
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                "job_member",
                member_tenant,
                "example.com",
                "web",
                "tester",
                "{}",
                "completed",
                "clean",
                1234567890.0,
            )

            # Query as org admin - should see member's job
            await conn.execute("SELECT set_app_current_tenant($1)", admin_tenant)
            jobs = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", member_tenant)
            assert len(jobs) == 1


class TestRLSPerformance:
    """Performance tests for RLS policies."""

    async def test_query_plan_uses_index(self, pg_pool, tenant_a):
        """Verify that queries use the policy indexes."""
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)

            # Explain query plan
            plan = await conn.fetch("EXPLAIN SELECT * FROM jobs WHERE tenant = $1", tenant_a)
            plan_text = " ".join([row["QUERY PLAN"] for row in plan])

            # Should use index scan
            assert "Index Scan" in plan_text or "Bitmap Heap Scan" in plan_text
            assert "idx_jobs_tenant_rls" in plan_text or "jobs_by_tenant" in plan_text

    async def test_plan_caching(self, pg_pool, tenant_a):
        """Test that prepared statements work with RLS (plan caching)."""
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)

            # Prepare a statement
            await conn.execute("PREPARE test_plan AS SELECT * FROM jobs WHERE tenant = $1")

            # Execute multiple times - should use cached plan
            for _ in range(5):
                result = await conn.fetch("EXECUTE test_plan($1)", tenant_a)
                assert isinstance(result, list)

            await conn.execute("DEALLOCATE test_plan")


class TestRLSMigration:
    """Tests for zero-downtime migration strategy."""

    async def test_backward_compatibility(self, pg_pool, tenant_a):
        """Test that application-level filtering still works alongside RLS."""
        # The application should still pass tenant_id in queries
        # RLS acts as a safety net
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)

            # Query with explicit tenant filter (app-level)
            jobs = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", tenant_a)

            # Query without tenant filter (RLS will filter)
            jobs_rls = await conn.fetch("SELECT * FROM jobs")

            # Results should be identical
            assert len(jobs) == len(jobs_rls)

    async def test_rls_can_be_disabled_for_migration(self, pg_pool):
        """Test that RLS can be temporarily disabled for maintenance."""
        async with pg_pool.acquire() as conn:
            # Disable RLS on a table (superuser operation)
            await conn.execute("ALTER TABLE jobs DISABLE ROW LEVEL SECURITY")

            # Verify disabled
            result = await conn.fetch("""
                SELECT relrowsecurity FROM pg_class WHERE relname = 'jobs'
            """)
            assert result[0]["relrowsecurity"] is False

            # Re-enable
            await conn.execute("ALTER TABLE jobs ENABLE ROW LEVEL SECURITY")
            result = await conn.fetch("""
                SELECT relrowsecurity FROM pg_class WHERE relname = 'jobs'
            """)
            assert result[0]["relrowsecurity"] is True


# Integration test markers
@pytest.mark.integration
class TestRLSIntegration:
    """Integration tests requiring full application stack."""

    async def test_api_endpoint_tenant_isolation(self):
        """Test that API endpoints respect RLS via middleware."""
        # This would use TestClient to make authenticated requests
        # and verify tenant isolation at the API level

    async def test_worker_jobs_respect_rls(self):
        """Test that background workers set tenant context correctly."""

    async def test_migration_rollback(self):
        """Test that migration can be rolled back safely."""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
