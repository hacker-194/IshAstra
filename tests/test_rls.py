"""Row-Level Security verification against a real PostgreSQL instance.

The schema (and the RLS step at version 28) is built by the application's own
PostgreSQL migration chain, so this suite exercises what ships rather than a
hand-written fixture.

The tests connect as a non-superuser role: a superuser bypasses row-level
security entirely, so the previous version of this suite could not have proved
anything even if it had created the schema.

Requires PostgreSQL. Set ISHASTRA_TEST_PG_DSN to run this suite.
"""

from __future__ import annotations

import os

import pytest

from ishastra.core import store

ADMIN_DSN = os.environ.get("ISHASTRA_TEST_PG_DSN")
if not ADMIN_DSN:
    pytest.skip("Set ISHASTRA_TEST_PG_DSN to run PostgreSQL RLS tests", allow_module_level=True)

asyncpg = pytest.importorskip("asyncpg")

APP_ROLE = "ishastra_rls_test"


SEED_ADMIN = "__rls_seed_admin__"


DATA_TABLES = (
    "jobs",
    "findings",
    "finding_events",
    "assets",
    "api_keys",
    "org_memberships",
    "organizations",
    "teams",
    "memberships",
    "mssp_partners",
    "mssp_customers",
    "mssp_usage_records",
    "mssp_invitations",
)


async def _seed_admin(conn: asyncpg.Connection) -> None:
    """Insert the seeding admin tenant (bypasses RLS as superuser)."""
    await conn.execute(
        """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
           VALUES ($1, $2, 'enterprise', true, true, 0)
           ON CONFLICT DO NOTHING""",
        SEED_ADMIN,
        "seed_admin_hash",
    )


@pytest.fixture
async def pg_ready():
    """Build a clean database with the application's migration chain applied."""
    admin = await asyncpg.create_pool(ADMIN_DSN, min_size=1, max_size=2)
    try:
        async with admin.acquire() as conn:
            await conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
            await conn.execute("CREATE SCHEMA public")
            await conn.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
            await conn.execute(
                f"""DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                        CREATE ROLE {APP_ROLE} NOLOGIN;
                    END IF;
                END
                $$"""
            )
            await conn.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")

        store.configure(ADMIN_DSN)
        await store.get_database()

        async with admin.acquire() as conn:
            await conn.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}"
            )
            await conn.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
            await _seed_admin(conn)

        yield admin
    finally:
        await store.close_database()
        await admin.close()


@pytest.fixture
async def pg_pool(pg_ready):
    """Pool that runs as the non-superuser application role, cleaned per test."""

    async def _switch_to_app_role(conn: asyncpg.Connection) -> None:
        await conn.execute(f"SET ROLE {APP_ROLE}")

    pool = await asyncpg.create_pool(ADMIN_DSN, min_size=1, max_size=5, init=_switch_to_app_role)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
async def admin_pool(pg_ready):
    """Superuser pool, for operations RLS correctly forbids to the app role."""
    pool = await asyncpg.create_pool(ADMIN_DSN, min_size=1, max_size=2)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
async def tenant_a(pg_pool) -> str:
    async with pg_pool.acquire() as conn:
        await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
        await conn.execute(
            """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT DO NOTHING""",
            "tenant_a_test",
            "hash_a",
            "free",
            False,
            True,
            1234567890.0,
        )
        return "tenant_a_test"


@pytest.fixture
async def tenant_b(pg_pool) -> str:
    async with pg_pool.acquire() as conn:
        await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
        await conn.execute(
            """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT DO NOTHING""",
            "tenant_b_test",
            "hash_b",
            "free",
            False,
            True,
            1234567890.0,
        )
        return "tenant_b_test"


@pytest.fixture
async def admin_tenant(pg_pool) -> str:
    async with pg_pool.acquire() as conn:
        await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
        await conn.execute(
            """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT DO NOTHING""",
            "admin_test",
            "hash_admin",
            "enterprise",
            True,
            True,
            1234567890.0,
        )
        return "admin_test"


async def _insert_job(conn: asyncpg.Connection, job_id: str, tenant: str, target: str) -> None:
    await conn.execute(
        """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict,
               coverage, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
        job_id,
        tenant,
        target,
        "web",
        "tester",
        "{}",
        "completed",
        "clean",
        "{}",
        1234567890.0,
    )


class TestRLSPolicies:
    """Tests for RLS policy enforcement."""

    async def test_tenant_isolation_jobs(self, pg_pool, tenant_a, tenant_b):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await _insert_job(conn, "job_a1", tenant_a, "example.com")

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            await _insert_job(conn, "job_b1", tenant_b, "example.org")

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            jobs_a = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs_a) == 1
            assert jobs_a[0]["tenant"] == tenant_a

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            jobs_b = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs_b) == 1
            assert jobs_b[0]["tenant"] == tenant_b

    async def test_tenant_isolation_findings(self, pg_pool, tenant_a, tenant_b):
        async with pg_pool.acquire() as conn:
            for tenant, job_id, fingerprint in (
                (tenant_a, "job_a1", "fp_a1"),
                (tenant_b, "job_b1", "fp_b1"),
            ):
                await conn.execute("SELECT set_app_current_tenant($1)", tenant)
                await _insert_job(conn, job_id, tenant, "example.com")
                await conn.execute(
                    """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                           severity, confidence, verification, status, detector, detector_version,
                           evidence, sources)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)""",
                    job_id,
                    tenant,
                    fingerprint,
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

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            findings_a = await conn.fetch("SELECT * FROM findings")
            assert len(findings_a) == 1
            assert findings_a[0]["tenant"] == tenant_a

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_b)
            findings_b = await conn.fetch("SELECT * FROM findings")
            assert len(findings_b) == 1
            assert findings_b[0]["tenant"] == tenant_b

    async def test_admin_bypass(self, pg_pool, admin_tenant, tenant_a):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await _insert_job(conn, "job_a1", tenant_a, "example.com")

            await conn.execute("SELECT set_app_current_tenant($1)", admin_tenant)
            jobs = await conn.fetch("SELECT * FROM jobs")
            assert len(jobs) >= 1

            jobs_a = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", tenant_a)
            assert len(jobs_a) == 1

    async def test_cross_tenant_insert_blocked(self, pg_pool, tenant_a, tenant_b):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            with pytest.raises(Exception) as exc_info:
                await _insert_job(conn, "job_bad", tenant_b, "example.com")
            message = str(exc_info.value).lower()
            assert "policy" in message or "rls" in message

    async def test_rls_functions_exist(self, pg_pool):
        async with pg_pool.acquire() as conn:
            functions = await conn.fetch(
                """SELECT proname FROM pg_proc
                   WHERE proname IN (
                       'set_app_current_tenant', 'current_app_tenant',
                       'is_global_admin', 'is_org_admin',
                       'is_mssp_partner_for_tenant', 'rls_bypass_tenant'
                   )"""
            )
            names = {row["proname"] for row in functions}
            assert names == {
                "set_app_current_tenant",
                "current_app_tenant",
                "is_global_admin",
                "is_org_admin",
                "is_mssp_partner_for_tenant",
                "rls_bypass_tenant",
            }

    async def test_policies_exist(self, pg_pool):
        async with pg_pool.acquire() as conn:
            policies = await conn.fetch(
                """SELECT polname, polrelid::regclass::text AS table_name
                   FROM pg_policy
                   WHERE polname LIKE '%_isolation'"""
            )
            tables = {row["table_name"] for row in policies}
            expected = {
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
            missing = expected - tables
            assert not missing, f"missing policies on {sorted(missing)}"

    async def test_rls_enabled_on_tables(self, pg_pool):
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT relname, relrowsecurity FROM pg_class
                   WHERE relname = ANY($1::text[]) AND relkind = 'r'""",
                [
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
                ],
            )
            disabled = [row["relname"] for row in rows if not row["relrowsecurity"]]
            assert not disabled, f"RLS not enabled on {disabled}"

    async def test_policy_indexes_exist(self, pg_pool):
        async with pg_pool.acquire() as conn:
            indexes = await conn.fetch(
                """SELECT indexrelid::regclass::text AS index_name
                   FROM pg_index
                   WHERE indexrelid::regclass::text LIKE 'idx_%_rls'"""
            )
            names = {row["index_name"] for row in indexes}
            expected = {
                f"idx_{table}_tenant_rls"
                for table in (
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
                )
            }
            missing = expected - names
            assert not missing, f"missing indexes {sorted(missing)}"

    async def test_mssp_partner_isolation(self, pg_pool):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
            await conn.execute(
                """INSERT INTO mssp_partners (partner_id, name, slug, tier, status, admin_key_hash,
                       contact_email, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                "mssp_test",
                "Test MSSP",
                "test-mssp",
                "authorized",
                "active",
                "partner_key_hash",
                "partner@example.com",
                1234567890.0,
                1234567890.0,
            )
            await conn.execute(
                """INSERT INTO mssp_customers (customer_id, partner_id, tenant_id, name, status, tier,
                       created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                "cust_1",
                "mssp_test",
                "customer_tenant",
                "Customer Corp",
                "active",
                "pro",
                1234567890.0,
                1234567890.0,
            )

            await conn.execute("SELECT set_app_current_tenant($1)", "partner_admin")
            await conn.execute("SELECT set_config('app.current_mssp_key_hash', 'partner_key_hash', false)")
            customers = await conn.fetch(
                "SELECT * FROM mssp_customers WHERE tenant_id = $1", "customer_tenant"
            )
            assert len(customers) == 1

            await conn.execute("SELECT set_config('app.current_mssp_key_hash', 'other_partner_hash', false)")
            other = await conn.fetch("SELECT * FROM mssp_customers")
            assert other == []

    async def test_org_admin_access(self, pg_pool):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
            await conn.execute(
                """INSERT INTO organizations (org_id, name, slug, tier, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                "org_test",
                "Test Org",
                "test-org",
                "enterprise",
                1234567890.0,
                1234567890.0,
            )
            for tenant, tier in (("admin_tenant", "enterprise"), ("member_tenant", "pro")):
                await conn.execute(
                    """INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, created_at)
                       VALUES ($1, $2, $3, false, true, $4)""",
                    tenant,
                    f"{tenant}_hash",
                    tier,
                    1234567890.0,
                )
            for tenant, role in (("admin_tenant", "admin"), ("member_tenant", "member")):
                await conn.execute(
                    """INSERT INTO org_memberships (org_id, tenant_id, role, joined_at)
                       VALUES ($1, $2, $3, $4)""",
                    "org_test",
                    tenant,
                    role,
                    1234567890.0,
                )

            await conn.execute("SELECT set_app_current_tenant($1)", "member_tenant")
            await _insert_job(conn, "job_member", "member_tenant", "example.com")

            await conn.execute("SELECT set_app_current_tenant($1)", "admin_tenant")
            jobs = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", "member_tenant")
            assert len(jobs) == 1


class TestRLSPerformance:
    """Performance characteristics of the policies."""

    async def test_query_plan_uses_index(self, pg_pool, tenant_a, tenant_b):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", SEED_ADMIN)
            await conn.executemany(
                """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state, verdict,
                       coverage, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
                [
                    (
                        f"job_bulk_{i}",
                        tenant_b,
                        "example.org",
                        "web",
                        "tester",
                        "{}",
                        "completed",
                        "clean",
                        "{}",
                        1234567890.0,
                    )
                    for i in range(200)
                ],
            )
            await _insert_job(conn, "job_one", tenant_a, "example.com")

            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            plan = await conn.fetch("EXPLAIN SELECT * FROM jobs WHERE tenant = $1", tenant_a)
            plan_text = " ".join(row["QUERY PLAN"] for row in plan)
            assert "Index Scan" in plan_text or "Bitmap Heap Scan" in plan_text, plan_text
            assert "idx_jobs_tenant_rls" in plan_text, plan_text

    async def test_plan_caching(self, pg_pool, tenant_a):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await _insert_job(conn, "job_a1", tenant_a, "example.com")

            await conn.execute(f"PREPARE test_plan AS SELECT * FROM jobs WHERE tenant = '{tenant_a}'")
            for _ in range(5):
                result = await conn.fetch("EXECUTE test_plan")
                assert len(result) == 1
            await conn.execute("DEALLOCATE test_plan")


class TestRLSMigration:
    """The migration must be applied by the application, not by hand."""

    async def test_backward_compatibility(self, pg_pool, tenant_a):
        async with pg_pool.acquire() as conn:
            await conn.execute("SELECT set_app_current_tenant($1)", tenant_a)
            await _insert_job(conn, "job_a1", tenant_a, "example.com")
            explicit = await conn.fetch("SELECT * FROM jobs WHERE tenant = $1", tenant_a)
            implicit = await conn.fetch("SELECT * FROM jobs")
            assert len(explicit) == len(implicit) == 1

    async def test_rls_applied_by_the_migration_chain(self, pg_ready):
        """No manual step: connecting to the database applies the RLS migration."""
        async with pg_ready.acquire() as conn:
            marker = await conn.fetchrow("SELECT value FROM settings WHERE key = 'rls_applied'")
            assert marker is not None
            helpers = await conn.fetch("SELECT 1 FROM pg_proc WHERE proname = 'rls_bypass_tenant'")
            assert helpers

    async def test_rls_can_be_disabled_for_migration(self, admin_pool):
        async with admin_pool.acquire() as conn:
            await conn.execute("ALTER TABLE jobs DISABLE ROW LEVEL SECURITY")
            row = await conn.fetchrow("SELECT relrowsecurity FROM pg_class WHERE relname = 'jobs'")
            assert row["relrowsecurity"] is False

            await conn.execute("ALTER TABLE jobs ENABLE ROW LEVEL SECURITY")
            row = await conn.fetchrow("SELECT relrowsecurity FROM pg_class WHERE relname = 'jobs'")
            assert row["relrowsecurity"] is True


async def test_transaction_applies_tenant_context(pg_ready, tenant_a):
    """RLS must be applied from the request context, not only by hand."""
    db = await store.get_database()
    assert db.is_postgresql()
    db.set_tenant_context(tenant_a)
    try:
        async with db.transaction() as conn:
            value = await conn.fetchval("SELECT current_setting('app.current_tenant', true)")
            assert value == tenant_a
    finally:
        db.set_tenant_context(None)

    # transaction-local setting must not leak through the pooled connection
    async with db.transaction() as conn:
        value = await conn.fetchval("SELECT current_setting('app.current_tenant', true)")
        assert value in (None, "")
