"""Initial schema: all tables up to version 18

Revision ID: a550477e21b9
Revises:
Create Date: 2026-11-15 11:50:02.108545

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a550477e21b9'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - creates all tables matching store.py MIGRATIONS up to version 18."""
    # Migration 1: jobs and findings tables
    op.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        tenant      TEXT NOT NULL,
        project     TEXT NOT NULL DEFAULT 'default',
        target      TEXT NOT NULL,
        profile     TEXT NOT NULL,
        actor       TEXT NOT NULL,
        policy      TEXT NOT NULL,
        state       TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        error       TEXT NOT NULL DEFAULT '',
        started_at  REAL,
        finished_at REAL,
        coverage    TEXT NOT NULL,
        created_at  REAL NOT NULL
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS jobs_by_tenant ON jobs (tenant, created_at DESC);")

    op.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        job_id           TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
        tenant           TEXT NOT NULL,
        fingerprint      TEXT NOT NULL,
        asset            TEXT NOT NULL,
        category         TEXT NOT NULL,
        title            TEXT NOT NULL,
        severity         TEXT NOT NULL,
        confidence       TEXT NOT NULL,
        verification     TEXT NOT NULL,
        status           TEXT NOT NULL,
        detector         TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        location         TEXT NOT NULL DEFAULT '',
        evidence         TEXT NOT NULL,
        description      TEXT NOT NULL DEFAULT '',
        remediation      TEXT NOT NULL DEFAULT '',
        cwe              TEXT NOT NULL DEFAULT '',
        cvss_score       TEXT NOT NULL DEFAULT '0.0',
        business_impact  TEXT NOT NULL DEFAULT 'low',
        asset_criticality TEXT NOT NULL DEFAULT 'medium',
        risk_rating      TEXT NOT NULL DEFAULT 'low',
        exploit_available INTEGER NOT NULL DEFAULT 0,
        user_impact      TEXT NOT NULL DEFAULT 'none',
        compliance_refs  TEXT NOT NULL DEFAULT '[]',
        remediation_status TEXT NOT NULL DEFAULT 'pending',
        discovered_date  TEXT NOT NULL DEFAULT '1970-01-01',
        reported_date    TEXT NOT NULL DEFAULT '1970-01-01',
        resolved_date    TEXT NOT NULL DEFAULT '1970-01-01',
        sources          TEXT NOT NULL,
        PRIMARY KEY (job_id, fingerprint)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS findings_by_tenant ON findings (tenant, category);")

    # Migration 2: api_keys, audit_log, audit_chain
    op.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        tenant_id  TEXT PRIMARY KEY,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      INTEGER NOT NULL,
        active     INTEGER NOT NULL,
        created_at REAL NOT NULL
    )
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT,
        event  TEXT,
        ts     REAL NOT NULL,
        data   TEXT NOT NULL
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS audit_log_by_tenant ON audit_log (tenant, id);")
    op.execute("""
    CREATE TABLE IF NOT EXISTS audit_chain (
        sequence      INTEGER PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    )
    """)

    # Migration 3: monitor_targets, settings
    op.execute("""
    CREATE TABLE IF NOT EXISTS monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at REAL NOT NULL
    )
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    # Migration 4: api_keys additions
    op.execute("ALTER TABLE api_keys ADD COLUMN expires_at REAL;")
    op.execute("ALTER TABLE api_keys ADD COLUMN last_used REAL;")
    op.execute("ALTER TABLE api_keys ADD COLUMN rotated_at REAL;")

    # Migration 5: engagement_policies, webhook_sinks
    op.execute("""
    CREATE TABLE IF NOT EXISTS engagement_policies (
        policy_id      TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        project        TEXT NOT NULL DEFAULT 'default',
        program        TEXT NOT NULL,
        authorized_by  TEXT NOT NULL,
        authorization_ref TEXT NOT NULL,
        include        TEXT NOT NULL,
        exclude        TEXT NOT NULL,
        authorized_networks TEXT NOT NULL,
        allowed_ports  TEXT NOT NULL,
        allow_broad_networks INTEGER NOT NULL DEFAULT 0,
        status         TEXT NOT NULL,
        version        INTEGER NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL,
        effective_at   REAL,
        expires_at     REAL,
        created_by     TEXT NOT NULL DEFAULT ''
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS policies_by_tenant ON engagement_policies (tenant_id, project, status);")
    op.execute("""
    CREATE TABLE IF NOT EXISTS webhook_sinks (
        name    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        added_at REAL NOT NULL
    )
    """)

    # Migration 6: jobs additions
    op.execute("ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;")
    op.execute("ALTER TABLE jobs ADD COLUMN worker TEXT NOT NULL DEFAULT '';")
    op.execute("ALTER TABLE jobs ADD COLUMN idempotency_key TEXT;")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency ON jobs (tenant, project, idempotency_key) WHERE idempotency_key IS NOT NULL;")
    op.execute("CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs (state, created_at);")

    # Migration 7: monitor_baseline
    op.execute("""
    CREATE TABLE IF NOT EXISTS monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   REAL NOT NULL
    )
    """)

    # Migration 8: api_keys ai_enabled
    op.execute("ALTER TABLE api_keys ADD COLUMN ai_enabled INTEGER NOT NULL DEFAULT 0;")

    # Migration 9: api_keys project column
    op.execute("ALTER TABLE api_keys ADD COLUMN project TEXT NOT NULL DEFAULT 'default';")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project ON api_keys (tenant_id, project);")

    # Migration 10: assessment_schedules, evidence_packs
    op.execute("""
    CREATE TABLE IF NOT EXISTS assessment_schedules (
        id              TEXT PRIMARY KEY,
        target          TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone        TEXT NOT NULL DEFAULT 'UTC',
        profile         TEXT NOT NULL DEFAULT 'web',
        state           TEXT NOT NULL DEFAULT 'active',
        policy_id       TEXT,
        created_at      REAL NOT NULL,
        updated_at      REAL NOT NULL,
        last_run        REAL,
        next_run        REAL,
        run_count       INTEGER NOT NULL DEFAULT 0,
        max_concurrent  INTEGER NOT NULL DEFAULT 1,
        catch_up        INTEGER NOT NULL DEFAULT 1,
        enabled         INTEGER NOT NULL DEFAULT 1
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS schedules_by_target ON assessment_schedules (target);")
    op.execute("CREATE INDEX IF NOT EXISTS schedules_by_state ON assessment_schedules (state);")

    op.execute("""
    CREATE TABLE IF NOT EXISTS evidence_packs (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        job_id        TEXT NOT NULL,
        period_start  REAL NOT NULL,
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS evidence_packs_by_tenant ON evidence_packs (tenant, period_start DESC);")

    # Migration 11: jobs cancel_requested
    op.execute("ALTER TABLE jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;")

    # Migration 12: assets, finding_events, finding_remediation
    op.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        tenant      TEXT NOT NULL,
        asset_key   TEXT NOT NULL,
        asset       TEXT NOT NULL,
        asset_type  TEXT NOT NULL DEFAULT 'unknown',
        owner       TEXT NOT NULL DEFAULT '',
        criticality TEXT NOT NULL DEFAULT 'medium',
        first_seen  REAL NOT NULL,
        last_seen   REAL NOT NULL,
        PRIMARY KEY (tenant, asset_key)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS assets_by_tenant ON assets (tenant, last_seen DESC);")
    op.execute("""
    CREATE TABLE IF NOT EXISTS finding_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant      TEXT NOT NULL,
        job_id      TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        event       TEXT NOT NULL,
        from_status TEXT NOT NULL DEFAULT '',
        to_status   TEXT NOT NULL DEFAULT '',
        actor       TEXT NOT NULL DEFAULT '',
        note        TEXT NOT NULL DEFAULT '',
        created_at  REAL NOT NULL
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS finding_events_by_finding ON finding_events (tenant, job_id, fingerprint, id);")
    op.execute("""
    CREATE TABLE IF NOT EXISTS finding_remediation (
        tenant                TEXT NOT NULL,
        job_id                TEXT NOT NULL,
        fingerprint           TEXT NOT NULL,
        owner                 TEXT NOT NULL DEFAULT '',
        due_at                REAL,
        exception_until       REAL,
        exception_reason      TEXT NOT NULL DEFAULT '',
        exception_approved_by TEXT NOT NULL DEFAULT '',
        updated_at            REAL NOT NULL,
        PRIMARY KEY (tenant, job_id, fingerprint)
    )
    """)

    # Migration 13: api_keys scope
    op.execute("ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'write';")

    # Migration 14: finding_records
    op.execute("""
    CREATE TABLE IF NOT EXISTS finding_records (
        tenant                TEXT NOT NULL,
        fingerprint           TEXT NOT NULL,
        owner                 TEXT NOT NULL DEFAULT '',
        due_at                REAL,
        exception_until       REAL,
        exception_reason      TEXT NOT NULL DEFAULT '',
        exception_approved_by TEXT NOT NULL DEFAULT '',
        resolution_state      TEXT NOT NULL DEFAULT 'open',
        resolved_at           REAL,
        resolved_job_id       TEXT NOT NULL DEFAULT '',
        resolution_evidence   TEXT NOT NULL DEFAULT '{}',
        updated_at            REAL NOT NULL,
        PRIMARY KEY (tenant, fingerprint)
    )
    """)
    op.execute("""
    INSERT INTO finding_records
        (tenant, fingerprint, owner, due_at, exception_until, exception_reason,
         exception_approved_by, updated_at)
    SELECT r.tenant, r.fingerprint, r.owner, r.due_at, r.exception_until,
           r.exception_reason, r.exception_approved_by, r.updated_at
      FROM finding_remediation r
     WHERE r.updated_at = (
           SELECT MAX(r2.updated_at) FROM finding_remediation r2
            WHERE r2.tenant = r.tenant AND r2.fingerprint = r.fingerprint)
    ON CONFLICT (tenant, fingerprint) DO NOTHING;
    """)

    # Migration 15: finding_records exception columns
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_state TEXT NOT NULL DEFAULT 'none';")
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_requested_by TEXT NOT NULL DEFAULT '';")
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_requested_at REAL;")
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_decided_by TEXT NOT NULL DEFAULT '';")
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_decided_at REAL;")
    op.execute("ALTER TABLE finding_records ADD COLUMN exception_note TEXT NOT NULL DEFAULT '';")
    op.execute("UPDATE finding_records SET exception_state = 'approved' WHERE exception_state = 'none' AND exception_until IS NOT NULL AND exception_approved_by != '';")

    # Migration 16: tenant_users
    op.execute("""
    CREATE TABLE IF NOT EXISTS tenant_users (
        user_id      TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role         TEXT NOT NULL,
        key_hash     TEXT NOT NULL UNIQUE,
        scope        TEXT NOT NULL,
        active       INTEGER NOT NULL,
        created_at   REAL NOT NULL,
        expires_at   REAL,
        last_used    REAL
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS tenant_users_by_tenant ON tenant_users (tenant_id, active);")

    # Migration 17: organizations, org_memberships
    op.execute("""
    CREATE TABLE IF NOT EXISTS organizations (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        admin_key_hash TEXT NOT NULL UNIQUE,
        tier           TEXT NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL
    )
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  REAL NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);")

    # Migration 18: api_keys org_id
    op.execute("ALTER TABLE api_keys ADD COLUMN org_id TEXT;")
    op.execute("CREATE INDEX IF NOT EXISTS api_keys_by_org ON api_keys (org_id);")


def downgrade() -> None:
    """Downgrade schema - drops all tables in reverse order."""
    # Migration 18
    op.execute("DROP INDEX IF EXISTS api_keys_by_org;")
    op.execute("ALTER TABLE api_keys DROP COLUMN org_id;")

    # Migration 17
    op.execute("DROP INDEX IF EXISTS org_memberships_by_tenant;")
    op.execute("DROP TABLE IF EXISTS org_memberships;")
    op.execute("DROP TABLE IF EXISTS organizations;")

    # Migration 16
    op.execute("DROP INDEX IF EXISTS tenant_users_by_tenant;")
    op.execute("DROP TABLE IF EXISTS tenant_users;")

    # Migration 15
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_note;")
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_decided_at;")
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_decided_by;")
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_requested_at;")
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_requested_by;")
    op.execute("ALTER TABLE finding_records DROP COLUMN exception_state;")

    # Migration 14
    op.execute("DROP TABLE IF EXISTS finding_records;")

    # Migration 13
    op.execute("ALTER TABLE api_keys DROP COLUMN scope;")

    # Migration 12
    op.execute("DROP TABLE IF EXISTS finding_remediation;")
    op.execute("DROP INDEX IF EXISTS finding_events_by_finding;")
    op.execute("DROP TABLE IF EXISTS finding_events;")
    op.execute("DROP INDEX IF EXISTS assets_by_tenant;")
    op.execute("DROP TABLE IF EXISTS assets;")

    # Migration 11
    op.execute("ALTER TABLE jobs DROP COLUMN cancel_requested;")

    # Migration 10
    op.execute("DROP INDEX IF EXISTS evidence_packs_by_tenant;")
    op.execute("DROP TABLE IF EXISTS evidence_packs;")
    op.execute("DROP INDEX IF EXISTS schedules_by_state;")
    op.execute("DROP INDEX IF EXISTS schedules_by_target;")
    op.execute("DROP TABLE IF EXISTS assessment_schedules;")

    # Migration 9
    op.execute("DROP INDEX IF EXISTS api_keys_tenant_project;")
    op.execute("ALTER TABLE api_keys DROP COLUMN project;")

    # Migration 8
    op.execute("ALTER TABLE api_keys DROP COLUMN ai_enabled;")

    # Migration 7
    op.execute("DROP TABLE IF EXISTS monitor_baseline;")

    # Migration 6
    op.execute("DROP INDEX IF EXISTS jobs_by_state;")
    op.execute("DROP INDEX IF EXISTS jobs_idempotency;")
    op.execute("ALTER TABLE jobs DROP COLUMN idempotency_key;")
    op.execute("ALTER TABLE jobs DROP COLUMN worker;")
    op.execute("ALTER TABLE jobs DROP COLUMN attempts;")

    # Migration 5
    op.execute("DROP TABLE IF EXISTS webhook_sinks;")
    op.execute("DROP INDEX IF EXISTS policies_by_tenant;")
    op.execute("DROP TABLE IF EXISTS engagement_policies;")

    # Migration 4
    op.execute("ALTER TABLE api_keys DROP COLUMN rotated_at;")
    op.execute("ALTER TABLE api_keys DROP COLUMN last_used;")
    op.execute("ALTER TABLE api_keys DROP COLUMN expires_at;")

    # Migration 3
    op.execute("DROP TABLE IF EXISTS settings;")
    op.execute("DROP TABLE IF EXISTS monitor_targets;")

    # Migration 2
    op.execute("DROP TABLE IF EXISTS audit_chain;")
    op.execute("DROP INDEX IF EXISTS audit_log_by_tenant;")
    op.execute("DROP TABLE IF EXISTS audit_log;")
    op.execute("DROP TABLE IF EXISTS api_keys;")

    # Migration 1
    op.execute("DROP INDEX IF EXISTS findings_by_tenant;")
    op.execute("DROP TABLE IF EXISTS findings;")
    op.execute("DROP INDEX IF EXISTS jobs_by_tenant;")
    op.execute("DROP TABLE IF EXISTS jobs;")