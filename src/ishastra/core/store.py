"""Unified SQLite/PostgreSQL persistence for assessment jobs and findings.

This module provides both async (primary) and sync (wrapper) APIs.
Async functions are the canonical implementation; sync wrappers delegate to them.

PostgreSQL support: each event loop gets its own pool (asyncpg pools are
loop-bound). The threaded worker creates its own event loop and pool.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

try:
    import asyncpg
except Exception:
    asyncpg = None

from ishastra.core.findings import (
    SEVERITY_RANK,
    Finding,
    allowed_transitions,
    dedupe,
    redact,
    validate_transition,
)
from ishastra.core.redaction import sanitize_target

log = logging.getLogger(__name__)


MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
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
    );
    CREATE INDEX IF NOT EXISTS jobs_by_tenant ON jobs (tenant, created_at DESC);
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
    );
    CREATE INDEX IF NOT EXISTS findings_by_tenant ON findings (tenant, category);
    """,
    ),
    (
        2,
        """
    CREATE TABLE IF NOT EXISTS api_keys (
        tenant_id  TEXT PRIMARY KEY,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      INTEGER NOT NULL,
        active     INTEGER NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant TEXT,
        event  TEXT,
        ts     REAL NOT NULL,
        data   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_log_by_tenant ON audit_log (tenant, id);
    CREATE TABLE IF NOT EXISTS audit_chain (
        sequence      INTEGER PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    );
    """,
    ),
    (
        3,
        """
    CREATE TABLE IF NOT EXISTS monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    ),
    (
        4,
        """
    ALTER TABLE api_keys ADD COLUMN expires_at REAL;
    ALTER TABLE api_keys ADD COLUMN last_used REAL;
    ALTER TABLE api_keys ADD COLUMN rotated_at REAL;
    """,
    ),
    (
        5,
        """
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
    );
    CREATE INDEX IF NOT EXISTS policies_by_tenant ON engagement_policies (tenant_id, project, status);
    CREATE TABLE IF NOT EXISTS webhook_sinks (
        name    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        added_at REAL NOT NULL
    );
    """,
    ),
    (
        6,
        """
    ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE jobs ADD COLUMN worker TEXT NOT NULL DEFAULT '';
    ALTER TABLE jobs ADD COLUMN idempotency_key TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency ON jobs (tenant, project, idempotency_key)
        WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs (state, created_at)
    """,
    ),
    (
        7,
        """
    CREATE TABLE IF NOT EXISTS monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   REAL NOT NULL
    )
    """,
    ),
    (
        8,
        """
    ALTER TABLE api_keys ADD COLUMN ai_enabled INTEGER NOT NULL DEFAULT 0;
    """,
    ),
    (
        9,
        """
    -- Add project column and unique constraint for multi-project support
    ALTER TABLE api_keys ADD COLUMN project TEXT NOT NULL DEFAULT 'default';
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project ON api_keys (tenant_id, project);
    """,
    ),
    (
        10,
        """
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
    );
    CREATE INDEX IF NOT EXISTS schedules_by_target ON assessment_schedules (target);
    CREATE INDEX IF NOT EXISTS schedules_by_state ON assessment_schedules (state);

    CREATE TABLE IF NOT EXISTS evidence_packs (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        job_id        TEXT NOT NULL,
        period_start  REAL NOT NULL,
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS evidence_packs_by_tenant ON evidence_packs (tenant, period_start DESC);
    """,
    ),
    (
        11,
        """
    ALTER TABLE jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;
    """,
    ),
    (
        12,
        """
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
    );
    CREATE INDEX IF NOT EXISTS assets_by_tenant ON assets (tenant, last_seen DESC);
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
    );
    CREATE INDEX IF NOT EXISTS finding_events_by_finding
        ON finding_events (tenant, job_id, fingerprint, id);
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
    );
    """,
    ),
    (
        13,
        """
    ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'write';
    """,
    ),
    (
        14,
        """
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
    );
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
    """,
    ),
    (
        15,
        """
    ALTER TABLE finding_records ADD COLUMN exception_state TEXT NOT NULL DEFAULT 'none';
    ALTER TABLE finding_records ADD COLUMN exception_requested_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE finding_records ADD COLUMN exception_requested_at REAL;
    ALTER TABLE finding_records ADD COLUMN exception_decided_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE finding_records ADD COLUMN exception_decided_at REAL;
    ALTER TABLE finding_records ADD COLUMN exception_note TEXT NOT NULL DEFAULT '';
    UPDATE finding_records SET exception_state = 'approved'
     WHERE exception_state = 'none' AND exception_until IS NOT NULL
       AND exception_approved_by != '';
    """,
    ),
    (
        16,
        """
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
    );
    CREATE INDEX IF NOT EXISTS tenant_users_by_tenant ON tenant_users (tenant_id, active);
    """,
    ),
    (
        17,
        """
    CREATE TABLE IF NOT EXISTS organizations (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        admin_key_hash TEXT NOT NULL UNIQUE,
        tier           TEXT NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  REAL NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    );
    CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);
    """,
    ),
    (
        18,
        """
    ALTER TABLE api_keys ADD COLUMN org_id TEXT;
    CREATE INDEX IF NOT EXISTS api_keys_by_org ON api_keys (org_id);
    """,
    ),
    (
        19,
        """
    ALTER TABLE api_keys ADD COLUMN include_hosts TEXT;
""",
    ),
    (
        20,
        """
    CREATE TABLE IF NOT EXISTS compliance_schedules (
        id              TEXT PRIMARY KEY,
        tenant          TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone        TEXT NOT NULL DEFAULT 'UTC',
        frameworks      TEXT NOT NULL DEFAULT '["nrb","nta","ncsp"]',
        frequency       TEXT NOT NULL DEFAULT 'quarterly',
        enabled         INTEGER NOT NULL DEFAULT 1,
        created_at      REAL NOT NULL,
        updated_at      REAL NOT NULL,
        last_run        REAL,
        next_run        REAL,
        run_count       INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS compliance_schedules_by_tenant ON compliance_schedules (tenant);
    CREATE INDEX IF NOT EXISTS compliance_schedules_by_enabled ON compliance_schedules (enabled);

    CREATE TABLE IF NOT EXISTS compliance_reports (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        schedule_id   TEXT NOT NULL,
        period_start  REAL NOT NULL,
        period_end    REAL NOT NULL,
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS compliance_reports_by_tenant ON compliance_reports (tenant, period_start DESC);
    CREATE INDEX IF NOT EXISTS compliance_reports_by_schedule ON compliance_reports (schedule_id);

    CREATE TABLE IF NOT EXISTS compliance_exports (
        report_id     TEXT NOT NULL,
        tenant        TEXT NOT NULL,
        format        TEXT NOT NULL DEFAULT 'csv',
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL,
        PRIMARY KEY (report_id, format)
    );
    CREATE INDEX IF NOT EXISTS compliance_exports_by_tenant ON compliance_exports (tenant, created_at DESC);
    """,
    ),
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
    (
        24,
        """
    -- Migration 24: Project-scoped API key extensions
    ALTER TABLE api_keys ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'tenant';
    ALTER TABLE api_keys ADD COLUMN project_id TEXT;
    ALTER TABLE api_keys ADD COLUMN allowed_projects TEXT;
    ALTER TABLE api_keys ADD COLUMN resource_filters TEXT;
    CREATE INDEX IF NOT EXISTS api_keys_by_project ON api_keys (project_id);
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project_id ON api_keys (tenant_id, project_id);
    """,
    ),
    (
        25,
        """
    -- Migration 25: Restore admin_key_hash for legacy org module
    ALTER TABLE organizations ADD COLUMN admin_key_hash TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS organizations_admin_key_hash ON organizations (admin_key_hash)
        WHERE admin_key_hash IS NOT NULL;
    -- Make slug nullable for backward compatibility with legacy org module
    CREATE TABLE organizations_v3 AS SELECT
        org_id, name, slug, settings, tier, created_at, updated_at, admin_key_hash
        FROM organizations;
    DROP TABLE organizations;
    CREATE TABLE organizations (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        slug           TEXT UNIQUE,
        settings       TEXT NOT NULL DEFAULT '{}',
        tier           TEXT NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL,
        admin_key_hash TEXT
    );
    INSERT INTO organizations SELECT * FROM organizations_v3;
    DROP TABLE organizations_v3;
    CREATE INDEX IF NOT EXISTS organizations_by_slug ON organizations (slug);
    """,
    ),
    (
        26,
        """
    -- Migration 26: Recreate org_memberships for legacy org module
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  REAL NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    );
    CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);
    """,
    ),
    (
        27,
        """
    -- Migration 27: Persist the email/identity for SCIM-provisioned users
    ALTER TABLE tenant_users ADD COLUMN email TEXT NOT NULL DEFAULT '';
    """,
    ),
    (
        28,
        """
    ALTER TABLE engagement_policies ADD COLUMN allowed_asns TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE engagement_policies ADD COLUMN allowed_countries TEXT NOT NULL DEFAULT '[]';
    """,
    ),
    (
        29,
        """
    -- Migration 29: Capability token revocation list
    CREATE TABLE IF NOT EXISTS capability_revocations (
        jti            TEXT PRIMARY KEY,
        key_id         TEXT NOT NULL,
        reason         TEXT NOT NULL DEFAULT '',
        revoked_at     REAL NOT NULL,
        revoked_by     TEXT NOT NULL DEFAULT '',
        job_id         TEXT,
        engagement_id  TEXT,
        tenant_id      TEXT
    );
    CREATE INDEX IF NOT EXISTS revocations_by_job ON capability_revocations (job_id);
    CREATE INDEX IF NOT EXISTS revocations_by_engagement ON capability_revocations (engagement_id);
    CREATE INDEX IF NOT EXISTS revocations_by_tenant ON capability_revocations (tenant_id);
    CREATE INDEX IF NOT EXISTS revocations_by_key ON capability_revocations (key_id);
    """,
    ),
    (
        30,
        """
    -- Migration 30: Capability token registry (tracks issued tokens for bulk revocation)
    CREATE TABLE IF NOT EXISTS capability_tokens (
        jti            TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        engagement_id  TEXT NOT NULL,
        job_id         TEXT NOT NULL,
        key_id         TEXT NOT NULL,
        issued_at      REAL NOT NULL,
        expires_at     REAL NOT NULL,
        policy_hash    TEXT NOT NULL,
        revoked        INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS tokens_by_job ON capability_tokens (job_id);
    CREATE INDEX IF NOT EXISTS tokens_by_engagement ON capability_tokens (engagement_id);
    CREATE INDEX IF NOT EXISTS tokens_by_tenant ON capability_tokens (tenant_id);
    CREATE INDEX IF NOT EXISTS tokens_by_key ON capability_tokens (key_id);
    """,
    ),
]


MIGRATIONS_PG: list[tuple[int, str]] = [
    (
        10,
        """
    -- Mirrors the SQLite schema. IDs, JSON payloads and epoch timestamps stay
    -- TEXT/TEXT/DOUBLE PRECISION because that is what the query layer binds;
    -- PostgreSQL-native UUID/TIMESTAMPTZ/JSONB columns rejected those values.
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
        started_at  DOUBLE PRECISION,
        finished_at DOUBLE PRECISION,
        coverage    TEXT NOT NULL,
        created_at  DOUBLE PRECISION NOT NULL,
        attempts    INTEGER NOT NULL DEFAULT 0,
        worker      TEXT NOT NULL DEFAULT '',
        idempotency_key TEXT
    );
    CREATE INDEX IF NOT EXISTS jobs_by_tenant ON jobs (tenant, created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency
        ON jobs (tenant, project, idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS jobs_by_state ON jobs (state, created_at);

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
        exploit_available BOOLEAN NOT NULL DEFAULT false,
        user_impact      TEXT NOT NULL DEFAULT 'none',
        compliance_refs  TEXT NOT NULL DEFAULT '[]',
        remediation_status TEXT NOT NULL DEFAULT 'pending',
        discovered_date  TEXT NOT NULL DEFAULT '1970-01-01',
        reported_date    TEXT NOT NULL DEFAULT '1970-01-01',
        resolved_date    TEXT NOT NULL DEFAULT '1970-01-01',
        sources          TEXT NOT NULL,
        PRIMARY KEY (job_id, fingerprint)
    );
    CREATE INDEX IF NOT EXISTS findings_by_tenant ON findings (tenant, category);

    CREATE TABLE IF NOT EXISTS api_keys (
        tenant_id  TEXT NOT NULL,
        key_hash   TEXT NOT NULL UNIQUE,
        tier       TEXT NOT NULL,
        admin      BOOLEAN NOT NULL,
        active     BOOLEAN NOT NULL,
        project    TEXT NOT NULL DEFAULT 'default',
        created_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION,
        last_used  DOUBLE PRECISION,
        rotated_at DOUBLE PRECISION,
        ai_enabled BOOLEAN NOT NULL DEFAULT false,
        PRIMARY KEY (tenant_id, project)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id     BIGSERIAL PRIMARY KEY,
        tenant TEXT,
        event  TEXT,
        ts     DOUBLE PRECISION NOT NULL,
        data   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_log_by_tenant ON audit_log (tenant, id);

    CREATE TABLE IF NOT EXISTS audit_chain (
        sequence      BIGINT PRIMARY KEY,
        previous_hash TEXT NOT NULL,
        hash          TEXT NOT NULL,
        data          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS monitor_targets (
        target   TEXT PRIMARY KEY,
        added_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

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
        allow_broad_networks BOOLEAN NOT NULL DEFAULT false,
        status         TEXT NOT NULL,
        version        INTEGER NOT NULL,
        created_at     DOUBLE PRECISION NOT NULL,
        updated_at     DOUBLE PRECISION NOT NULL,
        effective_at   DOUBLE PRECISION,
        expires_at     DOUBLE PRECISION,
        created_by     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS policies_by_tenant
        ON engagement_policies (tenant_id, project, status);

    CREATE TABLE IF NOT EXISTS webhook_sinks (
        name     TEXT PRIMARY KEY,
        url      TEXT NOT NULL,
        added_at DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS monitor_baseline (
        target       TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        updated_at   DOUBLE PRECISION NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assessment_schedules (
        id              TEXT PRIMARY KEY,
        target          TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone        TEXT NOT NULL DEFAULT 'UTC',
        profile         TEXT NOT NULL DEFAULT 'web',
        state           TEXT NOT NULL DEFAULT 'active',
        policy_id       TEXT,
        created_at      DOUBLE PRECISION NOT NULL,
        updated_at      DOUBLE PRECISION NOT NULL,
        last_run        DOUBLE PRECISION,
        next_run        DOUBLE PRECISION,
        run_count       INTEGER NOT NULL DEFAULT 0,
        max_concurrent  INTEGER NOT NULL DEFAULT 1,
        catch_up        BOOLEAN NOT NULL DEFAULT true,
        enabled         BOOLEAN NOT NULL DEFAULT true
    );
    CREATE INDEX IF NOT EXISTS schedules_by_target ON assessment_schedules (target);
    CREATE INDEX IF NOT EXISTS schedules_by_state ON assessment_schedules (state);

    CREATE TABLE IF NOT EXISTS evidence_packs (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        job_id        TEXT NOT NULL,
        period_start  DOUBLE PRECISION NOT NULL,
        data          TEXT NOT NULL,
        created_at    DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS evidence_packs_by_tenant ON evidence_packs (tenant, period_start DESC);
    """,
    ),
    (
        11,
        """
    ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT false;
    """,
    ),
    (
        12,
        """
    CREATE TABLE IF NOT EXISTS assets (
        tenant      TEXT NOT NULL,
        asset_key   TEXT NOT NULL,
        asset       TEXT NOT NULL,
        asset_type  TEXT NOT NULL DEFAULT 'unknown',
        owner       TEXT NOT NULL DEFAULT '',
        criticality TEXT NOT NULL DEFAULT 'medium',
        first_seen  DOUBLE PRECISION NOT NULL,
        last_seen   DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (tenant, asset_key)
    );
    CREATE INDEX IF NOT EXISTS assets_by_tenant ON assets (tenant, last_seen DESC);
    CREATE TABLE IF NOT EXISTS finding_events (
        id          BIGSERIAL PRIMARY KEY,
        tenant      TEXT NOT NULL,
        job_id      TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        event       TEXT NOT NULL,
        from_status TEXT NOT NULL DEFAULT '',
        to_status   TEXT NOT NULL DEFAULT '',
        actor       TEXT NOT NULL DEFAULT '',
        note        TEXT NOT NULL DEFAULT '',
        created_at  DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS finding_events_by_finding
        ON finding_events (tenant, job_id, fingerprint, id);
    CREATE TABLE IF NOT EXISTS finding_remediation (
        tenant                TEXT NOT NULL,
        job_id                TEXT NOT NULL,
        fingerprint           TEXT NOT NULL,
        owner                 TEXT NOT NULL DEFAULT '',
        due_at                DOUBLE PRECISION,
        exception_until       DOUBLE PRECISION,
        exception_reason      TEXT NOT NULL DEFAULT '',
        exception_approved_by TEXT NOT NULL DEFAULT '',
        updated_at            DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (tenant, job_id, fingerprint)
    );
    """,
    ),
    (
        13,
        """
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'write';
    """,
    ),
    (
        14,
        """
    CREATE TABLE IF NOT EXISTS finding_records (
        tenant                TEXT NOT NULL,
        fingerprint           TEXT NOT NULL,
        owner                 TEXT NOT NULL DEFAULT '',
        due_at                DOUBLE PRECISION,
        exception_until       DOUBLE PRECISION,
        exception_reason      TEXT NOT NULL DEFAULT '',
        exception_approved_by TEXT NOT NULL DEFAULT '',
        resolution_state      TEXT NOT NULL DEFAULT 'open',
        resolved_at           DOUBLE PRECISION,
        resolved_job_id       TEXT NOT NULL DEFAULT '',
        resolution_evidence   TEXT NOT NULL DEFAULT '{}',
        updated_at            DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (tenant, fingerprint)
    );
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
    """,
    ),
    (
        15,
        """
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_state TEXT NOT NULL DEFAULT 'none';
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_requested_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_requested_at DOUBLE PRECISION;
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_decided_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_decided_at DOUBLE PRECISION;
    ALTER TABLE finding_records ADD COLUMN IF NOT EXISTS exception_note TEXT NOT NULL DEFAULT '';
    UPDATE finding_records SET exception_state = 'approved'
     WHERE exception_state = 'none' AND exception_until IS NOT NULL
       AND exception_approved_by != '';
    """,
    ),
    (
        16,
        """
    CREATE TABLE IF NOT EXISTS tenant_users (
        user_id      TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role         TEXT NOT NULL,
        key_hash     TEXT NOT NULL UNIQUE,
        scope        TEXT NOT NULL,
        active       BOOLEAN NOT NULL,
        created_at   DOUBLE PRECISION NOT NULL,
        expires_at   DOUBLE PRECISION,
        last_used    DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS tenant_users_by_tenant ON tenant_users (tenant_id, active);
    """,
    ),
    (
        17,
        """
    CREATE TABLE IF NOT EXISTS organizations (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        admin_key_hash TEXT NOT NULL UNIQUE,
        tier           TEXT NOT NULL,
        created_at     DOUBLE PRECISION NOT NULL,
        updated_at     DOUBLE PRECISION NOT NULL
    );
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    );
    CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);
    """,
    ),
    (
        18,
        """
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS org_id TEXT;
    CREATE INDEX IF NOT EXISTS api_keys_by_org ON api_keys (org_id);
    """,
    ),
    (
        19,
        """
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS include_hosts TEXT;
    """,
    ),
    (
        20,
        """
    CREATE TABLE IF NOT EXISTS compliance_schedules (
        id              TEXT PRIMARY KEY,
        tenant          TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone        TEXT NOT NULL DEFAULT 'UTC',
        frameworks      TEXT NOT NULL DEFAULT '["nrb","nta","ncsp"]',
        frequency       TEXT NOT NULL DEFAULT 'quarterly',
        enabled         BOOLEAN NOT NULL DEFAULT true,
        created_at      DOUBLE PRECISION NOT NULL,
        updated_at      DOUBLE PRECISION NOT NULL,
        last_run        DOUBLE PRECISION,
        next_run        DOUBLE PRECISION,
        run_count       INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS compliance_schedules_by_tenant ON compliance_schedules (tenant);
    CREATE INDEX IF NOT EXISTS compliance_schedules_by_enabled ON compliance_schedules (enabled);

    CREATE TABLE IF NOT EXISTS compliance_reports (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        schedule_id   TEXT NOT NULL,
        period_start  DOUBLE PRECISION NOT NULL,
        period_end    DOUBLE PRECISION NOT NULL,
        data          TEXT NOT NULL,
        created_at    DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS compliance_reports_by_tenant ON compliance_reports (tenant, period_start DESC);
    CREATE INDEX IF NOT EXISTS compliance_reports_by_schedule ON compliance_reports (schedule_id);

    CREATE TABLE IF NOT EXISTS compliance_exports (
        report_id     TEXT NOT NULL,
        tenant        TEXT NOT NULL,
        format        TEXT NOT NULL DEFAULT 'csv',
        data          TEXT NOT NULL,
        created_at    DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (report_id, format)
    );
    CREATE INDEX IF NOT EXISTS compliance_exports_by_tenant ON compliance_exports (tenant, created_at DESC);
    """,
    ),
    (
        21,
        """
    -- Migration 21: Enhanced organizations table with slug and settings (PostgreSQL)
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
    -- Migration 22: Teams table (PostgreSQL)
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
    -- Migration 23: Memberships table (org and team level) (PostgreSQL)
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
    (
        24,
        """
    -- Migration 24: Project-scoped API key extensions (PostgreSQL)
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope_type TEXT NOT NULL DEFAULT 'tenant';
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS project_id TEXT;
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS allowed_projects TEXT;
    ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS resource_filters TEXT;
    CREATE INDEX IF NOT EXISTS api_keys_by_project ON api_keys (project_id);
    CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project_id ON api_keys (tenant_id, project_id);
    """,
    ),
    (
        25,
        """
    -- Migration 25: Restore admin_key_hash for legacy org module (PostgreSQL)
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS admin_key_hash TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS organizations_admin_key_hash ON organizations (admin_key_hash)
        WHERE admin_key_hash IS NOT NULL;
    """,
    ),
    (
        26,
        """
    -- Migration 26: Recreate org_memberships for legacy org module (PostgreSQL)
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    );
    CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);
    """,
    ),
    (
        27,
        """
    -- Migration 27: Persist the email/identity for SCIM-provisioned users (PostgreSQL)
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
    """,
    ),
    (
        28,
        """
    ALTER TABLE engagement_policies ADD COLUMN allowed_asns TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE engagement_policies ADD COLUMN allowed_countries TEXT NOT NULL DEFAULT '[]';
    """,
    ),
    (
        29,
        """
    -- Migration 29: Distributed leases table for leader election
    CREATE TABLE IF NOT EXISTS distributed_leases (
        name TEXT PRIMARY KEY,
        holder TEXT NOT NULL,
        lock_id BIGINT NOT NULL,
        category TEXT NOT NULL DEFAULT 'custom',
        acquired_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        ttl_seconds DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_distributed_leases_expires ON distributed_leases (expires_at);
    CREATE INDEX IF NOT EXISTS idx_distributed_leases_category ON distributed_leases (category);
    """,
    ),
    (
        30,
        """
    -- Migration 30: Capability token revocation list (PostgreSQL)
    CREATE TABLE IF NOT EXISTS capability_revocations (
        jti            TEXT PRIMARY KEY,
        key_id         TEXT NOT NULL,
        reason         TEXT NOT NULL DEFAULT '',
        revoked_at     DOUBLE PRECISION NOT NULL,
        revoked_by     TEXT NOT NULL DEFAULT '',
        job_id         TEXT,
        engagement_id  TEXT,
        tenant_id      TEXT
    );
    CREATE INDEX IF NOT EXISTS revocations_by_job ON capability_revocations (job_id);
    CREATE INDEX IF NOT EXISTS revocations_by_engagement ON capability_revocations (engagement_id);
    CREATE INDEX IF NOT EXISTS revocations_by_tenant ON capability_revocations (tenant_id);
    CREATE INDEX IF NOT EXISTS revocations_by_key ON capability_revocations (key_id);
    """,
    ),
    (
        31,
        """
    -- Migration 31: Capability token registry (tracks issued tokens for bulk revocation) (PostgreSQL)
    CREATE TABLE IF NOT EXISTS capability_tokens (
        jti            TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        engagement_id  TEXT NOT NULL,
        job_id         TEXT NOT NULL,
        key_id         TEXT NOT NULL,
        issued_at      DOUBLE PRECISION NOT NULL,
        expires_at     DOUBLE PRECISION NOT NULL,
        policy_hash    TEXT NOT NULL,
        revoked        BOOLEAN NOT NULL DEFAULT false
    );
    CREATE INDEX IF NOT EXISTS tokens_by_job ON capability_tokens (job_id);
    CREATE INDEX IF NOT EXISTS tokens_by_engagement ON capability_tokens (engagement_id);
    CREATE INDEX IF NOT EXISTS tokens_by_tenant ON capability_tokens (tenant_id);
    CREATE INDEX IF NOT EXISTS tokens_by_key ON capability_tokens (key_id);
    """,
    ),
    (
        32,
        """
    -- Migration 32: Lease fencing token for safe failover (PostgreSQL)
    ALTER TABLE distributed_leases
        ADD COLUMN IF NOT EXISTS fencing_token BIGINT NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS idx_distributed_leases_fencing_token
        ON distributed_leases (fencing_token);
    """,
    ),
    (
        33,
        """
    -- Migration 33: Durable PostgreSQL queue schema (worker runtime reads only)
    CREATE TABLE IF NOT EXISTS ishastra_queue (
        job_id             TEXT PRIMARY KEY,
        tenant_id          TEXT NOT NULL,
        target             TEXT NOT NULL,
        profile            TEXT NOT NULL,
        actor              TEXT NOT NULL,
        policy             TEXT NOT NULL,
        policy_id          TEXT NOT NULL DEFAULT '',
        state              TEXT NOT NULL DEFAULT 'queued',
        created_at         DOUBLE PRECISION NOT NULL,
        claimed_at         DOUBLE PRECISION,
        claimed_by         TEXT,
        visibility_timeout DOUBLE PRECISION,
        retries            INTEGER NOT NULL DEFAULT 0,
        max_attempts       INTEGER NOT NULL DEFAULT 3,
        idempotency_key    TEXT,
        cancel_requested   BOOLEAN NOT NULL DEFAULT FALSE,
        error              TEXT NOT NULL DEFAULT '',
        finished_at        DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS idx_ishastra_queue_state_created
        ON ishastra_queue (state, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ishastra_queue_idempotency
        ON ishastra_queue (idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_ishastra_queue_policy
        ON ishastra_queue (policy_id, state);
    CREATE TABLE IF NOT EXISTS job_attempts (
        id          BIGSERIAL PRIMARY KEY,
        job_id      TEXT NOT NULL,
        attempt     INTEGER NOT NULL,
        worker      TEXT NOT NULL,
        state       TEXT NOT NULL DEFAULT 'running',
        started_at  DOUBLE PRECISION NOT NULL,
        finished_at DOUBLE PRECISION,
        error       TEXT NOT NULL DEFAULT '',
        UNIQUE (job_id, attempt)
    );
    CREATE INDEX IF NOT EXISTS idx_job_attempts_job
        ON job_attempts (job_id, attempt DESC);
    """,
    ),
    (
        34,
        """
    -- Migration 34: SCIM 2.0 mapping and token tables
    CREATE TABLE IF NOT EXISTS scim_user_mappings (
        scim_id          TEXT PRIMARY KEY,
        ishastra_user_id TEXT NOT NULL,
        tenant_id        TEXT NOT NULL,
        scim_token       TEXT NOT NULL,
        created_at       DOUBLE PRECISION NOT NULL,
        UNIQUE(tenant_id, scim_token, scim_id)
    );
    CREATE INDEX IF NOT EXISTS scim_user_mappings_by_tenant
        ON scim_user_mappings (tenant_id, scim_token);
    CREATE TABLE IF NOT EXISTS scim_group_mappings (
        scim_id      TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        external_id  TEXT,
        tenant_id    TEXT NOT NULL,
        org_id       TEXT,
        member_ids   TEXT NOT NULL DEFAULT '[]',
        scim_token   TEXT NOT NULL,
        created_at   DOUBLE PRECISION NOT NULL,
        updated_at   DOUBLE PRECISION NOT NULL,
        UNIQUE(tenant_id, scim_token, scim_id)
    );
    CREATE INDEX IF NOT EXISTS scim_group_mappings_by_tenant
        ON scim_group_mappings (tenant_id, scim_token);
    CREATE TABLE IF NOT EXISTS scim_tokens (
        token_hash   TEXT PRIMARY KEY,
        tenant_id    TEXT NOT NULL,
        org_id       TEXT,
        name         TEXT NOT NULL,
        active       INTEGER NOT NULL DEFAULT 1,
        created_at   DOUBLE PRECISION NOT NULL,
        expires_at   DOUBLE PRECISION,
        last_used    DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS scim_tokens_by_tenant
        ON scim_tokens (tenant_id, active);
    """,
    ),
]

TERMINAL_STATES = ("completed", "partial", "failed", "cancelled")


class JobConflict(RuntimeError):
    """An idempotency key was already used by another job."""


class Database(ABC):
    """Abstract database interface supporting SQLite and PostgreSQL."""

    @abstractmethod
    async def execute(self, sql: str, *params: Any) -> Any:
        """Execute a SQL statement."""

    @abstractmethod
    async def fetchone(self, sql: str, *params: Any) -> Any:
        """Fetch one row."""

    @abstractmethod
    async def fetchall(self, sql: str, *params: Any) -> list[Any]:
        """Fetch all rows."""

    @abstractmethod
    async def executemany(self, sql: str, params_list: list[tuple]) -> None:
        """Execute many statements."""

    @abstractmethod
    async def close(self) -> None:
        """Close the database connection/pool."""

    @abstractmethod
    async def migrate(self) -> int:
        """Apply pending migrations. Returns the resulting schema version."""

    @abstractmethod
    async def schema_version(self) -> int:
        """Get current schema version."""

    @abstractmethod
    def is_postgresql(self) -> bool:
        """Return True if this is a PostgreSQL database."""

    @abstractmethod
    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Context manager for a transaction (yields connection)."""

    @abstractmethod
    def read_transaction(self) -> AbstractAsyncContextManager[Any]:
        """Context manager for a read-only transaction (yields connection).

        PostgreSQL: SET TRANSACTION READ ONLY. SQLite: PRAGMA query_only.
        Used by the capability verifier and revocation reads so a compromised
        read path cannot mutate state.
        """

    @abstractmethod
    def transaction_with_tenant(self, tenant_id: str | None) -> AbstractAsyncContextManager[Any]:
        """Context manager for a transaction with tenant context set.

        For PostgreSQL: sets app.current_tenant for RLS policies.
        For SQLite: no-op (uses application-level filtering).
        """

    @abstractmethod
    def advisory_lock(self, lock_id: int) -> AbstractAsyncContextManager[Any]:
        """Context manager for a transaction with an advisory lock held.

        For PostgreSQL: uses pg_advisory_xact_lock for writer coordination.
        For SQLite: returns a regular transaction (single-writer by design).
        """

    @abstractmethod
    async def try_advisory_lock(self, lock_id: int) -> bool:
        """Try to acquire an advisory lock without blocking. Returns True if acquired."""

    @abstractmethod
    async def release_advisory_lock(self, lock_id: int) -> bool:
        """Release an advisory lock. Returns True if released."""

    @abstractmethod
    def set_tenant_context(self, tenant_id: str | None) -> None:
        """Set the current tenant context for RLS policies.

        For PostgreSQL: sets thread-local tenant context.
        For SQLite: no-op (uses application-level filtering).
        """


class SQLiteDatabase(Database):
    """SQLite implementation using aiosqlite with per-event-loop pools.

    aiosqlite connections are bound to the event loop that created them.
    This class maintains a separate connection pool for each event loop
    to avoid cross-loop connection issues (e.g., worker threads with
    their own event loops).
    """

    def __init__(self, path: str, max_size: int = 10):
        self.path = path
        self.max_size = max_size
        self._memory_uri = f"file:ishastra_mem_{uuid.uuid4().hex}?mode=memory&cache=shared"

        self._pools: dict[int, dict] = {}
        self._pool_lock = threading.Lock()
        self._migrated = False

    def _get_loop_id(self) -> int:
        """Get the current event loop's identifier."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return 0
        return id(loop)

    def _get_pool(self) -> dict:
        """Get or create the pool state for the current event loop."""
        loop_id = self._get_loop_id()
        with self._pool_lock:
            if loop_id not in self._pools:
                self._pools[loop_id] = {
                    "pool": deque(),
                    "connections": set(),
                    "in_use": 0,
                    "migrated": False,
                }
            return self._pools[loop_id]

    async def _connect(self) -> aiosqlite.Connection:
        if self.path == ":memory:":
            conn = await aiosqlite.connect(self._memory_uri, uri=True)
        else:
            conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA busy_timeout = 10000")
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        await conn.execute("PRAGMA synchronous = NORMAL")
        pool = self._get_pool()
        pool["connections"].add(conn)
        return conn

    async def _get_conn(self) -> aiosqlite.Connection:
        """Get a connection from the pool (thread-safe, per-event-loop)."""
        while True:
            create = False
            pool = self._get_pool()
            with self._pool_lock:
                if pool["pool"]:
                    pool["in_use"] += 1
                    return pool["pool"].popleft()
                if pool["in_use"] < self.max_size:
                    pool["in_use"] += 1
                    create = True
            if create:
                try:
                    conn = await self._connect()

                    if not pool["migrated"]:
                        await self._migrate_sqlite(conn)
                        pool["migrated"] = True
                    return conn
                except Exception:
                    with self._pool_lock:
                        pool["in_use"] = max(0, pool["in_use"] - 1)
                    raise

            await asyncio.sleep(0.01)

    async def _put_conn(self, conn: aiosqlite.Connection) -> None:
        """Return a connection to the pool."""
        from ishastra import metrics

        pool = self._get_pool()
        with self._pool_lock:
            pool["in_use"] = max(0, pool["in_use"] - 1)
            pool["pool"].append(conn)
        metrics.record_db_pool("sqlite", self.max_size, max(0, self.max_size - pool["in_use"]))

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """Get a connection with an active transaction."""
        from ishastra import metrics

        acquire_started = time.monotonic()
        conn = await self._get_conn()
        metrics.observe_db_acquire("sqlite", time.monotonic() - acquire_started)
        pool = self._get_pool()
        metrics.record_db_pool("sqlite", self.max_size, max(0, self.max_size - pool["in_use"]))
        if self.path != ":memory:":
            size = None
            with contextlib.suppress(OSError):
                size = Path(self.path).stat().st_size
            if size is not None:
                metrics.record_db_size("sqlite", float(size))
        try:
            await conn.execute("BEGIN IMMEDIATE")
            yield conn
            await conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise
        finally:
            await self._put_conn(conn)

    @asynccontextmanager
    async def read_transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """A transaction where SQLite rejects writes (PRAGMA query_only)."""
        async with self.transaction() as conn:
            await conn.execute("PRAGMA query_only=ON")
            try:
                yield conn
            finally:
                await conn.execute("PRAGMA query_only=OFF")

    def transaction_with_tenant(
        self, tenant_id: str | None
    ) -> AbstractAsyncContextManager[aiosqlite.Connection]:
        """SQLite doesn't support RLS; this is a passthrough to transaction().

        Tenant filtering is done at the application level via query parameters.
        """
        return self.transaction()

    def advisory_lock(self, lock_id: int) -> AbstractAsyncContextManager[aiosqlite.Connection]:
        """SQLite is single-writer; advisory lock is a no-op passthrough to transaction()."""
        return self.transaction()

    async def try_advisory_lock(self, lock_id: int) -> bool:
        """SQLite doesn't support advisory locks; always returns True."""
        return True

    async def release_advisory_lock(self, lock_id: int) -> bool:
        """SQLite doesn't support advisory locks; always returns True."""
        return True

    async def execute(self, sql: str, *params: Any) -> Any:
        async with self.transaction() as conn:
            return await conn.execute(sql, params)

    async def fetchone(self, sql: str, *params: Any) -> Any:
        async with self.transaction() as conn:
            cursor = await conn.execute(sql, params)
            return await cursor.fetchone()

    async def fetchall(self, sql: str, *params: Any) -> list[Any]:
        async with self.transaction() as conn:
            cursor = await conn.execute(sql, params)
            return list(await cursor.fetchall())

    async def executemany(self, sql: str, params_list: list[tuple]) -> None:
        async with self.transaction() as conn:
            await conn.executemany(sql, params_list)

    async def close(self) -> None:
        all_connections = []
        with self._pool_lock:
            for pool in self._pools.values():
                all_connections.extend(pool["connections"])
            self._pools.clear()
        await _close_connections(all_connections)

    def discard_sync(self) -> None:
        """Close every connection without requiring a live event loop."""
        all_connections = []
        with self._pool_lock:
            for pool in self._pools.values():
                all_connections.extend(pool["connections"])
            self._pools.clear()
        if not all_connections:
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(_close_connections(all_connections))
        else:
            for conn in all_connections:
                with contextlib.suppress(Exception):
                    conn.stop()

    async def migrate(self) -> int:
        conn = await self._get_conn()
        try:
            version = await self._migrate_sqlite(conn)
        finally:
            await self._put_conn(conn)
        return version

    async def _migrate_sqlite(self, connection: aiosqlite.Connection) -> int:
        """Apply pending SQLite migrations. Returns the resulting schema version."""
        cursor = await connection.execute("PRAGMA user_version")
        row = await cursor.fetchone()
        version = int(row[0]) if row else 0
        for target, script in MIGRATIONS:
            if target <= version:
                continue
            await connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in script.split(";"):
                    stmt = "\n".join(
                        line for line in statement.splitlines() if not line.strip().startswith("--")
                    ).strip()
                    if stmt:
                        await connection.execute(stmt)
                await connection.execute(f"PRAGMA user_version = {int(target)}")
                await connection.commit()
            except Exception:
                await connection.rollback()
                raise
            version = target
        return version

    async def schema_version(self) -> int:
        async with self.transaction() as conn:
            row = await conn.execute("PRAGMA user_version")
            version_row = await row.fetchone()
            return version_row[0] if version_row else 0

    def is_postgresql(self) -> bool:
        return False

    def set_tenant_context(self, tenant_id: str | None) -> None:
        """Set the current tenant context for RLS policies.

        For SQLite: no-op (uses application-level filtering).
        """


class PostgreSQLDatabase(Database):
    """PostgreSQL implementation using asyncpg with per-event-loop pools.

    asyncpg pools are bound to the event loop that created them. This
    implementation uses thread-local storage to maintain a pool per event loop.

    RLS tenant context is set on connection checkout via init callback.
    """

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10):
        if asyncpg is None:
            raise RuntimeError("asyncpg is required for PostgreSQL support")
        self.dsn = dsn
        self.min_size = min_size
        self.max_size = max_size
        self._pools: dict[int, asyncpg.Pool] = {}
        self._pool_loops: dict[int, asyncio.AbstractEventLoop] = {}
        self._pool_lock = threading.Lock()

        self._tenant_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "ishastra_db_tenant", default=None
        )

    def set_tenant_context(self, tenant_id: str | None) -> None:
        """Set the tenant for transactions created in this task/context."""
        self._tenant_context.set(tenant_id)

    def get_tenant_context(self) -> str | None:
        """The tenant for this task/context, if any."""
        return self._tenant_context.get()

    async def _create_pool_with_rls(self) -> asyncpg.Pool:
        """Create the pool; tenant context is applied per transaction."""
        return await asyncpg.create_pool(
            self.dsn,
            min_size=self.min_size,
            max_size=self.max_size,
        )

    def _get_loop_id(self) -> int:
        """Get the current event loop's identifier."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return 0
        return id(loop)

    async def _ensure_pool(self) -> asyncpg.Pool:
        """Ensure pool is created and initialized for current loop."""
        loop_id = self._get_loop_id()
        with self._pool_lock:
            pool = self._pools.get(loop_id)
        if pool is None:
            pool = await self._create_pool_with_rls()

            async with pool.acquire() as conn:
                await self._migrate_pg(conn, self.dsn)
                from ishastra import metrics

                with contextlib.suppress(Exception):
                    size = await conn.fetchval("SELECT pg_database_size(current_database())")
                    metrics.record_db_size("postgres", float(size or 0))
            with self._pool_lock:
                if loop_id not in self._pools:
                    self._pools[loop_id] = pool
                    self._pool_loops[loop_id] = asyncio.get_running_loop()
                else:
                    await pool.close()
                    pool = self._pools[loop_id]
        return pool

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[asyncpg.Connection]:
        """Get a connection with an active transaction."""
        from ishastra import metrics

        acquire_started = time.monotonic()
        pool = await self._ensure_pool()
        tenant_id = self.get_tenant_context()
        async with pool.acquire() as conn, conn.transaction():
            metrics.observe_db_acquire("postgres", time.monotonic() - acquire_started)
            idle = getattr(pool, "get_idle_size", lambda: 0)()
            metrics.record_db_pool("postgres", pool.get_size(), idle)
            if tenant_id:
                await conn.execute("SELECT set_config('app.current_tenant', $1, true)", tenant_id)
            yield conn

    @asynccontextmanager
    async def read_transaction(self) -> AsyncIterator[asyncpg.Connection]:
        """A transaction PostgreSQL refuses to write in.

        This is the verifier/revocation read path. A dedicated read-only DB
        role is still recommended at deployment time; this makes the code path
        safe even when the process connects as a writer.
        """
        from ishastra import metrics

        acquire_started = time.monotonic()
        pool = await self._ensure_pool()
        tenant_id = self.get_tenant_context()
        async with pool.acquire() as conn, conn.transaction():
            metrics.observe_db_acquire("postgres", time.monotonic() - acquire_started)
            await conn.execute("SET TRANSACTION READ ONLY")
            if tenant_id:
                await conn.execute("SELECT set_config('app.current_tenant', $1, true)", tenant_id)
            yield conn

    @asynccontextmanager
    async def advisory_lock(self, lock_id: int) -> AsyncIterator[asyncpg.Connection]:
        """Get a connection with an advisory lock held.

        PostgreSQL advisory locks are session-scoped and don't block reads.
        They're ideal for coordinating writers without blocking readers.
        """
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            acquired = await conn.fetchval("SELECT pg_try_advisory_xact_lock($1::bigint)", lock_id)
            if not acquired:
                await conn.execute("SELECT pg_advisory_xact_lock($1::bigint)", lock_id)
            try:
                async with conn.transaction():
                    yield conn
            finally:
                await conn.execute("SELECT pg_advisory_unlock($1::bigint)", lock_id)

    async def try_advisory_lock(self, lock_id: int) -> bool:
        """Try to acquire an advisory lock without blocking. Returns True if acquired."""
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            return await conn.fetchval("SELECT pg_try_advisory_lock($1)", lock_id)

    async def release_advisory_lock(self, lock_id: int) -> bool:
        """Release an advisory lock. Returns True if released."""
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            return await conn.fetchval("SELECT pg_advisory_unlock($1)", lock_id)

    def transaction_with_tenant(
        self, tenant_id: str | None
    ) -> AbstractAsyncContextManager[asyncpg.Connection]:
        """Get a connection with tenant context set for RLS policies.

        This sets the app.current_tenant setting for the duration of the transaction,
        enabling RLS policies to filter by tenant. Pass None for admin/cross-tenant access.
        """

        @asynccontextmanager
        async def _ctx() -> AsyncIterator[asyncpg.Connection]:
            pool = await self._ensure_pool()
            async with pool.acquire() as conn, conn.transaction():
                if tenant_id:
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", tenant_id)
                yield conn

        return _ctx()

    async def execute(self, sql: str, *params: Any) -> Any:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(sql, *params)
            last = status.rsplit(" ", 1)[-1]
            from types import SimpleNamespace

            return SimpleNamespace(rowcount=int(last) if last.isdigit() else 0)

    async def fetchone(self, sql: str, *params: Any) -> Any:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            return await conn.fetchrow(sql, *params)

    async def fetchall(self, sql: str, *params: Any) -> list[Any]:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            return await conn.fetch(sql, *params)

    async def executemany(self, sql: str, params_list: list[tuple]) -> None:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            await conn.executemany(sql, params_list)

    async def close(self) -> None:
        with self._pool_lock:
            items = [(id_, pool, self._pool_loops.get(id_)) for id_, pool in list(self._pools.items())]
            self._pools.clear()
            self._pool_loops.clear()
        current = asyncio.get_running_loop()
        for _loop_id, pool, owner in items:
            if owner is current and not current.is_closed():
                with contextlib.suppress(Exception):
                    await pool.close()
            else:
                with contextlib.suppress(Exception):
                    pool.terminate()

    def discard_sync(self) -> None:
        """Close all pools without requiring a live event loop."""
        with self._pool_lock:
            pools = list(self._pools.values())
            self._pools.clear()
            self._pool_loops.clear()
        for pool in pools:
            with contextlib.suppress(Exception):
                pool.terminate()

    async def migrate(self) -> int:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            await self._migrate_pg(conn, self.dsn)
            row = await conn.fetchrow(
                "SELECT COALESCE(value::int, 0) FROM settings WHERE key = 'schema_version'"
            )
            return row[0] if row else 0

    async def _migrate_pg(self, conn: asyncpg.Connection, dsn: str) -> None:
        """Apply PostgreSQL migrations.

        Only executes DDL when the schema is missing or behind. A least-privilege
        runtime role may have no CREATE privilege on a current schema.
        """
        settings_exists = await conn.fetchval("SELECT to_regclass('public.settings') IS NOT NULL")
        if settings_exists:
            row = await conn.fetchrow(
                "SELECT COALESCE(value::int, 0) FROM settings WHERE key = 'schema_version'"
            )
            version = row[0] if row else 0
        else:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            version = 0
        for target, script in MIGRATIONS_PG:
            if target <= version:
                continue
            async with conn.transaction():
                try:
                    for statement in script.split(";"):
                        stmt = "\n".join(
                            line for line in statement.splitlines() if not line.strip().startswith("--")
                        ).strip()
                        if not stmt:
                            continue
                        await conn.execute(stmt)
                    await conn.execute(
                        "INSERT INTO settings (key, value) VALUES ('schema_version', $1) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                        str(target),
                    )
                except Exception:
                    raise
                version = target

        await self._migrate_pg_rls(conn)

    async def _migrate_pg_rls(self, conn: asyncpg.Connection) -> None:
        """Apply the row-level-security step once the schema is current."""
        from ishastra.core.pg_rls import RLS_SCHEMA_VERSION, apply_rls

        row = await conn.fetchrow("SELECT value FROM settings WHERE key = 'rls_applied'")
        if row and row["value"] == str(RLS_SCHEMA_VERSION):
            return
        await apply_rls(conn)
        await conn.execute(
            "INSERT INTO settings (key, value) VALUES ('rls_applied', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            str(RLS_SCHEMA_VERSION),
        )

    async def schema_version(self) -> int:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COALESCE(value::int, 0) FROM settings WHERE key = 'schema_version'"
            )
            return row[0] if row else 0

    def is_postgresql(self) -> bool:
        return True


async def _close_connections(connections: list[Any]) -> None:
    for conn in connections:
        with contextlib.suppress(Exception):
            await conn.close()


_database: Database | None = None
_database_lock = threading.Lock()
_database_creating = False
# Bumped whenever the configured database changes. A creation coroutine that
# started before the change must not publish its now-stale pool afterwards.
_generation = 0
_path: str = "ishastra.db"


def configure(path: str | Path) -> None:
    """Set the database file path or DSN. Resets the connection pool."""
    global _path, _database, _database_creating, _generation

    with _database_lock:
        _generation += 1
        previous, _database = _database, None
        _database_creating = False
        _path = str(path)
    if previous is not None and hasattr(previous, "discard_sync"):
        previous.discard_sync()


def current_path() -> str:
    return _path


def _detect_db_type(path_or_dsn: str) -> str:
    """Detect database type from path or DSN."""
    if path_or_dsn.startswith(("postgresql://", "postgres://")):
        return "postgresql"
    return "sqlite"


PG_POOL_DEFAULT_MIN = 1
PG_POOL_DEFAULT_MAX = 5
PG_POOL_MAX_LIMIT = 50


def _pg_pool_size(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        log.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default
    if value < 1:
        log.warning("%s=%d must be at least 1; using %d", name, value, default)
        return default
    if value > PG_POOL_MAX_LIMIT:
        log.warning("%s=%d clamped to %d", name, value, PG_POOL_MAX_LIMIT)
        return PG_POOL_MAX_LIMIT
    return value


def _pg_pool_sizes() -> tuple[int, int]:
    """``(min, max)`` asyncpg pool size for this process.

    Every process keeps its own pool, so ``max x replicas`` must stay under the
    server's ``max_connections`` (or every client must go through PgBouncer).
    A fleet of 30 workers with the old hard-coded 10 would ask for 300
    connections and fail to start.
    """
    minimum = _pg_pool_size("ISHASTRA_PG_POOL_MIN", PG_POOL_DEFAULT_MIN)
    maximum = _pg_pool_size("ISHASTRA_PG_POOL_MAX", PG_POOL_DEFAULT_MAX)
    if maximum < minimum:
        log.warning(
            "ISHASTRA_PG_POOL_MAX=%d is below ISHASTRA_PG_POOL_MIN=%d; using %d",
            maximum,
            minimum,
            minimum,
        )
        maximum = minimum
    return minimum, maximum


def _create_database() -> Database:
    """Create a database instance based on the configured path/DSN."""
    db_type = _detect_db_type(_path)
    if db_type == "postgresql":
        minimum, maximum = _pg_pool_sizes()
        return PostgreSQLDatabase(_path, min_size=minimum, max_size=maximum)
    return SQLiteDatabase(_path)


async def get_database() -> Database:
    """Get or create the database instance (singleton per process).

    Exactly one caller (on any event loop, in any thread) may build the
    database and run the schema migrations; everyone else waits and then
    reuses it.
    """
    global _database, _database_creating
    while True:
        with _database_lock:
            if _database is not None:
                return _database
            create = not _database_creating
            if create:
                _database_creating = True
                generation = _generation
        if create:
            try:
                db = _create_database()

                await db.migrate()

                _restrict_permissions(_path)
                with _database_lock:
                    if generation == _generation:
                        _database = db
                        return db
                # configure()/close_database() ran while this pool was being
                # built; discard it and build against the current target.
                await db.close()
            finally:
                with _database_lock:
                    _database_creating = False

        await asyncio.sleep(0.01)


async def close_database() -> None:
    """Close the database."""
    global _database, _generation
    with _database_lock:
        _generation += 1
        db, _database = _database, None
    if db is not None:
        await db.close()


async def reset_database() -> None:
    """Reset the database (used after configure)."""
    await close_database()
    await get_database()


def _restrict_permissions(path: str) -> None:
    """The database holds key hashes, findings and the audit trail: owner only."""
    if path.startswith(("postgresql://", "postgres://")):
        return
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):
            os.chmod(path + suffix, 0o600)


def _adapt_placeholders(sql: str, is_pg: bool) -> str:
    """Convert SQLite ? placeholders to PostgreSQL $1, $2, ... if needed."""
    if not is_pg:
        return sql
    parts = sql.split("?")
    if len(parts) == 1:
        return sql
    result = []
    for i, part in enumerate(parts):
        result.append(part)
        if i < len(parts) - 1:
            result.append(f"${i + 1}")
    return "".join(result)


def _is_postgresql_connection(conn: Any) -> bool:
    """Check if connection is asyncpg (PostgreSQL)."""
    return asyncpg is not None and isinstance(conn, asyncpg.Connection)


async def _execute(conn: Any, sql: str, *params: Any) -> Any:
    """Execute a SQL statement (works with both backends)."""
    is_pg = _is_postgresql_connection(conn)
    if is_pg and sql.lstrip().upper().startswith("BEGIN IMMEDIATE"):
        sql = "BEGIN"
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        status = await conn.execute(sql, *params)
        last = status.rsplit(" ", 1)[-1]
        from types import SimpleNamespace

        return SimpleNamespace(rowcount=int(last) if last.isdigit() else 0)
    return await conn.execute(sql, params)


async def _fetchone(conn: Any, sql: str, *params: Any) -> Any:
    """Fetch one row (works with both backends)."""
    is_pg = _is_postgresql_connection(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        return await conn.fetchrow(sql, *params)
    cursor = await conn.execute(sql, params)
    return await cursor.fetchone()


async def _fetchall(conn: Any, sql: str, *params: Any) -> list[Any]:
    """Fetch all rows (works with both backends)."""
    is_pg = _is_postgresql_connection(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        return await conn.fetch(sql, *params)
    cursor = await conn.execute(sql, params)
    return await cursor.fetchall()


async def _executemany(conn: Any, sql: str, params_list: list[tuple]) -> None:
    """Execute many statements (works with both backends)."""
    is_pg = _is_postgresql_connection(conn)
    sql = _adapt_placeholders(sql, is_pg)
    if is_pg:
        await conn.executemany(sql, params_list)
    else:
        await conn.executemany(sql, params_list)


@asynccontextmanager
async def get_db_async() -> AsyncIterator[Database]:
    """Get a database connection from the pool (initialized on first use)."""
    db = await get_database()
    yield db


async def schema_version() -> int:
    db = await get_database()
    return await db.schema_version()


async def save_job(
    job: Any,
    *,
    tenant: str,
    audit_chain_entry: dict[str, Any] | None = None,
    audit_hmac_key: str = "",
) -> str | None:
    """Persist a job and its findings in one transaction (async version).

    If ``audit_chain_entry`` is provided, also append a sealed entry to the
    audit chain within the same transaction. This allows any process (API,
    Redis worker, K8s job runner) to seal the chain atomically with the job
    save, fixing the gap where workers couldn't append to the chain.

    Returns the audit chain hash (digest) if an entry was appended, otherwise None.
    """
    rows = []
    for finding in dedupe(job.findings):
        data = finding.to_dict()
        rows.append(
            (
                job.id,
                tenant,
                data["fingerprint"],
                data["asset"],
                data["category"],
                data["title"],
                data["severity"],
                data["confidence"],
                data["verification"],
                data["status"],
                data["detector"],
                data["detector_version"],
                data["location"],
                data["evidence"],
                data["description"],
                data["remediation"],
                data["cwe"],
                json.dumps(data["sources"]),
            )
        )

    stored_target = sanitize_target(job.target)
    stored_error = redact(job.error)
    new_state, verdict = job.state.value, job.verdict
    finished_at = job.finished_at

    db = await get_database()
    chain_hash: str | None = None
    async with db.transaction() as conn:
        try:
            existing = await _fetchone(
                conn,
                "SELECT state, verdict, error, finished_at FROM jobs WHERE id = ?",
                job.id,
            )

            is_terminal_transition = (
                existing is not None
                and existing["state"] not in TERMINAL_STATES
                and new_state in TERMINAL_STATES
            )

            if (
                existing is not None
                and existing["state"] in TERMINAL_STATES
                and new_state not in TERMINAL_STATES
            ):
                state, verdict = existing["state"], existing["verdict"]
                stored_error, finished_at = existing["error"], existing["finished_at"]
            else:
                state = new_state
            try:
                await _execute(
                    conn,
                    """INSERT INTO jobs (id, tenant, target, profile, actor, policy, state,
                                         verdict, error, started_at, finished_at, coverage,
                                         created_at, attempts, worker, idempotency_key,
                                         cancel_requested)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT (id) DO UPDATE SET
                         state = excluded.state, verdict = excluded.verdict,
                         error = excluded.error, finished_at = excluded.finished_at,
                         coverage = excluded.coverage,
                         attempts = excluded.attempts, worker = excluded.worker,
                         started_at = COALESCE(jobs.started_at, excluded.started_at)""",
                    job.id,
                    tenant,
                    stored_target,
                    job.profile,
                    job.actor,
                    json.dumps(job.policy),
                    state,
                    verdict,
                    stored_error,
                    job.started_at,
                    finished_at,
                    json.dumps(job.coverage()),
                    time.time(),
                    int(getattr(job, "attempts", 0) or 0),
                    str(getattr(job, "worker_id", "") or ""),
                    getattr(job, "idempotency_key", None) or None,
                    False,
                )
            except Exception as exc:
                if "unique constraint" in str(exc).lower() or "duplicate key" in str(exc).lower():
                    raise JobConflict(f"idempotency key already used by another job: {exc}") from None
                raise
            await _execute(conn, "DELETE FROM findings WHERE job_id = ?", job.id)
            await _executemany(
                conn,
                """INSERT INTO findings (job_id, tenant, fingerprint, asset, category, title,
                                         severity, confidence, verification, status, detector,
                                         detector_version, location, evidence, description,
                                         remediation, cwe, sources)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            await _record_job_assets(conn, tenant, job)

            if audit_chain_entry is not None and is_terminal_transition:
                import hashlib
                import hmac

                from ishastra.audit import GENESIS_HASH

                def _seal(seq: int, prev: str) -> tuple[str, dict[str, Any]]:
                    body = {
                        **audit_chain_entry,
                        "previous_hash": prev,
                        "sequence": seq,
                        "timestamp": time.time(),
                    }
                    payload = json.dumps(body, sort_keys=True).encode()
                    if audit_hmac_key:
                        digest = hmac.new(audit_hmac_key.encode(), payload, hashlib.sha256).hexdigest()
                    else:
                        digest = hashlib.sha256(payload).hexdigest()
                    return digest, body

                _, chain_hash, _ = await chain_append_in_transaction(conn, _seal, genesis=GENESIS_HASH)

        except Exception:
            raise

    return chain_hash


def asset_key(asset: str) -> str:
    """Stable, tenant-scoped identity for an asset string."""
    return hashlib.sha256(asset.strip().lower().encode()).hexdigest()[:32]


def _asset_type(asset: str) -> str:
    lowered = asset.strip().lower()
    if lowered.startswith(("http://", "https://")):
        return "web"
    if lowered:
        return "host"
    return "unknown"


async def _record_job_assets(conn: Any, tenant: str, job: Any) -> None:
    """Upsert asset first/last-seen and one immutable ``created`` event per finding."""
    now = job.finished_at or time.time()
    for finding in job.findings:
        data = finding.to_dict()
        asset = str(data.get("asset") or "").strip()
        if not asset:
            continue
        key = asset_key(asset)
        await _execute(
            conn,
            """INSERT INTO assets
                   (tenant, asset_key, asset, asset_type, owner, criticality, first_seen, last_seen)
               VALUES (?, ?, ?, ?, '', 'medium', ?, ?)
               ON CONFLICT (tenant, asset_key) DO UPDATE SET
                   asset = excluded.asset,
                   asset_type = excluded.asset_type,
                   last_seen = excluded.last_seen""",
            tenant,
            key,
            asset,
            _asset_type(asset),
            now,
            now,
        )
        existing = await _fetchone(
            conn,
            """SELECT 1 FROM finding_events
               WHERE tenant = ? AND job_id = ? AND fingerprint = ? AND event = 'created'""",
            tenant,
            job.id,
            data["fingerprint"],
        )
        if existing is None:
            await _execute(
                conn,
                """INSERT INTO finding_events
                       (tenant, job_id, fingerprint, event, from_status, to_status,
                        actor, note, created_at)
                   VALUES (?, ?, ?, 'created', '', ?, ?, ?, ?)""",
                tenant,
                job.id,
                data["fingerprint"],
                data["status"],
                "system",
                f"detected by {data['detector']}",
                now,
            )

        await _execute(
            conn,
            """UPDATE finding_records
                  SET resolution_state = 'open', resolved_at = NULL,
                      resolved_job_id = '', resolution_evidence = '{}', updated_at = ?
                WHERE tenant = ? AND fingerprint = ? AND resolution_state = 'resolved'""",
            now,
            tenant,
            data["fingerprint"],
        )


def _job_row_to_dict(row: Any, findings: list[dict[str, Any]]) -> dict[str, Any]:
    finished, started = row["finished_at"], row["started_at"]
    return {
        "id": row["id"],
        "target": row["target"],
        "profile": row["profile"],
        "actor": row["actor"],
        "policy": json.loads(row["policy"]),
        "state": row["state"],
        "verdict": row["verdict"],
        "clean": row["state"] == "completed" and not findings,
        "created_at": row["created_at"],
        "started_at": started,
        "finished_at": finished,
        "duration_ms": (round((finished - started) * 1000, 1) if started and finished else None),
        "coverage": json.loads(row["coverage"]),
        "findings": findings,
        "error": row["error"],
        "tenant": row["tenant"],
        "attempts": row["attempts"],
        "worker": row["worker"],
        "idempotency_key": row["idempotency_key"],
        "cancel_requested": bool(row["cancel_requested"]),
    }


def _json_list(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, list | tuple) else []


def _finding_row_to_dict(row: Any) -> dict[str, Any]:
    status = row["status"]
    return {
        "fingerprint": row["fingerprint"],
        "asset": row["asset"],
        "category": row["category"],
        "title": row["title"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "verification": row["verification"],
        "status": status,
        "allowed_transitions": list(allowed_transitions(status)),
        "detector": row["detector"],
        "detector_version": row["detector_version"],
        "location": row["location"],
        "evidence": row["evidence"],
        "description": row["description"],
        "remediation": row["remediation"],
        "cwe": row["cwe"],
        "cvss_score": row["cvss_score"],
        "business_impact": row["business_impact"],
        "asset_criticality": row["asset_criticality"],
        "risk_rating": row["risk_rating"],
        "exploit_available": bool(row["exploit_available"]),
        "user_impact": row["user_impact"],
        "compliance_refs": _json_list(row["compliance_refs"]),
        "remediation_status": row["remediation_status"],
        "discovered_date": row["discovered_date"],
        "reported_date": row["reported_date"],
        "resolved_date": row["resolved_date"],
        "sources": _json_list(row["sources"]),
        "owner": "",
        "due_at": None,
        "exception_until": None,
        "exception_reason": "",
        "exception_approved_by": "",
    }


async def get_job(job_id: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Load a job. ``tenant=None`` is reserved for administrators."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            row = await _fetchone(conn, "SELECT * FROM jobs WHERE id = ?", job_id)
        else:
            row = await _fetchone(conn, "SELECT * FROM jobs WHERE id = ? AND tenant = ?", job_id, tenant)
        if row is None:
            return None
        findings = await _fetchall(
            conn, "SELECT * FROM findings WHERE job_id = ? ORDER BY fingerprint", job_id
        )
        metadata_rows = await _fetchall(
            conn,
            "SELECT * FROM finding_remediation WHERE tenant = ? AND job_id = ?",
            row["tenant"],
            job_id,
        )
        metadata = {item["fingerprint"]: _remediation_row_to_dict(item) for item in metadata_rows}
        parsed = []
        for item in findings:
            finding = _finding_row_to_dict(item)
            finding.update(metadata.get(finding["fingerprint"], {}))
            parsed.append(finding)
        return _job_row_to_dict(row, parsed)


async def latest_finished_job(target: str, *, tenant: str | None = None) -> dict[str, Any] | None:
    """Most recent job for ``target`` that produced a result (with its findings)."""
    target = sanitize_target(target)
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            row = await _fetchone(
                conn,
                "SELECT id FROM jobs WHERE target = ? AND state IN ('completed', 'partial') "
                "ORDER BY created_at DESC LIMIT 1",
                target,
            )
        else:
            row = await _fetchone(
                conn,
                "SELECT id FROM jobs WHERE target = ? AND tenant = ? "
                "AND state IN ('completed', 'partial') ORDER BY created_at DESC LIMIT 1",
                target,
                tenant,
            )
    return await get_job(row["id"], tenant=tenant) if row else None


async def list_jobs(*, tenant: str | None = None, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    """Recent job summaries (no findings payload)."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            rows = await _fetchall(
                conn, "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?", limit, offset
            )
        else:
            rows = await _fetchall(
                conn,
                "SELECT * FROM jobs WHERE tenant = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                tenant,
                limit,
                offset,
            )
        return [_job_row_to_dict(row, []) for row in rows]


async def fail_interrupted(*, created_before: float | None = None) -> int:
    """Mark jobs a previous process left queued/running as failed."""
    for attempt in range(3):
        try:
            db = await get_database()
            async with db.transaction() as conn:
                if created_before is not None:
                    cursor = await _execute(
                        conn,
                        """UPDATE jobs
                           SET state = 'failed',
                               verdict = 'failed -- no usable coverage',
                               error = 'interrupted by process restart',
                               finished_at = ?
                           WHERE state IN ('queued', 'running') AND created_at < ?""",
                        time.time(),
                        created_before,
                    )
                else:
                    cursor = await _execute(
                        conn,
                        """UPDATE jobs
                           SET state = 'failed',
                               verdict = 'failed -- no usable coverage',
                               error = 'interrupted by process restart',
                               finished_at = ?
                           WHERE state IN ('queued', 'running')""",
                        time.time(),
                    )
                return cursor.rowcount
        except Exception as e:
            if "database is locked" in str(e) and attempt < 2:
                await asyncio.sleep(0.1 * (attempt + 1))
                continue
            raise
    return 0


async def fail_running(*, created_before: float | None = None) -> int:
    """Mark jobs a previous process left running as failed.

    ``fail_interrupted`` also fails queued rows, which is right for the
    in-process queue (a queued row exists nowhere else) but wrong for the
    durable queue: those rows are still in the stream and must run.
    """
    db = await get_database()
    async with db.transaction() as conn:
        params: tuple[Any, ...] = (time.time(),)
        where = "state = 'running'"
        if created_before is not None:
            where += " AND created_at < ?"
            params += (created_before,)
        cursor = await _execute(
            conn,
            """UPDATE jobs
               SET state = 'failed',
                   verdict = 'failed -- no usable coverage',
                   error = 'interrupted by process restart',
                   finished_at = ?
               WHERE """
            + where,
            *params,
        )
        return cursor.rowcount


async def list_queued_jobs(*, limit: int = 1000) -> list[tuple[str, str]]:
    """``(id, tenant)`` for every queued job, oldest first.

    The durable queue replays these on start: a row that was never delivered
    (process died between the insert and publishing it) would otherwise sit
    queued forever.
    """
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(
            conn,
            "SELECT id, tenant FROM jobs WHERE state = 'queued' ORDER BY created_at LIMIT ?",
            limit,
        )
    return [(row["id"], row["tenant"]) for row in rows]


async def transition_job(
    job_id: str,
    *,
    tenant: str,
    from_states: tuple[str, ...],
    to_state: str,
    error: str | None = None,
    worker: str | None = None,
    now: float | None = None,
) -> bool:
    """Compare-and-set a job state. False when the row is not in ``from_states``.

    The state predicate is part of the UPDATE, so two processes racing on the
    same transition cannot both win. Terminal states record ``finished_at``;
    callers refuse to reopen a terminal job by passing only non-terminal
    ``from_states``.
    """
    if not from_states:
        raise ValueError("from_states must not be empty")
    known = {"queued", "running", "completed", "partial", "failed", "cancelled"}
    invalid = set(from_states) - known
    if invalid:
        raise ValueError(f"unknown job state(s): {', '.join(sorted(invalid))}")
    stamp = time.time() if now is None else now
    assignments = ["state = ?"]
    params: list[Any] = [to_state]
    if error is not None:
        assignments.append("error = ?")
        params.append(error)
    if worker is not None:
        assignments.append("worker = ?")
        params.append(worker)
    if to_state == "running":
        assignments.append("started_at = COALESCE(started_at, ?)")
        params.append(stamp)
    if to_state in TERMINAL_STATES:
        assignments.append("finished_at = ?")
        params.append(stamp)
    placeholders = ", ".join("?" for _ in from_states)
    sql = (
        f"UPDATE jobs SET {', '.join(assignments)} WHERE id = ? AND tenant = ? AND state IN ({placeholders})"
    )
    params.extend([job_id, tenant, *from_states])
    db = await get_database()
    async with db.transaction() as conn:
        cursor = await _execute(conn, sql, *params)
        return getattr(cursor, "rowcount", 0) == 1


async def mark_running(job_id: str, *, tenant: str, worker: str, now: float | None = None) -> bool:
    """Claim a queued job for one worker. False when another claim won.

    For PostgreSQL, uses SELECT FOR UPDATE SKIP LOCKED to allow concurrent
    workers to claim different jobs without blocking each other.
    """
    stamp = time.time() if now is None else now
    db = await get_database()
    async with db.transaction() as conn:
        if db.is_postgresql():
            row = await _fetchone(
                conn,
                """SELECT id FROM jobs
                   WHERE id = $1 AND tenant = $2 AND state = 'queued'
                   FOR UPDATE SKIP LOCKED""",
                job_id,
                tenant,
            )
            if row is None:
                return False
            cursor = await _execute(
                conn,
                """UPDATE jobs
                   SET state = 'running', worker = $1,
                       started_at = COALESCE(started_at, $2),
                       attempts = attempts + 1
                   WHERE id = $3""",
                worker,
                stamp,
                job_id,
            )
            return cursor.rowcount == 1
        cursor = await _execute(
            conn,
            """UPDATE jobs
                   SET state = 'running', worker = ?,
                       started_at = COALESCE(started_at, ?),
                       attempts = attempts + 1
                   WHERE id = ? AND tenant = ? AND state = 'queued'""",
            worker,
            stamp,
            job_id,
            tenant,
        )
        return cursor.rowcount == 1


async def claim_job(job_id: str, *, tenant: str, worker: str, now: float | None = None) -> bool:
    """Single-execution claim: True when this caller may run the job."""
    if await mark_running(job_id, tenant=tenant, worker=worker, now=now):
        return True
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT 1 FROM jobs WHERE id = ? AND tenant = ?", job_id, tenant)
        return row is None


async def request_cancel(job_id: str, *, tenant: str | None = None) -> bool:
    """Persist a cancellation request for a queued/running job.

    The flag is read by the process that owns execution (workers are
    allowed to run in another process), so cancellation does not depend on an
    in-memory event that only the submitting API process can see.
    """
    db = await get_database()
    async with db.transaction() as conn:
        where = "id = ? AND state IN ('queued', 'running')"
        params: list[Any] = [job_id]
        if tenant is not None:
            where += " AND tenant = ?"
            params.append(tenant)
        sql = "UPDATE jobs SET cancel_requested = ? WHERE " + where
        cursor = await _execute(conn, sql, True, *params)
        if cursor.rowcount != 1:
            return False

        await _execute(
            conn,
            """UPDATE jobs
               SET state = 'cancelled', verdict = 'cancelled; do not treat as clean',
                   error = 'cancelled by request', finished_at = ?
               WHERE id = ? AND state = 'queued'""",
            time.time(),
            job_id,
        )
        return True


async def is_cancel_requested(job_id: str, *, tenant: str) -> bool:
    """Whether a cancellation was requested for this tenant's job."""
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            "SELECT cancel_requested FROM jobs WHERE id = ? AND tenant = ?",
            job_id,
            tenant,
        )
    return bool(row and row["cancel_requested"])


async def request_cancel_for_policy(policy_id: str) -> int:
    """Persist cancellation for every active job bound to ``policy_id``.

    Policies are admin-owned and span tenants, so this deliberately has no
    tenant filter; the JSON binding is the authorization being withdrawn.
    """
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT id, policy FROM jobs WHERE state IN ('queued', 'running')")
        ids: list[str] = []
        for row in rows:
            try:
                binding = json.loads(row["policy"])
            except (TypeError, ValueError):
                continue
            if isinstance(binding, dict) and binding.get("policy_id") == policy_id:
                ids.append(row["id"])
        if not ids:
            return 0
        placeholders = ", ".join("?" for _ in ids)
        sql1 = "UPDATE jobs SET cancel_requested = ? WHERE id IN (" + placeholders + ")"
        cursor = await _execute(conn, sql1, True, *ids)

        sql2 = (
            "UPDATE jobs SET state = 'cancelled', verdict = 'cancelled; do not treat as clean', "
            "error = 'cancelled by policy revocation', finished_at = ? "
            "WHERE state = 'queued' AND id IN (" + placeholders + ")"
        )
        await _execute(conn, sql2, time.time(), *ids)
        return int(cursor.rowcount or 0)


async def find_job_id_by_idempotency(idempotency_key: str, *, tenant: str) -> str | None:
    """The job that already owns ``idempotency_key`` for this tenant, if any."""
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn, "SELECT id FROM jobs WHERE tenant = ? AND idempotency_key = ?", tenant, idempotency_key
        )
        return row["id"] if row else None


def _remediation_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "owner": row["owner"],
        "due_at": row["due_at"],
        "exception_until": row["exception_until"],
        "exception_reason": row["exception_reason"],
        "exception_approved_by": row["exception_approved_by"],
    }


async def list_assets(*, tenant: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    """Tenant-scoped asset inventory with finding counts (no cross-tenant reads)."""
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(
            conn,
            """SELECT a.tenant, a.asset_key, a.asset, a.asset_type, a.owner,
                      a.criticality, a.first_seen, a.last_seen,
                      COUNT(f.fingerprint) AS finding_count,
                      COALESCE(SUM(CASE WHEN f.status != 'closed' THEN 1 ELSE 0 END), 0)
                          AS open_finding_count
               FROM assets a
               LEFT JOIN findings f ON f.tenant = a.tenant AND f.asset = a.asset
               WHERE a.tenant = ?
               GROUP BY a.tenant, a.asset_key, a.asset, a.asset_type, a.owner,
                        a.criticality, a.first_seen, a.last_seen
               ORDER BY a.last_seen DESC
               LIMIT ? OFFSET ?""",
            tenant,
            limit,
            offset,
        )
    return [dict(row) for row in rows]


async def count_assets(*, tenant: str) -> int:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT COUNT(*) FROM assets WHERE tenant = ?", tenant)
    return int(row[0]) if row else 0


async def get_asset(*, tenant: str, key: str) -> dict[str, Any] | None:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            "SELECT * FROM assets WHERE tenant = ? AND asset_key = ?",
            tenant,
            key,
        )
        if row is None:
            return None
        findings = await _fetchall(
            conn,
            """SELECT f.*, j.state AS job_state, j.created_at AS job_created_at
               FROM findings f
               JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
               WHERE f.tenant = ? AND f.asset = ?
               ORDER BY j.created_at DESC, f.fingerprint""",
            tenant,
            row["asset"],
        )
    parsed = []
    for item in findings:
        finding = _finding_row_to_dict(item)
        finding.update(
            {
                "job_id": item["job_id"],
                "job_state": item["job_state"],
                "job_created_at": item["job_created_at"],
            }
        )
        parsed.append(finding)
    return {**dict(row), "findings": parsed}


_CROSS_JOB_FINDING_SELECT = """
    SELECT f.*, j.target AS job_target, j.state AS job_state,
           j.verdict AS job_verdict, j.created_at AS job_created_at,
           j.finished_at AS job_finished_at,
           r.owner AS record_owner, r.due_at AS record_due_at,
           r.exception_until AS record_exception_until,
           r.exception_reason AS record_exception_reason,
           r.exception_approved_by AS record_exception_approved_by,
           r.exception_state AS record_exception_state,
           r.exception_requested_by AS record_exception_requested_by,
           r.exception_requested_at AS record_exception_requested_at,
           r.exception_decided_by AS record_exception_decided_by,
           r.exception_decided_at AS record_exception_decided_at,
           r.exception_note AS record_exception_note,
           r.resolution_state AS record_resolution_state,
           r.resolved_at AS record_resolved_at,
           r.resolved_job_id AS record_resolved_job_id,
           r.resolution_evidence AS record_resolution_evidence,
           r.updated_at AS record_updated_at
      FROM findings f
      JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
      LEFT JOIN finding_records r ON r.tenant = f.tenant AND r.fingerprint = f.fingerprint
     WHERE f.tenant = ?
"""


def _finding_seen_at(row: Any) -> float:
    return row["job_finished_at"] or row["job_created_at"]


def _finding_occurrence(row: Any) -> dict[str, Any]:
    finding = _finding_row_to_dict(row)
    return {
        "job_id": row["job_id"],
        "target": row["job_target"],
        "job_state": row["job_state"],
        "job_verdict": row["job_verdict"],
        "job_created_at": row["job_created_at"],
        "job_finished_at": row["job_finished_at"],
        "seen_at": _finding_seen_at(row),
        "status": finding["status"],
        "severity": finding["severity"],
        "confidence": finding["confidence"],
        "verification": finding["verification"],
        "title": finding["title"],
        "detector": finding["detector"],
    }


def _effective_exception_state(state: str, until: float | None) -> str:
    if state in ("pending", "approved") and until is not None and until <= time.time():
        return "expired"
    return state


def _exception_fields(row: Any, prefix: str) -> dict[str, Any]:
    state = _effective_exception_state(
        row[f"{prefix}exception_state"] or "none", row[f"{prefix}exception_until"]
    )
    return {
        "state": state,
        "until": row[f"{prefix}exception_until"],
        "reason": row[f"{prefix}exception_reason"] or "",
        "requested_by": row[f"{prefix}exception_requested_by"] or "",
        "requested_at": row[f"{prefix}exception_requested_at"],
        "decided_by": row[f"{prefix}exception_decided_by"] or row[f"{prefix}exception_approved_by"] or "",
        "decided_at": row[f"{prefix}exception_decided_at"],
        "note": row[f"{prefix}exception_note"] or "",
    }


def _finding_record_fields(row: Any) -> dict[str, Any]:
    raw_evidence = row["record_resolution_evidence"]
    try:
        evidence = json.loads(raw_evidence) if raw_evidence else {}
    except (TypeError, ValueError):
        evidence = {}
    remediation = {
        "owner": row["record_owner"] or "",
        "due_at": row["record_due_at"],
        "exception_until": row["record_exception_until"],
        "exception_reason": row["record_exception_reason"] or "",
        "exception_approved_by": row["record_exception_approved_by"] or "",
    }
    return {
        **remediation,
        "remediation": remediation,
        "exception": _exception_fields(row, "record_"),
        "resolution": {
            "state": row["record_resolution_state"] or "open",
            "resolved_at": row["record_resolved_at"],
            "job_id": row["record_resolved_job_id"] or "",
            "evidence": evidence,
        },
        "record_updated_at": row["record_updated_at"],
    }


def _aggregate_cross_job_finding(rows: list[Any]) -> dict[str, Any]:
    """Aggregate one fingerprint's per-job findings; rows must be newest first."""
    latest = rows[0]
    finding = _finding_row_to_dict(latest)
    seen = [_finding_seen_at(row) for row in rows]
    finding.update(_finding_record_fields(latest))
    return {
        **finding,
        "first_seen": min(seen),
        "last_seen": max(seen),
        "occurrence_count": len(rows),
        "last_job": {
            "id": latest["job_id"],
            "target": latest["job_target"],
            "state": latest["job_state"],
            "verdict": latest["job_verdict"],
            "created_at": latest["job_created_at"],
            "finished_at": latest["job_finished_at"],
        },
    }


async def list_cross_job_findings(*, tenant: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    """Tenant finding records keyed by stable fingerprint, newest activity first.

    Aggregation is done after the paginated fingerprint query. That bounds the
    result page but still reads every occurrence for those fingerprints; add a
    summary table if per-finding history grows into thousands of jobs.
    """
    db = await get_database()
    async with db.transaction() as conn:
        page_rows = await _fetchall(
            conn,
            """SELECT f.fingerprint,
                      MAX(COALESCE(j.finished_at, j.created_at)) AS last_seen
                 FROM findings f
                 JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
                WHERE f.tenant = ?
                GROUP BY f.fingerprint
                ORDER BY last_seen DESC, f.fingerprint
                LIMIT ? OFFSET ?""",
            tenant,
            limit,
            offset,
        )
        if not page_rows:
            return []
        fingerprints = [row["fingerprint"] for row in page_rows]
        placeholders = ",".join("?" for _ in fingerprints)
        sql = (
            _CROSS_JOB_FINDING_SELECT
            + " AND f.fingerprint IN ("
            + placeholders
            + ")"
            + " ORDER BY COALESCE(j.finished_at, j.created_at) DESC, j.created_at DESC, j.id DESC"
        )
        rows = await _fetchall(conn, sql, tenant, *fingerprints)
    grouped: dict[str, list[Any]] = {}
    for row in rows:
        grouped.setdefault(row["fingerprint"], []).append(row)
    return [_aggregate_cross_job_finding(grouped[fp]) for fp in fingerprints if fp in grouped]


async def count_cross_job_findings(*, tenant: str) -> int:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            """SELECT COUNT(DISTINCT f.fingerprint)
                 FROM findings f
                 JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
                WHERE f.tenant = ?""",
            tenant,
        )
    return int(row[0]) if row else 0


async def get_cross_job_finding(*, tenant: str, fingerprint: str) -> dict[str, Any] | None:
    """One tenant finding record with its per-job occurrence history."""
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(
            conn,
            _CROSS_JOB_FINDING_SELECT
            + " AND f.fingerprint = ?"
            + " ORDER BY COALESCE(j.finished_at, j.created_at) DESC, j.created_at DESC, j.id DESC",
            tenant,
            fingerprint,
        )
    if not rows:
        return None
    return {
        **_aggregate_cross_job_finding(rows),
        "history": [_finding_occurrence(row) for row in reversed(rows)],
    }


async def overdue_findings(*, tenant: str, now: float, limit: int = 1000) -> list[dict[str, Any]]:
    """Findings past their remediation deadline, oldest deadline first.

    A finding is not overdue when it is resolved or holds an approved, still
    valid risk exception. ``limit`` is a hard ceiling on the scan, not a page.

    ponytail: no index on ``finding_records.due_at``; the table has one row per
    fingerprint and this scans only its own tenant. Add a partial index if a
    tenant accumulates tens of thousands of records.
    """
    db = await get_database()
    async with db.transaction() as conn:
        records = await _fetchall(
            conn,
            """SELECT fingerprint, owner, due_at, exception_state, exception_until,
                      COALESCE(resolution_state, 'open') AS resolution_state
                 FROM finding_records
                WHERE tenant = ? AND due_at IS NOT NULL AND due_at <= ?
                  AND COALESCE(resolution_state, 'open') != 'resolved'
                  AND NOT (exception_state = 'approved' AND COALESCE(exception_until, 0) > ?)
                ORDER BY due_at ASC
                LIMIT ?""",
            tenant,
            now,
            now,
            limit,
        )
        if not records:
            return []
        fingerprints = [row["fingerprint"] for row in records]
        placeholders = ",".join("?" for _ in fingerprints)
        findings = await _fetchall(
            conn,
            "SELECT fingerprint, severity, title, asset, category FROM findings "
            f"WHERE tenant = ? AND fingerprint IN ({placeholders})",
            tenant,
            *fingerprints,
        )

    best: dict[str, Any] = {}
    for row in findings:
        current = best.get(row["fingerprint"])
        if current is None or _severity_rank(row["severity"]) > _severity_rank(current["severity"]):
            best[row["fingerprint"]] = row

    items: list[dict[str, Any]] = []
    for record in records:
        finding = best.get(record["fingerprint"])
        if finding is None:
            continue
        items.append(
            {
                "fingerprint": record["fingerprint"],
                "severity": finding["severity"],
                "title": finding["title"],
                "asset": finding["asset"],
                "category": finding["category"],
                "owner": record["owner"] or "",
                "due_at": record["due_at"],
                "overdue_seconds": now - record["due_at"],
                "resolution_state": record["resolution_state"],
                "exception_state": record["exception_state"] or "none",
            }
        )
    return items


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)


def _record_to_dict(row: Any) -> dict[str, Any]:
    try:
        evidence = json.loads(row["resolution_evidence"]) if row["resolution_evidence"] else {}
    except (TypeError, ValueError):
        evidence = {}
    return {
        "owner": row["owner"],
        "due_at": row["due_at"],
        "exception_until": row["exception_until"],
        "exception_reason": row["exception_reason"],
        "exception_approved_by": row["exception_approved_by"],
        "exception": _exception_fields(row, ""),
        "resolution": {
            "state": row["resolution_state"],
            "resolved_at": row["resolved_at"],
            "job_id": row["resolved_job_id"],
            "evidence": evidence,
        },
        "updated_at": row["updated_at"],
    }


async def set_finding_record_remediation(
    *,
    tenant: str,
    fingerprint: str,
    owner: str = "",
    due_at: float | None = None,
    exception_until: float | None = None,
    exception_reason: str = "",
    exception_approved_by: str = "",
) -> dict[str, Any] | None:
    """Set tenant-level remediation metadata for a known finding record."""
    db = await get_database()
    async with db.transaction() as conn:
        finding = await _fetchone(
            conn,
            "SELECT 1 FROM findings WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if finding is None:
            return None
        await _execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, owner, due_at, exception_until,
                    exception_reason, exception_approved_by, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   owner = excluded.owner,
                   due_at = excluded.due_at,
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_approved_by = excluded.exception_approved_by,
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            owner,
            due_at,
            exception_until,
            exception_reason,
            exception_approved_by,
            time.time(),
        )
        row = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
    return _record_to_dict(row) if row is not None else None


async def get_finding_record(*, tenant: str, fingerprint: str) -> dict[str, Any] | None:
    """Get the finding record (remediation + exception metadata) for a fingerprint."""
    db = await get_database()
    async with db.transaction() as conn:
        finding = await _fetchone(
            conn,
            "SELECT 1 FROM findings WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if finding is None:
            return None
        row = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
    return _record_to_dict(row) if row is not None else None


async def request_finding_exception(
    *, tenant: str, fingerprint: str, until: float, reason: str, requested_by: str
) -> dict[str, Any] | None:
    """Request a risk acceptance; an administrator must decide it."""
    db = await get_database()
    async with db.transaction() as conn:
        finding = await _fetchone(
            conn,
            "SELECT 1 FROM findings WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if finding is None:
            return None
        now = time.time()
        await _execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, exception_until, exception_reason,
                    exception_state, exception_requested_by, exception_requested_at,
                    updated_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_state = 'pending',
                   exception_requested_by = excluded.exception_requested_by,
                   exception_requested_at = excluded.exception_requested_at,
                   exception_decided_by = '',
                   exception_decided_at = NULL,
                   exception_note = '',
                   exception_approved_by = '',
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            until,
            reason,
            requested_by,
            now,
            now,
        )
        row = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
    return _record_to_dict(row) if row is not None else None


async def decide_finding_exception(
    *,
    tenant: str,
    fingerprint: str,
    approved: bool,
    decided_by: str,
    note: str = "",
) -> dict[str, Any] | None:
    """Approve or reject a pending risk acceptance."""
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if row is None:
            return None
        if row["exception_state"] != "pending":
            raise ValueError("finding has no pending risk exception")
        state = "approved" if approved else "rejected"
        await _execute(
            conn,
            """UPDATE finding_records
                  SET exception_state = ?, exception_decided_by = ?,
                      exception_decided_at = ?, exception_note = ?,
                      exception_approved_by = ?, updated_at = ?
                WHERE tenant = ? AND fingerprint = ?""",
            state,
            decided_by,
            time.time(),
            note,
            decided_by if approved else "",
            time.time(),
            tenant,
            fingerprint,
        )
        updated = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
    return _record_to_dict(updated) if updated is not None else None


async def set_finding_resolution(
    *,
    tenant: str,
    fingerprint: str,
    resolved_at: float,
    job_id: str,
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    """Record coverage-backed resolution evidence for one finding record."""
    db = await get_database()
    async with db.transaction() as conn:
        finding = await _fetchone(
            conn,
            "SELECT 1 FROM findings WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
        if finding is None:
            return None
        await _execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, resolution_state, resolved_at,
                    resolved_job_id, resolution_evidence, updated_at)
               VALUES (?, ?, 'resolved', ?, ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   resolution_state = 'resolved',
                   resolved_at = excluded.resolved_at,
                   resolved_job_id = excluded.resolved_job_id,
                   resolution_evidence = excluded.resolution_evidence,
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            resolved_at,
            job_id,
            json.dumps(evidence),
            time.time(),
        )
        row = await _fetchone(
            conn,
            "SELECT * FROM finding_records WHERE tenant = ? AND fingerprint = ?",
            tenant,
            fingerprint,
        )
    return _record_to_dict(row) if row is not None else None


def _trend_key(timestamp: float, bucket: str) -> str:
    moment = datetime.fromtimestamp(timestamp, UTC)
    if bucket == "week":
        moment -= timedelta(days=moment.weekday())
    elif bucket == "month":
        moment = moment.replace(day=1)
    return moment.date().isoformat()


def _trend_keys(start: float, end: float, bucket: str) -> list[str]:
    keys: list[str] = []
    cursor = datetime.fromtimestamp(_bucket_epoch(start, bucket), UTC)
    last = datetime.fromtimestamp(end, UTC)
    while cursor <= last:
        keys.append(cursor.date().isoformat())
        if bucket == "week":
            cursor += timedelta(days=7)
        elif bucket == "month":
            cursor = (cursor.replace(day=28) + timedelta(days=4)).replace(day=1)
        else:
            cursor += timedelta(days=1)
    return keys


def _bucket_epoch(timestamp: float, bucket: str) -> float:
    moment = datetime.fromtimestamp(timestamp, UTC)
    if bucket == "week":
        moment -= timedelta(days=moment.weekday())
    elif bucket == "month":
        moment = moment.replace(day=1)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


async def finding_trends(*, tenant: str, start: float, end: float, bucket: str = "day") -> dict[str, Any]:
    """Observation/new/resolved counts per time bucket for one tenant.

    ponytail: scans the tenant's findings for the requested range (max 366 days)
    instead of maintaining rollups. Add a daily summary table if trend queries
    become a hot path on large datasets.
    """
    db = await get_database()
    async with db.transaction() as conn:
        observations = await _fetchall(
            conn,
            """SELECT f.fingerprint, f.severity,
                      COALESCE(j.finished_at, j.created_at) AS seen_at
                 FROM findings f
                 JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
                WHERE f.tenant = ? AND COALESCE(j.finished_at, j.created_at) >= ?
                  AND COALESCE(j.finished_at, j.created_at) <= ?""",
            tenant,
            start,
            end,
        )
        first_seen_rows = await _fetchall(
            conn,
            """SELECT f.fingerprint, MIN(COALESCE(j.finished_at, j.created_at)) AS first_seen
                 FROM findings f
                 JOIN jobs j ON j.id = f.job_id AND j.tenant = f.tenant
                WHERE f.tenant = ?
                GROUP BY f.fingerprint""",
            tenant,
        )
        resolutions = await _fetchall(
            conn,
            """SELECT fingerprint, resolved_at FROM finding_records
                WHERE tenant = ? AND resolution_state = 'resolved'
                  AND resolved_at >= ? AND resolved_at <= ?""",
            tenant,
            start,
            end,
        )

    keys = _trend_keys(start, end, bucket)
    series: dict[str, dict[str, Any]] = {
        key: {
            "bucket": key,
            "observations": 0,
            "unique_findings": set(),
            "new_findings": set(),
            "resolved_findings": set(),
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        for key in keys
    }
    first_seen = {row["fingerprint"]: row["first_seen"] for row in first_seen_rows}
    for row in observations:
        key = _trend_key(row["seen_at"], bucket)
        point = series.get(key)
        if point is None:
            continue
        point["observations"] += 1
        point["unique_findings"].add(row["fingerprint"])
        point["severity"][row["severity"]] += 1
        if _trend_key(first_seen[row["fingerprint"]], bucket) == key:
            point["new_findings"].add(row["fingerprint"])
    for row in resolutions:
        key = _trend_key(row["resolved_at"], bucket)
        if key in series:
            series[key]["resolved_findings"].add(row["fingerprint"])

    points = []
    for key in keys:
        point = series[key]
        points.append(
            {
                **{name: point[name] for name in ("bucket", "observations", "severity")},
                "unique_findings": len(point["unique_findings"]),
                "new_findings": len(point["new_findings"]),
                "resolved_findings": len(point["resolved_findings"]),
            }
        )
    return {"start": start, "end": end, "bucket": bucket, "buckets": points}


async def update_asset_metadata(
    *, tenant: str, key: str, owner: str | None = None, criticality: str | None = None
) -> dict[str, Any] | None:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT * FROM assets WHERE tenant = ? AND asset_key = ?", tenant, key)
        if row is None:
            return None
        await _execute(
            conn,
            "UPDATE assets SET owner = ?, criticality = ? WHERE tenant = ? AND asset_key = ?",
            row["owner"] if owner is None else owner,
            row["criticality"] if criticality is None else criticality,
            tenant,
            key,
        )
        updated = await _fetchone(
            conn, "SELECT * FROM assets WHERE tenant = ? AND asset_key = ?", tenant, key
        )
    return dict(updated) if updated is not None else None


async def list_finding_events(*, tenant: str, job_id: str, fingerprint: str) -> list[dict[str, Any]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(
            conn,
            """SELECT * FROM finding_events
               WHERE tenant = ? AND job_id = ? AND fingerprint = ?
               ORDER BY id""",
            tenant,
            job_id,
            fingerprint,
        )
    return [dict(row) for row in rows]


async def get_finding_remediation(*, tenant: str, job_id: str, fingerprint: str) -> dict[str, Any] | None:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            """SELECT * FROM finding_remediation
               WHERE tenant = ? AND job_id = ? AND fingerprint = ?""",
            tenant,
            job_id,
            fingerprint,
        )
    return _remediation_row_to_dict(row) if row is not None else None


async def set_finding_remediation(
    *,
    tenant: str,
    job_id: str,
    fingerprint: str,
    owner: str = "",
    due_at: float | None = None,
    exception_until: float | None = None,
    exception_reason: str = "",
    exception_approved_by: str = "",
) -> dict[str, Any] | None:
    db = await get_database()
    async with db.transaction() as conn:
        finding = await _fetchone(
            conn,
            "SELECT 1 FROM findings WHERE tenant = ? AND job_id = ? AND fingerprint = ?",
            tenant,
            job_id,
            fingerprint,
        )
        if finding is None:
            return None
        await _execute(
            conn,
            """INSERT INTO finding_remediation
                   (tenant, job_id, fingerprint, owner, due_at, exception_until,
                    exception_reason, exception_approved_by, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (tenant, job_id, fingerprint) DO UPDATE SET
                   owner = excluded.owner,
                   due_at = excluded.due_at,
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_approved_by = excluded.exception_approved_by,
                   updated_at = excluded.updated_at""",
            tenant,
            job_id,
            fingerprint,
            owner,
            due_at,
            exception_until,
            exception_reason,
            exception_approved_by,
            time.time(),
        )
        await _execute(
            conn,
            """INSERT INTO finding_records
                   (tenant, fingerprint, owner, due_at, exception_until,
                    exception_reason, exception_approved_by, exception_state, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (tenant, fingerprint) DO UPDATE SET
                   owner = excluded.owner,
                   due_at = excluded.due_at,
                   exception_until = excluded.exception_until,
                   exception_reason = excluded.exception_reason,
                   exception_approved_by = excluded.exception_approved_by,
                   exception_state = excluded.exception_state,
                   updated_at = excluded.updated_at""",
            tenant,
            fingerprint,
            owner,
            due_at,
            exception_until,
            exception_reason,
            exception_approved_by,
            ("approved" if exception_until is not None and exception_approved_by.strip() else "none"),
            time.time(),
        )
        row = await _fetchone(
            conn,
            """SELECT * FROM finding_remediation
               WHERE tenant = ? AND job_id = ? AND fingerprint = ?""",
            tenant,
            job_id,
            fingerprint,
        )
    return _remediation_row_to_dict(row) if row is not None else None


async def count_jobs(*, tenant: str | None = None) -> int:
    """Total job count for a tenant (or all tenants if None)."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            row = await _fetchone(conn, "SELECT COUNT(*) FROM jobs")
        else:
            row = await _fetchone(conn, "SELECT COUNT(*) FROM jobs WHERE tenant = ?", tenant)
        return row[0] if row else 0


async def count_findings(*, tenant: str) -> int:
    """How many findings a tenant owns — scoped in SQL."""
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT COUNT(*) FROM findings WHERE tenant = ?", tenant)
        if row is None:
            raise RuntimeError("COUNT(*) query returned no row")
        return int(row[0])


async def jobs_by_state(*, tenant: str | None = None) -> dict[str, int]:
    """Jobs grouped by state — aggregate SQL, optionally scoped to a tenant."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            rows = await _fetchall(conn, "SELECT state, COUNT(*) AS n FROM jobs GROUP BY state")
        else:
            rows = await _fetchall(
                conn, "SELECT state, COUNT(*) AS n FROM jobs WHERE tenant = ? GROUP BY state", tenant
            )
    return {str(row["state"]): int(row["n"]) for row in rows}


async def findings_by_severity(*, tenant: str | None = None) -> dict[str, int]:
    """Findings grouped by severity — aggregate SQL, optionally scoped to a tenant."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            rows = await _fetchall(conn, "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        else:
            rows = await _fetchall(
                conn,
                "SELECT severity, COUNT(*) AS n FROM findings WHERE tenant = ? GROUP BY severity",
                tenant,
            )
    return {str(row["severity"]): int(row["n"]) for row in rows}


async def get_findings(job_id: str, *, tenant: str | None = None) -> list[Finding]:
    """Rehydrate findings for report generation (SARIF)."""
    db = await get_database()
    async with db.transaction() as conn:
        if tenant is None:
            rows = await _fetchall(
                conn, "SELECT * FROM findings WHERE job_id = ? ORDER BY fingerprint", job_id
            )
        else:
            rows = await _fetchall(
                conn,
                "SELECT * FROM findings WHERE job_id = ? AND tenant = ? ORDER BY fingerprint",
                job_id,
                tenant,
            )

    findings = []
    for row in rows:
        data = _finding_row_to_dict(row)
        findings.append(
            Finding(
                asset=data["asset"],
                category=data["category"],
                title=data["title"],
                severity=data["severity"],
                confidence=data["confidence"],
                detector=data["detector"],
                detector_version=data["detector_version"],
                evidence=redact(data["evidence"]),
                location=data["location"],
                description=data["description"],
                remediation=data["remediation"],
                cwe=data["cwe"],
                verification=data["verification"],
                status=data["status"],
                cvss_score=data["cvss_score"],
                business_impact=data["business_impact"],
                asset_criticality=data["asset_criticality"],
                risk_rating=data["risk_rating"],
                exploit_available=data["exploit_available"],
                user_impact=data["user_impact"],
                compliance_refs=tuple(data["compliance_refs"]),
                remediation_status=data["remediation_status"],
                discovered_date=data["discovered_date"],
                reported_date=data["reported_date"],
                resolved_date=data["resolved_date"],
                sources=tuple(data["sources"]),
            )
        )
    return findings


_REMEDIATION_BY_STATUS = {
    "new": "pending",
    "triaged": "pending",
    "in_progress": "in_progress",
    "fix_verified": "fix_verified",
    "closed": "closed",
    "reopened": "in_progress",
    "deferred": "pending",
}


async def update_finding_status(
    job_id: str,
    fingerprint: str,
    *,
    tenant: str | None,
    to_status: str,
    actor: str = "",
    note: str = "",
) -> dict[str, Any] | None:
    """Move one finding through its lifecycle, enforcing the transition table.

    Returns the updated finding, or None when the job/finding is not visible to
    this tenant. Raises ValueError for an invalid transition.
    """
    from datetime import UTC, datetime

    db = await get_database()
    async with db.transaction() as conn:
        where = "job_id = ? AND fingerprint = ?"
        params: list[Any] = [job_id, fingerprint]
        if tenant is not None:
            where += " AND tenant = ?"
            params.append(tenant)
        sql_select = "SELECT * FROM findings WHERE " + where
        row = await _fetchone(conn, sql_select, *params)
        if row is None:
            return None

        from_status = row["status"]
        validate_transition(from_status, to_status)
        resolved_date = (
            row["resolved_date"] if to_status != "closed" else datetime.now(UTC).date().isoformat()
        )
        if to_status == "reopened":
            resolved_date = ""
        sql_update = (
            "UPDATE findings SET status = ?, remediation_status = ?, resolved_date = ? WHERE " + where
        )
        await _execute(
            conn,
            sql_update,
            to_status,
            _REMEDIATION_BY_STATUS[to_status],
            resolved_date,
            *params,
        )
        await _execute(
            conn,
            """INSERT INTO finding_events
                   (tenant, job_id, fingerprint, event, from_status, to_status,
                    actor, note, created_at)
               VALUES (?, ?, ?, 'status_changed', ?, ?, ?, ?, ?)""",
            row["tenant"],
            job_id,
            fingerprint,
            from_status,
            to_status,
            actor,
            note,
            time.time(),
        )
        updated = await _fetchone(conn, sql_select, *params)
    return _finding_row_to_dict(updated) if updated is not None else None


async def save_api_key(
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
    project: str = "default",
    scope: str = "write",
    include_hosts: str | None = None,
    scope_type: str = "tenant",
    project_id: str | None = None,
    allowed_projects: list[str] | None = None,
    resource_filters: dict[str, Any] | None = None,
) -> None:
    import json

    db = await get_database()
    async with db.transaction_with_tenant(tenant_id) as conn:
        await _execute(
            conn,
            "INSERT INTO api_keys (tenant_id, key_hash, tier, admin, active, scope, project, "
            "scope_type, project_id, allowed_projects, resource_filters, "
            "created_at, expires_at, last_used, rotated_at, ai_enabled, include_hosts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, project) DO UPDATE SET "
            "key_hash = excluded.key_hash, tier = excluded.tier, admin = excluded.admin, "
            "active = excluded.active, scope = excluded.scope, "
            "scope_type = excluded.scope_type, project_id = excluded.project_id, "
            "allowed_projects = excluded.allowed_projects, resource_filters = excluded.resource_filters, "
            "created_at = excluded.created_at, expires_at = excluded.expires_at, "
            "last_used = excluded.last_used, rotated_at = excluded.rotated_at, "
            "ai_enabled = excluded.ai_enabled, include_hosts = excluded.include_hosts",
            tenant_id,
            key_hash,
            tier,
            bool(admin),
            bool(active),
            scope,
            project,
            scope_type,
            project_id,
            json.dumps(allowed_projects) if allowed_projects else None,
            json.dumps(resource_filters) if resource_filters else None,
            created_at,
            expires_at,
            last_used,
            rotated_at,
            bool(ai_enabled),
            include_hosts,
        )


async def load_api_keys() -> list[dict[str, Any]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT * FROM api_keys")
        return [dict(row) for row in rows]


def load_api_keys_sync() -> list[dict[str, Any]]:
    """Synchronous wrapper for load_api_keys.

    Delegates to ``_run_async``, which uses a private pool when a loop is
    already running. A throwaway loop in a thread hits the caller's aiosqlite
    connections across loops, fails, and leaves the coroutine unawaited.
    """
    return _run_async(load_api_keys())


def save_api_key_sync(
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
    project: str = "default",
    scope: str = "write",
    include_hosts: str | None = None,
) -> None:
    """Synchronous wrapper for save_api_key.

    Delegates to ``_run_async`` so a call made from inside a running loop uses
    the private pool. The old copy scheduled a throwaway loop in a thread
    against the caller's aiosqlite connections; that cross-loop failure left
    the coroutine unawaited and the key persisted nowhere.
    """
    return _run_async(
        save_api_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier=tier,
            admin=admin,
            active=active,
            created_at=created_at,
            expires_at=expires_at,
            last_used=last_used,
            rotated_at=rotated_at,
            ai_enabled=ai_enabled,
            project=project,
            scope=scope,
            include_hosts=include_hosts,
        )
    )


async def save_tenant_user(
    *,
    user_id: str,
    tenant_id: str,
    email: str = "",
    display_name: str,
    role: str,
    key_hash: str,
    scope: str,
    active: bool,
    created_at: float,
    expires_at: float | None = None,
    last_used: float | None = None,
) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            """INSERT INTO tenant_users
                   (user_id, tenant_id, email, display_name, role, key_hash, scope,
                    active, created_at, expires_at, last_used)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (user_id) DO UPDATE SET
                   email = excluded.email,
                   display_name = excluded.display_name,
                   role = excluded.role,
                   key_hash = excluded.key_hash,
                   scope = excluded.scope,
                   active = excluded.active,
                   expires_at = excluded.expires_at,
                   last_used = excluded.last_used""",
            user_id,
            tenant_id,
            email,
            display_name,
            role,
            key_hash,
            scope,
            bool(active),
            created_at,
            expires_at,
            last_used,
        )


async def load_tenant_users() -> list[dict[str, Any]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT * FROM tenant_users")
        return [dict(row) for row in rows]


async def deactivate_tenant_user(*, tenant_id: str, user_id: str) -> bool:
    db = await get_database()
    async with db.transaction() as conn:
        cursor = await _execute(
            conn,
            "UPDATE tenant_users SET active = ? WHERE tenant_id = ? AND user_id = ? AND active = ?",
            False,
            tenant_id,
            user_id,
            True,
        )
        return bool(cursor.rowcount)


async def append_audit(entry: dict[str, Any]) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            "INSERT INTO audit_log (tenant, event, ts, data) VALUES (?, ?, ?, ?)",
            entry.get("tenant"),
            entry.get("event"),
            entry.get("timestamp", time.time()),
            json.dumps(entry, sort_keys=True),
        )


async def recent_audit(limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` entries, returned oldest-first."""
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT data FROM audit_log ORDER BY id DESC LIMIT ?", limit)
    return [json.loads(row["data"]) for row in reversed(list(rows))]


async def chain_tip() -> tuple[int, str] | None:
    """(sequence, hash) of the last sealed entry, or None for an empty chain."""
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT sequence, hash FROM audit_chain ORDER BY sequence DESC LIMIT 1")
    return (row["sequence"], row["hash"]) if row else None


async def chain_insert(sequence: int, previous_hash: str, digest: str, data: dict[str, Any]) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
            sequence,
            previous_hash,
            digest,
            json.dumps(data, sort_keys=True),
        )


def _is_chain_race(exc: BaseException) -> bool:
    """Whether the database reported the concurrent-append race.

    PostgreSQL answers with a unique violation (or a serialization failure under
    SERIALIZABLE); SQLite answers with a busy/locked writer.
    """
    text = str(exc).lower()
    return (
        "unique constraint" in text
        or "duplicate key" in text
        or "database is locked" in text
        or "database table is locked" in text
        or "could not serialize" in text
        or "deadlock detected" in text
    )


async def chain_append_in_transaction(
    conn: Any,
    seal: Callable[[int, str], tuple[str, dict[str, Any]]],
    *,
    genesis: str,
) -> tuple[int, str, dict[str, Any]]:
    """Seal one audit entry within an existing transaction.

    This variant assumes the caller already holds a transaction and does not
    retry on race conditions (the outer transaction handles that).
    """

    is_pg = _is_postgresql_connection(conn)
    if is_pg:
        await conn.execute("SELECT pg_advisory_xact_lock(1)")

    row = await _fetchone(conn, "SELECT sequence, hash FROM audit_chain ORDER BY sequence DESC LIMIT 1")
    sequence, previous = (row["sequence"] + 1, row["hash"]) if row else (1, genesis)
    digest, body = seal(sequence, previous)
    await _execute(
        conn,
        "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
        sequence,
        previous,
        digest,
        json.dumps(body, sort_keys=True),
    )
    return sequence, digest, body


async def chain_append(
    seal: Callable[[int, str], tuple[str, dict[str, Any]]],
    *,
    genesis: str,
    attempts: int = 8,
) -> tuple[int, str, dict[str, Any]]:
    """Seal one audit entry: allocate its sequence, hash it and insert it atomically.

    Reading the tip and inserting the next sequence in separate transactions
    lets two processes pick the same sequence; one insert then fails on the
    primary key and *its audit entry is lost*. Both steps happen in one
    transaction here, and the race is retried instead of dropped, so every
    sealed entry lands. Returns ``(sequence, digest, body)``.
    """
    last: BaseException | None = None
    for attempt in range(attempts):
        try:
            db = await get_database()
            async with db.transaction() as conn:
                return await chain_append_in_transaction(conn, seal, genesis=genesis)
        except Exception as exc:
            if not _is_chain_race(exc) or attempt + 1 >= attempts:
                raise
            last = exc
            await asyncio.sleep(0.005 * (attempt + 1))
    raise RuntimeError(f"could not seal audit entry after {attempts} attempts: {last}")


async def chain_rows() -> AsyncIterator[dict[str, Any]]:
    """Stream the whole chain in order without loading it into memory."""
    db = await get_database()
    async with db.transaction() as conn:
        if db.is_postgresql():
            async for row in conn.cursor(
                "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
            ):
                yield dict(row)
        else:
            cursor = await conn.execute(
                "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
            )
            async for row in cursor:
                yield dict(row)


async def chain_count() -> int:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT COUNT(*) FROM audit_chain")
        if row is None:
            raise RuntimeError("COUNT(*) query returned no row")
        return row[0]


_LEASE_LOCK_BASE = 1000
_LEASE_LOCK_RANGES = {
    "scheduler": (1000, 1999),
    "rate_limiter": (2000, 2999),
    "custom": (3000, 3999),
}


def _lease_lock_id(name: str, category: str = "custom") -> int:
    """Derive a deterministic advisory lock ID from a lease name and category."""
    base, limit = _LEASE_LOCK_RANGES.get(category, _LEASE_LOCK_RANGES["custom"])

    digest = hashlib.sha256(name.encode()).digest()

    hash_val = int.from_bytes(digest[:8], "big", signed=False)
    return base + (hash_val % (limit - base + 1))


class Lease:
    """Represents a held distributed lease."""

    def __init__(
        self,
        name: str,
        holder: str,
        category: str = "custom",
        lock_id: int | None = None,
        fencing_token: int = 0,
    ) -> None:
        self.name = name
        self.holder = holder
        self.category = category
        self.lock_id = lock_id or _lease_lock_id(name, category)
        self._acquired = False
        self.fencing_token = fencing_token

    @property
    def acquired(self) -> bool:
        return self._acquired

    def __repr__(self) -> str:
        return (
            f"Lease(name={self.name!r}, holder={self.holder!r}, "
            f"lock_id={self.lock_id}, fencing_token={self.fencing_token}, acquired={self._acquired})"
        )


async def try_acquire_lease(
    name: str,
    holder: str,
    *,
    category: str = "custom",
    lock_id: int | None = None,
    ttl_seconds: float = 30.0,
) -> Lease | None:
    """Try to acquire a distributed lease (leader election).

    Uses PostgreSQL advisory locks for coordination. Returns a Lease object
    if acquired, None if another holder has it.

    Fencing token ensures that even if a stale holder tries to operate after
    losing the lease, its operations are rejected due to stale token.

    Args:
        name: Unique lease name (e.g., "scheduler", "rate_limiter:tenant123")
        holder: Identifier for this process (e.g., hostname:pid, pod name)
        category: Lease category ("scheduler", "rate_limiter", "custom")
        lock_id: Optional explicit lock ID (normally derived from name)
        ttl_seconds: Lease TTL for monitoring (not enforced by DB)

    Returns:
        Lease object with fencing_token if acquired, None if not available
    """
    db = await get_database()
    if not db.is_postgresql():
        lease = Lease(name, holder, category, lock_id)
        lease._acquired = True
        return lease

    lock_id = lock_id or _lease_lock_id(name, category)

    async with db.advisory_lock(lock_id) as conn:
        row = await _fetchone(
            conn,
            "SELECT holder, expires_at, fencing_token FROM distributed_leases WHERE name = ?",
            name,
        )
        now = time.time()
        if row and row["holder"] != holder and row["expires_at"] and row["expires_at"] > now:
            return None

        # Determine fencing token: 1 for new acquisition, increment for renewal
        fencing_token = 1
        if row and row["holder"] == holder:
            # Renewing existing lease - increment fencing token
            fencing_token = (row["fencing_token"] or 0) + 1

        await _execute(
            conn,
            """INSERT INTO distributed_leases
               (name, holder, lock_id, category, acquired_at, expires_at, ttl_seconds, fencing_token)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (name) DO UPDATE SET
                   holder = excluded.holder,
                   lock_id = excluded.lock_id,
                   category = excluded.category,
                   acquired_at = excluded.acquired_at,
                   expires_at = excluded.expires_at,
                   ttl_seconds = excluded.ttl_seconds,
                   fencing_token = excluded.fencing_token""",
            name,
            holder,
            lock_id,
            category,
            now,
            now + ttl_seconds,
            ttl_seconds,
            fencing_token,
        )

    lease = Lease(name, holder, category, lock_id, fencing_token=fencing_token)
    lease._acquired = True
    return lease


async def release_lease(name: str, holder: str, fencing_token: int | None = None) -> bool:
    """Release a held lease.

    If fencing_token is provided, only releases if the token matches (prevents
    stale holders from releasing a lease they no longer own).

    Returns True if the lease was released, False if not held by this holder
    or token mismatch.
    """
    db = await get_database()
    if not db.is_postgresql():
        return True

    async with db.transaction() as conn:
        if fencing_token is not None:
            cursor = await _execute(
                conn,
                "DELETE FROM distributed_leases WHERE name = ? AND holder = ? AND fencing_token = ?",
                name,
                holder,
                fencing_token,
            )
        else:
            cursor = await _execute(
                conn,
                "DELETE FROM distributed_leases WHERE name = ? AND holder = ?",
                name,
                holder,
            )
        return cursor.rowcount > 0


async def get_lease_holder(name: str) -> tuple[str | None, int]:
    """Get the current holder of a lease and its fencing token, if any.

    Returns (holder, fencing_token) or (None, 0) if lease doesn't exist.
    """
    db = await get_database()
    if not db.is_postgresql():
        return None, 0
    async with db.transaction() as conn:
        row = await _fetchone(
            conn,
            "SELECT holder, fencing_token FROM distributed_leases WHERE name = ?",
            name,
        )
        if row:
            return row["holder"], row["fencing_token"] or 0
        return None, 0


async def renew_lease(name: str, holder: str, ttl_seconds: float = 30.0) -> tuple[bool, int]:
    """Renew a lease's TTL and increment fencing token.

    Returns (True, new_fencing_token) if renewed, (False, 0) if not held by this
    holder or lease doesn't exist. The fencing token increments on each renewal,
    ensuring stale holders cannot operate after losing the lease.
    """
    db = await get_database()
    if not db.is_postgresql():
        return True, 0

    now = time.time()
    async with db.transaction() as conn:
        # Increment fencing token atomically with renewal
        row = await _fetchone(
            conn,
            """UPDATE distributed_leases
               SET expires_at = ?, ttl_seconds = ?, fencing_token = fencing_token + 1
               WHERE name = ? AND holder = ?
               RETURNING fencing_token""",
            now + ttl_seconds,
            ttl_seconds,
            name,
            holder,
        )
        if row:
            return True, row["fencing_token"]
        return False, 0


async def cleanup_expired_leases() -> int:
    """Remove expired lease records. Returns count of removed leases."""
    db = await get_database()
    if not db.is_postgresql():
        return 0

    now = time.time()
    async with db.transaction() as conn:
        cursor = await _execute(
            conn,
            "DELETE FROM distributed_leases WHERE expires_at < ?",
            now,
        )
        return cursor.rowcount


async def list_active_leases() -> list[dict[str, Any]]:
    """List all active (non-expired) leases."""
    db = await get_database()
    if not db.is_postgresql():
        return []

    now = time.time()
    async with db.transaction() as conn:
        rows = await _fetchall(
            conn,
            "SELECT name, holder, category, lock_id, acquired_at, expires_at, ttl_seconds, fencing_token "
            "FROM distributed_leases WHERE expires_at > ?",
            now,
        )
    return [dict(row) for row in rows]


async def _ensure_leases_table() -> None:
    """Create the distributed_leases table if it doesn't exist."""
    db = await get_database()
    if not db.is_postgresql():
        return

    async with db.transaction() as conn:
        await _execute(
            conn,
            """CREATE TABLE IF NOT EXISTS distributed_leases (
                name TEXT PRIMARY KEY,
                holder TEXT NOT NULL,
                lock_id BIGINT NOT NULL,
                category TEXT NOT NULL DEFAULT 'custom',
                acquired_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                ttl_seconds DOUBLE PRECISION NOT NULL,
                fencing_token BIGINT NOT NULL DEFAULT 0
            )""",
        )
        await _execute(
            conn,
            "CREATE INDEX IF NOT EXISTS idx_distributed_leases_expires ON distributed_leases (expires_at)",
        )
        await _execute(
            conn,
            "CREATE INDEX IF NOT EXISTS idx_distributed_leases_category ON distributed_leases (category)",
        )
        await _execute(
            conn,
            "CREATE INDEX IF NOT EXISTS idx_distributed_leases_fencing_token "
            "ON distributed_leases (fencing_token)",
        )


async def prune_finished_jobs(older_than: float) -> int:
    """Delete terminal-state jobs finished before the cutoff epoch."""
    db = await get_database()
    async with db.transaction() as conn:
        placeholders = ", ".join("?" for _ in TERMINAL_STATES)
        params = tuple(TERMINAL_STATES) + (older_than,)
        cursor = await _execute(
            conn,
            f"""DELETE FROM jobs
                WHERE state IN ({placeholders})
                  AND finished_at IS NOT NULL AND finished_at < ?""",
            *params,
        )
        return cursor.rowcount


async def prune_audit_log(older_than: float) -> int:
    """Delete plain audit-log entries older than the cutoff epoch."""
    db = await get_database()
    async with db.transaction() as conn:
        cursor = await _execute(conn, "DELETE FROM audit_log WHERE ts < ?", older_than)
        return cursor.rowcount


async def _connect_direct() -> Any:
    """Open a direct database connection (not from pool) for VACUUM operations.

    VACUUM requires exclusive access to the database, which is impossible when
    the request pool has other connections open.
    """
    from ishastra.config import get_settings

    settings = get_settings()
    db_path = current_path() or settings.db_path
    db_type = _detect_db_type(db_path)

    if db_type == "postgresql":
        if asyncpg is None:
            raise RuntimeError("asyncpg is required for PostgreSQL support")
        conn = await asyncpg.connect(db_path)

        await PostgreSQLDatabase._migrate_pg(PostgreSQLDatabase(""), conn, db_path)
        _restrict_permissions(db_path)
        return conn

    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA busy_timeout = 10000")
    await db.execute("PRAGMA foreign_keys = ON")
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA synchronous = NORMAL")

    conn = SQLiteDatabase(db_path)
    await conn._migrate_sqlite(db)
    _restrict_permissions(db_path)
    return db


async def vacuum() -> None:
    """Reclaim file space after bulk retention deletes (WAL is checkpointed).

    Uses a direct connection (not from pool) because VACUUM requires
    exclusive access to the database.
    """
    db = await _connect_direct()
    try:
        if _detect_db_type(current_path()) == "postgresql":
            await db.execute("VACUUM")
        else:
            for statement in ("PRAGMA wal_checkpoint(TRUNCATE)", "VACUUM"):
                cursor = await db.execute(statement)
                try:
                    await cursor.fetchall()
                finally:
                    await cursor.close()
    finally:
        await db.close()


async def save_monitor_config(targets: list[str], interval_seconds: int) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            "INSERT INTO settings (key, value) VALUES ('monitor_targets', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            json.dumps(targets),
        )
        await _execute(
            conn,
            "INSERT INTO settings (key, value) VALUES ('monitor_interval', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            str(interval_seconds),
        )


async def load_monitor_config() -> tuple[list[str], int | None]:
    db = await get_database()
    async with db.transaction() as conn:
        row = await _fetchone(conn, "SELECT value FROM settings WHERE key = 'monitor_targets'")
        targets = json.loads(row["value"]) if row else []
        row = await _fetchone(conn, "SELECT value FROM settings WHERE key = 'monitor_interval'")
        interval = int(row["value"]) if row else None
        return targets, interval


async def save_monitor_baseline(target: str, fingerprints: list[str] | set[str]) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            "INSERT INTO monitor_baseline (target, fingerprints, updated_at) "
            "VALUES (?, ?, ?) ON CONFLICT(target) DO UPDATE SET "
            "fingerprints = excluded.fingerprints, updated_at = excluded.updated_at",
            target,
            json.dumps(list(fingerprints)),
            time.time(),
        )


async def load_monitor_baseline() -> dict[str, set[str]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT target, fingerprints FROM monitor_baseline")
        return {row["target"]: set(json.loads(row["fingerprints"])) for row in rows}


async def delete_monitor_baseline(target: str) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(conn, "DELETE FROM monitor_baseline WHERE target = ?", target)


async def save_policy(policy: dict[str, Any]) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            """INSERT INTO engagement_policies (policy_id, tenant_id, program, authorized_by,
                authorization_ref, include, exclude, authorized_networks, allowed_ports,
                allowed_asns, allowed_countries,
                allow_broad_networks, status, version, created_at, updated_at,
                effective_at, expires_at, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(policy_id) DO UPDATE SET
                -- tenant_id is IMMUTABLE: never update it on conflict.
                -- This prevents a policy from being moved between tenants.
                program = excluded.program,
                authorized_by = excluded.authorized_by, authorization_ref = excluded.authorization_ref,
                include = excluded.include, exclude = excluded.exclude,
                authorized_networks = excluded.authorized_networks,
                allowed_ports = excluded.allowed_ports,
                allowed_asns = excluded.allowed_asns,
                allowed_countries = excluded.allowed_countries,
                allow_broad_networks = excluded.allow_broad_networks, status = excluded.status,
                version = excluded.version, created_at = excluded.created_at,
                updated_at = excluded.updated_at, effective_at = excluded.effective_at,
                expires_at = excluded.expires_at, created_by = excluded.created_by""",
            policy["policy_id"],
            policy["tenant_id"],
            policy["program"],
            policy["authorized_by"],
            policy["authorization_ref"],
            json.dumps(policy["include"]),
            json.dumps(policy["exclude"]),
            json.dumps(policy["authorized_networks"]),
            json.dumps(policy["allowed_ports"]),
            json.dumps(policy.get("allowed_asns") or []),
            json.dumps(policy.get("allowed_countries") or []),
            bool(policy["allow_broad_networks"]),
            policy["status"],
            policy["version"],
            policy["created_at"],
            policy["updated_at"],
            policy.get("effective_at"),
            policy.get("expires_at"),
            policy.get("created_by", ""),
        )


async def load_policies() -> list[dict[str, Any]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT * FROM engagement_policies")
        result = []
        for row in rows:
            row_dict = dict(row)

            for field in (
                "include",
                "exclude",
                "authorized_networks",
                "allowed_ports",
                "allowed_asns",
                "allowed_countries",
            ):
                if row_dict.get(field):
                    row_dict[field] = json.loads(row_dict[field])
            result.append(row_dict)
        return result


async def save_webhook_sink(name: str, url: str) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(
            conn,
            "INSERT INTO webhook_sinks (name, url, added_at) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET url = excluded.url",
            name,
            url,
            time.time(),
        )


async def delete_webhook_sink(name: str) -> None:
    db = await get_database()
    async with db.transaction() as conn:
        await _execute(conn, "DELETE FROM webhook_sinks WHERE name = ?", name)


async def load_webhook_sinks() -> list[dict[str, Any]]:
    db = await get_database()
    async with db.transaction() as conn:
        rows = await _fetchall(conn, "SELECT * FROM webhook_sinks")
        return [dict(row) for row in rows]


_sync_bridge_lock = threading.Lock()


def _run_async(coro):
    """Run one store operation from sync code, on a private pool.

    A throwaway ``asyncio.run()`` loop must not leave connections in the
    process-wide pool: aiosqlite's connection thread is non-daemon, so a single
    leaked connection keeps the interpreter alive forever (a CLI that appears to
    hang and has to be force-quit). The private pool is discarded before
    returning, and the server's pool is left untouched.
    """
    global _database
    with _sync_bridge_lock:
        saved = _database
        _database = None
        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(coro)

            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, coro)
                return future.result()
        finally:
            private = _database
            _database = saved
            if private is not None and hasattr(private, "discard_sync"):
                private.discard_sync()


def reset_audit_chain_sync() -> int:
    """Clear the sealed audit chain on explicit operator request."""

    async def _reset():
        db = await get_database()
        async with db.transaction() as conn:
            cursor = await _execute(conn, "DELETE FROM audit_chain")
            return int(cursor.rowcount)

    return _run_async(_reset())


get_db_pool = get_database
close_db_pool = close_database
reset_db_pool = reset_database
