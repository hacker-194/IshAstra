"""Migration 20: compliance_schedules, compliance_reports, compliance_exports

Revision ID: c20000000020
Revises: b19000000019
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c20000000020'
down_revision: Union[str, Sequence[str], None] = 'b19000000019'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
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
    """)
    op.execute("CREATE INDEX IF NOT EXISTS compliance_schedules_by_tenant ON compliance_schedules (tenant);")
    op.execute("CREATE INDEX IF NOT EXISTS compliance_schedules_by_enabled ON compliance_schedules (enabled);")

    op.execute("""
    CREATE TABLE IF NOT EXISTS compliance_reports (
        id            TEXT PRIMARY KEY,
        tenant        TEXT NOT NULL,
        schedule_id   TEXT NOT NULL,
        period_start  REAL NOT NULL,
        period_end    REAL NOT NULL,
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS compliance_reports_by_tenant ON compliance_reports (tenant, period_start DESC);")
    op.execute("CREATE INDEX IF NOT EXISTS compliance_reports_by_schedule ON compliance_reports (schedule_id);")

    op.execute("""
    CREATE TABLE IF NOT EXISTS compliance_exports (
        report_id     TEXT NOT NULL,
        tenant        TEXT NOT NULL,
        format        TEXT NOT NULL DEFAULT 'csv',
        data          TEXT NOT NULL,
        created_at    REAL NOT NULL,
        PRIMARY KEY (report_id, format)
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS compliance_exports_by_tenant ON compliance_exports (tenant, created_at DESC);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS compliance_exports_by_tenant;")
    op.execute("DROP TABLE IF EXISTS compliance_exports;")
    op.execute("DROP INDEX IF EXISTS compliance_reports_by_schedule;")
    op.execute("DROP INDEX IF EXISTS compliance_reports_by_tenant;")
    op.execute("DROP TABLE IF EXISTS compliance_reports;")
    op.execute("DROP INDEX IF EXISTS compliance_schedules_by_enabled;")
    op.execute("DROP INDEX IF EXISTS compliance_schedules_by_tenant;")
    op.execute("DROP TABLE IF EXISTS compliance_schedules;")
