"""Migration 25: Restore admin_key_hash for legacy org module

Revision ID: h25000000025
Revises: g24000000024
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'h25000000025'
down_revision: Union[str, Sequence[str], None] = 'g24000000024'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE organizations ADD COLUMN admin_key_hash TEXT;")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS organizations_admin_key_hash ON organizations (admin_key_hash) WHERE admin_key_hash IS NOT NULL;")
    op.execute("""
    CREATE TABLE organizations_v3 AS SELECT
        org_id, name, slug, settings, tier, created_at, updated_at, admin_key_hash
        FROM organizations;
    """)
    op.execute("DROP TABLE organizations;")
    op.execute("""
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
    """)
    op.execute("INSERT INTO organizations SELECT * FROM organizations_v3;")
    op.execute("DROP TABLE organizations_v3;")
    op.execute("CREATE INDEX IF NOT EXISTS organizations_by_slug ON organizations (slug);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS organizations_by_slug;")
    op.execute("DROP INDEX IF EXISTS organizations_admin_key_hash;")
    op.execute("DROP TABLE IF EXISTS organizations;")
