"""Migration 21: Enhanced organizations table with slug and settings

Revision ID: d21000000021
Revises: c20000000020
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd21000000021'
down_revision: Union[str, Sequence[str], None] = 'c20000000020'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS organizations_v2 (
        org_id         TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL UNIQUE,
        settings       TEXT NOT NULL DEFAULT '{}',
        tier           TEXT NOT NULL,
        created_at     REAL NOT NULL,
        updated_at     REAL NOT NULL
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS organizations_by_slug ON organizations_v2 (slug);")
    op.execute("""
    INSERT INTO organizations_v2 (org_id, name, slug, settings, tier, created_at, updated_at)
    SELECT org_id, name, LOWER(REPLACE(name, ' ', '-')), '{}', tier, created_at, updated_at
    FROM organizations WHERE NOT EXISTS (SELECT 1 FROM organizations_v2 WHERE org_id = organizations.org_id);
    """)
    op.execute("DROP TABLE IF EXISTS organizations;")
    op.execute("ALTER TABLE organizations_v2 RENAME TO organizations;")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS organizations_by_slug;")
    op.execute("DROP TABLE IF EXISTS organizations;")
