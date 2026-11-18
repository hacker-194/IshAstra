"""Migration 22: Teams table

Revision ID: e22000000022
Revises: d21000000021
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e22000000022'
down_revision: Union[str, Sequence[str], None] = 'd21000000021'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS teams (
        team_id        TEXT PRIMARY KEY,
        org_id         TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        name           TEXT NOT NULL,
        slug           TEXT NOT NULL,
        role_mappings  TEXT NOT NULL DEFAULT '{}',
        created_at     REAL NOT NULL,
        UNIQUE(org_id, slug)
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS teams_by_org ON teams (org_id);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS teams_by_org;")
    op.execute("DROP TABLE IF EXISTS teams;")
