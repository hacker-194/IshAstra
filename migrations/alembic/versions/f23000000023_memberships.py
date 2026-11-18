"""Migration 23: Memberships table (org and team level)

Revision ID: f23000000023
Revises: e22000000022
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f23000000023'
down_revision: Union[str, Sequence[str], None] = 'e22000000022'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
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
    """)
    op.execute("CREATE INDEX IF NOT EXISTS memberships_by_org ON memberships (org_id);")
    op.execute("CREATE INDEX IF NOT EXISTS memberships_by_team ON memberships (team_id);")
    op.execute("CREATE INDEX IF NOT EXISTS memberships_by_user ON memberships (user_id);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS memberships_by_user;")
    op.execute("DROP INDEX IF EXISTS memberships_by_team;")
    op.execute("DROP INDEX IF EXISTS memberships_by_org;")
    op.execute("DROP TABLE IF EXISTS memberships;")
