"""Migration 26: Recreate org_memberships for legacy org module

Revision ID: i26000000026
Revises: h25000000025
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'i26000000026'
down_revision: Union[str, Sequence[str], None] = 'h25000000025'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS org_memberships (
        org_id     TEXT NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
        tenant_id  TEXT NOT NULL,
        role       TEXT NOT NULL,
        joined_at  REAL NOT NULL,
        PRIMARY KEY (org_id, tenant_id)
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS org_memberships_by_tenant ON org_memberships (tenant_id);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS org_memberships_by_tenant;")
    op.execute("DROP TABLE IF EXISTS org_memberships;")
