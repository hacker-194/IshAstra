"""Migration 27: Add org_id to api_keys for tenant-org linkage

Revision ID: j27000000027
Revises: i26000000026
Create Date: 2026-11-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'j27000000027'
down_revision: Union[str, Sequence[str], None] = 'i26000000026'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('api_keys', sa.Column('org_id', sa.Text()))
    op.execute("CREATE INDEX IF NOT EXISTS api_keys_by_org ON api_keys (org_id);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS api_keys_by_org;")
    op.drop_column('api_keys', 'org_id')