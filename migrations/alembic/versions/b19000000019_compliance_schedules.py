"""Migration 19: api_keys include_hosts column

Revision ID: b19000000019
Revises: a550477e21b9
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b19000000019'
down_revision: Union[str, Sequence[str], None] = 'a550477e21b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE api_keys ADD COLUMN include_hosts TEXT;")


def downgrade() -> None:
    op.execute("ALTER TABLE api_keys DROP COLUMN include_hosts;")
