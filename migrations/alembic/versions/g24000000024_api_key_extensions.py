"""Migration 24: Project-scoped API key extensions

Revision ID: g24000000024
Revises: f23000000023
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g24000000024'
down_revision: Union[str, Sequence[str], None] = 'f23000000023'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE api_keys ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'tenant';")
    op.execute("ALTER TABLE api_keys ADD COLUMN project_id TEXT;")
    op.execute("ALTER TABLE api_keys ADD COLUMN allowed_projects TEXT;")
    op.execute("ALTER TABLE api_keys ADD COLUMN resource_filters TEXT;")
    op.execute("CREATE INDEX IF NOT EXISTS api_keys_by_project ON api_keys (project_id);")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_project_id ON api_keys (tenant_id, project_id);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS api_keys_tenant_project_id;")
    op.execute("DROP INDEX IF EXISTS api_keys_by_project;")
    op.execute("ALTER TABLE api_keys DROP COLUMN resource_filters;")
    op.execute("ALTER TABLE api_keys DROP COLUMN allowed_projects;")
    op.execute("ALTER TABLE api_keys DROP COLUMN project_id;")
    op.execute("ALTER TABLE api_keys DROP COLUMN scope_type;")
