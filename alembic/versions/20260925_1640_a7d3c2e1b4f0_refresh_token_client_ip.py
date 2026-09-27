"""refresh_tokens.client_ip

Revision ID: a7d3c2e1b4f0
Revises: f1c10595eb9a
Create Date: 2026-09-25 19:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a7d3c2e1b4f0'
down_revision: str | Sequence[str] | None = 'f1c10595eb9a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('client_ip', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True)
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_column('client_ip')
