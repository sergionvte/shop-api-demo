"""refresh_tokens: índice (user_id, client_ip)

Revision ID: c4e8b19d0a52
Revises: a7d3c2e1b4f0
Create Date: 2026-09-25 16:41:00.000000

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c4e8b19d0a52'
down_revision: str | Sequence[str] | None = 'a7d3c2e1b4f0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.create_index(
            'ix_refresh_tokens_user_id_client_ip', ['user_id', 'client_ip'], unique=False
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_index('ix_refresh_tokens_user_id_client_ip')
