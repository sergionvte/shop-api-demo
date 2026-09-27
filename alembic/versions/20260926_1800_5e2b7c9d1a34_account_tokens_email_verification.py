"""account tokens, email log and users.email_verified_at

Revision ID: 5e2b7c9d1a34
Revises: 9b3216eaa705
Create Date: 2026-09-26 18:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel

import app.db.types
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5e2b7c9d1a34'
down_revision: str | Sequence[str] | None = '9b3216eaa705'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('email_verified_at', app.db.types.UTCDateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column('locale', sqlmodel.sql.sqltypes.AutoString(length=10), nullable=True)
        )
    # Los usuarios que ya existían se dan por verificados: activar
    # EMAIL_VERIFICATION=required no debe dejar fuera a nadie (REQ-F13).
    op.execute(sa.text('UPDATE users SET email_verified_at = created_at'))

    op.create_table('account_tokens',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('purpose', sqlmodel.sql.sqltypes.AutoString(length=20), nullable=False),
    sa.Column('token_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
    sa.Column('email', sqlmodel.sql.sqltypes.AutoString(length=320), nullable=False),
    sa.Column('created_at', app.db.types.UTCDateTime(timezone=True), nullable=False),
    sa.Column('expires_at', app.db.types.UTCDateTime(timezone=True), nullable=False),
    sa.Column('used_at', app.db.types.UTCDateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_account_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_account_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_account_tokens_token_hash'))
    )
    with op.batch_alter_table('account_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_account_tokens_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index('ix_account_tokens_user_purpose', ['user_id', 'purpose', 'created_at'], unique=False)

    op.create_table('email_log',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('job_id', sa.Uuid(), nullable=True),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
    sa.Column('recipient_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
    sa.Column('created_at', app.db.types.UTCDateTime(timezone=True), nullable=False),
    sa.Column('sent_at', app.db.types.UTCDateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_email_log_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_email_log')),
    sa.UniqueConstraint('job_id', name=op.f('uq_email_log_job_id'))
    )
    with op.batch_alter_table('email_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_email_log_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_email_log_recipient_hash'), ['recipient_hash'], unique=False)
        batch_op.create_index(batch_op.f('ix_email_log_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('email_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_email_log_user_id'))
        batch_op.drop_index(batch_op.f('ix_email_log_recipient_hash'))
        batch_op.drop_index(batch_op.f('ix_email_log_created_at'))
    op.drop_table('email_log')
    with op.batch_alter_table('account_tokens', schema=None) as batch_op:
        batch_op.drop_index('ix_account_tokens_user_purpose')
        batch_op.drop_index(batch_op.f('ix_account_tokens_expires_at'))
    op.drop_table('account_tokens')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('locale')
        batch_op.drop_column('email_verified_at')
