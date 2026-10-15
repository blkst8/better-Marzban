"""add ip_limit to users and create user_online_ips

Revision ID: 990c34d69c6b
Revises: 2b231de97dc3
Create Date: 2026-10-14 22:45:00.000000

"""
import sqlalchemy as sa
from alembic import op

revision = '990c34d69c6b'
down_revision = '2b231de97dc3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('ip_limit', sa.Integer(), nullable=True))

    op.create_table(
        'user_online_ips',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('device', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('device_name', sa.String(length=128), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'user_id', 'node_id', 'ip', 'device', name='uq_user_online_ips_session'
        ),
    )
    op.create_index(op.f('ix_user_online_ips_user_id'), 'user_online_ips', ['user_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_user_online_ips_user_id'), table_name='user_online_ips')
    op.drop_table('user_online_ips')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('ip_limit')