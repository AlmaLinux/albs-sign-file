"""Key permissions and signing audit trail

Adds the tables needed by the RPM header signing endpoint (PF-3304):
``user_keys`` restricts which keys a caller may sign with, and
``sign_audit_records`` records who signed what with which key.

Revision ID: 002
Revises: 001
Create Date: 2026-09-18

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'user_keys',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('keyid', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ['user_id'], ['users.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'user_id', 'keyid', name='uq_user_keys_user_keyid'
        ),
    )
    op.create_index(
        op.f('ix_user_keys_user_id'), 'user_keys', ['user_id'], unique=False
    )
    op.create_index(
        op.f('ix_user_keys_keyid'), 'user_keys', ['keyid'], unique=False
    )

    op.create_table(
        'sign_audit_records',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('operation', sa.String(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('keyid', sa.String(), nullable=False),
        sa.Column('filename', sa.String(), nullable=True),
        sa.Column('package_nevra', sa.String(), nullable=True),
        sa.Column('sha256_before', sa.String(), nullable=True),
        sa.Column('sha256_after', sa.String(), nullable=True),
        sa.Column('signature', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('detail', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_sign_audit_records_created_at'),
        'sign_audit_records',
        ['created_at'],
        unique=False,
    )
    op.create_index(
        op.f('ix_sign_audit_records_user_id'),
        'sign_audit_records',
        ['user_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_sign_audit_records_user_email'),
        'sign_audit_records',
        ['user_email'],
        unique=False,
    )
    op.create_index(
        op.f('ix_sign_audit_records_keyid'),
        'sign_audit_records',
        ['keyid'],
        unique=False,
    )
    op.create_index(
        op.f('ix_sign_audit_records_package_nevra'),
        'sign_audit_records',
        ['package_nevra'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_sign_audit_records_package_nevra'),
        table_name='sign_audit_records',
    )
    op.drop_index(
        op.f('ix_sign_audit_records_keyid'), table_name='sign_audit_records'
    )
    op.drop_index(
        op.f('ix_sign_audit_records_user_email'),
        table_name='sign_audit_records',
    )
    op.drop_index(
        op.f('ix_sign_audit_records_user_id'),
        table_name='sign_audit_records',
    )
    op.drop_index(
        op.f('ix_sign_audit_records_created_at'),
        table_name='sign_audit_records',
    )
    op.drop_table('sign_audit_records')

    op.drop_index(op.f('ix_user_keys_keyid'), table_name='user_keys')
    op.drop_index(op.f('ix_user_keys_user_id'), table_name='user_keys')
    op.drop_table('user_keys')
