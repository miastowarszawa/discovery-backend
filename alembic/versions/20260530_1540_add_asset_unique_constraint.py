"""add asset unique constraint

Revision ID: 20260530_1540
Revises: 20260530_1500
Create Date: 2026-05-30 15:40:00
"""

from alembic import op
import sqlalchemy as sa


revision = '20260530_1540'
down_revision = '20260530_1500'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        'uq_asset_target_type_value',
        'asset',
        ['target_id', 'asset_type', 'value'],
    )
    op.create_index('ix_asset_target_id', 'asset', ['target_id'], unique=False)
    op.create_index('ix_asset_asset_type', 'asset', ['asset_type'], unique=False)
    op.create_index('ix_asset_value', 'asset', ['value'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_asset_value', table_name='asset')
    op.drop_index('ix_asset_asset_type', table_name='asset')
    op.drop_index('ix_asset_target_id', table_name='asset')
    op.drop_constraint('uq_asset_target_type_value', 'asset', type_='unique')
