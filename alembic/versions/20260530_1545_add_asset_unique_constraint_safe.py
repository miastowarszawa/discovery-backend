"""add asset unique constraint safe

Revision ID: 20260530_1545
Revises: 20260530_1540
Create Date: 2026-05-30 15:45:00
"""

from alembic import op
import sqlalchemy as sa


revision = '20260530_1545'
down_revision = '20260530_1540'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    duplicate_check_sql = sa.text(
        """
        SELECT target_id, asset_type, value, COUNT(*) AS cnt
        FROM asset
        GROUP BY target_id, asset_type, value
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    )
    duplicate = bind.execute(duplicate_check_sql).fetchone()
    if duplicate is not None:
        raise RuntimeError(
            'Duplicate assets still exist. Run cleanup_duplicate_assets.py before applying this migration.'
        )

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
