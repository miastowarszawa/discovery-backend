import pytest
from sqlalchemy import select, func

from app.models.asset import Asset
from app.scripts.cleanup_duplicate_assets import cleanup_duplicate_assets


@pytest.mark.asyncio
async def test_cleanup_duplicate_assets_merges_attributes_and_deletes_duplicates(db_session, target):
    asset1 = Asset(
        target_id=target.id,
        asset_type='host',
        value='app.example.com',
        source='nmap_xml_import',
        attributes_json={'tags': ['web'], 'service': {'name': 'https'}},
    )
    asset2 = Asset(
        target_id=target.id,
        asset_type='host',
        value='app.example.com',
        source=None,
        attributes_json={'tags': ['prod'], 'service': {'version': '1.24.0'}},
    )
    db_session.add_all([asset1, asset2])
    await db_session.commit()

    summary = await cleanup_duplicate_assets(dry_run=False, session=db_session)

    assert summary['duplicate_groups'] >= 1
    assert summary['deleted_assets'] >= 1

    remaining = await db_session.execute(
        select(Asset).where(
            Asset.target_id == target.id,
            Asset.asset_type == 'host',
            Asset.value == 'app.example.com',
        )
    )
    items = list(remaining.scalars().all())

    assert len(items) == 1
    merged = items[0].attributes_json
    assert 'web' in merged['tags']
    assert 'prod' in merged['tags']
    assert merged['service']['name'] == 'https'
    assert merged['service']['version'] == '1.24.0'


@pytest.mark.asyncio
async def test_cleanup_duplicate_assets_dry_run_does_not_modify_rows(db_session, target):
    db_session.add_all([
        Asset(target_id=target.id, asset_type='host', value='dup.example.com', attributes_json={'a': 1}),
        Asset(target_id=target.id, asset_type='host', value='dup.example.com', attributes_json={'b': 2}),
    ])
    await db_session.commit()

    before = await db_session.scalar(select(func.count()).select_from(Asset))
    summary = await cleanup_duplicate_assets(dry_run=True, session=db_session)
    await db_session.rollback()
    after = await db_session.scalar(select(func.count()).select_from(Asset))

    assert summary['dry_run'] is True
    assert before == after
