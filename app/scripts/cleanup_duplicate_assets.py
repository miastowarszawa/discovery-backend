import asyncio
from collections.abc import Mapping

from sqlalchemy import func, select

from app.db.session import AsyncSessionLocal
from app.models.asset import Asset


def _is_scalar(value) -> bool:
    return not isinstance(value, (dict, list))


def _merge_json(base, incoming):
    if base in (None, '', [], {}):
        return incoming
    if incoming in (None, '', [], {}):
        return base

    if isinstance(base, Mapping) and isinstance(incoming, Mapping):
        merged = dict(base)
        for key, value in incoming.items():
            if key in merged:
                merged[key] = _merge_json(merged[key], value)
            else:
                merged[key] = value
        return merged

    if isinstance(base, list) and isinstance(incoming, list):
        merged = []
        for item in [*base, *incoming]:
            if item not in merged:
                merged.append(item)
        return merged

    if _is_scalar(base) and _is_scalar(incoming):
        return base if base not in (None, '') else incoming

    return base


def _pick_keeper(assets: list[Asset]) -> Asset:
    def sort_key(asset: Asset):
        created_at = asset.created_at.isoformat() if asset.created_at else ''
        return (created_at, str(asset.id))

    return sorted(assets, key=sort_key)[0]


async def _cleanup_with_session(session, dry_run: bool = True) -> dict:
    duplicate_groups_result = await session.execute(
        select(
            Asset.target_id,
            Asset.asset_type,
            Asset.value,
            func.count(Asset.id).label('cnt'),
        )
        .group_by(Asset.target_id, Asset.asset_type, Asset.value)
        .having(func.count(Asset.id) > 1)
        .order_by(Asset.target_id, Asset.asset_type, Asset.value)
    )
    groups = duplicate_groups_result.all()

    summary = {
        'dry_run': dry_run,
        'duplicate_groups': len(groups),
        'deleted_assets': 0,
        'updated_assets': 0,
    }

    for target_id, asset_type, value, _ in groups:
        assets_result = await session.execute(
            select(Asset)
            .where(
                Asset.target_id == target_id,
                Asset.asset_type == asset_type,
                Asset.value == value,
            )
            .order_by(Asset.created_at.asc(), Asset.id.asc())
        )
        assets = list(assets_result.scalars().all())
        if len(assets) < 2:
            continue

        keeper = _pick_keeper(assets)
        duplicates = [asset for asset in assets if asset.id != keeper.id]

        merged_attributes = keeper.attributes_json or {}
        keeper_source = keeper.source

        for duplicate in duplicates:
            merged_attributes = _merge_json(merged_attributes, duplicate.attributes_json or {})
            if not keeper_source and duplicate.source:
                keeper_source = duplicate.source

        keeper.attributes_json = merged_attributes
        keeper.source = keeper_source

        if not dry_run:
            session.add(keeper)
            for duplicate in duplicates:
                await session.delete(duplicate)
            await session.flush()

        summary['updated_assets'] += 1
        summary['deleted_assets'] += len(duplicates)

    if dry_run:
        await session.rollback()
    else:
        await session.commit()

    return summary


async def cleanup_duplicate_assets(dry_run: bool = True, session=None) -> dict:
    if session is not None:
        return await _cleanup_with_session(session=session, dry_run=dry_run)

    async with AsyncSessionLocal() as session:
        return await _cleanup_with_session(session=session, dry_run=dry_run)


async def _main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Cleanup duplicate asset rows before unique constraint migration')
    parser.add_argument('--apply', action='store_true', help='Apply cleanup changes. Default is dry-run.')
    args = parser.parse_args()

    result = await cleanup_duplicate_assets(dry_run=not args.apply)
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    asyncio.run(_main())
