from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset


def _normalize_asset_value(asset_type: str, value: str) -> str:
    normalized = value.strip()
    if asset_type in {'host', 'domain', 'service'}:
        normalized = normalized.lower()
    return normalized


def _merge_attributes(existing: dict | None, incoming: dict | None) -> dict:
    existing = existing or {}
    incoming = incoming or {}

    merged = dict(existing)

    for key, value in incoming.items():
        if key not in merged or merged[key] in (None, '', [], {}):
            merged[key] = value
            continue

        if isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = list(dict.fromkeys([*merged[key], *value]))
            continue

        if isinstance(merged[key], dict) and isinstance(value, dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
            continue

    return merged


async def _find_existing_asset(
    *,
    db: AsyncSession,
    target_id,
    asset_type: str,
    value: str,
) -> Asset | None:
    result = await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type == asset_type,
            Asset.value == value,
        )
    )
    return result.scalar_one_or_none()


async def get_or_create_asset(
    *,
    db: AsyncSession,
    target_id,
    asset_type: str,
    value: str,
    source: str,
    attributes_json: dict | None = None,
) -> tuple[Asset, bool]:
    normalized_value = _normalize_asset_value(asset_type, value)

    asset = await _find_existing_asset(
        db=db,
        target_id=target_id,
        asset_type=asset_type,
        value=normalized_value,
    )

    if asset:
        asset.attributes_json = _merge_attributes(asset.attributes_json, attributes_json)
        if not getattr(asset, 'source', None):
            asset.source = source
        db.add(asset)
        await db.flush()
        return asset, False

    asset = Asset(
        target_id=target_id,
        asset_type=asset_type,
        value=normalized_value,
        source=source,
        attributes_json=attributes_json or {},
    )
    db.add(asset)

    try:
        await db.flush()
        return asset, True
    except IntegrityError:
        await db.rollback()

    asset = await _find_existing_asset(
        db=db,
        target_id=target_id,
        asset_type=asset_type,
        value=normalized_value,
    )
    if asset is None:
        raise RuntimeError('Asset uniqueness conflict occurred but existing asset could not be reloaded')

    asset.attributes_json = _merge_attributes(asset.attributes_json, attributes_json)
    if not getattr(asset, 'source', None):
        asset.source = source
    db.add(asset)
    await db.flush()
    return asset, False
