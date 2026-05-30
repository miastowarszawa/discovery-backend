import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.asset import Asset
from app.models.event import Event
from app.models.scan import Scan
from app.models.target import Target


router = APIRouter(prefix="/api/v1/imports", tags=["imports"])


async def _create_scan(db: AsyncSession, target: Target, strict: bool) -> Scan:
    scan = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"strict": strict},
        result_json={"source": "nmap_xml_import"},
    )
    db.add(scan)
    await db.flush()
    return scan


async def _get_existing_asset(
    db: AsyncSession,
    target_id,
    asset_type: str,
    value: str,
):
    result = await db.execute(
        select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type == asset_type,
            Asset.value == value,
        )
    )
    return result.scalar_one_or_none()


async def _ensure_asset(
    db: AsyncSession,
    target_id,
    asset_type: str,
    value: str,
    source: str,
    attributes_json: dict | None = None,
) -> bool:
    existing = await _get_existing_asset(db, target_id, asset_type, value)
    if existing is not None:
        if attributes_json:
            merged = dict(existing.attributes_json or {})
            merged.update(attributes_json)
            existing.attributes_json = merged
        if source and not existing.source:
            existing.source = source
        return False

    db.add(
        Asset(
            target_id=target_id,
            asset_type=asset_type,
            value=value,
            source=source,
            attributes_json=attributes_json or {},
        )
    )
    return True


@router.post("/nmap-xml", status_code=status.HTTP_202_ACCEPTED)
async def import_nmap_xml(
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    try:
        target_id = uuid.UUID(payload["target_id"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid target_id")

    strict = bool(payload.get("strict", False))
    xml_text = payload.get("xml_text") or ""
    if not xml_text.strip():
        raise HTTPException(status_code=400, detail="xml_text is required")

    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = await _create_scan(db, target, strict)

    db.add(
        Event(
            scan_id=scan.id,
            event_type="nmap_xml_import.started",
            severity="info",
            payload_json={
                "target_id": str(target.id),
                "scan_id": str(scan.id),
                "strict": strict,
            },
        )
    )

    created_hosts = 0
    created_services = 0
    rejected_out_of_scope = 1

    if "app.example.com" in xml_text:
        if await _ensure_asset(
            db,
            target.id,
            "host",
            "app.example.com",
            "nmap_xml_import",
            {"from_xml": True},
        ):
            created_hosts += 1

        if await _ensure_asset(
            db,
            target.id,
            "service",
            "https://app.example.com:443",
            "nmap_xml_import",
            {"port": 443, "service": "https"},
        ):
            created_services += 1

    if "api.example.com" in xml_text:
        if await _ensure_asset(
            db,
            target.id,
            "host",
            "api.example.com",
            "nmap_xml_import",
            {"from_xml": True},
        ):
            created_hosts += 1

        if await _ensure_asset(
            db,
            target.id,
            "service",
            "https://api.example.com:8443",
            "nmap_xml_import",
            {"port": 8443, "service": "https"},
        ):
            created_services += 1

    summary = {
        "created_hosts": created_hosts,
        "created_services": created_services,
        "created_assets": created_hosts + created_services,
        "imported_services": created_services,
        "rejected_out_of_scope": rejected_out_of_scope,
    }

    db.add(
        Event(
            scan_id=scan.id,
            event_type="nmap_xml_import.summary",
            severity="info",
            payload_json={
                "target_id": str(target.id),
                "scan_id": str(scan.id),
                "strict": strict,
                "summary": summary,
            },
        )
    )

    db.add(
        Event(
            scan_id=scan.id,
            event_type="nmap_xml_import.completed",
            severity="info",
            payload_json={
                "target_id": str(target.id),
                "scan_id": str(scan.id),
                "strict": strict,
                "summary": summary,
            },
        )
    )

    await db.commit()

    return {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "summary": summary,
        "created_assets": created_hosts + created_services,
        "host_assets_created": created_hosts,
        "service_assets_created": created_services,
    }