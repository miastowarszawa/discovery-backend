import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.event import Event
from app.models.scan import Scan
from app.models.target import Target


router = APIRouter(tags=["scans"])


class ScanDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: str
    scan_type: str
    status: str
    config_json: dict[str, Any]
    result_json: dict[str, Any]


class ScanEventItem(BaseModel):
    id: str
    event_type: str
    severity: str
    payload_json: dict[str, Any]


class ScanEventsResponse(BaseModel):
    scan_id: str
    items: list[ScanEventItem]


class TargetScanItem(BaseModel):
    id: str
    target_id: str
    scan_type: str
    status: str
    config_json: dict[str, Any]
    result_json: dict[str, Any]


class TargetScansResponse(BaseModel):
    target_id: str
    items: list[TargetScanItem]


class TargetScanSummary(BaseModel):
    target_id: str
    total_scans: int
    latest_scan_id: str | None = None
    latest_scan_type: str | None = None
    latest_scan_status: str | None = None


class ScanEventSummary(BaseModel):
    scan_id: str
    total_events: int
    events_by_type: dict[str, int]
    events_by_severity: dict[str, int]


def sort_scan_events(events: list[Event]) -> list[Event]:
    def event_sort_key(event: Event):
        if event.event_type.endswith(".started"):
            priority = 0
        elif event.event_type.endswith(".completed"):
            priority = 2
        else:
            priority = 1
        return (priority, event.created_at, str(event.id))

    return sorted(events, key=event_sort_key)


def sort_target_scans(scans: list[Scan]) -> list[Scan]:
    return sorted(scans, key=lambda scan: str(scan.id), reverse=True)


@router.post("/api/v1/scans/start", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(target_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    queue_name = "recon:jobs"

    scan = Scan(
        target_id=target.id,
        scan_type="recon",
        status="queued",
        config_json={"queue": queue_name},
        result_json={},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    return {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "queue": queue_name,
    }


@router.get(
    "/api/v1/targets/{target_id}/latest-scan",
    response_model=ScanDetail,
)
async def get_target_latest_scan(target_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .order_by(desc(Scan.created_at), desc(Scan.id))
        .limit(1)
    )
    scan = result.scalars().first()

    if scan is None:
        raise HTTPException(status_code=404, detail="No scans found for target")

    return {
        "id": str(scan.id),
        "target_id": str(scan.target_id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "config_json": scan.config_json,
        "result_json": scan.result_json,
    }


@router.get(
    "/api/v1/targets/{target_id}/scan-summary",
    response_model=TargetScanSummary,
)
async def get_target_scan_summary(target_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    count_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.target_id == target_id)
    )
    total_scans = count_result.scalar_one()

    latest_result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .order_by(desc(Scan.created_at), desc(Scan.id))
        .limit(1)
    )
    latest_scan = latest_result.scalars().first()

    return {
        "target_id": str(target.id),
        "total_scans": total_scans,
        "latest_scan_id": str(latest_scan.id) if latest_scan else None,
        "latest_scan_type": latest_scan.scan_type if latest_scan else None,
        "latest_scan_status": latest_scan.status if latest_scan else None,
    }


@router.get(
    "/api/v1/targets/{target_id}/scans",
    response_model=TargetScansResponse,
)
async def get_target_scans(target_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Scan).where(Scan.target_id == target_id)
    )
    scans = list(result.scalars().all())
    scans = sort_target_scans(scans)

    return {
        "target_id": str(target.id),
        "items": [
            {
                "id": str(scan.id),
                "target_id": str(scan.target_id),
                "scan_type": scan.scan_type,
                "status": scan.status,
                "config_json": scan.config_json,
                "result_json": scan.result_json,
            }
            for scan in scans
        ],
    }


@router.get(
    "/api/v1/scans/{scan_id}/event-summary",
    response_model=ScanEventSummary,
)
async def get_scan_event_summary(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    total_result = await db.execute(
        select(func.count()).select_from(Event).where(Event.scan_id == scan_id)
    )
    total_events = total_result.scalar_one()

    type_result = await db.execute(
        select(Event.event_type, func.count())
        .where(Event.scan_id == scan_id)
        .group_by(Event.event_type)
    )
    events_by_type = {event_type: count for event_type, count in type_result.all()}

    severity_result = await db.execute(
        select(Event.severity, func.count())
        .where(Event.scan_id == scan_id)
        .group_by(Event.severity)
    )
    events_by_severity = {severity: count for severity, count in severity_result.all()}

    return {
        "scan_id": str(scan.id),
        "total_events": total_events,
        "events_by_type": events_by_type,
        "events_by_severity": events_by_severity,
    }


@router.get(
    "/api/v1/scans/{scan_id}/events",
    response_model=ScanEventsResponse,
)
async def get_scan_events(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Event).where(Event.scan_id == scan_id)
    )
    events = list(result.scalars().all())
    events = sort_scan_events(events)

    return {
        "scan_id": str(scan.id),
        "items": [
            {
                "id": str(event.id),
                "event_type": event.event_type,
                "severity": event.severity,
                "payload_json": event.payload_json,
            }
            for event in events
        ],
    }


@router.get("/api/v1/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": str(scan.id),
        "target_id": str(scan.target_id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "config_json": scan.config_json,
        "result_json": scan.result_json,
    }