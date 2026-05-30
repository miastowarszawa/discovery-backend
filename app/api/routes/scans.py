import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.event import Event
from app.models.scan import Scan
from app.models.target import Target


router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
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


@router.get("/{scan_id}/events")
async def get_scan_events(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Event).where(Event.scan_id == scan_id)
    )
    events = list(result.scalars().all())

    def event_sort_key(event: Event):
        if event.event_type.endswith(".started"):
            priority = 0
        elif event.event_type.endswith(".completed"):
            priority = 2
        else:
            priority = 1
        return (priority, event.created_at, str(event.id))

    events.sort(key=event_sort_key)

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


@router.get("/{scan_id}")
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