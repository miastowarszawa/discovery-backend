from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.models.scan import Scan
from app.schemas.recon import ReconJobCreate


async def create_recon_job(db: AsyncSession, payload: ReconJobCreate) -> Scan:
    scan = Scan(
        target_id=payload.target_id,
        scan_type=payload.scan_type,
        status='queued',
        config_json=payload.config_json or {},
        result_json={},
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan_events(db: AsyncSession, scan_id: str) -> list[dict]:
    result = await db.execute(
        select(Event)
        .where(Event.scan_id == scan_id)
        .order_by(Event.created_at.asc())
    )
    items = []
    for event in result.scalars().all():
        items.append(
            {
                'id': str(event.id),
                'scan_id': str(event.scan_id),
                'event_type': event.event_type,
                'severity': event.severity,
                'payload': event.payload_json or {},
                'created_at': event.created_at.isoformat() if event.created_at else None,
            }
        )
    return items
