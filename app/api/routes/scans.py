import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db, get_redis
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.jobs import ReconJobPayload
from app.services.recon_queue import enqueue_recon_job

router = APIRouter(prefix='/api/v1/scans', tags=['scans'])


@router.post('/start', status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail='Target not found')

    scan = Scan(target_id=target.id, scan_type='recon', status='queued', config_json={'tools': ['subfinder', 'httpx', 'naabu']})
    db.add(scan)
    await db.flush()

    payload = ReconJobPayload(
        target_id=target.id,
        scan_id=scan.id,
        domain=target.domain,
        requested_at=datetime.now(timezone.utc),
    )
    await enqueue_recon_job(redis, payload)
    await db.commit()
    await db.refresh(scan)

    return {'scan_id': str(scan.id), 'status': scan.status, 'queue': 'recon:jobs'}
