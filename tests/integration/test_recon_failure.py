from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select, func

from app.models.event import Event
from app.models.scan import Scan
from app.schemas.jobs import ReconJobPayload
from app.services.recon_pipeline import process_recon_job


@pytest.mark.asyncio
async def test_process_recon_job_marks_failed_and_creates_event(db_session, target):
    scan = Scan(target_id=target.id, scan_type='recon', status='queued', config_json={'tools': ['subfinder']})
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    payload = ReconJobPayload(
        target_id=target.id,
        scan_id=scan.id,
        domain=target.domain,
        requested_at=datetime.now(timezone.utc),
    )

    with patch('app.services.recon_pipeline.run_subfinder', new=AsyncMock(side_effect=RuntimeError('subfinder boom'))):
        with pytest.raises(RuntimeError):
            await process_recon_job(db_session, payload)

    refreshed_scan = await db_session.get(Scan, scan.id)
    assert refreshed_scan.status == 'failed'
    assert refreshed_scan.result_json['error'] == 'subfinder boom'

    event_count = await db_session.scalar(select(func.count()).select_from(Event))
    assert event_count == 2
