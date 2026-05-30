import pytest
from sqlalchemy import select

from app.models.scan import Scan


@pytest.mark.asyncio
async def test_start_scan_enqueues_job_and_creates_scan(client, db_session, target):
    response = await client.post('/api/v1/scans/start', params={'target_id': str(target.id)})
    assert response.status_code == 202
    data = response.json()
    assert data['status'] == 'queued'
    assert data['queue'] == 'recon:jobs'

    scans = await db_session.execute(select(Scan).where(Scan.target_id == target.id))
    rows = list(scans.scalars().all())
    assert len(rows) == 1
    assert rows[0].status == 'queued'
