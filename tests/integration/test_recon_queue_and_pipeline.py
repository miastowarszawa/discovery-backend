import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.event import Event
from app.models.scan import Scan
from app.schemas.jobs import ReconJobPayload
from app.services.recon_pipeline import process_recon_job


@pytest.mark.asyncio
async def test_process_recon_job_creates_scan_assets_and_events(db_session, target):
    scan = Scan(target_id=target.id, scan_type='recon', status='queued', config_json={'tools': ['subfinder', 'httpx', 'naabu']})
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    payload = ReconJobPayload(
        target_id=target.id,
        scan_id=scan.id,
        domain=target.domain,
        requested_at=datetime.now(timezone.utc),
    )

    with patch('app.services.recon_pipeline.run_subfinder', new=AsyncMock(return_value=[
        {'host': 'app.example.com'},
        {'host': 'api.example.com'},
    ])), patch('app.services.recon_pipeline.run_httpx', new=AsyncMock(return_value=[
        {'url': 'https://app.example.com', 'status_code': 200, 'tech': ['nginx']},
        {'url': 'https://api.example.com', 'status_code': 200, 'tech': ['fastapi']},
    ])), patch('app.services.recon_pipeline.run_naabu', new=AsyncMock(return_value=[
        {'host': 'app.example.com', 'port': 443},
        {'host': 'api.example.com', 'port': 8443},
    ])):
        result = await process_recon_job(db_session, payload)

    refreshed_scan = await db_session.get(Scan, scan.id)
    assert refreshed_scan.status == 'completed'
    assert result['subfinder_count'] == 2
    assert result['httpx_count'] == 2
    assert result['naabu_count'] == 2

    asset_count = await db_session.scalar(select(func.count()).select_from(Asset))
    event_count = await db_session.scalar(select(func.count()).select_from(Event))
    assert asset_count == 6
    assert event_count == 2
