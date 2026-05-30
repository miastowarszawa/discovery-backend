import uuid
from datetime import datetime, timedelta, UTC

import pytest

from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_target_latest_scan_returns_latest_scan_for_target(client, db_session, target):
    base_time = datetime.now(UTC)

    older_scan = Scan(
        target_id=target.id,
        scan_type="recon",
        status="queued",
        config_json={"source": "older"},
        result_json={},
        created_at=base_time,
    )
    newer_scan = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"source": "newer"},
        result_json={"imported": True},
        created_at=base_time + timedelta(seconds=1),
    )

    db_session.add_all([older_scan, newer_scan])
    await db_session.commit()

    response = await client.get(f"/api/v1/targets/{target.id}/latest-scan")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(newer_scan.id)
    assert body["target_id"] == str(target.id)
    assert body["scan_type"] == "nmap_xml_import"
    assert body["status"] == "finished"


@pytest.mark.asyncio
async def test_get_target_latest_scan_returns_404_when_target_has_no_scans(client, target):
    response = await client.get(f"/api/v1/targets/{target.id}/latest-scan")

    assert response.status_code == 404
    assert response.json()["detail"] == "No scans found for target"


@pytest.mark.asyncio
async def test_get_target_latest_scan_returns_404_for_missing_target(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/targets/{missing_id}/latest-scan")

    assert response.status_code == 404
    assert response.json()["detail"] == "Target not found"