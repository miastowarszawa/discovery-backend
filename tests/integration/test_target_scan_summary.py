import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_target_scan_summary_returns_counts_and_latest_scan(client, db_session, target):
    base_time = datetime.now(UTC)

    first_scan = Scan(
        target_id=target.id,
        scan_type="recon",
        status="queued",
        config_json={"source": "first"},
        result_json={},
        created_at=base_time,
    )
    latest_scan = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"source": "latest"},
        result_json={"imported": True},
        created_at=base_time + timedelta(seconds=1),
    )

    db_session.add_all([first_scan, latest_scan])
    await db_session.commit()

    response = await client.get(f"/api/v1/targets/{target.id}/scan-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == str(target.id)
    assert body["total_scans"] == 2
    assert body["latest_scan_id"] == str(latest_scan.id)
    assert body["latest_scan_type"] == "nmap_xml_import"
    assert body["latest_scan_status"] == "finished"


@pytest.mark.asyncio
async def test_get_target_scan_summary_returns_zero_counts_when_target_has_no_scans(client, target):
    response = await client.get(f"/api/v1/targets/{target.id}/scan-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == str(target.id)
    assert body["total_scans"] == 0
    assert body["latest_scan_id"] is None
    assert body["latest_scan_type"] is None
    assert body["latest_scan_status"] is None


@pytest.mark.asyncio
async def test_get_target_scan_summary_returns_404_for_missing_target(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/targets/{missing_id}/scan-summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Target not found"