import uuid

import pytest
from sqlalchemy import select

from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_scan_returns_scan_details(client, db_session, target):
    scan = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"strict": False},
        result_json={"source": "nmap_xml_import"},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    response = await client.get(f"/api/v1/scans/{scan.id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(scan.id)
    assert body["target_id"] == str(target.id)
    assert body["scan_type"] == "nmap_xml_import"
    assert body["status"] == "finished"
    assert body["config_json"] == {"strict": False}
    assert body["result_json"] == {"source": "nmap_xml_import"}


@pytest.mark.asyncio
async def test_get_scan_returns_404_for_missing_scan(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/scans/{missing_id}")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"