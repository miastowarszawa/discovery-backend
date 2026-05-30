import uuid

import pytest

from app.models.event import Event
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_scan_events_returns_items(client, db_session, target):
    scan = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"strict": False},
        result_json={"source": "nmap_xml_import"},
    )
    db_session.add(scan)
    await db_session.flush()

    event1 = Event(
        scan_id=scan.id,
        event_type="nmap_xml_import.started",
        severity="info",
        payload_json={"step": "start"},
    )
    event2 = Event(
        scan_id=scan.id,
        event_type="nmap_xml_import.completed",
        severity="info",
        payload_json={"step": "done"},
    )
    db_session.add_all([event1, event2])
    await db_session.commit()

    response = await client.get(f"/api/v1/scans/{scan.id}/events")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == str(scan.id)
    assert len(body["items"]) == 2
    assert body["items"][0]["event_type"] == "nmap_xml_import.started"
    assert body["items"][1]["event_type"] == "nmap_xml_import.completed"


@pytest.mark.asyncio
async def test_get_scan_events_returns_empty_list_for_scan_without_events(client, db_session, target):
    scan = Scan(
        target_id=target.id,
        scan_type="recon",
        status="queued",
        config_json={},
        result_json={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    response = await client.get(f"/api/v1/scans/{scan.id}/events")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == str(scan.id)
    assert body["items"] == []


@pytest.mark.asyncio
async def test_get_scan_events_returns_404_for_missing_scan(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/scans/{missing_id}/events")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"