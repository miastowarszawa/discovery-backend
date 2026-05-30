import uuid

import pytest

from app.models.event import Event
from app.models.scan import Scan


@pytest.mark.asyncio
async def test_get_scan_event_summary_returns_grouped_counts(client, db_session, target):
    scan = Scan(
        target_id=target.id,
        scan_type="recon",
        status="finished",
        config_json={},
        result_json={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    events = [
        Event(
            scan_id=scan.id,
            event_type="recon.started",
            severity="info",
            payload_json={"step": 1},
        ),
        Event(
            scan_id=scan.id,
            event_type="host.discovered",
            severity="info",
            payload_json={"host": "example.com"},
        ),
        Event(
            scan_id=scan.id,
            event_type="host.discovered",
            severity="info",
            payload_json={"host": "www.example.com"},
        ),
        Event(
            scan_id=scan.id,
            event_type="port.open",
            severity="medium",
            payload_json={"port": 443},
        ),
        Event(
            scan_id=scan.id,
            event_type="recon.completed",
            severity="info",
            payload_json={"ok": True},
        ),
    ]

    db_session.add_all(events)
    await db_session.commit()

    response = await client.get(f"/api/v1/scans/{scan.id}/event-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == str(scan.id)
    assert body["total_events"] == 5
    assert body["events_by_type"] == {
        "recon.started": 1,
        "host.discovered": 2,
        "port.open": 1,
        "recon.completed": 1,
    }
    assert body["events_by_severity"] == {
        "info": 4,
        "medium": 1,
    }


@pytest.mark.asyncio
async def test_get_scan_event_summary_returns_zero_counts_when_scan_has_no_events(client, db_session, target):
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

    response = await client.get(f"/api/v1/scans/{scan.id}/event-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == str(scan.id)
    assert body["total_events"] == 0
    assert body["events_by_type"] == {}
    assert body["events_by_severity"] == {}


@pytest.mark.asyncio
async def test_get_scan_event_summary_returns_404_for_missing_scan(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/scans/{missing_id}/event-summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"