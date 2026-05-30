import uuid

import pytest

from app.models.scan import Scan
from app.models.target import Target


@pytest.mark.asyncio
async def test_get_target_scans_returns_only_target_scans(client, db_session, target):
    other_target = Target(
        name="other-target",
        domain="other.example.com",
    )
    db_session.add(other_target)
    await db_session.flush()

    scan1 = Scan(
        target_id=target.id,
        scan_type="recon",
        status="queued",
        config_json={"source": "first"},
        result_json={},
    )
    scan2 = Scan(
        target_id=target.id,
        scan_type="nmap_xml_import",
        status="finished",
        config_json={"source": "second"},
        result_json={"imported": True},
    )
    other_scan = Scan(
        target_id=other_target.id,
        scan_type="recon",
        status="failed",
        config_json={"source": "other"},
        result_json={"error": "boom"},
    )

    db_session.add_all([scan1, scan2, other_scan])
    await db_session.commit()

    response = await client.get(f"/api/v1/targets/{target.id}/scans")

    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == str(target.id)
    assert len(body["items"]) == 2

    returned_target_ids = {item["target_id"] for item in body["items"]}
    assert returned_target_ids == {str(target.id)}

    returned_scan_types = {item["scan_type"] for item in body["items"]}
    assert returned_scan_types == {"recon", "nmap_xml_import"}


@pytest.mark.asyncio
async def test_get_target_scans_returns_empty_list_for_target_without_scans(client, db_session, target):
    response = await client.get(f"/api/v1/targets/{target.id}/scans")

    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == str(target.id)
    assert body["items"] == []


@pytest.mark.asyncio
async def test_get_target_scans_returns_404_for_missing_target(client):
    missing_id = uuid.uuid4()

    response = await client.get(f"/api/v1/targets/{missing_id}/scans")

    assert response.status_code == 404
    assert response.json()["detail"] == "Target not found"