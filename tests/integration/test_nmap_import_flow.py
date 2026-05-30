import pytest
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.event import Event
from app.models.scan import Scan


MIXED_XML = '<?xml version="1.0" encoding="UTF-8"?>\n<nmaprun scanner="nmap" args="nmap -sV -oX mixed.xml app.example.com evil.test" start="1717072200" startstr="2026-05-30 15:00 CEST">\n  <host>\n    <status state="up" reason="syn-ack" reason_ttl="0"/>\n    <address addr="192.168.1.10" addrtype="ipv4"/>\n    <hostnames>\n      <hostname name="app.example.com" type="user"/>\n    </hostnames>\n    <ports>\n      <port protocol="tcp" portid="443">\n        <state state="open" reason="syn-ack" reason_ttl="0"/>\n        <service name="https" product="nginx" version="1.24.0" method="probed" conf="10"/>\n      </port>\n    </ports>\n  </host>\n  <host>\n    <status state="up" reason="syn-ack" reason_ttl="0"/>\n    <address addr="203.0.113.99" addrtype="ipv4"/>\n    <hostnames>\n      <hostname name="evil.test" type="user"/>\n    </hostnames>\n    <ports>\n      <port protocol="tcp" portid="22">\n        <state state="open" reason="syn-ack" reason_ttl="0"/>\n        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/>\n      </port>\n    </ports>\n  </host>\n</nmaprun>'


@pytest.mark.asyncio
async def test_nmap_import_permissive_creates_scan_assets_and_events(client, db_session, target):
    response = await client.post(
        '/api/v1/imports/nmap-xml',
        json={
            'target_id': str(target.id),
            'strict': False,
            'xml_text': MIXED_XML,
        },
    )

    assert response.status_code == 202
    body = response.json()
    assert body['scan_type'] == 'nmap_xml_import'
    assert body['status'] == 'finished'
    assert body['summary']['rejected_out_of_scope'] == 1
    assert body['summary']['imported_services'] >= 1

    scan_count = await db_session.scalar(select(func.count()).select_from(Scan))
    asset_count = await db_session.scalar(select(func.count()).select_from(Asset))
    event_count = await db_session.scalar(select(func.count()).select_from(Event))

    assert scan_count == 1
    assert asset_count >= 2
    assert event_count >= 3


@pytest.mark.asyncio
async def test_reimport_same_xml_does_not_create_duplicate_assets(client, db_session, target):
    payload = {
        'target_id': str(target.id),
        'strict': False,
        'xml_text': MIXED_XML,
    }

    response1 = await client.post('/api/v1/imports/nmap-xml', json=payload)
    response2 = await client.post('/api/v1/imports/nmap-xml', json=payload)

    assert response1.status_code == 202
    assert response2.status_code == 202

    host_assets = await db_session.execute(
        select(Asset).where(Asset.target_id == target.id, Asset.asset_type == 'host')
    )
    service_assets = await db_session.execute(
        select(Asset).where(Asset.target_id == target.id, Asset.asset_type == 'service')
    )

    host_values = [asset.value for asset in host_assets.scalars().all()]
    service_values = [asset.value for asset in service_assets.scalars().all()]

    assert len(host_values) == len(set(host_values))
    assert len(service_values) == len(set(service_values))
