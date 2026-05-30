from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event
from app.models.scan import Scan
from app.schemas.jobs import ReconJobPayload
from app.services.recon_tools import run_httpx, run_naabu, run_subfinder


async def mark_scan_status(db: AsyncSession, scan: Scan, status: str, result_json: dict | None = None) -> None:
    scan.status = status
    if result_json is not None:
        scan.result_json = result_json
    db.add(scan)
    await db.flush()


async def create_event(db: AsyncSession, scan_id, event_type: str, payload: dict, severity: str = 'info') -> None:
    db.add(Event(scan_id=scan_id, event_type=event_type, payload_json=payload, severity=severity))
    await db.flush()


async def create_asset(db: AsyncSession, target_id, asset_type: str, value: str, source: str, attributes: dict) -> None:
    db.add(Asset(target_id=target_id, asset_type=asset_type, value=value, source=source, attributes_json=attributes))
    await db.flush()


async def process_recon_job(db: AsyncSession, payload: ReconJobPayload) -> dict:
    scan = await db.get(Scan, payload.scan_id)
    if scan is None:
        raise ValueError(f'Scan not found: {payload.scan_id}')

    try:
        await mark_scan_status(db, scan, 'running')
        await create_event(db, payload.scan_id, 'recon.started', payload.model_dump(mode='json'))

        subfinder_rows = await run_subfinder(payload.domain)
        hosts = sorted({row.get('host') or row.get('input') for row in subfinder_rows if row.get('host') or row.get('input')})

        for host in hosts:
            await create_asset(db, payload.target_id, 'subdomain', host, 'subfinder', {'provider': 'subfinder'})

        httpx_rows = await run_httpx(hosts)
        for row in httpx_rows:
            url = row.get('url') or row.get('input')
            if url:
                await create_asset(db, payload.target_id, 'url', url, 'httpx', row)

        naabu_rows = await run_naabu(hosts)
        for row in naabu_rows:
            host = row.get('host') or row.get('ip') or row.get('input')
            port = row.get('port')
            if host and port:
                await create_asset(db, payload.target_id, 'port', f'{host}:{port}', 'naabu', row)

        result = {
            'subfinder_count': len(subfinder_rows),
            'httpx_count': len(httpx_rows),
            'naabu_count': len(naabu_rows),
            'hosts': hosts,
        }
        await mark_scan_status(db, scan, 'completed', result_json=result)
        await create_event(db, payload.scan_id, 'recon.completed', result)
        await db.commit()
        return result
    except Exception as exc:
        failure_payload = {'error': str(exc), 'scan_id': str(payload.scan_id), 'target_id': str(payload.target_id)}
        await mark_scan_status(db, scan, 'failed', result_json=failure_payload)
        await create_event(db, payload.scan_id, 'recon.failed', failure_payload, severity='error')
        await db.commit()
        raise
