from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.nmap_import import HostScopeDecision, NmapImportRequest
from app.services.asset_dedupe import get_or_create_asset
from app.services.nmap_xml_parser import parse_nmap_xml
from app.services.scope_guard import evaluate_host_scope


def _pick_primary_host(hostnames: list[str], addresses: list[str]) -> str:
    if hostnames:
        return hostnames[0]
    if addresses:
        return addresses[0]
    return 'unknown'


def _service_to_asset_value(host: str, port: int, protocol: str) -> str:
    return f'{host}:{port}/{protocol}'


async def import_nmap_xml(
    *,
    db: AsyncSession,
    target: Target,
    payload: NmapImportRequest,
    source_file: str | None = None,
) -> Scan:
    parsed = parse_nmap_xml(payload.xml_text)

    scan = Scan(
        target_id=target.id,
        scan_type='nmap_xml_import',
        status='running',
        config_json={
            'strict': payload.strict,
            'import_type': 'nmap_xml',
        },
        result_json={},
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    db.add(
        Event(
            scan_id=scan.id,
            event_type='nmap.import.started',
            severity='info',
            payload_json={
                'strict': payload.strict,
                'scanner': parsed.scanner,
                'args': parsed.args,
                'source_file': source_file,
                'summary': parsed.summary.model_dump(),
            },
        )
    )
    await db.flush()

    imported_hosts = 0
    imported_services = 0
    imported_scripts = 0
    rejected_hosts = 0
    deduped_hosts = 0
    deduped_services = 0

    for host in parsed.hosts:
        decision: HostScopeDecision = evaluate_host_scope(
            target=target,
            addresses=host.addresses,
            hostnames=host.hostnames,
        )

        if not decision.in_scope:
            rejected_hosts += 1

            db.add(
                Event(
                    scan_id=scan.id,
                    event_type='nmap.import.rejected_host',
                    severity='medium',
                    payload_json={
                        'addresses': host.addresses,
                        'hostnames': host.hostnames,
                        'reasons': decision.rejected_reasons,
                    },
                )
            )

            if payload.strict:
                scan.status = 'failed'
                scan.finished_at = datetime.now(timezone.utc)
                scan.result_json = {
                    'import_type': 'nmap_xml',
                    'strict': payload.strict,
                    'scanner': parsed.scanner,
                    'args': parsed.args,
                    'started': parsed.started,
                    'source_file': source_file,
                    'summary': {
                        **parsed.summary.model_dump(),
                        'imported_hosts': imported_hosts,
                        'imported_services': imported_services,
                        'imported_scripts': imported_scripts,
                        'rejected_out_of_scope': rejected_hosts,
                        'deduped_hosts': deduped_hosts,
                        'deduped_services': deduped_services,
                    },
                    'error': 'host_out_of_scope',
                }

                db.add(
                    Event(
                        scan_id=scan.id,
                        event_type='nmap.import.failed',
                        severity='high',
                        payload_json={
                            'reason': 'host_out_of_scope',
                            'addresses': host.addresses,
                            'hostnames': host.hostnames,
                        },
                    )
                )

                await db.commit()
                await db.refresh(scan)
                return scan

            continue

        primary_host = _pick_primary_host(host.hostnames, host.addresses)

        host_asset_created = False

        for hostname in host.hostnames:
            _, created = await get_or_create_asset(
                db=db,
                target_id=target.id,
                asset_type='host',
                value=hostname,
                source='nmap_xml_import',
                attributes_json={
                    'matched_by': decision.matched_by,
                    'status': host.status,
                    'addresses': host.addresses,
                },
            )
            if created:
                host_asset_created = True
            else:
                deduped_hosts += 1

        for address in host.addresses:
            _, created = await get_or_create_asset(
                db=db,
                target_id=target.id,
                asset_type='host',
                value=address,
                source='nmap_xml_import',
                attributes_json={
                    'matched_by': decision.matched_by,
                    'status': host.status,
                    'hostnames': host.hostnames,
                },
            )
            if created:
                host_asset_created = True
            else:
                deduped_hosts += 1

        if host_asset_created:
            imported_hosts += 1

        db.add(
            Event(
                scan_id=scan.id,
                event_type='nmap.import.host',
                severity='info',
                payload_json={
                    'host': primary_host,
                    'status': host.status,
                    'matched_by': decision.matched_by,
                    'addresses': host.addresses,
                    'hostnames': host.hostnames,
                },
            )
        )

        for script in host.scripts:
            imported_scripts += 1
            db.add(
                Event(
                    scan_id=scan.id,
                    event_type='nmap.import.host_script',
                    severity='info',
                    payload_json={
                        'host': primary_host,
                        'script_id': script.script_id,
                        'output': script.output,
                    },
                )
            )

        for port in host.ports:
            _, created = await get_or_create_asset(
                db=db,
                target_id=target.id,
                asset_type='service',
                value=_service_to_asset_value(primary_host, port.port, port.protocol),
                source='nmap_xml_import',
                attributes_json={
                    'host': primary_host,
                    'port': port.port,
                    'protocol': port.protocol,
                    'state': port.state,
                    'reason': port.reason,
                    'service': port.service.model_dump() if port.service else None,
                },
            )

            if created:
                imported_services += 1
            else:
                deduped_services += 1

            db.add(
                Event(
                    scan_id=scan.id,
                    event_type='nmap.import.service',
                    severity='info',
                    payload_json={
                        'host': primary_host,
                        'port': port.port,
                        'protocol': port.protocol,
                        'state': port.state,
                        'service': port.service.model_dump() if port.service else None,
                    },
                )
            )

            for script in port.scripts:
                imported_scripts += 1
                db.add(
                    Event(
                        scan_id=scan.id,
                        event_type='nmap.import.port_script',
                        severity='info',
                        payload_json={
                            'host': primary_host,
                            'port': port.port,
                            'protocol': port.protocol,
                            'script_id': script.script_id,
                            'output': script.output,
                        },
                    )
                )

    scan.status = 'finished'
    scan.finished_at = datetime.now(timezone.utc)
    scan.result_json = {
        'import_type': 'nmap_xml',
        'strict': payload.strict,
        'scanner': parsed.scanner,
        'args': parsed.args,
        'started': parsed.started,
        'source_file': source_file,
        'summary': {
            **parsed.summary.model_dump(),
            'imported_hosts': imported_hosts,
            'imported_services': imported_services,
            'imported_scripts': imported_scripts,
            'rejected_out_of_scope': rejected_hosts,
            'deduped_hosts': deduped_hosts,
            'deduped_services': deduped_services,
        },
    }

    db.add(
        Event(
            scan_id=scan.id,
            event_type='nmap.import.finished',
            severity='info',
            payload_json=scan.result_json['summary'],
        )
    )

    await db.commit()
    await db.refresh(scan)
    return scan