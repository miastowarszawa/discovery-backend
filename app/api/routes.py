import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.nmap_import import NmapImportRequest, NmapImportResponse
from app.schemas.recon import ReconJobCreate, ReconJobResponse
from app.services.nmap_importer import import_nmap_xml
from app.services.recon_jobs import create_recon_job, get_scan_events

router = APIRouter()


@router.get('/ping', tags=['meta'])
async def ping():
    return {'message': 'pong'}


@router.post('/scans/recon', response_model=ReconJobResponse, status_code=status.HTTP_202_ACCEPTED, tags=['recon'])
async def start_recon(payload: ReconJobCreate, db: AsyncSession = Depends(get_db)):
    scan = await create_recon_job(db=db, payload=payload)
    return ReconJobResponse.model_validate(scan)


@router.post('/imports/nmap-xml', response_model=NmapImportResponse, status_code=status.HTTP_202_ACCEPTED, tags=['imports'])
async def import_nmap_xml_route(payload: NmapImportRequest, db: AsyncSession = Depends(get_db)):
    target_result = await db.execute(select(Target).where(Target.id == payload.target_id))
    target = target_result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail='Target not found')

    scan = await import_nmap_xml(
        db=db,
        target=target,
        payload=payload,
    )

    return NmapImportResponse(
        scan_id=scan.id,
        scan_type=scan.scan_type,
        status=scan.status,
        strict=bool((scan.config_json or {}).get('strict', True)),
        summary=(scan.result_json or {}).get('summary', {}),
    )


@router.post('/imports/nmap-xml-file', response_model=NmapImportResponse, status_code=status.HTTP_202_ACCEPTED, tags=['imports'])
async def import_nmap_xml_file_route(
    target_id: uuid.UUID = Form(...),
    strict: bool = Form(True),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    target_result = await db.execute(select(Target).where(Target.id == target_id))
    target = target_result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail='Target not found')

    if not file.filename or not file.filename.lower().endswith('.xml'):
        raise HTTPException(status_code=400, detail='Only .xml files are supported')

    raw = await file.read()

    try:
        xml_text = raw.decode('utf-8')
    except UnicodeDecodeError:
        try:
            xml_text = raw.decode('utf-8-sig')
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail='Unable to decode XML file as UTF-8') from exc

    payload = NmapImportRequest(
        target_id=target_id,
        xml_text=xml_text,
        strict=strict,
    )

    scan = await import_nmap_xml(
        db=db,
        target=target,
        payload=payload,
        source_file=file.filename,
    )

    return NmapImportResponse(
        scan_id=scan.id,
        scan_type=scan.scan_type,
        status=scan.status,
        strict=bool((scan.config_json or {}).get('strict', True)),
        summary=(scan.result_json or {}).get('summary', {}),
    )


@router.get('/scans/{scan_id}', response_model=ReconJobResponse, tags=['recon'])
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')

    return ReconJobResponse.model_validate(scan)


@router.get('/scans/{scan_id}/events', tags=['recon'])
async def scan_events(scan_id: str, db: AsyncSession = Depends(get_db)):
    return {'items': await get_scan_events(db=db, scan_id=scan_id)}