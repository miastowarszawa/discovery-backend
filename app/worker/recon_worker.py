import asyncio
import logging

from app.db.session import AsyncSessionLocal, redis_client
from app.services.recon_pipeline import process_recon_job
from app.services.recon_queue import dequeue_recon_job

logger = logging.getLogger(__name__)


async def run_worker_loop(poll_timeout: int = 5):
    while True:
        payload = await dequeue_recon_job(redis_client, timeout=poll_timeout)
        if payload is None:
            continue
        try:
            async with AsyncSessionLocal() as session:
                await process_recon_job(session, payload)
        except Exception:
            logger.exception('recon worker job failed', extra={'scan_id': str(payload.scan_id)})


if __name__ == '__main__':
    asyncio.run(run_worker_loop())
