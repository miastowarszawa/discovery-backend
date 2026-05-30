import json

from redis.asyncio import Redis

from app.schemas.jobs import ReconJobPayload

QUEUE_NAME = 'recon:jobs'


async def enqueue_recon_job(redis: Redis, payload: ReconJobPayload) -> int:
    return await redis.lpush(QUEUE_NAME, payload.model_dump_json())


async def dequeue_recon_job(redis: Redis, timeout: int = 5) -> ReconJobPayload | None:
    result = await redis.brpop(QUEUE_NAME, timeout=timeout)
    if not result:
        return None
    _, raw = result
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8')
    return ReconJobPayload.model_validate_json(raw)
