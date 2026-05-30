import os
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+psycopg://postgres:postgres@postgres:5432/reconpp')
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')

engine = create_async_engine(DATABASE_URL, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

try:
    from redis.asyncio import Redis
    redis_client: Any = Redis.from_url(REDIS_URL, decode_responses=False)
    REDIS_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
    Redis = Any  # type: ignore
    redis_client = None
    REDIS_IMPORT_ERROR = exc


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def get_redis():
    if redis_client is None:
        raise RuntimeError(
            "Redis client is unavailable. Install dependency with: python -m pip install redis"
        ) from REDIS_IMPORT_ERROR
    return redis_client
