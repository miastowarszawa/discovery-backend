import asyncio
import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.session import get_db, get_redis
from app.main import app
from app.models.asset import Asset  # noqa: F401
from app.models.event import Event  # noqa: F401
from app.models.scan import Scan  # noqa: F401
from app.models.target import Target  # noqa: F401


class FakeRedis:
    def __init__(self):
        self.items = []

    async def lpush(self, key, value):
        self.items.insert(0, (key, value))
        return len(self.items)

    async def brpop(self, key, timeout=5):
        for idx, (stored_key, value) in enumerate(self.items):
            if stored_key == key:
                self.items.pop(idx)
                return key, value
        return None


TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "sqlite+aiosqlite:///./test_recon_pp.db",
)

engine = create_async_engine(TEST_DATABASE_URL, future=True)
TestingSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
fake_redis = FakeRedis()


async def override_get_db() -> AsyncIterator[AsyncSession]:
    async with TestingSessionLocal() as session:
        yield session


async def override_get_redis():
    return fake_redis


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True)
async def truncate_tables():
    async with engine.begin() as conn:
        for table in [Asset.__table__, Event.__table__, Scan.__table__, Target.__table__]:
            await conn.execute(text(f"DELETE FROM {table.name}"))
    fake_redis.items.clear()
    yield


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    async with TestingSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def target(db_session: AsyncSession) -> Target:
    random_domain = f"example-{uuid.uuid4().hex}.com"
    target = Target(
        id=uuid.uuid4(),
        name="Example Target",
        domain=random_domain,
        metadata_json={"scope": {"allowed_ips": ["192.168.1.10"]}},
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    return target