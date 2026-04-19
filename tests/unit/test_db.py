import pytest
import uuid
from detection_forge.db import init_db, CTIRecord, Rule

@pytest.mark.asyncio
async def test_init_db_creates_tables():
    factory = await init_db("sqlite+aiosqlite:///:memory:")
    async with factory() as session:
        record = CTIRecord(
            id=str(uuid.uuid4()),
            title="Test CTI",
            source_type="text",
            raw_text="some threat intel",
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        assert record.title == "Test CTI"
