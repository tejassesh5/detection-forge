import pytest
from httpx import AsyncClient, ASGITransport
from detection_forge.api.app import create_app
from detection_forge.db import init_db


@pytest.fixture
async def client_with_db():
    app = create_app()
    db = await init_db("sqlite+aiosqlite:///:memory:")
    app.state.db = db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_metrics_endpoint(client_with_db):
    response = await client_with_db.get("/metrics")
    assert response.status_code == 200
    assert "detection_forge_rules_total" in response.text
    assert "detection_forge_cti_total" in response.text
