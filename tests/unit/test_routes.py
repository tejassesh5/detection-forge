import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from detection_forge.api.app import create_app
from detection_forge.db import init_db


@pytest.fixture
async def client():
    app = create_app()
    # Initialise an in-memory DB and wire it into app state so the lifespan
    # dependency (get_db) works without needing the full ASGI lifespan to run.
    app.state.db = await init_db("sqlite+aiosqlite:///:memory:")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_ingest_text_returns_id(client):
    response = await client.post(
        "/api/cti/ingest/text",
        json={"text": "APT29 used 10.0.0.1 for C2", "title": "Test CTI"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["title"] == "Test CTI"


@pytest.mark.asyncio
async def test_list_rules_empty(client):
    response = await client.get("/api/rules/")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_get_rule_not_found(client):
    response = await client.get(f"/api/rules/{uuid.uuid4()}")
    assert response.status_code == 404
