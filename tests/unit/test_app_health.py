import pytest
from httpx import AsyncClient, ASGITransport
from detection_forge.api.app import create_app

@pytest.mark.asyncio
async def test_health_check():
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
