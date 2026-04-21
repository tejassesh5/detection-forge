import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from detection_forge.api.app import create_app
from detection_forge.db import init_db, Rule as RuleDB


@pytest.fixture
async def db_factory():
    return await init_db("sqlite+aiosqlite:///:memory:")


@pytest.fixture
async def client(db_factory):
    app = create_app()
    app.state.db = db_factory
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _seed_rule(db_factory) -> str:
    async with db_factory() as session:
        rule = RuleDB(
            id=str(uuid.uuid4()),
            title="Test Rule",
            rule_type="sigma",
            content="title: Test\ndetection:\n  condition: selection",
            confidence=0.8,
            attack_techniques=["T1021"],
        )
        session.add(rule)
        await session.commit()
        return rule.id


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


@pytest.mark.asyncio
async def test_post_score_creates_test_run(client, db_factory):
    rule_id = await _seed_rule(db_factory)
    r = await client.post(f"/api/rules/{rule_id}/score", json={
        "matched": True,
        "event_count": 42,
        "duration_ms": 1500,
        "technique_id": "T1021",
        "atomic_name": "SMB Admin Shares",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["rule_id"] == rule_id
    assert data["score"] == 1.0
    assert data["matched"] is True
    assert data["tp_count"] == 1
    assert "id" in data


@pytest.mark.asyncio
async def test_post_score_unmatched_gives_zero(client, db_factory):
    rule_id = await _seed_rule(db_factory)
    r = await client.post(f"/api/rules/{rule_id}/score", json={
        "matched": False,
        "event_count": 0,
        "duration_ms": 30000,
        "technique_id": "T1021",
        "atomic_name": "SMB Admin Shares",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["score"] == 0.0
    assert data["tp_count"] == 0


@pytest.mark.asyncio
async def test_post_score_rule_not_found(client):
    r = await client.post(f"/api/rules/{uuid.uuid4()}/score", json={
        "matched": True, "event_count": 1, "duration_ms": 100,
    })
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_scores_returns_history(client, db_factory):
    rule_id = await _seed_rule(db_factory)
    await client.post(f"/api/rules/{rule_id}/score", json={
        "matched": True, "event_count": 5, "duration_ms": 800,
    })
    await client.post(f"/api/rules/{rule_id}/score", json={
        "matched": False, "event_count": 0, "duration_ms": 500,
    })
    r = await client.get(f"/api/rules/{rule_id}/score")
    assert r.status_code == 200
    runs = r.json()
    assert len(runs) == 2
    scores = {run["score"] for run in runs}
    assert scores == {0.0, 1.0}


@pytest.mark.asyncio
async def test_get_scores_rule_not_found(client):
    r = await client.get(f"/api/rules/{uuid.uuid4()}/score")
    assert r.status_code == 404
