from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.deps import get_db
from ...cti.parsers.text import parse_text
from ...db import CTIRecord

router = APIRouter()


class IngestRequest(BaseModel):
    text: str
    title: str | None = None


@router.post("/ingest/text")
async def ingest_text(body: IngestRequest, request: Request, db: AsyncSession = Depends(get_db)):
    item = parse_text(body.text, title=body.title)

    similar: list[dict] = []
    if hasattr(request.app.state, "vector_store"):
        similar = await request.app.state.vector_store.search(item.text, limit=3)

    record = CTIRecord(
        id=item.id,
        title=item.title,
        source_type=item.source_type.value,
        raw_text=item.text,
    )
    db.add(record)
    await db.commit()

    if hasattr(request.app.state, "vector_store"):
        await request.app.state.vector_store.upsert(
            doc_id=item.id,
            text=item.text,
            payload={"title": item.title, "type": "cti"},
        )

    return {
        "id": item.id,
        "title": item.title,
        "ioc_count": len(item.raw_iocs),
        "similar_cti": similar[:3],
    }
