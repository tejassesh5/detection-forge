from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.deps import get_db
from ...config import build_gateway
from ...cti.models import CTIItem, SourceType
from ...db import CTIRecord
from ...db import Rule as RuleDB
from ...forge.pipeline import ForgePipeline

router = APIRouter()


class ForgeRequest(BaseModel):
    cti_id: str


@router.post("/forge")
async def forge_rule(body: ForgeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CTIRecord).where(CTIRecord.id == body.cti_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="CTI not found")

    cti = CTIItem(
        id=record.id,
        title=record.title,
        text=record.raw_text,
        source_type=SourceType(record.source_type),
        raw_iocs=[],
    )

    gateway = build_gateway()
    pipeline = ForgePipeline(gateway)
    draft = await pipeline.forge(cti)

    rule = RuleDB(
        id=str(uuid.uuid4()),
        title=draft.title,
        rule_type=draft.rule_type.value,
        content=draft.content,
        confidence=draft.confidence,
        attack_techniques=draft.attack_techniques,
        source_cti_id=record.id,
    )
    db.add(rule)
    await db.commit()

    return {
        "id": rule.id,
        "title": rule.title,
        "rule_type": rule.rule_type,
        "content": rule.content,
        "confidence": rule.confidence,
        "attack_techniques": rule.attack_techniques,
        "valid": draft.is_valid,
        "validation_errors": [e.message for e in draft.validation_errors],
    }


@router.get("/", response_model=list[dict])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).order_by(RuleDB.created_at.desc()))
    rules = result.scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "rule_type": r.rule_type,
            "confidence": r.confidence,
            "attack_techniques": r.attack_techniques,
            "created_at": r.created_at.isoformat(),
        }
        for r in rules
    ]


@router.get("/partials/list", response_class=HTMLResponse)
async def rules_list_partial(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).order_by(RuleDB.created_at.desc()).limit(50))
    rules = result.scalars().all()
    tmpl = request.app.state.templates
    return tmpl.TemplateResponse(
        "partials/rule_card.html", {"request": request, "rules": rules}
    )


@router.get("/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).where(RuleDB.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "id": rule.id,
        "title": rule.title,
        "rule_type": rule.rule_type,
        "content": rule.content,
        "confidence": rule.confidence,
        "attack_techniques": rule.attack_techniques,
        "created_at": rule.created_at.isoformat(),
    }


@router.get("/{rule_id}/export")
async def export_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).where(RuleDB.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404)
    ext = "yml" if rule.rule_type == "sigma" else "yar"
    return PlainTextResponse(
        content=rule.content,
        headers={"Content-Disposition": f'attachment; filename="{rule.id}.{ext}"'},
    )
