from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.deps import get_db
from ...db import Rule as RuleDB

router = APIRouter()


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
