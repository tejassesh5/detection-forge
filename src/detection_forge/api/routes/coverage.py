from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def coverage_page(request: Request):
    return request.app.state.templates.TemplateResponse(
        "coverage.html", {"request": request}
    )


@router.get("/api")
async def coverage_api():
    return {"message": "Coverage endpoint — ATT&CK bundle loaded on demand"}
