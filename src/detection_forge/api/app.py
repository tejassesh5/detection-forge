from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select as sa_select2

from ..config import get_settings
from ..db import init_db

log = structlog.get_logger()

TEMPLATES = Jinja2Templates(
    directory=str(Path(__file__).parent.parent / "web" / "templates")
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    Path("data").mkdir(exist_ok=True)
    app.state.db = await init_db(settings.database_url)
    app.state.settings = settings
    app.state.templates = TEMPLATES

    from ..vector.store import VectorStore
    try:
        vs = VectorStore(host=settings.qdrant_host, port=settings.qdrant_port)
        await asyncio.wait_for(vs.ensure_collection(), timeout=5)
        app.state.vector_store = vs
        log.info("qdrant.connected")
    except Exception as e:
        log.warning("qdrant.unavailable", error=str(e))
        app.state.vector_store = None

    log.info("startup.complete")
    yield
    log.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(title="detection-forge", version="0.1.0", lifespan=lifespan)

    static_dir = Path(__file__).parent.parent / "web" / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from .routes import cti as cti_router
    from .routes import rules as rules_router

    app.include_router(cti_router.router, prefix="/api/cti", tags=["cti"])
    app.include_router(rules_router.router, prefix="/api/rules", tags=["rules"])

    from .routes import coverage as coverage_router
    app.include_router(coverage_router.router, prefix="/coverage", tags=["coverage"])

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    from sqlalchemy import select as sa_select
    from ..db import Rule as RuleDB, CTIRecord

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return app.state.templates.TemplateResponse(
            "index.html", {"request": request}
        )

    @app.get("/rules/{rule_id}", response_class=HTMLResponse)
    async def rule_detail(rule_id: str, request: Request):
        async with request.app.state.db() as session:
            result = await session.execute(sa_select(RuleDB).where(RuleDB.id == rule_id))
            rule = result.scalar_one_or_none()
        if not rule:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")
        return app.state.templates.TemplateResponse(
            "rule_editor.html", {"request": request, "rule": rule}
        )

    from ..db import Rule as RuleDB2, CTIRecord as CTIRecord2

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request):
        async with request.app.state.db() as session:
            rule_count = (
                await session.execute(sa_select2(func.count()).select_from(RuleDB2))
            ).scalar() or 0
            cti_count = (
                await session.execute(sa_select2(func.count()).select_from(CTIRecord2))
            ).scalar() or 0
        output = (
            "# HELP detection_forge_rules_total Total rules generated\n"
            "# TYPE detection_forge_rules_total gauge\n"
            f"detection_forge_rules_total {rule_count}\n"
            "# HELP detection_forge_cti_total Total CTI reports ingested\n"
            "# TYPE detection_forge_cti_total gauge\n"
            f"detection_forge_cti_total {cti_count}\n"
        )
        return PlainTextResponse(output, media_type="text/plain; version=0.0.4")

    return app


app = create_app()
