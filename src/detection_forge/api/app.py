from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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

    from fastapi import Request
    from fastapi.responses import HTMLResponse

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    return app


app = create_app()
