# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from malwar.api.middleware import RateLimitMiddleware, RequestMiddleware
from malwar.api.routes import campaigns, health, reports, scan, signatures

_WEB_DIST = Path(__file__).resolve().parent.parent.parent.parent / "web" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, init_db

    settings = get_settings()
    await init_db(settings.db_path)
    yield
    await close_db()


def create_app() -> FastAPI:
    app = FastAPI(
        title="malwar",
        description="Malware detection engine for agentic skills",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS for development (Vite dev server)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
    app.include_router(campaigns.router, prefix="/api/v1", tags=["campaigns"])
    app.include_router(signatures.router, prefix="/api/v1", tags=["signatures"])
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
    app.add_middleware(RequestMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # Serve frontend in production (when web/dist exists)
    if _WEB_DIST.is_dir():
        app.mount("/", StaticFiles(directory=str(_WEB_DIST), html=True), name="web")

    return app
