# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from malwar.api.routes import health, scan


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
    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
    return app
