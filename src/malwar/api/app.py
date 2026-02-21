# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from malwar.api.keys import router as keys_router
from malwar.api.middleware import RateLimitMiddleware, RequestMiddleware, UsageLoggingMiddleware
from malwar.api.routes import (
    analytics,
    audit,
    cache,
    campaigns,
    dashboard,
    diff,
    export,
    feed,
    health,
    ingest,
    notifications,
    plugins,
    reports,
    scan,
    schedules,
    signatures,
)
from malwar.audit.middleware import AuditMiddleware

_WEB_DIST = Path(__file__).resolve().parent.parent.parent.parent / "web" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    from malwar.core.config import get_settings
    from malwar.storage.database import close_db, get_db, init_db

    settings = get_settings()
    await init_db(settings.db_path, auto_migrate=settings.auto_migrate)

    # Start the scheduler unless explicitly disabled
    scheduler_engine = None
    if getattr(app.state, "enable_scheduler", True):
        from malwar.scheduler.engine import SchedulerEngine
        from malwar.scheduler.store import JobStore

        db = await get_db()
        store = JobStore(db)
        scheduler_engine = SchedulerEngine(store)
        await scheduler_engine.start()

    yield

    if scheduler_engine is not None:
        await scheduler_engine.stop()
    await close_db()


def create_app(*, enable_scheduler: bool = True) -> FastAPI:
    app = FastAPI(
        title="malwar",
        description="Malware detection engine for agentic skills",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.state.enable_scheduler = enable_scheduler

    # CORS for development (Vite dev server)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
    app.include_router(diff.router, prefix="/api/v1", tags=["diff"])
    app.include_router(campaigns.router, prefix="/api/v1", tags=["campaigns"])
    app.include_router(signatures.router, prefix="/api/v1", tags=["signatures"])
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
    app.include_router(feed.router, prefix="/api/v1", tags=["feed"])
    app.include_router(analytics.router, prefix="/api/v1", tags=["analytics"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["dashboard"])
    app.include_router(export.router, prefix="/api/v1", tags=["export"])
    app.include_router(ingest.router, prefix="/api/v1", tags=["ingest"])
    app.include_router(schedules.router, prefix="/api/v1", tags=["schedules"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(notifications.router, prefix="/api/v1", tags=["notifications"])
    app.include_router(plugins.router, prefix="/api/v1", tags=["plugins"])
    app.include_router(cache.router, prefix="/api/v1", tags=["cache"])
    app.include_router(keys_router, prefix="/api/v1", tags=["keys"])
    app.add_middleware(AuditMiddleware)
    app.add_middleware(UsageLoggingMiddleware)
    app.add_middleware(RequestMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # Serve frontend in production (when web/dist exists)
    if _WEB_DIST.is_dir():
        _index = str(_WEB_DIST / "index.html")

        # Mount static files for assets
        app.mount("/assets", StaticFiles(directory=str(_WEB_DIST / "assets")), name="assets")

        # Catch-all for SPA client-side routes
        @app.api_route("/{path:path}", methods=["GET"], include_in_schema=False)
        async def _spa_fallback(request: Request, path: str) -> FileResponse:
            # Serve actual static files if they exist (favicon, vite.svg, etc.)
            static_file = _WEB_DIST / path
            if path and static_file.is_file():
                return FileResponse(str(static_file))
            return FileResponse(_index)

    return app


def _create_app_from_env() -> FastAPI:
    """Factory wrapper that reads MALWAR_NO_SCHEDULER env var."""
    import os

    enable_scheduler = os.environ.get("MALWAR_NO_SCHEDULER", "") != "1"
    return create_app(enable_scheduler=enable_scheduler)
