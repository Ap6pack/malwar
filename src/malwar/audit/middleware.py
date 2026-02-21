# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""FastAPI middleware that automatically logs API requests as audit events."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from malwar.audit.logger import get_audit_logger, hash_api_key

# Paths that should not generate audit events (noise reduction)
_SKIP_PATHS: set[str] = {"/api/v1/health", "/api/docs", "/api/redoc", "/api/openapi.json"}


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs every API request as an audit event.

    Captures the actor (from X-API-Key header or IP), the endpoint, method,
    status code, and duration.  Gracefully degrades if the audit store is
    unavailable.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 1)

        # Fire-and-forget: never let audit logging break the response
        try:
            api_key = request.headers.get("X-API-Key", "")
            actor = hash_api_key(api_key) if api_key else "anonymous"
            ip_address = request.client.host if request.client else ""

            audit_logger = get_audit_logger()
            await audit_logger.log_api_request(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                actor=actor,
                ip_address=ip_address,
                duration_ms=duration_ms,
            )
        except Exception:
            pass  # Graceful degradation

        return response
