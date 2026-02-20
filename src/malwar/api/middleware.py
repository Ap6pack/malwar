# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Request middleware for logging, request ID tracking, and rate limiting."""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from malwar.core.config import get_settings

logger = logging.getLogger("malwar.api.middleware")

# ---------------------------------------------------------------------------
# Rate-limit state (in-memory, per-process)
# ---------------------------------------------------------------------------
_request_log: dict[str, list[float]] = defaultdict(list)
_CLEANUP_INTERVAL = 60.0  # seconds between full sweeps
_last_cleanup: float = 0.0

_RATE_LIMIT_SKIP_PATHS: set[str] = {"/api/v1/health"}


def _cleanup_old_entries(now: float, window: float) -> None:
    """Remove timestamps older than *window* seconds for every tracked IP."""
    global _last_cleanup
    expired_ips: list[str] = []
    for ip, timestamps in _request_log.items():
        _request_log[ip] = [t for t in timestamps if now - t < window]
        if not _request_log[ip]:
            expired_ips.append(ip)
    for ip in expired_ips:
        del _request_log[ip]
    _last_cleanup = now


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory per-IP rate limiter.

    * Default: 60 requests / minute (configurable via ``MALWAR_RATE_LIMIT_RPM``).
    * Returns **429 Too Many Requests** with a ``Retry-After`` header.
    * Skips the ``/api/v1/health`` endpoint.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in _RATE_LIMIT_SKIP_PATHS:
            return await call_next(request)

        settings = get_settings()
        rpm = settings.rate_limit_rpm
        window = 60.0  # seconds

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()

        # Periodic cleanup to avoid memory leaks
        global _last_cleanup
        if now - _last_cleanup > _CLEANUP_INTERVAL:
            _cleanup_old_entries(now, window)

        # Prune this IP's old timestamps
        timestamps = _request_log[client_ip]
        _request_log[client_ip] = [t for t in timestamps if now - t < window]
        timestamps = _request_log[client_ip]

        if len(timestamps) >= rpm:
            oldest = min(timestamps)
            retry_after = int(window - (now - oldest)) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)
        return await call_next(request)


class RequestMiddleware(BaseHTTPMiddleware):
    """Adds request logging and X-Request-ID header to every response."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = uuid.uuid4().hex
        start = time.monotonic()

        response = await call_next(request)

        duration_ms = round((time.monotonic() - start) * 1000, 1)
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "%s %s %s %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )

        return response
