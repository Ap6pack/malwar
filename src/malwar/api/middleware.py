# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Request middleware for logging, request ID tracking, rate limiting, and usage metering."""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime

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
    """Remove timestamps older than *window* seconds for every tracked key."""
    global _last_cleanup
    expired_keys: list[str] = []
    for key, timestamps in _request_log.items():
        _request_log[key] = [t for t in timestamps if now - t < window]
        if not _request_log[key]:
            expired_keys.append(key)
    for key in expired_keys:
        del _request_log[key]
    _last_cleanup = now


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limiter with per-API-key and per-IP support.

    * Authenticated requests (with ``X-API-Key`` header): limited to
      ``rate_limit_per_key`` requests per minute (default 600).
    * Unauthenticated requests: limited to ``rate_limit_per_ip`` requests
      per minute (default 60), keyed by client IP.
    * Returns **429 Too Many Requests** with a ``Retry-After`` header.
    * Adds ``X-RateLimit-Limit``, ``X-RateLimit-Remaining``, and
      ``X-RateLimit-Reset`` headers on all responses.
    * Skips the ``/api/v1/health`` endpoint.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in _RATE_LIMIT_SKIP_PATHS:
            return await call_next(request)

        settings = get_settings()
        window = 60.0  # seconds

        # Determine identity and limit: API key takes precedence over IP
        api_key = request.headers.get("X-API-Key")
        if api_key:
            identity = f"key:{api_key}"
            limit = settings.rate_limit_per_key
        else:
            client_ip = request.client.host if request.client else "unknown"
            identity = f"ip:{client_ip}"
            limit = settings.rate_limit_per_ip

        now = time.monotonic()

        # Periodic cleanup to avoid memory leaks
        global _last_cleanup
        if now - _last_cleanup > _CLEANUP_INTERVAL:
            _cleanup_old_entries(now, window)

        # Prune this identity's old timestamps
        timestamps = _request_log[identity]
        _request_log[identity] = [t for t in timestamps if now - t < window]
        timestamps = _request_log[identity]

        remaining = max(0, limit - len(timestamps))
        # Compute seconds until the oldest request in the window expires
        if timestamps:
            oldest = min(timestamps)
            reset_seconds = int(window - (now - oldest)) + 1
        else:
            reset_seconds = int(window)

        if len(timestamps) >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(reset_seconds),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_seconds),
                },
            )

        timestamps.append(now)
        remaining = max(0, limit - len(timestamps))

        response = await call_next(request)

        # Add rate-limit headers to every successful response
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_seconds)

        return response


class UsageLoggingMiddleware(BaseHTTPMiddleware):
    """Logs API usage to the ``api_usage`` table after each request.

    Gracefully degrades: if the table does not exist (migration not yet
    applied), the error is silently swallowed so the request still succeeds.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        # Fire-and-forget usage logging; never block the response
        try:
            api_key = request.headers.get("X-API-Key", "")
            endpoint = request.url.path
            method = request.method
            status_code = response.status_code
            timestamp = datetime.now(UTC).isoformat()

            from malwar.storage.database import get_db

            db = await get_db()
            await db.execute(
                """
                INSERT INTO api_usage (api_key, endpoint, method, status_code, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (api_key, endpoint, method, status_code, timestamp),
            )
            await db.commit()
        except Exception:
            # Graceful degradation: table may not exist yet, DB may not be
            # initialized, etc.  Never let usage logging break the request.
            pass

        return response


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
