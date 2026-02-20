# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""API key authentication dependency."""

from __future__ import annotations

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from malwar.core.config import get_settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str:
    """Validate the X-API-Key header.

    If no API keys are configured in settings, authentication is disabled
    (open access). Otherwise the provided key must match one of the
    configured keys.
    """
    settings = get_settings()

    # No keys configured = auth disabled
    if not settings.api_keys:
        return "anonymous"

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    if api_key not in settings.api_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")

    return api_key
