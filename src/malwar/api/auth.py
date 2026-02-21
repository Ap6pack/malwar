# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""API key authentication dependency.

This module preserves the original ``require_api_key`` interface for
backward compatibility.  Internally it delegates to the RBAC-aware
authentication logic so that existing routes continue to work without
changes while new routes can use the finer-grained permission
dependencies from :mod:`malwar.api.rbac`.
"""

from __future__ import annotations

from fastapi import Security
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str:
    """Validate the ``X-API-Key`` header (backward-compatible wrapper).

    Delegates to the RBAC authentication logic internally, then
    returns the key ID as a string so that existing route signatures
    (``_api_key: str = Depends(require_api_key)``) keep working.
    """
    from malwar.api.rbac import authenticate_key_value

    auth = await authenticate_key_value(api_key)
    return auth.key_id
