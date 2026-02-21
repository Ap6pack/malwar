# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Role-based access control for API keys.

Defines roles, permissions, role-to-permission mappings, and a FastAPI
dependency that enforces permission checks on routes.
"""

from __future__ import annotations

import hashlib
import os
from enum import StrEnum

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from malwar.core.config import get_settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ---------------------------------------------------------------------------
# Role and Permission enumerations
# ---------------------------------------------------------------------------


class Role(StrEnum):
    """Roles assignable to API keys."""

    ADMIN = "admin"
    ANALYST = "analyst"
    SCANNER = "scanner"
    READONLY = "readonly"


class Permission(StrEnum):
    """Fine-grained permissions checked on API routes."""

    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SIGNATURE_MANAGE = "signature:manage"
    CAMPAIGN_MANAGE = "campaign:manage"
    AUDIT_READ = "audit:read"
    CONFIG_MANAGE = "config:manage"
    API_KEY_MANAGE = "api_key:manage"


# ---------------------------------------------------------------------------
# Role -> Permission mapping
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.ANALYST: frozenset({
        Permission.SCAN_CREATE,
        Permission.SCAN_READ,
        Permission.SIGNATURE_MANAGE,
        Permission.CAMPAIGN_MANAGE,
        Permission.AUDIT_READ,
    }),
    Role.SCANNER: frozenset({
        Permission.SCAN_CREATE,
        Permission.SCAN_READ,
    }),
    Role.READONLY: frozenset({
        Permission.SCAN_READ,
        Permission.AUDIT_READ,
    }),
}


def role_has_permission(role: Role, permission: Permission) -> bool:
    """Check whether *role* grants *permission*."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


# ---------------------------------------------------------------------------
# Authenticated identity returned by the dependency chain
# ---------------------------------------------------------------------------


class AuthenticatedKey:
    """Represents a validated API key with its associated role."""

    __slots__ = ("key_id", "name", "role")

    def __init__(self, key_id: str, name: str, role: Role) -> None:
        self.key_id = key_id
        self.name = name
        self.role = role

    def has_permission(self, permission: Permission) -> bool:
        return role_has_permission(self.role, permission)


# ---------------------------------------------------------------------------
# Hash helper (used when verifying incoming keys against stored hashes)
# ---------------------------------------------------------------------------


def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of *raw_key*."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_raw_key() -> str:
    """Generate a cryptographically random API key string."""
    return f"mlw_{os.urandom(24).hex()}"


# ---------------------------------------------------------------------------
# Core authentication logic (non-dependency, reusable)
# ---------------------------------------------------------------------------


async def authenticate_key_value(api_key: str | None) -> AuthenticatedKey:
    """Validate a raw API key string and return an :class:`AuthenticatedKey`.

    This is the core authentication logic, usable from any context
    (FastAPI dependencies, CLI, tests).

    Backward compatibility:
    * If no API keys are configured at all (neither env-var ``MALWAR_API_KEYS``
      nor any rows in the ``api_keys`` DB table), authentication is disabled
      and an anonymous admin identity is returned.
    * If the legacy ``MALWAR_API_KEYS`` env var is set and the provided key
      matches, it is treated as admin.
    * Otherwise the key is looked up in the ``api_keys`` table by hash.
    """
    settings = get_settings()

    # ------------------------------------------------------------------
    # 1. Attempt to check DB-managed keys first (may fail if DB not ready)
    # ------------------------------------------------------------------
    db_key_record = None
    db_has_keys = False
    try:
        from malwar.api.keys import get_key_manager

        km = await get_key_manager()
        db_has_keys = await km.has_any_keys()
        if api_key and db_has_keys:
            db_key_record = await km.verify_key(api_key)
    except Exception:
        # DB may not be initialised yet (e.g. during tests) -- fall through
        pass

    if db_key_record is not None:
        # Update last_used timestamp (fire-and-forget)
        try:
            from malwar.api.keys import get_key_manager

            km = await get_key_manager()
            await km.touch_last_used(db_key_record["id"])
        except Exception:
            pass
        return AuthenticatedKey(
            key_id=db_key_record["id"],
            name=db_key_record["name"],
            role=Role(db_key_record["role"]),
        )

    # ------------------------------------------------------------------
    # 2. Legacy env-var keys (backward compat)
    # ------------------------------------------------------------------
    if settings.api_keys:
        if not api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        if api_key in settings.api_keys:
            return AuthenticatedKey(
                key_id="env",
                name="env-configured-key",
                role=Role.ADMIN,
            )
        # Key provided but not in env list -- may still be a DB key that
        # we couldn't look up (DB not ready).  Deny access.
        if not db_has_keys:
            raise HTTPException(status_code=403, detail="Invalid API key")

    # ------------------------------------------------------------------
    # 3. No keys configured anywhere => open access (anonymous admin)
    # ------------------------------------------------------------------
    if not settings.api_keys and not db_has_keys:
        return AuthenticatedKey(
            key_id="anonymous",
            name="anonymous",
            role=Role.ADMIN,
        )

    # ------------------------------------------------------------------
    # 4. Keys exist but none matched
    # ------------------------------------------------------------------
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    raise HTTPException(status_code=403, detail="Invalid API key")


# ---------------------------------------------------------------------------
# FastAPI dependency (extracts key from header, delegates to core logic)
# ---------------------------------------------------------------------------


async def authenticate_key(
    api_key: str | None = Security(_api_key_header),
) -> AuthenticatedKey:
    """FastAPI dependency: extract ``X-API-Key`` header and authenticate."""
    return await authenticate_key_value(api_key)


# ---------------------------------------------------------------------------
# Permission-checking dependency factory
# ---------------------------------------------------------------------------


def require_permission(permission: Permission):
    """Return a FastAPI dependency that enforces *permission*.

    The returned dependency is meant to be stored as a module-level
    singleton and referenced (not called) inside ``Depends()``.
    """
    _auth_security = Security(authenticate_key)

    async def _check(
        auth: AuthenticatedKey = _auth_security,
    ) -> AuthenticatedKey:
        if not auth.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: requires {permission.value}",
            )
        return auth

    return _check


# ---------------------------------------------------------------------------
# Pre-built dependency singletons (avoids ruff B008 in route signatures)
# ---------------------------------------------------------------------------

require_scan_create = require_permission(Permission.SCAN_CREATE)
require_scan_read = require_permission(Permission.SCAN_READ)
require_signature_manage = require_permission(Permission.SIGNATURE_MANAGE)
require_campaign_manage = require_permission(Permission.CAMPAIGN_MANAGE)
require_audit_read = require_permission(Permission.AUDIT_READ)
require_config_manage = require_permission(Permission.CONFIG_MANAGE)
require_api_key_manage = require_permission(Permission.API_KEY_MANAGE)
