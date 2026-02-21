# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""API key management — generation, storage, verification, and revocation.

Keys are stored in the ``api_keys`` SQLite table.  The raw key value is
never stored; only its SHA-256 hash is persisted.  The raw key is returned
**exactly once** at creation time.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from malwar.api.rbac import (
    Role,
    generate_raw_key,
    hash_api_key,
    require_api_key_manage,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class APIKeyRecord(BaseModel):
    """Public representation of a stored API key (never exposes the raw key)."""

    id: str
    name: str
    role: str
    created_at: str
    last_used: str | None = None
    is_active: bool = True


class APIKeyCreateRequest(BaseModel):
    """Request body for creating a new API key."""

    name: str = Field(description="Human-readable label for the key")
    role: Role = Field(default=Role.SCANNER, description="Role to assign")


class APIKeyCreateResponse(BaseModel):
    """Response returned exactly once after key creation."""

    id: str
    name: str
    role: str
    raw_key: str = Field(description="The API key value. Store it securely — it cannot be retrieved again.")
    created_at: str


class APIKeyRoleUpdateRequest(BaseModel):
    """Request body for updating a key's role."""

    role: Role


class APIKeyListResponse(BaseModel):
    """Wrapper for the list of keys."""

    keys: list[APIKeyRecord]


# ---------------------------------------------------------------------------
# APIKeyManager — data-access layer
# ---------------------------------------------------------------------------


class APIKeyManager:
    """Manages API keys in the ``api_keys`` SQLite table."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    # -- queries -----------------------------------------------------------

    async def has_any_keys(self) -> bool:
        """Return True if at least one key exists in the table."""
        try:
            cursor = await self._db.execute("SELECT 1 FROM api_keys LIMIT 1")
            row = await cursor.fetchone()
            return row is not None
        except Exception:
            return False

    async def verify_key(self, raw_key: str) -> dict[str, Any] | None:
        """Look up *raw_key* by its hash; return the row dict or None."""
        key_hash = hash_api_key(raw_key)
        cursor = await self._db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def touch_last_used(self, key_id: str) -> None:
        """Update the ``last_used`` timestamp for a key."""
        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (now, key_id),
        )
        await self._db.commit()

    async def create_key(self, name: str, role: Role) -> tuple[dict[str, Any], str]:
        """Create a new API key.

        Returns ``(record_dict, raw_key)`` — the raw key is returned
        only this once.
        """
        raw_key = generate_raw_key()
        key_hash = hash_api_key(raw_key)
        key_id = f"key-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        await self._db.execute(
            """
            INSERT INTO api_keys (id, key_hash, name, role, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (key_id, key_hash, name, role.value, now),
        )
        await self._db.commit()

        record = {
            "id": key_id,
            "key_hash": key_hash,
            "name": name,
            "role": role.value,
            "created_at": now,
            "last_used": None,
            "is_active": True,
        }
        return record, raw_key

    async def list_keys(self) -> list[dict[str, Any]]:
        """Return all keys (active and revoked), without hashes."""
        cursor = await self._db.execute(
            "SELECT id, name, role, created_at, last_used, is_active FROM api_keys ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_key(self, key_id: str) -> dict[str, Any] | None:
        """Fetch a single key by ID."""
        cursor = await self._db.execute(
            "SELECT id, name, role, created_at, last_used, is_active FROM api_keys WHERE id = ?",
            (key_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def revoke_key(self, key_id: str) -> bool:
        """Revoke (deactivate) a key.  Returns True if the key existed."""
        cursor = await self._db.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (key_id,),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def update_role(self, key_id: str, role: Role) -> bool:
        """Change the role of an existing key.  Returns True on success."""
        cursor = await self._db.execute(
            "UPDATE api_keys SET role = ? WHERE id = ?",
            (role.value, key_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Helper to get the manager bound to the current DB connection
# ---------------------------------------------------------------------------


async def get_key_manager() -> APIKeyManager:
    """Return an :class:`APIKeyManager` bound to the active DB connection."""
    from malwar.storage.database import get_db

    db = await get_db()
    return APIKeyManager(db)


# ---------------------------------------------------------------------------
# API endpoints (admin-only)
# ---------------------------------------------------------------------------


@router.post("/keys", response_model=APIKeyCreateResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreateRequest,
    _auth: object = Depends(require_api_key_manage),
) -> APIKeyCreateResponse:
    """Create a new API key.  The raw key is returned **only once**."""
    km = await get_key_manager()
    record, raw_key = await km.create_key(body.name, body.role)
    return APIKeyCreateResponse(
        id=record["id"],
        name=record["name"],
        role=record["role"],
        raw_key=raw_key,
        created_at=record["created_at"],
    )


@router.get("/keys", response_model=APIKeyListResponse)
async def list_api_keys(
    _auth: object = Depends(require_api_key_manage),
) -> APIKeyListResponse:
    """List all API keys (without revealing raw key values)."""
    km = await get_key_manager()
    rows = await km.list_keys()
    keys = [
        APIKeyRecord(
            id=r["id"],
            name=r["name"],
            role=r["role"],
            created_at=r["created_at"],
            last_used=r.get("last_used"),
            is_active=bool(r.get("is_active", 1)),
        )
        for r in rows
    ]
    return APIKeyListResponse(keys=keys)


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    _auth: object = Depends(require_api_key_manage),
) -> None:
    """Revoke an API key."""
    km = await get_key_manager()
    revoked = await km.revoke_key(key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")


@router.put("/keys/{key_id}/role", response_model=APIKeyRecord)
async def update_api_key_role(
    key_id: str,
    body: APIKeyRoleUpdateRequest,
    _auth: object = Depends(require_api_key_manage),
) -> APIKeyRecord:
    """Change the role assigned to an API key."""
    km = await get_key_manager()
    updated = await km.update_role(key_id, body.role)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    record = await km.get_key(key_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    return APIKeyRecord(
        id=record["id"],
        name=record["name"],
        role=record["role"],
        created_at=record["created_at"],
        last_used=record.get("last_used"),
        is_active=bool(record.get("is_active", 1)),
    )
