# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Plugin management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class PluginResponse(BaseModel):
    name: str
    version: str
    author: str
    description: str
    layer_name: str
    enabled: bool


class PluginActionResponse(BaseModel):
    name: str
    enabled: bool
    message: str


def _get_manager():
    """Lazy import to avoid circular dependencies."""
    from malwar.plugins.manager import PluginManager

    # Use a module-level singleton; the app lifespan will populate it.
    if not hasattr(_get_manager, "_instance"):
        _get_manager._instance = PluginManager()
    return _get_manager._instance


def set_manager(manager) -> None:
    """Allow the app lifespan (or tests) to inject the manager instance."""
    _get_manager._instance = manager  # type: ignore[attr-defined]


@router.get("/plugins", response_model=list[PluginResponse])
async def list_plugins() -> list[PluginResponse]:
    """List all installed plugins with metadata and status."""
    mgr = _get_manager()
    return [
        PluginResponse(
            name=p.name,
            version=p.version,
            author=p.author,
            description=p.description,
            layer_name=p.layer_name,
            enabled=p.enabled,
        )
        for p in mgr.list_plugins()
    ]


@router.post("/plugins/{name}/enable", response_model=PluginActionResponse)
async def enable_plugin(name: str) -> PluginActionResponse:
    """Enable a plugin by name."""
    mgr = _get_manager()
    if not mgr.enable(name):
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
    return PluginActionResponse(name=name, enabled=True, message=f"Plugin '{name}' enabled")


@router.post("/plugins/{name}/disable", response_model=PluginActionResponse)
async def disable_plugin(name: str) -> PluginActionResponse:
    """Disable a plugin by name."""
    mgr = _get_manager()
    if not mgr.disable(name):
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
    return PluginActionResponse(name=name, enabled=False, message=f"Plugin '{name}' disabled")
