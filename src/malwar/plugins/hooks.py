# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Hook system allowing plugins to react to scan lifecycle events."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from enum import StrEnum
from typing import Any

logger = logging.getLogger("malwar.plugins.hooks")


class HookType(StrEnum):
    """Supported hook points in the scan pipeline."""

    PRE_SCAN = "pre_scan"
    POST_SCAN = "post_scan"
    ON_FINDING = "on_finding"


# A hook callback is any callable.  Async hooks are awaited; sync hooks are
# called directly.  All hooks receive ``**kwargs`` with context-dependent data.
HookCallback = Callable[..., Any]


class HookManager:
    """Registry and dispatcher for plugin hooks.

    Plugins register callbacks for specific ``HookType`` events.  The scan
    pipeline invokes ``fire`` at the appropriate points.
    """

    def __init__(self) -> None:
        self._hooks: dict[HookType, list[HookCallback]] = defaultdict(list)

    def register(self, hook_type: HookType, callback: HookCallback) -> None:
        """Register *callback* for *hook_type*."""
        self._hooks[hook_type].append(callback)
        logger.debug("Registered hook %s -> %s", hook_type, callback)

    def unregister(self, hook_type: HookType, callback: HookCallback) -> None:
        """Remove a previously-registered callback (no-op if missing)."""
        import contextlib

        with contextlib.suppress(ValueError):
            self._hooks[hook_type].remove(callback)

    async def fire(self, hook_type: HookType, **kwargs: Any) -> None:
        """Invoke all callbacks registered for *hook_type*.

        Each callback receives ``**kwargs``.  Exceptions are logged and
        swallowed so that one misbehaving plugin cannot break the pipeline.
        """
        import asyncio

        for cb in self._hooks[hook_type]:
            try:
                result = cb(**kwargs)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Hook %s callback %s raised an exception", hook_type, cb)

    def clear(self) -> None:
        """Remove all registered hooks."""
        self._hooks.clear()
