# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Plugin system for third-party detector modules."""

from malwar.plugins.base import DetectorPlugin
from malwar.plugins.hooks import HookManager, HookType
from malwar.plugins.loader import PluginLoader
from malwar.plugins.manager import PluginManager

__all__ = [
    "DetectorPlugin",
    "HookManager",
    "HookType",
    "PluginLoader",
    "PluginManager",
]
