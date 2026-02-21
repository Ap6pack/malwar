# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Plugin lifecycle manager — load, validate, enable/disable, list."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from malwar.plugins.base import DetectorPlugin
from malwar.plugins.hooks import HookManager
from malwar.plugins.loader import PluginLoader

logger = logging.getLogger("malwar.plugins.manager")


@dataclass
class PluginInfo:
    """Snapshot of a plugin's metadata and runtime state."""

    name: str
    version: str
    author: str
    description: str
    layer_name: str
    enabled: bool


@dataclass
class _PluginEntry:
    """Internal bookkeeping for a loaded plugin."""

    plugin: DetectorPlugin
    enabled: bool = True


class PluginManager:
    """Manages the full lifecycle of detector plugins.

    Typical usage::

        mgr = PluginManager()
        mgr.discover(plugins_dir="/opt/malwar/plugins", module_paths=[])
        for det in mgr.get_enabled_detectors():
            pipeline.register_detector(det)
    """

    def __init__(self, *, hook_manager: HookManager | None = None) -> None:
        self._entries: dict[str, _PluginEntry] = {}
        self._loader = PluginLoader()
        self.hooks = hook_manager or HookManager()

    # -- discovery ---------------------------------------------------------

    def discover(
        self,
        *,
        plugins_dir: str = "",
        module_paths: list[str] | None = None,
        enabled_names: list[str] | None = None,
    ) -> None:
        """Discover and register plugins from all configured sources.

        Parameters
        ----------
        plugins_dir:
            Filesystem directory containing ``*.py`` plugin files.
        module_paths:
            Dotted Python module paths to import.
        enabled_names:
            If provided, only these plugins will be enabled after loading.
            An empty list means *none* are enabled.  ``None`` means *all* are
            enabled (the default).
        """
        all_plugins: list[DetectorPlugin] = []

        # 1. entry points
        all_plugins.extend(self._loader.load_from_entry_points())

        # 2. directory
        if plugins_dir:
            all_plugins.extend(self._loader.load_from_directory(plugins_dir))

        # 3. explicit module paths
        if module_paths:
            all_plugins.extend(self._loader.load_from_module_paths(module_paths))

        for plugin in all_plugins:
            self._register(plugin, enabled_names=enabled_names)

    def _register(
        self,
        plugin: DetectorPlugin,
        *,
        enabled_names: list[str] | None,
    ) -> None:
        meta = plugin.plugin_metadata
        name = meta.name

        if not self._validate(plugin):
            logger.warning("Plugin %s failed validation — skipping", name)
            return

        enabled = enabled_names is None or name in enabled_names
        self._entries[name] = _PluginEntry(plugin=plugin, enabled=enabled)
        logger.info(
            "Registered plugin %s v%s (enabled=%s)", name, meta.version, enabled
        )

    @staticmethod
    def _validate(plugin: DetectorPlugin) -> bool:
        """Basic sanity checks on a plugin instance."""
        meta = plugin.plugin_metadata
        if not meta.name or not meta.name.strip():
            logger.error("Plugin has empty name")
            return False
        if not meta.version or not meta.version.strip():
            logger.error("Plugin %s has empty version", meta.name)
            return False
        if not meta.layer_name or not meta.layer_name.strip():
            logger.error("Plugin %s has empty layer_name", meta.name)
            return False
        return True

    # -- enable / disable --------------------------------------------------

    def enable(self, name: str) -> bool:
        """Enable plugin *name*. Returns ``True`` on success."""
        entry = self._entries.get(name)
        if entry is None:
            return False
        entry.enabled = True
        logger.info("Enabled plugin %s", name)
        return True

    def disable(self, name: str) -> bool:
        """Disable plugin *name*. Returns ``True`` on success."""
        entry = self._entries.get(name)
        if entry is None:
            return False
        entry.enabled = False
        logger.info("Disabled plugin %s", name)
        return True

    # -- query -------------------------------------------------------------

    def list_plugins(self) -> list[PluginInfo]:
        """Return metadata + status for every loaded plugin."""
        result: list[PluginInfo] = []
        for entry in self._entries.values():
            meta = entry.plugin.plugin_metadata
            result.append(
                PluginInfo(
                    name=meta.name,
                    version=meta.version,
                    author=meta.author,
                    description=meta.description,
                    layer_name=meta.layer_name,
                    enabled=entry.enabled,
                )
            )
        return result

    def get_plugin(self, name: str) -> DetectorPlugin | None:
        """Return the plugin instance by name, or ``None``."""
        entry = self._entries.get(name)
        return entry.plugin if entry else None

    def get_enabled_detectors(self) -> list[DetectorPlugin]:
        """Return enabled plugins as ``BaseDetector``-compatible instances."""
        return [e.plugin for e in self._entries.values() if e.enabled]

    def is_enabled(self, name: str) -> bool | None:
        """Return enabled state, or ``None`` if the plugin is not loaded."""
        entry = self._entries.get(name)
        return entry.enabled if entry else None
