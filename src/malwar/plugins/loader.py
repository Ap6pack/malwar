# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Plugin discovery and loading from multiple sources."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import sys
from pathlib import Path

from malwar.plugins.base import DetectorPlugin

logger = logging.getLogger("malwar.plugins.loader")

ENTRY_POINT_GROUP = "malwar.detectors"


class PluginLoader:
    """Discovers and instantiates :class:`DetectorPlugin` subclasses.

    Sources (checked in order):
      1. ``importlib.metadata`` entry points in the ``malwar.detectors`` group.
      2. Python files in a configurable plugins directory.
      3. Explicit dotted module paths supplied via configuration.
    """

    def load_from_entry_points(self) -> list[DetectorPlugin]:
        """Load plugins registered as ``malwar.detectors`` entry points."""
        plugins: list[DetectorPlugin] = []
        try:
            eps = importlib.metadata.entry_points()
            group_eps = eps.select(group=ENTRY_POINT_GROUP)
        except Exception:
            logger.debug("No entry points found for group %s", ENTRY_POINT_GROUP)
            return plugins

        for ep in group_eps:
            try:
                cls = ep.load()
                plugin = self._instantiate(cls, source=f"entrypoint:{ep.name}")
                if plugin is not None:
                    plugins.append(plugin)
            except Exception:
                logger.exception("Failed to load entry-point plugin %s", ep.name)

        return plugins

    def load_from_directory(self, directory: str | Path) -> list[DetectorPlugin]:
        """Import all ``*.py`` files in *directory* and collect plugin classes."""
        plugins: list[DetectorPlugin] = []
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning("Plugins directory does not exist: %s", dir_path)
            return plugins

        # Ensure the directory is on sys.path so relative imports work
        dir_str = str(dir_path.resolve())
        if dir_str not in sys.path:
            sys.path.insert(0, dir_str)

        for py_file in sorted(dir_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = py_file.stem
            try:
                module = importlib.import_module(module_name)
                plugins.extend(self._collect_from_module(module, source=f"dir:{py_file}"))
            except Exception:
                logger.exception("Failed to load plugin from %s", py_file)

        return plugins

    def load_from_module_paths(self, paths: list[str]) -> list[DetectorPlugin]:
        """Import each dotted module path and collect plugin classes."""
        plugins: list[DetectorPlugin] = []
        for mod_path in paths:
            try:
                module = importlib.import_module(mod_path)
                plugins.extend(
                    self._collect_from_module(module, source=f"module:{mod_path}")
                )
            except Exception:
                logger.exception("Failed to import plugin module %s", mod_path)
        return plugins

    # -- helpers -----------------------------------------------------------

    def _collect_from_module(
        self, module: object, *, source: str
    ) -> list[DetectorPlugin]:
        """Scan *module* for concrete ``DetectorPlugin`` subclasses."""
        plugins: list[DetectorPlugin] = []
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, DetectorPlugin)
                and obj is not DetectorPlugin
            ):
                plugin = self._instantiate(obj, source=source)
                if plugin is not None:
                    plugins.append(plugin)
        return plugins

    @staticmethod
    def _instantiate(cls: type, *, source: str) -> DetectorPlugin | None:
        """Instantiate a plugin class, returning ``None`` on failure."""
        try:
            instance = cls()
            logger.info(
                "Loaded plugin %s v%s from %s",
                instance.plugin_metadata.name,
                instance.plugin_metadata.version,
                source,
            )
            return instance  # type: ignore[no-any-return]
        except Exception:
            logger.exception("Failed to instantiate plugin class %s from %s", cls, source)
            return None
