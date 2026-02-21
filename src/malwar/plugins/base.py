# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract base class for detector plugins."""

from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field

from malwar.scanner.base import BaseDetector


@dataclass(frozen=True)
class PluginMetadata:
    """Immutable metadata describing a detector plugin."""

    name: str
    version: str
    author: str
    description: str
    layer_name: str
    tags: list[str] = field(default_factory=list)


class DetectorPlugin(BaseDetector):
    """Abstract base class that third-party detector plugins must extend.

    Subclasses **must** implement:
      - ``plugin_metadata`` (class-level property returning ``PluginMetadata``)
      - ``detect`` (inherited from ``BaseDetector``)

    The ``layer_name`` and ``order`` required by ``BaseDetector`` are derived
    automatically from ``plugin_metadata``.
    """

    @property
    @abstractmethod
    def plugin_metadata(self) -> PluginMetadata:
        """Return metadata describing this plugin."""
        ...

    # -- BaseDetector interface wired to metadata --------------------------

    @property
    def layer_name(self) -> str:
        return self.plugin_metadata.layer_name

    @property
    def order(self) -> int:
        """Plugins run after the built-in layers (order >= 100)."""
        return 100
