# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract base detector interface for all detection layers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from malwar.models.finding import Finding
from malwar.scanner.context import ScanContext


class BaseDetector(ABC):
    """All detection layers must implement this interface."""

    @property
    @abstractmethod
    def layer_name(self) -> str:
        """Unique identifier for this detection layer."""
        ...

    @property
    @abstractmethod
    def order(self) -> int:
        """Execution order (lower runs first)."""
        ...

    @abstractmethod
    async def detect(self, context: ScanContext) -> list[Finding]:
        """Analyze the scan context and return findings."""
        ...

    async def setup(self) -> None:
        """Optional initialization."""

    async def teardown(self) -> None:
        """Optional cleanup."""
