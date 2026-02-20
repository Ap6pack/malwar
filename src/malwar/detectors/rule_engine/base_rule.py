# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract base class for detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from malwar.core.constants import Severity, ThreatCategory
from malwar.models.finding import Finding
from malwar.models.skill import SkillContent


class BaseRule(ABC):
    """All detection rules must inherit from this class."""

    rule_id: str
    title: str
    severity: Severity
    category: ThreatCategory
    description: str
    enabled: bool = True

    @abstractmethod
    def check(self, skill: SkillContent) -> list[Finding]:
        """Run the rule against parsed skill content. Return findings."""
        ...
