# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Rule registration and discovery."""

from __future__ import annotations

from typing import TypeVar

from malwar.detectors.rule_engine.base_rule import BaseRule

T = TypeVar("T", bound=BaseRule)


class RuleRegistry:
    """Central registry for all detection rules."""

    _rules: dict[str, type[BaseRule]] = {}

    @classmethod
    def register(cls, rule_class: type[T]) -> type[T]:
        cls._rules[rule_class.rule_id] = rule_class
        return rule_class

    @classmethod
    def get_all(cls) -> list[type[BaseRule]]:
        return list(cls._rules.values())

    @classmethod
    def get_enabled(cls) -> list[BaseRule]:
        return [r() for r in cls._rules.values() if r.enabled]

    @classmethod
    def get_by_category(cls, category: str) -> list[type[BaseRule]]:
        return [r for r in cls._rules.values() if r.category == category]

    @classmethod
    def clear(cls) -> None:
        """Clear all registered rules (for testing)."""
        cls._rules.clear()


def rule(cls: type[T]) -> type[T]:
    """Decorator to register a rule class."""
    return RuleRegistry.register(cls)
