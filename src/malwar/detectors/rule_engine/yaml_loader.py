# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Load, validate, and register YAML-based custom detection rules."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from malwar.detectors.rule_engine.registry import RuleRegistry
from malwar.detectors.rule_engine.yaml_rule import YamlRule, YamlRuleDefinition

logger = logging.getLogger("malwar.detectors.rule_engine.yaml_loader")


def load_yaml_rules_from_directory(rules_dir: str | Path) -> list[YamlRule]:
    """Discover, validate, and register YAML rules from *rules_dir*.

    Parameters
    ----------
    rules_dir:
        Path to a directory containing ``.yml`` / ``.yaml`` rule files.

    Returns
    -------
    list[YamlRule]
        The list of successfully loaded and registered rules.
    """
    rules_path = Path(rules_dir)

    if not rules_path.is_dir():
        logger.warning("Custom rules directory does not exist: %s", rules_path)
        return []

    loaded_rules: list[YamlRule] = []
    yaml_files = sorted(
        [*rules_path.glob("*.yml"), *rules_path.glob("*.yaml")]
    )

    if not yaml_files:
        logger.info("No YAML rule files found in %s", rules_path)
        return []

    for filepath in yaml_files:
        try:
            rule = _load_single_rule(filepath)
            if rule is not None:
                loaded_rules.append(rule)
        except Exception as exc:
            logger.warning("Failed to load rule from %s: %s", filepath, exc)

    logger.info(
        "Loaded %d custom YAML rules from %s", len(loaded_rules), rules_path
    )
    return loaded_rules


def _load_single_rule(filepath: Path) -> YamlRule | None:
    """Parse a single YAML file into a :class:`YamlRule` and register it."""
    raw_text = filepath.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        logger.warning("Invalid YAML syntax in %s: %s", filepath.name, exc)
        return None

    if not isinstance(data, dict):
        logger.warning("Expected a mapping at top level in %s, got %s", filepath.name, type(data).__name__)
        return None

    try:
        definition = YamlRuleDefinition(**data)
    except ValidationError as exc:
        logger.warning("Schema validation failed for %s: %s", filepath.name, exc)
        return None

    rule = YamlRule(definition)

    # Register into the global registry so the rule engine picks it up.
    _register_yaml_rule(rule)

    logger.debug("Registered YAML rule %s from %s", rule.rule_id, filepath.name)
    return rule


def _register_yaml_rule(rule: YamlRule) -> None:
    """Insert a *YamlRule instance* into the :class:`RuleRegistry`.

    The existing registry expects *classes* (it instantiates them via ``r()``).
    We create a tiny wrapper class whose ``__init__`` returns a pre-built
    instance so the registry's ``get_enabled()`` works transparently.
    """
    # Build a one-off class that, when instantiated, behaves like our rule.
    # We store the singleton instance and override __new__ to return it.
    instance = rule

    class _Wrapper(YamlRule):
        rule_id = instance.rule_id  # type: ignore[assignment]
        title = instance.title  # type: ignore[assignment]
        severity = instance.severity  # type: ignore[assignment]
        category = instance.category  # type: ignore[assignment]
        description = instance.description  # type: ignore[assignment]
        enabled = instance.enabled

        def __new__(cls) -> _Wrapper:  # type: ignore[override]
            return instance  # type: ignore[return-value]

    _Wrapper.__name__ = f"YamlRule_{instance.rule_id}"
    _Wrapper.__qualname__ = _Wrapper.__name__

    RuleRegistry._rules[instance.rule_id] = _Wrapper  # type: ignore[assignment]
