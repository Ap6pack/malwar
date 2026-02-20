# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 1: Rule-based detection engine."""

from __future__ import annotations

import logging

import malwar.detectors.rule_engine.rules.agent_hijacking
import malwar.detectors.rule_engine.rules.credential_exposure
import malwar.detectors.rule_engine.rules.env_harvesting
import malwar.detectors.rule_engine.rules.exfiltration
import malwar.detectors.rule_engine.rules.known_malware
import malwar.detectors.rule_engine.rules.multi_step

# Import all rule modules to trigger registration
import malwar.detectors.rule_engine.rules.obfuscation
import malwar.detectors.rule_engine.rules.persistence
import malwar.detectors.rule_engine.rules.prompt_injection
import malwar.detectors.rule_engine.rules.social_engineering
import malwar.detectors.rule_engine.rules.steganography
import malwar.detectors.rule_engine.rules.supply_chain
import malwar.detectors.rule_engine.rules.suspicious_commands  # noqa: F401
from malwar.core.config import get_settings
from malwar.core.constants import DetectorLayer
from malwar.detectors.rule_engine.registry import RuleRegistry
from malwar.detectors.rule_engine.yaml_loader import load_yaml_rules_from_directory
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

logger = logging.getLogger("malwar.detectors.rule_engine")


class RuleEngineDetector(BaseDetector):
    """Layer 1: Pattern matching and signature-based detection."""

    _yaml_rules_loaded: bool = False

    @property
    def layer_name(self) -> str:
        return DetectorLayer.RULE_ENGINE

    @property
    def order(self) -> int:
        return 10

    async def setup(self) -> None:
        """Load custom YAML rules on first startup."""
        if not RuleEngineDetector._yaml_rules_loaded:
            settings = get_settings()
            if settings.custom_rules_dir:
                logger.info("Loading custom YAML rules from %s", settings.custom_rules_dir)
                load_yaml_rules_from_directory(settings.custom_rules_dir)
            RuleEngineDetector._yaml_rules_loaded = True

    async def detect(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        rules = RuleRegistry.get_enabled()

        logger.info("Running %d rules against %s", len(rules), context.skill.file_path)

        for rule_instance in rules:
            try:
                rule_findings = rule_instance.check(context.skill)
                findings.extend(rule_findings)
            except Exception as exc:
                error_msg = f"Rule {rule_instance.rule_id} failed: {exc}"
                logger.error(error_msg)
                context.errors.append(error_msg)

        logger.info(
            "Rule engine found %d findings for %s",
            len(findings),
            context.skill.file_path,
        )
        return findings
