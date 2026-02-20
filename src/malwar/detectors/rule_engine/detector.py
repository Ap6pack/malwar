# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 1: Rule-based detection engine."""

from __future__ import annotations

import logging

from malwar.core.constants import DetectorLayer
from malwar.detectors.rule_engine.registry import RuleRegistry
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

# Import all rule modules to trigger registration
import malwar.detectors.rule_engine.rules.obfuscation  # noqa: F401
import malwar.detectors.rule_engine.rules.social_engineering  # noqa: F401
import malwar.detectors.rule_engine.rules.prompt_injection  # noqa: F401
import malwar.detectors.rule_engine.rules.known_malware  # noqa: F401
import malwar.detectors.rule_engine.rules.credential_exposure  # noqa: F401
import malwar.detectors.rule_engine.rules.suspicious_commands  # noqa: F401
import malwar.detectors.rule_engine.rules.exfiltration  # noqa: F401

logger = logging.getLogger("malwar.detectors.rule_engine")


class RuleEngineDetector(BaseDetector):
    """Layer 1: Pattern matching and signature-based detection."""

    @property
    def layer_name(self) -> str:
        return DetectorLayer.RULE_ENGINE

    @property
    def order(self) -> int:
        return 10

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
