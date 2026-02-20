# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""YAML-based custom rule: parses a YAML definition into a BaseRule-compatible object."""

from __future__ import annotations

import re
from enum import StrEnum
from string import Template
from typing import Any

from pydantic import BaseModel, Field, field_validator

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent

# ---------------------------------------------------------------------------
# Enums for YAML rule schema
# ---------------------------------------------------------------------------


class MatchType(StrEnum):
    """Supported pattern-matching strategies."""

    REGEX = "regex"
    EXACT = "exact"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"


class MatchTarget(StrEnum):
    """Where in the skill content the pattern should be applied."""

    CONTENT = "content"
    METADATA_NAME = "metadata.name"
    METADATA_AUTHOR = "metadata.author"
    METADATA_DESCRIPTION = "metadata.description"
    METADATA_TAGS = "metadata.tags"
    URLS = "urls"
    CODE_BLOCKS = "code_blocks"


class MatchLogic(StrEnum):
    """How multiple patterns within a rule are combined."""

    ALL = "all"  # AND - every pattern must match
    ANY = "any"  # OR  - at least one pattern must match


# ---------------------------------------------------------------------------
# Pydantic models for YAML rule validation
# ---------------------------------------------------------------------------


class PatternDefinition(BaseModel):
    """A single match condition inside a YAML rule."""

    pattern: str
    match_type: MatchType = MatchType.CONTAINS
    target: MatchTarget = MatchTarget.CONTENT

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, v: str) -> str:
        if not v.strip():
            msg = "Pattern must not be empty"
            raise ValueError(msg)
        return v


class YamlRuleDefinition(BaseModel):
    """Schema for a single YAML rule file."""

    id: str
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: ThreatCategory = ThreatCategory.SUSPICIOUS_COMMAND
    confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    enabled: bool = True
    match: MatchLogic = MatchLogic.ALL
    patterns: list[PatternDefinition] = Field(min_length=1)
    evidence_template: str = "Matched custom rule: ${rule_id}"

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        if not v.strip():
            msg = "Rule id must not be empty"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------


def _match_pattern(text: str, pattern: str, match_type: MatchType) -> re.Match[str] | None:
    """Return a Match object (truthy) when *text* satisfies the pattern."""
    if match_type == MatchType.REGEX:
        return re.search(pattern, text)
    if match_type == MatchType.EXACT:
        # Exact match - full string comparison (case-sensitive)
        return re.match(r"\Z", "") if text == pattern else None  # truthy sentinel
    if match_type == MatchType.CONTAINS:
        return re.match(r"\Z", "") if pattern in text else None
    if match_type == MatchType.STARTS_WITH:
        return re.match(r"\Z", "") if text.startswith(pattern) else None
    if match_type == MatchType.ENDS_WITH:
        return re.match(r"\Z", "") if text.endswith(pattern) else None
    return None


def _extract_target_strings(skill: SkillContent, target: MatchTarget) -> list[str]:
    """Return the list of text values to match against for a given target."""
    if target == MatchTarget.CONTENT:
        return [skill.raw_content]
    if target == MatchTarget.METADATA_NAME:
        return [skill.metadata.name or ""]
    if target == MatchTarget.METADATA_AUTHOR:
        return [skill.metadata.author or ""]
    if target == MatchTarget.METADATA_DESCRIPTION:
        return [skill.metadata.description or ""]
    if target == MatchTarget.METADATA_TAGS:
        return list(skill.metadata.tags)
    if target == MatchTarget.URLS:
        return list(skill.urls)
    if target == MatchTarget.CODE_BLOCKS:
        return [cb.content for cb in skill.code_blocks]
    return []


# ---------------------------------------------------------------------------
# The concrete rule class produced from YAML definitions
# ---------------------------------------------------------------------------


class YamlRule(BaseRule):
    """A detection rule instantiated from a YAML definition.

    Behaves identically to hand-coded Python rules: it is registered in the
    :class:`RuleRegistry` and returns standard :class:`Finding` objects.
    """

    def __init__(self, definition: YamlRuleDefinition) -> None:
        self._def = definition
        # Satisfy the BaseRule interface attributes
        self.rule_id = definition.id
        self.title = definition.title
        self.severity = definition.severity
        self.category = definition.category
        self.description = definition.description
        self.enabled = definition.enabled

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def check(self, skill: SkillContent) -> list[Finding]:
        """Evaluate all patterns against the skill and return any findings."""
        pattern_results: list[dict[str, Any]] = []

        for pat in self._def.patterns:
            targets = _extract_target_strings(skill, pat.target)
            matched = False
            matched_value = ""
            matched_line: int | None = None

            for text in targets:
                m = _match_pattern(text, pat.pattern, pat.match_type)
                if m is not None:
                    matched = True
                    matched_value = (
                        m.group(0) if hasattr(m, "group") and m.group(0) else pat.pattern
                    )
                    # Attempt to locate the line number in raw content
                    if pat.target == MatchTarget.CONTENT:
                        matched_line = _find_line_number(skill.raw_content, pat.pattern, pat.match_type)
                    break

            pattern_results.append({
                "pattern": pat.pattern,
                "match_type": pat.match_type,
                "target": pat.target,
                "matched": matched,
                "value": matched_value,
                "line": matched_line,
            })

        # Combine results according to match logic
        matched_patterns = [r for r in pattern_results if r["matched"]]

        if self._def.match == MatchLogic.ALL:
            triggered = len(matched_patterns) == len(self._def.patterns)
        else:  # ANY
            triggered = len(matched_patterns) > 0

        if not triggered:
            return []

        # Build evidence from template
        evidence = self._render_evidence(matched_patterns)

        # Determine a best-guess location from the first matched pattern
        first_line = next((r["line"] for r in matched_patterns if r["line"]), None)
        location = Location(line_start=first_line, snippet="") if first_line else None

        return [
            Finding(
                id=f"{self.rule_id}-YAML",
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=self.severity,
                confidence=self._def.confidence,
                category=self.category,
                detector_layer=DetectorLayer.RULE_ENGINE,
                location=location,
                evidence=evidence,
            )
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _render_evidence(self, matched_patterns: list[dict[str, Any]]) -> list[str]:
        """Render the evidence_template for each matched pattern."""
        evidence: list[str] = []
        for result in matched_patterns:
            try:
                tpl = Template(self._def.evidence_template)
                rendered = tpl.safe_substitute(
                    rule_id=self.rule_id,
                    pattern=result["pattern"],
                    match_type=result["match_type"],
                    target=result["target"],
                    value=result["value"],
                )
                evidence.append(rendered)
            except Exception:
                evidence.append(f"Matched pattern: {result['pattern']}")
        return evidence


def _find_line_number(content: str, pattern: str, match_type: MatchType) -> int | None:
    """Locate the first line number where the pattern matches in *content*."""
    for line_num, line in enumerate(content.splitlines(), 1):
        if _match_pattern(line, pattern, match_type) is not None:
            return line_num
    return None
