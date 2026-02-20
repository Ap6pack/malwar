# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Parse LLM response JSON into structured Finding objects."""

from __future__ import annotations

import json
import logging
import re

from pydantic import BaseModel, Field

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.core.exceptions import LLMError
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent

logger = logging.getLogger("malwar.detectors.llm_analyzer.parser")

# ---------------------------------------------------------------------------
# LLM response models
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "social_engineering": ThreatCategory.SOCIAL_ENGINEERING,
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "malware_delivery": ThreatCategory.KNOWN_MALWARE,
    "credential_theft": ThreatCategory.CREDENTIAL_EXPOSURE,
    "deception": ThreatCategory.SOCIAL_ENGINEERING,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class LlmFinding(BaseModel):
    """A single finding returned by the LLM."""

    category: str
    severity: str
    title: str
    description: str
    evidence: str
    line_hint: str = ""


class LlmAnalysisResult(BaseModel):
    """The full structured response from the LLM."""

    threat_assessment: str
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[LlmFinding]
    summary: str


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


def parse_llm_response(response_text: str) -> LlmAnalysisResult:
    """Parse the LLM response text into an :class:`LlmAnalysisResult`.

    Handles:
    - Raw JSON
    - JSON wrapped in markdown code fences (```json ... ```)
    - Trailing text after JSON
    """
    text = response_text.strip()

    # Try to extract JSON from markdown code fences first
    fence_match = _JSON_FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    # If it doesn't start with '{', try to find the first '{' and last '}'
    if not text.startswith("{"):
        start = text.find("{")
        if start == -1:
            raise LLMError(f"No JSON object found in LLM response: {response_text[:200]}")
        text = text[start:]

    # Find the matching closing brace
    end = text.rfind("}")
    if end == -1:
        raise LLMError(f"No closing brace found in LLM response: {response_text[:200]}")
    text = text[: end + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"Invalid JSON in LLM response: {exc}") from exc

    try:
        return LlmAnalysisResult.model_validate(data)
    except Exception as exc:
        raise LLMError(f"LLM response does not match expected schema: {exc}") from exc


# ---------------------------------------------------------------------------
# Conversion to Finding objects
# ---------------------------------------------------------------------------


def _resolve_line_hint(line_hint: str, skill: SkillContent) -> int | None:
    """Try to resolve a line_hint string to an actual line number.

    Supports:
    - Bare numbers (e.g. "15")
    - "line 15" / "Line 15"
    - If the hint is a text fragment, search for it in the raw content
    """
    if not line_hint:
        return None

    # Try to extract a number
    num_match = re.search(r"\d+", line_hint)
    if num_match:
        line_num = int(num_match.group(0))
        total_lines = skill.raw_content.count("\n") + 1
        if 1 <= line_num <= total_lines:
            return line_num

    # Try to find the hint text in the raw content
    hint_lower = line_hint.lower().strip()
    for i, line in enumerate(skill.raw_content.splitlines(), start=1):
        if hint_lower in line.lower():
            return i

    return None


def llm_findings_to_findings(
    llm_result: LlmAnalysisResult, skill: SkillContent
) -> list[Finding]:
    """Convert LLM findings into standard :class:`Finding` objects."""
    findings: list[Finding] = []

    for idx, lf in enumerate(llm_result.findings):
        # Map category
        category = _CATEGORY_MAP.get(lf.category.lower())
        if category is None:
            logger.warning("Unknown LLM category %r, defaulting to SOCIAL_ENGINEERING", lf.category)
            category = ThreatCategory.SOCIAL_ENGINEERING

        # Map severity
        severity = _SEVERITY_MAP.get(lf.severity.lower())
        if severity is None:
            logger.warning("Unknown LLM severity %r, defaulting to MEDIUM", lf.severity)
            severity = Severity.MEDIUM

        # Resolve location
        line_num = _resolve_line_hint(lf.line_hint, skill)
        location = None
        if line_num is not None:
            location = Location(line_start=line_num, snippet=lf.evidence[:200])

        # Build unique finding ID
        finding_id = f"MALWAR-LLM-{idx + 1:03d}"
        if line_num is not None:
            finding_id += f"-L{line_num}"

        finding = Finding(
            id=finding_id,
            rule_id=f"llm-{lf.category.lower()}",
            title=lf.title,
            description=lf.description,
            severity=severity,
            confidence=llm_result.confidence,
            category=category,
            detector_layer=DetectorLayer.LLM_ANALYZER,
            location=location,
            evidence=[lf.evidence] if lf.evidence else [],
            remediation="Review the flagged content and remove or replace it if malicious.",
            metadata={
                "threat_assessment": llm_result.threat_assessment,
                "llm_summary": llm_result.summary,
            },
        )
        findings.append(finding)

    return findings
