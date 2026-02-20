# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 3: LLM-powered semantic analysis of SKILL.md content."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import anthropic

from malwar.core.config import Settings, get_settings
from malwar.core.constants import DetectorLayer
from malwar.core.exceptions import LLMError
from malwar.detectors.llm_analyzer.parser import (
    llm_findings_to_findings,
    parse_llm_response,
)
from malwar.detectors.llm_analyzer.prompts import SYSTEM_PROMPT, build_user_prompt
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

if TYPE_CHECKING:
    pass

logger = logging.getLogger("malwar.detectors.llm_analyzer")


def _summarize_prior_findings(context: ScanContext) -> str:
    """Build a concise summary of findings from earlier detection layers."""
    prior = [
        f
        for f in context.findings
        if f.detector_layer in (DetectorLayer.RULE_ENGINE, DetectorLayer.URL_CRAWLER)
    ]
    if not prior:
        return ""

    lines: list[str] = []
    for f in prior:
        lines.append(
            f"- [{f.severity.upper()}] {f.title} (category={f.category}, "
            f"rule={f.rule_id}): {f.description[:150]}"
        )
    return "\n".join(lines)


class LlmAnalyzerDetector(BaseDetector):
    """Layer 3: Uses an LLM to perform semantic threat analysis."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def layer_name(self) -> str:
        return DetectorLayer.LLM_ANALYZER

    @property
    def order(self) -> int:
        return 30

    async def detect(self, context: ScanContext) -> list[Finding]:
        """Send skill content to the LLM and parse the threat analysis."""
        settings = self._settings

        # Guard: skip if no API key is configured
        if not settings.anthropic_api_key:
            logger.warning(
                "Anthropic API key not configured; skipping LLM analysis for %s",
                context.skill.file_path,
            )
            return []

        # 1. Build prior findings summary
        prior_summary = _summarize_prior_findings(context)

        # 2. Build user prompt
        user_prompt = build_user_prompt(context.skill, prior_summary)

        # 3. Call the Anthropic API
        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        try:
            response = await client.messages.create(
                model=settings.llm_model,
                max_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.APIError as exc:
            error_msg = f"Anthropic API error during LLM analysis: {exc}"
            logger.error(error_msg)
            context.errors.append(error_msg)
            return []
        except Exception as exc:
            error_msg = f"Unexpected error calling Anthropic API: {exc}"
            logger.error(error_msg)
            context.errors.append(error_msg)
            return []

        # 4. Extract response text
        response_text = ""
        for block in response.content:
            if block.type == "text":
                response_text += block.text

        if not response_text:
            error_msg = "LLM returned empty response"
            logger.error(error_msg)
            context.errors.append(error_msg)
            return []

        # 5. Parse the response
        try:
            llm_result = parse_llm_response(response_text)
        except LLMError as exc:
            error_msg = f"Failed to parse LLM response: {exc}"
            logger.error(error_msg)
            context.errors.append(error_msg)
            return []

        # 6. Store raw analysis in context
        context.llm_analysis = {
            "threat_assessment": llm_result.threat_assessment,
            "confidence": llm_result.confidence,
            "summary": llm_result.summary,
            "raw_findings_count": len(llm_result.findings),
        }

        # 7. Convert to standard Finding objects
        findings = llm_findings_to_findings(llm_result, context.skill)

        logger.info(
            "LLM analyzer found %d findings for %s (assessment=%s, confidence=%.2f)",
            len(findings),
            context.skill.file_path,
            llm_result.threat_assessment,
            llm_result.confidence,
        )

        return findings
