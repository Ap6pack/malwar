# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 3: LLM-powered semantic analysis of SKILL.md content."""

from __future__ import annotations

import logging

import anthropic

from malwar.core.config import Settings, get_settings
from malwar.core.constants import DetectorLayer
from malwar.core.exceptions import LLMError
from malwar.detectors.llm_analyzer.parser import (
    apply_suppressions,
    llm_findings_to_findings,
    parse_llm_response,
)
from malwar.detectors.llm_analyzer.prompts import SYSTEM_PROMPT, build_user_prompt
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

logger = logging.getLogger("malwar.detectors.llm_analyzer")


def _prior_findings(context: ScanContext) -> list[Finding]:
    """Findings from earlier layers that the LLM is shown and may suppress."""
    return [
        f
        for f in context.findings
        if f.detector_layer in (DetectorLayer.RULE_ENGINE, DetectorLayer.URL_CRAWLER)
    ]


def _summarize_prior_findings(prior: list[Finding]) -> str:
    """Build a concise summary of findings from earlier detection layers.

    Includes each finding's ``id`` so the LLM can reference a specific
    finding (not just a rule) in a suppression annotation.
    """
    if not prior:
        return ""

    lines: list[str] = []
    for f in prior:
        lines.append(
            f"- [{f.severity.upper()}] {f.title} (id={f.id}, category={f.category}, "
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

    @staticmethod
    def _build_client(settings: Settings) -> anthropic.AsyncAnthropic | None:
        """Resolve Anthropic credentials, or return None if none are available.

        Resolution order:
          1. An explicit ``MALWAR_ANTHROPIC_API_KEY`` (the settings value).
          2. The SDK's own credential chain — ``ANTHROPIC_API_KEY``,
             ``ANTHROPIC_AUTH_TOKEN``, or an OAuth profile from ``ant auth
             login`` / the Claude Code CLI login. Constructing the client with
             no explicit key lets the SDK resolve these; it raises when nothing
             is available, which we treat as "no credentials".

        This is why ``malwar scan`` picks up the LLM layer automatically when
        run from an already-authenticated Claude Code CLI, without setting a
        malwar-specific key.
        """
        if settings.anthropic_api_key:
            return anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        try:
            return anthropic.AsyncAnthropic()
        except anthropic.AnthropicError:
            return None

    async def detect(self, context: ScanContext) -> list[Finding]:
        """Send skill content to the LLM and parse the threat analysis."""
        settings = self._settings

        # Guard: skip if no Anthropic credentials can be resolved.
        client = self._build_client(settings)
        if client is None:
            logger.warning(
                "No Anthropic credentials found (set MALWAR_ANTHROPIC_API_KEY or "
                "ANTHROPIC_API_KEY, or run `ant auth login`); skipping LLM "
                "analysis for %s",
                context.skill.file_path,
            )
            return []

        # 1. Build prior findings summary
        prior_findings = _prior_findings(context)
        prior_summary = _summarize_prior_findings(prior_findings)

        # 2. Build user prompt
        user_prompt = build_user_prompt(context.skill, prior_summary)

        # 3. Call the Anthropic API
        try:
            # No `temperature`: current-generation models (Sonnet 5, Opus 4.8,
            # Fable 5) reject non-default sampling parameters, and temperature=0
            # never guaranteed determinism anyway. Omitting it keeps the call
            # compatible across model generations.
            response = await client.messages.create(
                model=settings.llm_model,
                max_tokens=settings.llm_max_tokens,
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

        # 6. Apply any suppressions to prior-layer findings the LLM is
        # confident are false positives. Mutates the matched Finding objects
        # in place (they remain in context.findings / the eventual
        # ScanResult.findings for transparency, just excluded from scoring).
        suppressed_ids = apply_suppressions(prior_findings, llm_result)
        if suppressed_ids:
            logger.info(
                "LLM suppressed %d prior finding(s) as false positives for %s: %s",
                len(suppressed_ids),
                context.skill.file_path,
                suppressed_ids,
            )

        # 7. Store raw analysis in context
        context.llm_analysis = {
            "threat_assessment": llm_result.threat_assessment,
            "confidence": llm_result.confidence,
            "summary": llm_result.summary,
            "raw_findings_count": len(llm_result.findings),
            "suppressed_finding_ids": suppressed_ids,
        }

        # 8. Convert to standard Finding objects
        findings = llm_findings_to_findings(llm_result, context.skill)

        logger.info(
            "LLM analyzer found %d findings for %s (assessment=%s, confidence=%.2f)",
            len(findings),
            context.skill.file_path,
            llm_result.threat_assessment,
            llm_result.confidence,
        )

        return findings
