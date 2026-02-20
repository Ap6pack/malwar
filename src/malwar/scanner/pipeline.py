# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Scanner pipeline orchestrator — chains the 4 detection layers."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

from malwar.core.config import Settings, get_settings
from malwar.core.constants import ScanStatus
from malwar.core.exceptions import ScanError
from malwar.models.scan import ScanResult
from malwar.models.skill import SkillContent
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

logger = logging.getLogger("malwar.scanner.pipeline")


class ScanPipeline:
    """Orchestrates the 4-layer detection pipeline.

    Layers execute sequentially: rule_engine -> url_crawler -> llm_analyzer -> threat_intel.
    Each layer enriches the shared ScanContext.
    """

    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._detectors: list[BaseDetector] = []
        if detectors:
            self._detectors = sorted(detectors, key=lambda d: d.order)

    def register_detector(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)
        self._detectors.sort(key=lambda d: d.order)

    async def setup(self) -> None:
        for detector in self._detectors:
            await detector.setup()

    async def teardown(self) -> None:
        for detector in self._detectors:
            await detector.teardown()

    async def scan(
        self,
        skill: SkillContent,
        layers: list[str] | None = None,
    ) -> ScanResult:
        """Run the detection pipeline on a parsed skill.

        Args:
            skill: Parsed SKILL.md content.
            layers: Optional list of layer names to execute.
                    Defaults to all registered detectors.

        Returns:
            ScanResult with findings from all executed layers.
        """
        scan_id = uuid.uuid4().hex[:12]
        allowed_layers = set(layers) if layers else None

        context = ScanContext(skill=skill, scan_id=scan_id)
        result = ScanResult(
            scan_id=scan_id,
            target=skill.file_path,
            status=ScanStatus.RUNNING,
            skill_sha256=skill.sha256_hash,
            skill_name=skill.metadata.name,
            skill_author=skill.metadata.author,
        )

        start_time = time.monotonic()

        for detector in self._detectors:
            if allowed_layers and detector.layer_name not in allowed_layers:
                continue

            # Skip LLM layer if risk is below threshold (cost control)
            # But never skip if the user explicitly requested this layer
            if (
                detector.layer_name == "llm_analyzer"
                and context.current_risk_score < self._settings.llm_skip_below_risk
                and allowed_layers is None
            ):
                logger.info(
                    "Skipping LLM analysis: risk score %d < threshold %d",
                    context.current_risk_score,
                    self._settings.llm_skip_below_risk,
                )
                continue

            try:
                logger.info("Running detector: %s", detector.layer_name)
                findings = await detector.detect(context)
                context.add_findings(findings)
                result.layers_executed.append(detector.layer_name)
            except Exception as exc:
                error_msg = f"{detector.layer_name}: {exc}"
                logger.error("Detector failed: %s", error_msg)
                context.errors.append(error_msg)
                result.errors.append(error_msg)

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        result.findings = context.findings
        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.now(UTC)
        result.duration_ms = elapsed_ms

        logger.info(
            "Scan %s complete: verdict=%s risk=%d findings=%d duration=%dms",
            scan_id,
            result.verdict,
            result.risk_score,
            len(result.findings),
            elapsed_ms,
        )

        return result

    async def scan_file(
        self,
        file_path: str,
        layers: list[str] | None = None,
    ) -> ScanResult:
        """Parse and scan a SKILL.md file.

        Convenience method that handles parsing before scanning.
        """
        from malwar.parsers.skill_parser import parse_skill_file

        try:
            skill = await parse_skill_file(file_path)
        except Exception as exc:
            raise ScanError(f"Failed to parse {file_path}: {exc}") from exc

        return await self.scan(skill, layers=layers)
