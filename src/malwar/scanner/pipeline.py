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
        cache_manager: object | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._detectors: list[BaseDetector] = []
        if detectors:
            self._detectors = sorted(detectors, key=lambda d: d.order)
        # Cache manager for scan deduplication (lazy import avoids circular deps)
        self._cache_manager = cache_manager

    def register_detector(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)
        self._detectors.sort(key=lambda d: d.order)

    async def setup(self) -> None:
        for detector in self._detectors:
            await detector.setup()

    async def teardown(self) -> None:
        for detector in self._detectors:
            await detector.teardown()

    def _get_cache_manager(self):
        """Return the cache manager, lazily importing the singleton if needed."""
        if self._cache_manager is not None:
            return self._cache_manager
        try:
            from malwar.cache.manager import get_cache_manager

            return get_cache_manager()
        except Exception:
            return None

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
        scan_layers = layers or list(self._settings.scan_default_layers)

        # --- Cache lookup ---
        cache_mgr = self._get_cache_manager()
        if cache_mgr is not None:
            try:
                cached = await cache_mgr.get_cached_result(
                    content=skill.raw_content,
                    layers=scan_layers,
                )
                if cached is not None:
                    logger.info("Returning cached result for %s", skill.file_path)
                    return cached  # type: ignore[no-any-return]
            except Exception:
                logger.debug("Cache lookup failed, proceeding with scan", exc_info=True)

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

        # --- ML risk scoring (after rule engine) ---
        if self._settings.ml_enabled:
            try:
                from malwar.ml.calibrator import RiskCalibrator
                from malwar.ml.features import FeatureExtractor
                from malwar.ml.model import RiskScorer

                extractor = FeatureExtractor()
                features = extractor.extract(skill)
                scorer = RiskScorer.default()
                ml_prob = scorer.predict_proba(features)
                result.ml_risk_score = ml_prob

                calibrator = RiskCalibrator(ml_weight=self._settings.ml_weight)
                blended = calibrator.calibrate(result.risk_score, ml_prob)
                logger.info(
                    "ML scoring: prob=%.4f rule=%d blended=%.1f",
                    ml_prob,
                    result.risk_score,
                    blended,
                )
            except Exception as exc:
                logger.warning("ML scoring failed: %s", exc)

        logger.info(
            "Scan %s complete: verdict=%s risk=%d findings=%d duration=%dms",
            scan_id,
            result.verdict,
            result.risk_score,
            len(result.findings),
            elapsed_ms,
        )

        # --- Cache store ---
        if cache_mgr is not None:
            try:
                await cache_mgr.store_result(
                    content=skill.raw_content,
                    layers=scan_layers,
                    result=result,
                )
            except Exception:
                logger.debug("Failed to cache scan result", exc_info=True)

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
