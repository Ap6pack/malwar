# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Calibrator: blends ML risk score with rule engine risk score."""

from __future__ import annotations

import logging

logger = logging.getLogger("malwar.ml.calibrator")


class RiskCalibrator:
    """Combine ML-based and rule-engine risk scores using a weighted average.

    Parameters
    ----------
    ml_weight:
        Weight assigned to the ML risk score (0.0 to 1.0).
        The rule engine score gets weight ``1 - ml_weight``.
    """

    def __init__(self, ml_weight: float = 0.3) -> None:
        if not 0.0 <= ml_weight <= 1.0:
            msg = f"ml_weight must be between 0.0 and 1.0, got {ml_weight}"
            raise ValueError(msg)
        self.ml_weight = ml_weight

    def calibrate(
        self,
        rule_score: int,
        ml_probability: float,
    ) -> float:
        """Blend a rule engine risk score with an ML probability.

        Parameters
        ----------
        rule_score:
            Rule engine risk score, integer in [0, 100].
        ml_probability:
            ML model output probability in [0.0, 1.0].

        Returns
        -------
        Blended risk score as a float in [0.0, 100.0].
        """
        # Normalize rule_score to [0, 100] range
        rule_normalized = max(0.0, min(float(rule_score), 100.0))

        # Convert ML probability to 0-100 scale
        ml_score = ml_probability * 100.0

        rule_weight = 1.0 - self.ml_weight
        blended = rule_weight * rule_normalized + self.ml_weight * ml_score

        logger.debug(
            "Calibration: rule=%.1f (w=%.2f) + ml=%.1f (w=%.2f) = %.1f",
            rule_normalized,
            rule_weight,
            ml_score,
            self.ml_weight,
            blended,
        )

        return max(0.0, min(blended, 100.0))

    def calibrate_int(
        self,
        rule_score: int,
        ml_probability: float,
    ) -> int:
        """Blended risk score as an integer (rounded)."""
        return round(self.calibrate(rule_score, ml_probability))
