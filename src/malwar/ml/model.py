# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Logistic regression risk scorer implemented in pure Python (no numpy/sklearn)."""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
from pathlib import Path

from malwar.ml.features import FEATURE_NAMES

logger = logging.getLogger("malwar.ml.model")

# Default weights path ships with the package
_DEFAULT_WEIGHTS_PATH = Path(__file__).parent / "weights.json"


def _sigmoid(z: float) -> float:
    """Numerically stable sigmoid function."""
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    exp_z = math.exp(z)
    return exp_z / (1.0 + exp_z)


def _dot(a: list[float], b: list[float]) -> float:
    """Dot product of two equal-length vectors."""
    return sum(x * y for x, y in zip(a, b, strict=True))


class ModelMetadata:
    """Metadata about the trained model."""

    def __init__(
        self,
        version: str = "1.0.0",
        trained_at: str = "",
        num_features: int = 0,
        training_samples: int = 0,
        training_accuracy: float = 0.0,
        feature_names: list[str] | None = None,
    ) -> None:
        self.version = version
        self.trained_at = trained_at or datetime.now(UTC).isoformat()
        self.num_features = num_features
        self.training_samples = training_samples
        self.training_accuracy = training_accuracy
        self.feature_names = feature_names or list(FEATURE_NAMES)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "trained_at": self.trained_at,
            "num_features": self.num_features,
            "training_samples": self.training_samples,
            "training_accuracy": self.training_accuracy,
            "feature_names": self.feature_names,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ModelMetadata:
        return cls(
            version=str(data.get("version", "1.0.0")),
            trained_at=str(data.get("trained_at", "")),
            num_features=int(data.get("num_features", 0)),  # type: ignore[call-overload]
            training_samples=int(data.get("training_samples", 0)),  # type: ignore[call-overload]
            training_accuracy=float(data.get("training_accuracy", 0.0)),  # type: ignore[arg-type]
            feature_names=list(data.get("feature_names", FEATURE_NAMES)),  # type: ignore[call-overload]
        )


class RiskScorer:
    """Logistic regression model for malware risk probability scoring.

    Computes: P(malicious) = sigmoid(X @ weights + bias)

    Weights are loaded from a JSON file (no pickle for security).
    """

    def __init__(
        self,
        weights: list[float] | None = None,
        bias: float = 0.0,
        feature_means: list[float] | None = None,
        feature_stds: list[float] | None = None,
        metadata: ModelMetadata | None = None,
    ) -> None:
        num_features = len(FEATURE_NAMES)
        self.weights = weights or [0.0] * num_features
        self.bias = bias
        self.feature_means = feature_means or [0.0] * num_features
        self.feature_stds = feature_stds or [1.0] * num_features
        self.metadata = metadata or ModelMetadata(num_features=num_features)

    def _standardize(self, features: list[float]) -> list[float]:
        """Standardize features using stored means and standard deviations."""
        return [
            (x - mu) / max(sigma, 1e-10)
            for x, mu, sigma in zip(
                features, self.feature_means, self.feature_stds, strict=True
            )
        ]

    def predict_proba(self, features: list[float]) -> float:
        """Predict malware probability from a feature vector.

        Parameters
        ----------
        features:
            Numerical feature vector matching FEATURE_NAMES order.

        Returns
        -------
        Risk probability in [0.0, 1.0].
        """
        if len(features) != len(self.weights):
            msg = (
                f"Feature vector length {len(features)} does not match "
                f"model weight count {len(self.weights)}"
            )
            raise ValueError(msg)

        standardized = self._standardize(features)
        z = _dot(standardized, self.weights) + self.bias
        return _sigmoid(z)

    def predict(self, features: list[float], threshold: float = 0.5) -> bool:
        """Predict whether the skill is malicious (True) or benign (False)."""
        return self.predict_proba(features) >= threshold

    def save(self, path: str | Path | None = None) -> None:
        """Serialize model weights to a JSON file."""
        path = Path(path) if path else _DEFAULT_WEIGHTS_PATH
        data = {
            "weights": self.weights,
            "bias": self.bias,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "metadata": self.metadata.to_dict(),
        }
        path.write_text(json.dumps(data, indent=2))
        logger.info("Model saved to %s", path)

    @classmethod
    def load(cls, path: str | Path | None = None) -> RiskScorer:
        """Load model weights from a JSON file."""
        path = Path(path) if path else _DEFAULT_WEIGHTS_PATH
        if not path.exists():
            logger.warning("Weights file not found at %s; using default zeros", path)
            return cls()

        raw = path.read_text()
        data = json.loads(raw)
        return cls(
            weights=data["weights"],
            bias=data["bias"],
            feature_means=data.get("feature_means", [0.0] * len(data["weights"])),
            feature_stds=data.get("feature_stds", [1.0] * len(data["weights"])),
            metadata=ModelMetadata.from_dict(data.get("metadata", {})),
        )

    @classmethod
    def default(cls) -> RiskScorer:
        """Load the default shipped model."""
        return cls.load(_DEFAULT_WEIGHTS_PATH)
