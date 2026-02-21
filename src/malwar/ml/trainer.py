# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Model trainer: trains/retrains logistic regression from labeled scan data."""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime
from pathlib import Path

from malwar.ml.features import FEATURE_NAMES, FeatureExtractor
from malwar.ml.model import ModelMetadata, RiskScorer, _sigmoid
from malwar.models.skill import SkillContent

logger = logging.getLogger("malwar.ml.trainer")


class ModelTrainer:
    """Train a logistic regression model from labeled SkillContent samples.

    Uses gradient descent on binary cross-entropy loss with L2 regularization.
    All math is pure Python -- no numpy or sklearn dependency.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        epochs: int = 500,
        l2_lambda: float = 0.01,
    ) -> None:
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2_lambda = l2_lambda
        self._extractor = FeatureExtractor()

    @staticmethod
    def _compute_mean_std(
        feature_matrix: list[list[float]],
    ) -> tuple[list[float], list[float]]:
        """Compute per-feature mean and standard deviation."""
        n = len(feature_matrix)
        if n == 0:
            return [], []

        num_features = len(feature_matrix[0])
        means = [0.0] * num_features
        stds = [0.0] * num_features

        for row in feature_matrix:
            for j in range(num_features):
                means[j] += row[j]

        for j in range(num_features):
            means[j] /= n

        for row in feature_matrix:
            for j in range(num_features):
                stds[j] += (row[j] - means[j]) ** 2

        for j in range(num_features):
            stds[j] = math.sqrt(stds[j] / max(n, 1))
            if stds[j] < 1e-10:
                stds[j] = 1.0  # Avoid division by zero

        return means, stds

    @staticmethod
    def _standardize_matrix(
        matrix: list[list[float]],
        means: list[float],
        stds: list[float],
    ) -> list[list[float]]:
        """Standardize a feature matrix in place."""
        result: list[list[float]] = []
        for row in matrix:
            standardized = [
                (x - mu) / max(sigma, 1e-10)
                for x, mu, sigma in zip(row, means, stds, strict=True)
            ]
            result.append(standardized)
        return result

    def train(
        self,
        samples: list[tuple[SkillContent, bool]],
    ) -> RiskScorer:
        """Train a model from labeled samples.

        Parameters
        ----------
        samples:
            List of (SkillContent, is_malicious) tuples.

        Returns
        -------
        A trained RiskScorer instance.
        """
        if len(samples) < 2:
            msg = "Need at least 2 samples to train"
            raise ValueError(msg)

        # Extract features
        feature_matrix: list[list[float]] = []
        labels: list[float] = []
        for skill, is_malicious in samples:
            features = self._extractor.extract(skill)
            feature_matrix.append(features)
            labels.append(1.0 if is_malicious else 0.0)

        n = len(feature_matrix)
        num_features = len(FEATURE_NAMES)

        # Compute normalization parameters
        means, stds = self._compute_mean_std(feature_matrix)

        # Standardize
        standardized = self._standardize_matrix(feature_matrix, means, stds)

        # Initialize weights
        weights = [0.0] * num_features
        bias = 0.0

        # Gradient descent
        for epoch in range(self.epochs):
            # Forward pass
            predictions = []
            for row in standardized:
                z = sum(w * x for w, x in zip(weights, row, strict=True)) + bias
                predictions.append(_sigmoid(z))

            # Compute loss (for logging)
            loss = 0.0
            for y_true, y_pred in zip(labels, predictions, strict=True):
                y_pred_clipped = max(min(y_pred, 1.0 - 1e-15), 1e-15)
                loss -= y_true * math.log(y_pred_clipped) + (
                    1 - y_true
                ) * math.log(1 - y_pred_clipped)
            loss /= n
            # Add L2 regularization to loss
            loss += (self.l2_lambda / (2 * n)) * sum(w * w for w in weights)

            # Compute gradients
            grad_w = [0.0] * num_features
            grad_b = 0.0
            for i in range(n):
                error = predictions[i] - labels[i]
                for j in range(num_features):
                    grad_w[j] += error * standardized[i][j]
                grad_b += error

            # Average gradients and add L2 regularization
            for j in range(num_features):
                grad_w[j] = grad_w[j] / n + (self.l2_lambda / n) * weights[j]
            grad_b /= n

            # Update weights
            for j in range(num_features):
                weights[j] -= self.learning_rate * grad_w[j]
            bias -= self.learning_rate * grad_b

            if epoch % 100 == 0:
                logger.debug("Epoch %d: loss=%.6f", epoch, loss)

        # Compute training accuracy
        correct = 0
        for i in range(n):
            z = sum(w * x for w, x in zip(weights, standardized[i], strict=True)) + bias
            pred = 1.0 if _sigmoid(z) >= 0.5 else 0.0
            if pred == labels[i]:
                correct += 1
        accuracy = correct / n

        logger.info(
            "Training complete: %d samples, accuracy=%.2f%%, final_loss=%.6f",
            n,
            accuracy * 100,
            loss,
        )

        metadata = ModelMetadata(
            version="1.0.0",
            trained_at=datetime.now(UTC).isoformat(),
            num_features=num_features,
            training_samples=n,
            training_accuracy=accuracy,
            feature_names=list(FEATURE_NAMES),
        )

        return RiskScorer(
            weights=weights,
            bias=bias,
            feature_means=means,
            feature_stds=stds,
            metadata=metadata,
        )

    def train_from_files(
        self,
        labeled_files: list[tuple[str, bool]],
    ) -> RiskScorer:
        """Train from file paths with labels.

        Parameters
        ----------
        labeled_files:
            List of (file_path, is_malicious) tuples.

        Returns
        -------
        A trained RiskScorer instance.
        """
        from malwar.parsers.skill_parser import parse_skill_content

        samples: list[tuple[SkillContent, bool]] = []
        for file_path, is_malicious in labeled_files:
            raw_content = Path(file_path).read_text(encoding="utf-8")
            skill = parse_skill_content(raw_content, file_path=file_path)
            samples.append((skill, is_malicious))

        return self.train(samples)

    def save_model(
        self,
        model: RiskScorer,
        path: str | Path | None = None,
    ) -> None:
        """Save a trained model to disk."""
        model.save(path)
