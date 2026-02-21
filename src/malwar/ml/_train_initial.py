# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""One-off script to train the initial model from test fixtures."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    """Train initial model weights from test fixtures."""
    from malwar.ml.trainer import ModelTrainer

    fixtures_dir = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "skills"
    benign_dir = fixtures_dir / "benign"
    malicious_dir = fixtures_dir / "malicious"

    labeled_files: list[tuple[str, bool]] = []

    for md_file in sorted(benign_dir.glob("*.md")):
        labeled_files.append((str(md_file), False))

    for md_file in sorted(malicious_dir.glob("*.md")):
        labeled_files.append((str(md_file), True))

    print(f"Training on {len(labeled_files)} files "  # noqa: T201
          f"({sum(1 for _, m in labeled_files if not m)} benign, "
          f"{sum(1 for _, m in labeled_files if m)} malicious)")

    trainer = ModelTrainer(learning_rate=0.5, epochs=1000, l2_lambda=0.001)
    model = trainer.train_from_files(labeled_files)

    weights_path = Path(__file__).parent / "weights.json"
    model.save(weights_path)

    print(f"Model saved to {weights_path}")  # noqa: T201
    print(f"Training accuracy: {model.metadata.training_accuracy:.2%}")  # noqa: T201

    # Verify predictions
    from malwar.ml.features import FeatureExtractor
    from malwar.parsers.skill_parser import parse_skill_content

    extractor = FeatureExtractor()
    correct = 0
    total = 0
    for file_path, is_malicious in labeled_files:
        raw = Path(file_path).read_text(encoding="utf-8")
        skill = parse_skill_content(raw, file_path=file_path)
        features = extractor.extract(skill)
        prob = model.predict_proba(features)
        predicted = prob >= 0.5
        status = "OK" if predicted == is_malicious else "WRONG"
        label = "MALICIOUS" if is_malicious else "BENIGN"
        print(f"  {status} {label:9s} p={prob:.4f} {Path(file_path).name}")  # noqa: T201
        if predicted == is_malicious:
            correct += 1
        total += 1

    print(f"\nVerification: {correct}/{total} correct ({correct/total:.0%})")  # noqa: T201


if __name__ == "__main__":
    main()
    sys.exit(0)
