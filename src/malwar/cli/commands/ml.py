# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""CLI commands for ML risk scoring model management."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def train(
    fixtures_dir: Annotated[
        str | None,
        typer.Option(
            "--fixtures-dir",
            help="Directory containing benign/ and malicious/ subdirs with labeled .md files",
        ),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output path for weights.json"),
    ] = None,
    learning_rate: Annotated[
        float,
        typer.Option("--lr", help="Learning rate for gradient descent"),
    ] = 0.5,
    epochs: Annotated[
        int,
        typer.Option("--epochs", help="Number of training epochs"),
    ] = 1000,
) -> None:
    """Train or retrain the ML risk scoring model from labeled skill files."""
    from malwar.ml.model import RiskScorer
    from malwar.ml.trainer import ModelTrainer

    if fixtures_dir is None:
        # Default to test fixtures
        project_root = Path(__file__).resolve().parents[4]
        fixtures_path = project_root / "tests" / "fixtures" / "skills"
    else:
        fixtures_path = Path(fixtures_dir)

    benign_dir = fixtures_path / "benign"
    malicious_dir = fixtures_path / "malicious"

    if not benign_dir.is_dir():
        typer.echo(f"Benign directory not found: {benign_dir}", err=True)
        raise typer.Exit(1)
    if not malicious_dir.is_dir():
        typer.echo(f"Malicious directory not found: {malicious_dir}", err=True)
        raise typer.Exit(1)

    labeled_files: list[tuple[str, bool]] = []
    for md_file in sorted(benign_dir.glob("*.md")):
        labeled_files.append((str(md_file), False))
    for md_file in sorted(malicious_dir.glob("*.md")):
        labeled_files.append((str(md_file), True))

    benign_count = sum(1 for _, m in labeled_files if not m)
    malicious_count = sum(1 for _, m in labeled_files if m)
    typer.echo(f"Training on {len(labeled_files)} files ({benign_count} benign, {malicious_count} malicious)")

    trainer = ModelTrainer(learning_rate=learning_rate, epochs=epochs)
    model = trainer.train_from_files(labeled_files)

    if output:
        weights_path = Path(output)
    else:
        weights_path = Path(RiskScorer.default.__func__.__code__.co_filename).parent / "weights.json"  # type: ignore[attr-defined]
        # Simpler: use the module path
        from malwar.ml import model as ml_model_mod

        weights_path = Path(ml_model_mod.__file__).parent / "weights.json"

    model.save(weights_path)
    typer.echo(f"Model saved to {weights_path}")
    typer.echo(f"Training accuracy: {model.metadata.training_accuracy:.2%}")


@app.command()
def info() -> None:
    """Show metadata about the current ML risk scoring model."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    from malwar.ml.features import FEATURE_NAMES
    from malwar.ml.model import RiskScorer

    console = Console()

    try:
        model = RiskScorer.default()
    except Exception as exc:
        typer.echo(f"Failed to load model: {exc}", err=True)
        raise typer.Exit(1) from exc

    meta = model.metadata

    info_lines = [
        f"Version:           {meta.version}",
        f"Trained at:        {meta.trained_at}",
        f"Features:          {meta.num_features}",
        f"Training samples:  {meta.training_samples}",
        f"Training accuracy: {meta.training_accuracy:.2%}",
    ]
    console.print(Panel("\n".join(info_lines), title="ML Risk Scoring Model"))

    # Feature weights table
    table = Table(title="Feature Weights")
    table.add_column("Feature", style="cyan")
    table.add_column("Weight", justify="right", style="bold")
    table.add_column("Mean", justify="right")
    table.add_column("Std", justify="right")

    for i, name in enumerate(FEATURE_NAMES):
        weight = model.weights[i] if i < len(model.weights) else 0.0
        mean = model.feature_means[i] if i < len(model.feature_means) else 0.0
        std = model.feature_stds[i] if i < len(model.feature_stds) else 1.0
        table.add_row(name, f"{weight:.4f}", f"{mean:.4f}", f"{std:.4f}")

    console.print(table)
    console.print(f"\nBias: {model.bias:.4f}")
