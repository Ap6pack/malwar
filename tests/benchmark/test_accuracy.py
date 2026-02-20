# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Detection accuracy benchmark — runs all test fixtures through the scanner.

Scans every .md fixture in tests/fixtures/skills/ using the rule_engine and
threat_intel layers (no LLM, no URL crawling) and publishes precision/recall
metrics against known ground-truth labels.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from malwar import scan
from malwar.models.scan import ScanResult

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "skills"

BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
REAL_BENIGN_DIR = FIXTURES_DIR / "real" / "benign"
REAL_MALICIOUS_DIR = FIXTURES_DIR / "real" / "malicious"
REAL_CLAWHUB_DIR = FIXTURES_DIR / "real" / "clawhub"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class FixtureResult:
    """Result of scanning a single fixture file."""

    file_path: str
    category: str
    expected: str  # "CLEAN" or "MALICIOUS"
    actual_verdict: str
    risk_score: int
    findings_count: int
    matched_rule_ids: list[str] = field(default_factory=list)
    correct: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_fixtures() -> list[tuple[Path, str, str]]:
    """Return list of (path, category, expected_verdict) tuples."""
    fixtures: list[tuple[Path, str, str]] = []

    for md in sorted(BENIGN_DIR.glob("*.md")):
        fixtures.append((md, "benign", "CLEAN"))

    for md in sorted(MALICIOUS_DIR.glob("*.md")):
        fixtures.append((md, "malicious", "MALICIOUS"))

    for md in sorted(REAL_BENIGN_DIR.glob("*.md")):
        fixtures.append((md, "real/benign", "CLEAN"))

    for md in sorted(REAL_MALICIOUS_DIR.glob("*.md")):
        fixtures.append((md, "real/malicious", "MALICIOUS"))

    for md in sorted(REAL_CLAWHUB_DIR.glob("*.md")):
        # clawhub samples: classify based on actual scan results
        fixtures.append((md, "real/clawhub", "UNKNOWN"))

    return fixtures


async def _scan_fixture(path: Path) -> ScanResult:
    """Scan a single fixture file with rule_engine + threat_intel only."""
    content = path.read_text(encoding="utf-8")
    return await scan(
        content,
        file_name=path.name,
        use_llm=False,
        use_urls=False,
    )


def _is_correct(expected: str, actual: str) -> bool:
    """Check if the actual verdict matches the expected classification.

    For CLEAN expected: verdict must be CLEAN.
    For MALICIOUS expected: verdict must NOT be CLEAN (i.e. MALICIOUS,
    SUSPICIOUS, or CAUTION all count as detected).
    For UNKNOWN: always considered correct (clawhub samples).
    """
    if expected == "UNKNOWN":
        return True
    if expected == "CLEAN":
        return actual == "CLEAN"
    # expected == "MALICIOUS" — any non-CLEAN detection is a true positive
    return actual != "CLEAN"


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAccuracyBenchmark:
    """Run all fixtures and print accuracy metrics."""

    async def test_detection_accuracy(self) -> None:
        fixtures = _collect_fixtures()
        assert len(fixtures) > 0, "No fixture files found"

        results: list[FixtureResult] = []
        rule_counter: Counter[str] = Counter()
        category_stats: dict[str, dict[str, int]] = {}

        for path, category, expected in fixtures:
            result = await _scan_fixture(path)
            rule_ids = [f.rule_id for f in result.findings]
            rule_counter.update(rule_ids)

            correct = _is_correct(expected, result.verdict)
            fr = FixtureResult(
                file_path=str(path.relative_to(FIXTURES_DIR)),
                category=category,
                expected=expected,
                actual_verdict=result.verdict,
                risk_score=result.risk_score,
                findings_count=len(result.findings),
                matched_rule_ids=rule_ids,
                correct=correct,
            )
            results.append(fr)

            # Per-category stats
            if category not in category_stats:
                category_stats[category] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
            stats = category_stats[category]
            if expected == "UNKNOWN":
                pass  # clawhub samples don't count in metrics
            elif expected == "MALICIOUS" and correct:
                stats["tp"] += 1
            elif expected == "MALICIOUS" and not correct:
                stats["fn"] += 1
            elif expected == "CLEAN" and correct:
                stats["tn"] += 1
            elif expected == "CLEAN" and not correct:
                stats["fp"] += 1

        # ---------------------------------------------------------------
        # Compute overall metrics (exclude UNKNOWN / clawhub)
        # ---------------------------------------------------------------
        labeled = [r for r in results if r.expected != "UNKNOWN"]
        tp = sum(1 for r in labeled if r.expected == "MALICIOUS" and r.correct)
        fn = sum(1 for r in labeled if r.expected == "MALICIOUS" and not r.correct)
        tn = sum(1 for r in labeled if r.expected == "CLEAN" and r.correct)
        fp = sum(1 for r in labeled if r.expected == "CLEAN" and not r.correct)

        total_labeled = len(labeled)
        accuracy = (tp + tn) / total_labeled if total_labeled else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0

        # ---------------------------------------------------------------
        # Print summary
        # ---------------------------------------------------------------



        for _r in results:
            pass

        for _rule_id, _count in rule_counter.most_common():
            pass

        for cat in sorted(category_stats):
            s = category_stats[cat]
            cat_total = s["tp"] + s["fp"] + s["tn"] + s["fn"]
            (s["tp"] + s["tn"]) / cat_total if cat_total else 0

        # ---------------------------------------------------------------
        # Print false positives and false negatives
        # ---------------------------------------------------------------
        fps = [r for r in labeled if r.expected == "CLEAN" and not r.correct]
        fns = [r for r in labeled if r.expected == "MALICIOUS" and not r.correct]

        if fps:
            for r in fps:
                for _rid in r.matched_rule_ids:
                    pass

        if fns:
            for _r in fns:
                pass

        # ---------------------------------------------------------------
        # Clawhub sample results
        # ---------------------------------------------------------------
        clawhub_results = [r for r in results if r.expected == "UNKNOWN"]
        if clawhub_results:
            for r in clawhub_results:
                for _rid in r.matched_rule_ids:
                    pass


        # ---------------------------------------------------------------
        # Assertions — the benchmark should not regress
        # ---------------------------------------------------------------
        assert accuracy >= 0.70, (
            f"Accuracy {accuracy:.1%} dropped below 70% threshold"
        )
        assert recall >= 0.70, (
            f"Recall {recall:.1%} dropped below 70% threshold"
        )

        # Store results on the class for report generation
        TestAccuracyBenchmark._results = results
        TestAccuracyBenchmark._metrics = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": accuracy, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr,
        }
        TestAccuracyBenchmark._rule_counter = rule_counter
        TestAccuracyBenchmark._category_stats = category_stats
