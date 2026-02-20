# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Shared test fixtures and configuration."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


@pytest.fixture
def benign_dir() -> Path:
    return BENIGN_DIR


@pytest.fixture
def malicious_dir() -> Path:
    return MALICIOUS_DIR
