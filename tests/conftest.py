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


@pytest.fixture(autouse=True)
def _clear_rate_limit_state():
    """Reset the in-memory rate-limit state between tests."""
    from malwar.api.middleware import _request_log

    _request_log.clear()
    yield
    _request_log.clear()


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset the scan cache singleton between tests."""
    from malwar.cache.manager import reset_cache_manager

    reset_cache_manager()
    yield
    reset_cache_manager()
