# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Storage layer -- database backends, migrations, and repositories."""

from malwar.storage.backend import DatabaseBackend
from malwar.storage.database import close_db, get_backend, get_db, init_backend, init_db
from malwar.storage.migrations import run_migrations
from malwar.storage.query_adapter import adapt_query
from malwar.storage.repositories.campaigns import CampaignRepository
from malwar.storage.repositories.findings import FindingRepository
from malwar.storage.repositories.publishers import PublisherRepository
from malwar.storage.repositories.scans import ScanRepository
from malwar.storage.repositories.signatures import SignatureRepository

__all__ = [
    "CampaignRepository",
    "DatabaseBackend",
    "FindingRepository",
    "PublisherRepository",
    "ScanRepository",
    "SignatureRepository",
    "adapt_query",
    "close_db",
    "get_backend",
    "get_db",
    "init_backend",
    "init_db",
    "run_migrations",
]
