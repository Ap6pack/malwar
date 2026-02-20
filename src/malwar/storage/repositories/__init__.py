# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Repository modules for database access."""

from malwar.storage.repositories.campaigns import CampaignRepository
from malwar.storage.repositories.findings import FindingRepository
from malwar.storage.repositories.publishers import PublisherRepository
from malwar.storage.repositories.scans import ScanRepository
from malwar.storage.repositories.signatures import SignatureRepository

__all__ = [
    "CampaignRepository",
    "FindingRepository",
    "PublisherRepository",
    "ScanRepository",
    "SignatureRepository",
]
