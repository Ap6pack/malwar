"""Campaign ingestion system for importing threat intelligence from external sources."""

from malwar.ingestion.importer import CampaignImporter, ImportResult
from malwar.ingestion.sources import (
    CampaignData,
    CsvFileSource,
    HttpFeedSource,
    IOCData,
    JsonFileSource,
    SignatureData,
    StixBundleSource,
    ThreatSource,
)

__all__ = [
    "CampaignData",
    "CampaignImporter",
    "CsvFileSource",
    "HttpFeedSource",
    "IOCData",
    "ImportResult",
    "JsonFileSource",
    "SignatureData",
    "StixBundleSource",
    "ThreatSource",
]
