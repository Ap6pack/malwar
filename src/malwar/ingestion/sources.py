# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Threat source adapters for ingesting campaign data from external formats.

Provides a base ``ThreatSource`` class and concrete implementations for
JSON files, CSV files, STIX 2.1 bundles, and HTTP feeds.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IOCData:
    """A single indicator of compromise."""

    type: str  # ip, domain, url, hash
    value: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class SignatureData:
    """A detection signature to import."""

    pattern_type: str  # exact, regex, fuzzy, ioc
    pattern_value: str
    ioc_type: str  # ip, domain, url, hash
    severity: str = "medium"
    confidence: float = 0.8


@dataclass(slots=True)
class CampaignData:
    """Represents a campaign with its IOCs and signatures."""

    name: str
    attributed_to: str = ""
    first_seen: str = ""
    iocs: list[IOCData] = field(default_factory=list)
    signatures: list[SignatureData] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class ThreatSource(ABC):
    """Base class for threat intelligence sources."""

    name: str

    @abstractmethod
    async def fetch(self) -> list[CampaignData]:
        """Fetch campaigns and IOCs from this source.

        Returns a list of ``CampaignData`` objects ready for import.
        """


# ---------------------------------------------------------------------------
# JSON file source
# ---------------------------------------------------------------------------


class JsonFileSource(ThreatSource):
    """Import campaigns from a JSON file matching the ``ImportPayload`` schema."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.name = f"json:{self._path.name}"

    async def fetch(self) -> list[CampaignData]:
        from malwar.ingestion.schema import ImportPayload

        text = self._path.read_text(encoding="utf-8")
        payload = ImportPayload.model_validate_json(text)
        return _payload_to_campaigns(payload)


class JsonStringSource(ThreatSource):
    """Import campaigns from a raw JSON string (used by the API endpoint)."""

    def __init__(self, data: str) -> None:
        self._data = data
        self.name = "json:api"

    async def fetch(self) -> list[CampaignData]:
        from malwar.ingestion.schema import ImportPayload

        payload = ImportPayload.model_validate_json(self._data)
        return _payload_to_campaigns(payload)


def _payload_to_campaigns(payload: Any) -> list[CampaignData]:
    """Convert a validated ``ImportPayload`` to a list of ``CampaignData``."""
    results: list[CampaignData] = []
    for c in payload.campaigns:
        iocs = [IOCData(type=i.type, value=i.value, description=i.description) for i in c.iocs]
        sigs = [
            SignatureData(
                pattern_type=s.pattern_type,
                pattern_value=s.pattern_value,
                ioc_type=s.ioc_type,
                severity=s.severity,
                confidence=s.confidence,
            )
            for s in c.signatures
        ]
        results.append(
            CampaignData(
                name=c.name,
                attributed_to=c.attributed_to,
                first_seen=c.first_seen,
                iocs=iocs,
                signatures=sigs,
            )
        )
    return results


# ---------------------------------------------------------------------------
# CSV file source
# ---------------------------------------------------------------------------


class CsvFileSource(ThreatSource):
    """Import campaigns from a CSV file.

    Expected columns: ``campaign``, ``ioc_type``, ``ioc_value``, ``severity``.
    Rows are grouped by campaign name.  Each row produces an IOC and a
    corresponding exact-match signature.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.name = f"csv:{self._path.name}"

    async def fetch(self) -> list[CampaignData]:
        text = self._path.read_text(encoding="utf-8")
        return _parse_csv(text)


class CsvStringSource(ThreatSource):
    """Import campaigns from a raw CSV string (used by the API endpoint)."""

    def __init__(self, data: str) -> None:
        self._data = data
        self.name = "csv:api"

    async def fetch(self) -> list[CampaignData]:
        return _parse_csv(self._data)


def _parse_csv(text: str) -> list[CampaignData]:
    """Parse CSV text into campaign data, grouping rows by campaign name."""
    reader = csv.DictReader(io.StringIO(text))

    # Validate required columns
    required = {"campaign", "ioc_type", "ioc_value", "severity"}
    if reader.fieldnames is None:
        msg = "CSV file is empty or has no header row"
        raise ValueError(msg)

    missing = required - set(reader.fieldnames)
    if missing:
        msg = f"CSV missing required columns: {', '.join(sorted(missing))}"
        raise ValueError(msg)

    groups: dict[str, CampaignData] = {}

    for row in reader:
        name = row["campaign"].strip()
        if not name:
            continue

        ioc_type = row["ioc_type"].strip()
        ioc_value = row["ioc_value"].strip()
        severity = row.get("severity", "medium").strip() or "medium"

        if name not in groups:
            groups[name] = CampaignData(name=name)

        campaign = groups[name]
        campaign.iocs.append(IOCData(type=ioc_type, value=ioc_value))
        campaign.signatures.append(
            SignatureData(
                pattern_type="exact",
                pattern_value=ioc_value,
                ioc_type=ioc_type,
                severity=severity,
            )
        )

    return list(groups.values())


# ---------------------------------------------------------------------------
# STIX 2.1 bundle source
# ---------------------------------------------------------------------------


class StixBundleSource(ThreatSource):
    """Import campaigns from a STIX 2.1 JSON bundle.

    This is the reverse of Malwar's STIX export.  It extracts campaigns,
    threat actors, and indicators from the bundle and maps them back to
    ``CampaignData`` objects.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.name = f"stix:{self._path.name}"

    async def fetch(self) -> list[CampaignData]:
        text = self._path.read_text(encoding="utf-8")
        return _parse_stix_bundle(text)


class StixStringSource(ThreatSource):
    """Import campaigns from a raw STIX JSON string (used by the API endpoint)."""

    def __init__(self, data: str) -> None:
        self._data = data
        self.name = "stix:api"

    async def fetch(self) -> list[CampaignData]:
        return _parse_stix_bundle(self._data)


# Reverse map: STIX pattern -> (ioc_type, value)
_STIX_PATTERN_RE = re.compile(
    r"\["
    r"(?:ipv4-addr:value|domain-name:value|url:value|file:hashes\.'SHA-256'|email-addr:value|artifact:payload_bin)"
    r"\s*=\s*'([^']+)'"
    r"\]"
)

_STIX_TYPE_MAP: dict[str, str] = {
    "ipv4-addr:value": "ip",
    "domain-name:value": "domain",
    "url:value": "url",
    "file:hashes.'SHA-256'": "hash",
    "email-addr:value": "email",
    "artifact:payload_bin": "hash",
}


def _extract_ioc_from_pattern(pattern: str) -> tuple[str, str] | None:
    """Extract (ioc_type, value) from a STIX indicator pattern string."""
    match = _STIX_PATTERN_RE.search(pattern)
    if not match:
        return None

    value = match.group(1)

    # Determine type from the observable in the pattern
    for stix_key, ioc_type in _STIX_TYPE_MAP.items():
        if stix_key in pattern:
            return ioc_type, value

    return None


def _parse_stix_bundle(text: str) -> list[CampaignData]:
    """Parse a STIX 2.1 bundle JSON string into campaign data."""
    bundle = json.loads(text)

    if bundle.get("type") != "bundle":
        msg = "Input is not a STIX 2.1 bundle (missing type: bundle)"
        raise ValueError(msg)

    objects = bundle.get("objects", [])

    # Index objects by ID
    obj_by_id: dict[str, dict[str, Any]] = {
        obj["id"]: obj for obj in objects if "id" in obj
    }

    # Collect campaigns
    stix_campaigns: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") == "campaign":
            stix_campaigns[obj["id"]] = obj

    # Build relationship maps: campaign_id -> list[indicator_id]
    campaign_indicators: dict[str, list[str]] = {cid: [] for cid in stix_campaigns}
    # Also map campaign -> threat-actor for attribution
    campaign_attribution: dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")

        if rel_type == "indicates" and target in stix_campaigns:
            campaign_indicators.setdefault(target, []).append(source)
        elif rel_type == "attributed-to" and source in stix_campaigns:
            # target is a threat-actor
            ta = obj_by_id.get(target)
            if ta:
                campaign_attribution[source] = ta.get("name", "")

    # Convert to CampaignData
    results: list[CampaignData] = []

    for cid, campaign_obj in stix_campaigns.items():
        name = campaign_obj.get("name", "")
        first_seen = campaign_obj.get("first_seen", "")
        if first_seen and "T" in first_seen:
            first_seen = first_seen.split("T")[0]

        attributed_to = campaign_attribution.get(cid, "")

        iocs: list[IOCData] = []
        sigs: list[SignatureData] = []

        for ind_id in campaign_indicators.get(cid, []):
            indicator = obj_by_id.get(ind_id)
            if not indicator or indicator.get("type") != "indicator":
                continue

            pattern = indicator.get("pattern", "")
            extracted = _extract_ioc_from_pattern(pattern)
            if not extracted:
                continue

            ioc_type, value = extracted
            severity = "medium"
            # Try to extract severity from labels
            for label in indicator.get("labels", []):
                if label.startswith("severity:"):
                    severity = label.split(":")[1]
                    break

            confidence = 0.8
            if indicator.get("confidence") is not None:
                raw_conf = indicator["confidence"]
                confidence = raw_conf / 100.0 if raw_conf > 1 else raw_conf

            iocs.append(IOCData(type=ioc_type, value=value))
            sigs.append(
                SignatureData(
                    pattern_type="exact",
                    pattern_value=value,
                    ioc_type=ioc_type,
                    severity=severity,
                    confidence=confidence,
                )
            )

        results.append(
            CampaignData(
                name=name,
                attributed_to=attributed_to,
                first_seen=first_seen,
                iocs=iocs,
                signatures=sigs,
            )
        )

    # If no campaigns found but there are standalone indicators, group them
    if not results:
        standalone_indicators = [
            obj for obj in objects if obj.get("type") == "indicator"
        ]
        if standalone_indicators:
            iocs: list[IOCData] = []
            sigs: list[SignatureData] = []
            for indicator in standalone_indicators:
                pattern = indicator.get("pattern", "")
                extracted = _extract_ioc_from_pattern(pattern)
                if not extracted:
                    continue
                ioc_type, value = extracted
                severity = "medium"
                for label in indicator.get("labels", []):
                    if label.startswith("severity:"):
                        severity = label.split(":")[1]
                        break
                iocs.append(IOCData(type=ioc_type, value=value))
                sigs.append(
                    SignatureData(
                        pattern_type="exact",
                        pattern_value=value,
                        ioc_type=ioc_type,
                        severity=severity,
                    )
                )
            if iocs:
                results.append(
                    CampaignData(
                        name="Imported STIX Indicators",
                        iocs=iocs,
                        signatures=sigs,
                    )
                )

    return results


# ---------------------------------------------------------------------------
# HTTP feed source
# ---------------------------------------------------------------------------


class HttpFeedSource(ThreatSource):
    """Fetch threat data from an HTTP endpoint (JSON or CSV).

    Supports ETag-based caching: if the server responds with an ``ETag``
    header, subsequent fetches include ``If-None-Match``.  A 304 response
    returns an empty list (no new data).
    """

    def __init__(
        self,
        url: str,
        *,
        format: str = "json",  # noqa: A002
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._url = url
        self._format = format
        self._headers = headers or {}
        self._timeout = timeout
        self._etag: str | None = None
        self.name = f"http:{url}"

    async def fetch(self) -> list[CampaignData]:
        import httpx

        request_headers = dict(self._headers)
        if self._etag:
            request_headers["If-None-Match"] = self._etag

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(self._url, headers=request_headers)

        # Cache hit — no new data
        if response.status_code == 304:
            logger.info("HTTP feed %s returned 304 Not Modified", self._url)
            return []

        response.raise_for_status()

        # Store ETag for next fetch
        etag = response.headers.get("etag")
        if etag:
            self._etag = etag

        text = response.text

        if self._format == "csv":
            return _parse_csv(text)

        # Default to JSON
        from malwar.ingestion.schema import ImportPayload

        payload = ImportPayload.model_validate_json(text)
        return _payload_to_campaigns(payload)
