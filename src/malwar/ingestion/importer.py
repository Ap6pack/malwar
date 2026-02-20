# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Campaign import engine with deduplication and merge support.

The ``CampaignImporter`` class coordinates fetching data from a
``ThreatSource``, deduplicating against existing records, and persisting
new campaigns and signatures to the database.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from malwar.ingestion.sources import CampaignData, ThreatSource

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ImportResult:
    """Summary of an import operation."""

    campaigns_added: int = 0
    campaigns_updated: int = 0
    signatures_added: int = 0
    signatures_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON responses."""
        return {
            "campaigns_added": self.campaigns_added,
            "campaigns_updated": self.campaigns_updated,
            "signatures_added": self.signatures_added,
            "signatures_skipped": self.signatures_skipped,
            "errors": self.errors,
        }


class CampaignImporter:
    """Import engine: fetch from a source, deduplicate, persist.

    Parameters
    ----------
    db:
        An active ``aiosqlite.Connection``.
    merge:
        When True, existing campaigns are updated with new IOCs instead of
        being skipped entirely.
    """

    def __init__(self, db: aiosqlite.Connection, *, merge: bool = True) -> None:
        self._db = db
        self._merge = merge

    async def import_from(self, source: ThreatSource) -> ImportResult:
        """Run a full import from *source* and return the result summary."""
        result = ImportResult()

        try:
            campaigns = await source.fetch()
        except Exception as exc:
            result.errors.append(f"Failed to fetch from {source.name}: {exc}")
            return result

        for campaign_data in campaigns:
            try:
                await self._import_campaign(campaign_data, source.name, result)
            except Exception as exc:
                msg = f"Error importing campaign '{campaign_data.name}': {exc}"
                logger.exception(msg)
                result.errors.append(msg)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _import_campaign(
        self,
        data: CampaignData,
        source_name: str,
        result: ImportResult,
    ) -> None:
        """Import a single campaign, creating or merging as needed."""
        existing = await self._find_campaign_by_name(data.name)

        if existing is None:
            campaign_id = await self._create_campaign(data)
            result.campaigns_added += 1
        else:
            campaign_id = existing["id"]
            if self._merge:
                await self._merge_campaign(existing, data)
                result.campaigns_updated += 1
            else:
                # Not merging — skip the campaign but still try signatures
                pass

        # Import signatures
        for sig_data in data.signatures:
            if await self._signature_exists(data.name, sig_data.pattern_value):
                result.signatures_skipped += 1
            else:
                await self._create_signature(sig_data, campaign_id, source_name)
                result.signatures_added += 1

        await self._db.commit()

    async def _find_campaign_by_name(self, name: str) -> dict[str, Any] | None:
        """Look up a campaign by its name."""
        cursor = await self._db.execute(
            "SELECT * FROM campaigns WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def _create_campaign(self, data: CampaignData) -> str:
        """Insert a new campaign row and return its ID."""
        campaign_id = f"campaign-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).strftime("%Y-%m-%d")
        first_seen = data.first_seen or now

        iocs_json = json.dumps(
            [{"type": ioc.type, "value": ioc.value, "description": ioc.description} for ioc in data.iocs]
        )

        await self._db.execute(
            """
            INSERT INTO campaigns (
                id, name, description, first_seen, last_seen,
                attributed_to, iocs, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                campaign_id,
                data.name,
                f"Imported campaign: {data.name}",
                first_seen,
                now,
                data.attributed_to or None,
                iocs_json,
            ),
        )
        return campaign_id

    async def _merge_campaign(
        self,
        existing: dict[str, Any],
        data: CampaignData,
    ) -> None:
        """Merge new IOCs into an existing campaign."""
        existing_iocs_raw = existing.get("iocs", "[]")
        if isinstance(existing_iocs_raw, str):
            try:
                existing_iocs = json.loads(existing_iocs_raw)
            except (json.JSONDecodeError, TypeError):
                existing_iocs = []
        else:
            existing_iocs = existing_iocs_raw

        # Determine which IOC values already exist
        if existing_iocs and isinstance(existing_iocs[0], dict):
            existing_values = {ioc.get("value") for ioc in existing_iocs}
        else:
            existing_values = set(existing_iocs)

        new_iocs = []
        for ioc in data.iocs:
            if ioc.value not in existing_values:
                new_iocs.append(
                    {"type": ioc.type, "value": ioc.value, "description": ioc.description}
                )

        if new_iocs:
            # If existing IOCs were plain strings, convert to dicts
            if existing_iocs and isinstance(existing_iocs[0], str):
                merged = [{"type": "unknown", "value": v} for v in existing_iocs] + new_iocs
            else:
                merged = existing_iocs + new_iocs

            merged_json = json.dumps(merged)
            await self._db.execute(
                "UPDATE campaigns SET iocs = ?, updated_at = datetime('now') WHERE id = ?",
                (merged_json, existing["id"]),
            )

    async def _signature_exists(self, campaign_name: str, pattern_value: str) -> bool:
        """Check whether a signature already exists (by campaign name + pattern_value)."""
        cursor = await self._db.execute(
            """
            SELECT 1 FROM signatures s
            JOIN campaigns c ON s.campaign_id = c.id
            WHERE c.name = ? AND s.pattern_value = ?
            LIMIT 1
            """,
            (campaign_name, pattern_value),
        )
        return await cursor.fetchone() is not None

    async def _create_signature(
        self,
        sig: Any,
        campaign_id: str,
        source_name: str,
    ) -> None:
        """Insert a new signature row."""
        sig_id = f"sig-{uuid.uuid4().hex[:12]}"
        sig_name = f"{sig.ioc_type}-{sig.pattern_value[:40]}"

        await self._db.execute(
            """
            INSERT INTO signatures (
                id, name, description, severity, category,
                pattern_type, pattern_value, ioc_type,
                campaign_id, source, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                sig_id,
                sig_name,
                f"Imported signature: {sig.pattern_value}",
                sig.severity,
                "known_malware",
                sig.pattern_type,
                sig.pattern_value,
                sig.ioc_type,
                campaign_id,
                source_name,
            ),
        )
