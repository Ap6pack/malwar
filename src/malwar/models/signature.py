# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Threat signature and campaign models."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from malwar.core.constants import Severity, ThreatCategory


class ThreatSignature(BaseModel):
    """A stored signature for known threats."""

    id: str
    name: str
    description: str
    severity: Severity
    category: ThreatCategory
    pattern_type: str = Field(description="regex | exact | fuzzy | ioc")
    pattern_value: str
    ioc_type: str | None = Field(default=None, description="ip | domain | url | hash | email")
    campaign_id: str | None = None
    source: str = "manual"
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Campaign(BaseModel):
    """A tracked malware campaign."""

    id: str
    name: str
    description: str
    first_seen: datetime
    last_seen: datetime
    attributed_to: str | None = None
    iocs: list[str] = Field(default_factory=list)
    signature_ids: list[str] = Field(default_factory=list)
    total_skills_affected: int = 0
    status: str = "active"
