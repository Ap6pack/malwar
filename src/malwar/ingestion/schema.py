# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Pydantic models for the JSON import schema used by the campaign ingestion system."""

from __future__ import annotations

from pydantic import BaseModel, Field


class IOCSchema(BaseModel):
    """A single indicator of compromise in the import payload."""

    type: str = Field(
        ...,
        description="IOC type: ip, domain, url, or hash",
        pattern=r"^(ip|domain|url|hash)$",
    )
    value: str = Field(..., min_length=1, description="IOC value")
    description: str = Field("", description="Optional description of this IOC")


class SignatureSchema(BaseModel):
    """A detection signature in the import payload."""

    pattern_type: str = Field(
        ...,
        description="Pattern type: exact, regex, fuzzy, or ioc",
    )
    pattern_value: str = Field(..., min_length=1, description="Pattern to match")
    ioc_type: str = Field(
        ...,
        description="IOC type: ip, domain, url, or hash",
    )
    severity: str = Field(
        "medium",
        description="Severity: critical, high, medium, low, or info",
        pattern=r"^(critical|high|medium|low|info)$",
    )
    confidence: float = Field(
        0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0",
    )


class CampaignSchema(BaseModel):
    """A single campaign in the import payload."""

    name: str = Field(..., min_length=1, description="Campaign name")
    attributed_to: str = Field("", description="Attribution (threat actor)")
    first_seen: str = Field("", description="First seen date (YYYY-MM-DD)")
    iocs: list[IOCSchema] = Field(default_factory=list, description="IOC list")
    signatures: list[SignatureSchema] = Field(
        default_factory=list, description="Signature list"
    )


class ImportPayload(BaseModel):
    """Top-level JSON import payload."""

    campaigns: list[CampaignSchema] = Field(
        ..., min_length=1, description="List of campaigns to import"
    )
