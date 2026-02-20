# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Batch scan report models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from malwar.models.scan import ScanResult


class BatchScanReport(BaseModel):
    """Report for scanning multiple skills."""

    report_id: str
    started_at: datetime
    completed_at: datetime | None = None
    total_skills: int = 0
    skills_scanned: int = 0
    skills_malicious: int = 0
    skills_suspicious: int = 0
    skills_clean: int = 0
    skills_errored: int = 0
    results: list[ScanResult] = Field(default_factory=list)
    top_threats: list[str] = Field(default_factory=list)
    campaign_matches: list[str] = Field(default_factory=list)
