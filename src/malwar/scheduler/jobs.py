# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""ScanJob dataclass and related types for scheduled scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ScanJob:
    """A scheduled scan job definition."""

    job_id: str
    name: str
    target_path: str
    schedule: str  # cron expression (5-field)
    layers: list[str] = field(default_factory=lambda: [
        "rule_engine", "url_crawler", "llm_analyzer", "threat_intel",
    ])
    enabled: bool = True
    last_run: datetime | None = None
    next_run: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict:
        """Serialize to a dictionary suitable for DB storage / API response."""
        return {
            "job_id": self.job_id,
            "name": self.name,
            "target_path": self.target_path,
            "schedule": self.schedule,
            "layers": ",".join(self.layers),
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class JobRun:
    """A single execution record for a scheduled scan job."""

    run_id: str
    job_id: str
    scan_id: str | None = None
    status: str = "pending"  # pending | running | completed | failed
    verdict: str | None = None
    risk_score: int | None = None
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def to_dict(self) -> dict:
        """Serialize to a dictionary suitable for DB storage / API response."""
        return {
            "run_id": self.run_id,
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "status": self.status,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
