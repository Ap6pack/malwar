# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Notification event models for scan result dispatching."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from malwar.models.scan import ScanResult


class EventType(StrEnum):
    SCAN_COMPLETE = "scan_complete"
    THREAT_FOUND = "threat_found"
    SCAN_FAILED = "scan_failed"


class FindingSummary(BaseModel):
    """Condensed finding info for notification payloads."""

    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str


class NotificationEvent(BaseModel):
    """Event dispatched to notification channels after a scan."""

    event_type: EventType
    scan_id: str
    target: str
    verdict: str
    risk_score: int
    finding_count: int
    findings_summary: list[FindingSummary] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    skill_name: str | None = None
    overall_severity: str | None = None
    duration_ms: int | None = None

    @classmethod
    def from_scan_result(cls, result: ScanResult) -> NotificationEvent:
        """Build a NotificationEvent from a completed ScanResult."""
        if result.status == "failed":
            event_type = EventType.SCAN_FAILED
        elif result.verdict in ("MALICIOUS", "SUSPICIOUS"):
            event_type = EventType.THREAT_FOUND
        else:
            event_type = EventType.SCAN_COMPLETE

        summaries = [
            FindingSummary(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
            )
            for f in result.findings[:10]
        ]

        return cls(
            event_type=event_type,
            scan_id=result.scan_id,
            target=result.target,
            verdict=result.verdict,
            risk_score=result.risk_score,
            finding_count=len(result.findings),
            findings_summary=summaries,
            skill_name=result.skill_name,
            overall_severity=result.overall_severity,
            duration_ms=result.duration_ms,
        )
