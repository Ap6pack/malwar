"""Threat finding models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory


class Location(BaseModel):
    """Where in the SKILL.md the finding was located."""

    line_start: int
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    snippet: str = ""


class Finding(BaseModel):
    """A single detected threat indicator."""

    id: str = Field(description="Unique finding ID, e.g. MALWAR-OBF-001-L15")
    rule_id: str = Field(description="Rule that triggered this finding")
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: ThreatCategory
    detector_layer: DetectorLayer
    location: Location | None = None
    evidence: list[str] = Field(default_factory=list)
    ioc_values: list[str] = Field(default_factory=list)
    remediation: str = ""
    metadata: dict[str, object] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Suppression: a later layer (currently only the LLM analyzer) can mark an
    # earlier layer's finding as a false positive after reviewing full context.
    # Suppressed findings are excluded from risk scoring but remain in the
    # findings list and scan output for transparency and auditability.
    suppressed: bool = False
    suppressed_reason: str | None = None
    suppressed_by: DetectorLayer | None = None
