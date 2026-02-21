# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Audit event data model and event type enumeration."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditEventType(StrEnum):
    """Categories of auditable security-relevant events."""

    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FINDING_DETECTED = "finding_detected"
    API_KEY_USED = "api_key_used"
    CONFIG_CHANGED = "config_changed"
    SIGNATURE_CREATED = "signature_created"
    SIGNATURE_UPDATED = "signature_updated"
    SIGNATURE_DELETED = "signature_deleted"
    API_REQUEST = "api_request"


class AuditEvent(BaseModel):
    """A single auditable event with full provenance metadata.

    Each event is assigned a unique UUID and records who (actor), what (action),
    on which resource, and when.
    """

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: AuditEventType
    actor: str = Field(
        default="cli",
        description="API key hash or 'cli' for command-line usage",
    )
    resource_type: str = Field(
        default="",
        description="Type of resource affected (scan, signature, config, etc.)",
    )
    resource_id: str = Field(
        default="",
        description="Identifier of the affected resource",
    )
    action: str = Field(
        default="",
        description="Human-readable description of the action taken",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary structured details about the event",
    )
    ip_address: str = Field(
        default="",
        description="Client IP address (for API requests)",
    )
