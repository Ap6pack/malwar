# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Notification channel API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from malwar.api.auth import require_api_key
from malwar.core.config import get_settings
from malwar.notifications.events import EventType, NotificationEvent
from malwar.notifications.factory import build_router

logger = logging.getLogger("malwar.api.notifications")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ChannelStatus(BaseModel):
    name: str
    configured: bool
    event_types: list[str]
    verdicts: list[str]
    min_risk_score: int


class TestNotificationRequest(BaseModel):
    channel: str | None = Field(
        default=None,
        description="Send test only to this channel name. None = all channels.",
    )


class TestNotificationResult(BaseModel):
    channel: str
    success: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/notifications/channels", response_model=list[ChannelStatus])
async def list_channels(
    _api_key: str = Depends(require_api_key),
) -> list[ChannelStatus]:
    """List configured notification channels and their status."""
    settings = get_settings()
    notification_router = build_router(settings)
    statuses = notification_router.get_channel_status()
    return [
        ChannelStatus(
            name=str(s["name"]),
            configured=bool(s["configured"]),
            event_types=list(s["event_types"]),  # type: ignore[call-overload]
            verdicts=list(s["verdicts"]),  # type: ignore[call-overload]
            min_risk_score=int(s["min_risk_score"]),  # type: ignore[call-overload]
        )
        for s in statuses
    ]


@router.post("/notifications/test", response_model=list[TestNotificationResult])
async def test_notifications(
    body: TestNotificationRequest | None = None,
    _api_key: str = Depends(require_api_key),
) -> list[TestNotificationResult]:
    """Send a test notification to verify channel configuration."""
    settings = get_settings()
    notification_router = build_router(settings)

    test_event = NotificationEvent(
        event_type=EventType.SCAN_COMPLETE,
        scan_id="test-notification-000",
        target="test/SKILL.md",
        verdict="CLEAN",
        risk_score=0,
        finding_count=0,
        findings_summary=[],
        skill_name="test-skill",
    )

    channel_filter = body.channel if body else None
    results: list[TestNotificationResult] = []

    for channel in notification_router.channels:
        if channel_filter and channel.name != channel_filter:
            continue
        if not channel.is_configured():
            results.append(TestNotificationResult(channel=channel.name, success=False))
            continue
        try:
            success = await channel.send(test_event)
            results.append(TestNotificationResult(channel=channel.name, success=success))
        except Exception:
            logger.exception("Test notification failed for channel %s", channel.name)
            results.append(TestNotificationResult(channel=channel.name, success=False))

    return results
