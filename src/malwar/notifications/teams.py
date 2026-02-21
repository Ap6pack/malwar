# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Microsoft Teams notification channel using Adaptive Cards."""

from __future__ import annotations

import logging

import httpx

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import EventType, NotificationEvent

logger = logging.getLogger("malwar.notifications.teams")

_TIMEOUT_SECONDS = 10.0

_VERDICT_COLORS = {
    "MALICIOUS": "attention",
    "SUSPICIOUS": "warning",
    "CAUTION": "accent",
    "CLEAN": "good",
}

_EVENT_LABELS = {
    EventType.SCAN_COMPLETE: "Scan Complete",
    EventType.THREAT_FOUND: "Threat Detected",
    EventType.SCAN_FAILED: "Scan Failed",
}


def _build_adaptive_card(event: NotificationEvent) -> dict:
    """Build a Teams Adaptive Card payload."""
    color = _VERDICT_COLORS.get(event.verdict, "default")
    label = _EVENT_LABELS.get(event.event_type, "Notification")

    facts = [
        {"title": "Verdict", "value": event.verdict},
        {"title": "Risk Score", "value": f"{event.risk_score}/100"},
        {"title": "Scan ID", "value": event.scan_id},
        {"title": "Findings", "value": str(event.finding_count)},
        {"title": "Target", "value": event.target},
    ]
    if event.skill_name:
        facts.append({"title": "Skill", "value": event.skill_name})

    body: list[dict] = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"malwar: {label}",
            "style": color,
        },
        {
            "type": "FactSet",
            "facts": facts,
        },
    ]

    if event.findings_summary:
        items = []
        for f in event.findings_summary[:5]:
            items.append(
                {
                    "type": "TextBlock",
                    "text": f"**{f.rule_id}** - {f.title} ({f.severity}, {f.confidence:.0%})",
                    "wrap": True,
                }
            )
        body.append({"type": "TextBlock", "text": "**Top Findings:**", "weight": "Bolder"})
        body.extend(items)

    body.append(
        {
            "type": "TextBlock",
            "text": f"Scanned at {event.timestamp.isoformat()}",
            "isSubtle": True,
            "size": "Small",
        }
    )

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


class TeamsChannel(NotificationChannel):
    """Send notifications to Microsoft Teams via incoming webhook with Adaptive Cards."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "teams"

    def is_configured(self) -> bool:
        return bool(self._webhook_url)

    async def send(self, event: NotificationEvent) -> bool:
        if not self._webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False

        payload = _build_adaptive_card(event)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(self._webhook_url, json=payload)
                response.raise_for_status()
            logger.info("Teams notification sent for scan %s", event.scan_id)
            return True
        except Exception:
            logger.exception("Failed to send Teams notification for scan %s", event.scan_id)
            return False
