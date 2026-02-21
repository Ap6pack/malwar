# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Slack notification channel using Block Kit formatting."""

from __future__ import annotations

import logging

import httpx

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import EventType, NotificationEvent

logger = logging.getLogger("malwar.notifications.slack")

_TIMEOUT_SECONDS = 10.0

_VERDICT_EMOJI = {
    "MALICIOUS": ":rotating_light:",
    "SUSPICIOUS": ":warning:",
    "CAUTION": ":large_yellow_circle:",
    "CLEAN": ":white_check_mark:",
}

_EVENT_LABELS = {
    EventType.SCAN_COMPLETE: "Scan Complete",
    EventType.THREAT_FOUND: "Threat Detected",
    EventType.SCAN_FAILED: "Scan Failed",
}


def _build_blocks(event: NotificationEvent) -> list[dict]:
    """Build Slack Block Kit blocks for the notification."""
    emoji = _VERDICT_EMOJI.get(event.verdict, ":question:")
    label = _EVENT_LABELS.get(event.event_type, "Notification")

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} malwar: {label}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Verdict:*\n{event.verdict}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{event.risk_score}/100"},
                {"type": "mrkdwn", "text": f"*Scan ID:*\n`{event.scan_id}`"},
                {"type": "mrkdwn", "text": f"*Findings:*\n{event.finding_count}"},
            ],
        },
    ]

    if event.skill_name:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Skill:* {event.skill_name}  |  *Target:* `{event.target}`",
                },
            }
        )

    if event.findings_summary:
        lines = []
        for f in event.findings_summary[:5]:
            lines.append(f"- `{f.rule_id}` {f.title} ({f.severity}, {f.confidence:.0%})")
        findings_text = "\n".join(lines)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{findings_text}"},
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"malwar scan at {event.timestamp.isoformat()}",
                }
            ],
        }
    )

    return blocks


class SlackChannel(NotificationChannel):
    """Send notifications to Slack via incoming webhook with Block Kit formatting."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "slack"

    def is_configured(self) -> bool:
        return bool(self._webhook_url)

    async def send(self, event: NotificationEvent) -> bool:
        if not self._webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        blocks = _build_blocks(event)
        payload = {"blocks": blocks}

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(self._webhook_url, json=payload)
                response.raise_for_status()
            logger.info("Slack notification sent for scan %s", event.scan_id)
            return True
        except Exception:
            logger.exception("Failed to send Slack notification for scan %s", event.scan_id)
            return False
