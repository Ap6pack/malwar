# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""PagerDuty notification channel using Events API v2."""

from __future__ import annotations

import logging

import httpx

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import NotificationEvent

logger = logging.getLogger("malwar.notifications.pagerduty")

_EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
_TIMEOUT_SECONDS = 10.0

# Only create PagerDuty incidents for high-severity verdicts.
_TRIGGER_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS"})

_VERDICT_PD_SEVERITY = {
    "MALICIOUS": "critical",
    "SUSPICIOUS": "error",
    "CAUTION": "warning",
    "CLEAN": "info",
}


def _build_event_payload(event: NotificationEvent, routing_key: str) -> dict:
    """Build a PagerDuty Events API v2 payload."""
    pd_severity = _VERDICT_PD_SEVERITY.get(event.verdict, "info")

    summary = (
        f"malwar: {event.verdict} verdict for scan {event.scan_id} "
        f"(risk {event.risk_score}/100, {event.finding_count} findings)"
    )
    if event.skill_name:
        summary = f"malwar: {event.verdict} — {event.skill_name} ({event.risk_score}/100)"

    custom_details: dict[str, object] = {
        "scan_id": event.scan_id,
        "target": event.target,
        "verdict": event.verdict,
        "risk_score": event.risk_score,
        "finding_count": event.finding_count,
        "event_type": event.event_type,
    }
    if event.skill_name:
        custom_details["skill_name"] = event.skill_name
    if event.findings_summary:
        custom_details["top_findings"] = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
            }
            for f in event.findings_summary[:5]
        ]

    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"malwar-scan-{event.scan_id}",
        "payload": {
            "summary": summary,
            "source": "malwar",
            "severity": pd_severity,
            "component": "scan-pipeline",
            "group": event.skill_name or "unknown",
            "custom_details": custom_details,
            "timestamp": event.timestamp.isoformat(),
        },
    }


class PagerDutyChannel(NotificationChannel):
    """Create PagerDuty incidents via Events API v2 for critical/high findings."""

    def __init__(self, routing_key: str) -> None:
        self._routing_key = routing_key

    @property
    def name(self) -> str:
        return "pagerduty"

    def is_configured(self) -> bool:
        return bool(self._routing_key)

    async def send(self, event: NotificationEvent) -> bool:
        if not self._routing_key:
            logger.warning("PagerDuty routing key not configured")
            return False

        if event.verdict not in _TRIGGER_VERDICTS:
            logger.debug(
                "Skipping PagerDuty for verdict %s (only triggers for %s)",
                event.verdict,
                ", ".join(sorted(_TRIGGER_VERDICTS)),
            )
            return True  # Not an error — just filtered out

        payload = _build_event_payload(event, self._routing_key)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(_EVENTS_API_URL, json=payload)
                response.raise_for_status()
            logger.info("PagerDuty incident created for scan %s", event.scan_id)
            return True
        except Exception:
            logger.exception(
                "Failed to create PagerDuty incident for scan %s", event.scan_id
            )
            return False
