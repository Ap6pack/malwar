# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Notification router — dispatches events to configured channels based on filters."""

from __future__ import annotations

import logging

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import EventType, NotificationEvent

logger = logging.getLogger("malwar.notifications.router")

# Default: dispatch for all event types and all verdicts
_ALL_EVENT_TYPES = frozenset(EventType)
_ALL_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS", "CAUTION", "CLEAN"})


class ChannelEntry:
    """A channel registration with optional filters."""

    def __init__(
        self,
        channel: NotificationChannel,
        *,
        event_types: frozenset[EventType] | None = None,
        verdicts: frozenset[str] | None = None,
        min_risk_score: int = 0,
    ) -> None:
        self.channel = channel
        self.event_types = event_types or _ALL_EVENT_TYPES
        self.verdicts = verdicts or _ALL_VERDICTS
        self.min_risk_score = min_risk_score

    def matches(self, event: NotificationEvent) -> bool:
        """Return True if the event passes this entry's filters."""
        if event.event_type not in self.event_types:
            return False
        if event.verdict not in self.verdicts:
            return False
        return event.risk_score >= self.min_risk_score


class NotificationRouter:
    """Dispatch :class:`NotificationEvent` instances to registered channels.

    Channels are registered with optional severity/verdict filters so only
    relevant notifications are sent to each channel.
    """

    def __init__(self) -> None:
        self._entries: list[ChannelEntry] = []

    @property
    def channels(self) -> list[NotificationChannel]:
        """Return all registered channels."""
        return [entry.channel for entry in self._entries]

    def register(
        self,
        channel: NotificationChannel,
        *,
        event_types: frozenset[EventType] | None = None,
        verdicts: frozenset[str] | None = None,
        min_risk_score: int = 0,
    ) -> None:
        """Register a notification channel with optional filters."""
        self._entries.append(
            ChannelEntry(
                channel,
                event_types=event_types,
                verdicts=verdicts,
                min_risk_score=min_risk_score,
            )
        )
        logger.info("Registered notification channel: %s", channel.name)

    async def dispatch(self, event: NotificationEvent) -> dict[str, bool]:
        """Send the event to all matching channels.

        Returns:
            Mapping of channel name to delivery success (True/False).
        """
        results: dict[str, bool] = {}

        for entry in self._entries:
            if not entry.matches(event):
                logger.debug(
                    "Channel %s filtered out event %s (verdict=%s, risk=%d)",
                    entry.channel.name,
                    event.event_type,
                    event.verdict,
                    event.risk_score,
                )
                continue

            try:
                success = await entry.channel.send(event)
                results[entry.channel.name] = success
            except Exception:
                logger.exception(
                    "Unhandled error dispatching to channel %s", entry.channel.name
                )
                results[entry.channel.name] = False

        return results

    def get_channel_status(self) -> list[dict[str, object]]:
        """Return status info for all registered channels."""
        return [
            {
                "name": entry.channel.name,
                "configured": entry.channel.is_configured(),
                "event_types": sorted(entry.event_types),
                "verdicts": sorted(entry.verdicts),
                "min_risk_score": entry.min_risk_score,
            }
            for entry in self._entries
        ]
