# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Abstract base class for notification channels."""

from __future__ import annotations

import abc

from malwar.notifications.events import NotificationEvent


class NotificationChannel(abc.ABC):
    """Base class for all notification channels.

    Each concrete channel must implement ``send()`` to deliver a
    :class:`NotificationEvent` to its backing service (Slack, Teams,
    PagerDuty, email, generic webhook, etc.).
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable channel name (e.g. ``'slack'``)."""

    @abc.abstractmethod
    async def send(self, event: NotificationEvent) -> bool:
        """Deliver a notification event.

        Returns:
            ``True`` if the delivery succeeded, ``False`` otherwise.
        """

    def is_configured(self) -> bool:
        """Return ``True`` if the channel has valid configuration.

        Subclasses should override this to check required credentials.
        """
        return True
