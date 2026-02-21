# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Factory to build a NotificationRouter from application settings."""

from __future__ import annotations

import logging

from malwar.core.config import Settings
from malwar.notifications.email_channel import EmailChannel
from malwar.notifications.generic_webhook import GenericWebhookChannel
from malwar.notifications.pagerduty import PagerDutyChannel
from malwar.notifications.router import NotificationRouter
from malwar.notifications.slack import SlackChannel
from malwar.notifications.teams import TeamsChannel

logger = logging.getLogger("malwar.notifications.factory")


def build_router(settings: Settings) -> NotificationRouter:
    """Create a :class:`NotificationRouter` from :class:`Settings`.

    Channels listed in ``settings.notification_channels`` are instantiated
    and registered.  If the list is empty, auto-detect based on which
    credentials are present.
    """
    router = NotificationRouter()
    channels = set(settings.notification_channels)

    # Auto-detect if no explicit list
    if not channels:
        if settings.slack_webhook_url:
            channels.add("slack")
        if settings.teams_webhook_url:
            channels.add("teams")
        if settings.pagerduty_routing_key:
            channels.add("pagerduty")
        if settings.smtp_host and settings.smtp_to:
            channels.add("email")
        if settings.webhook_url or settings.webhook_urls:
            channels.add("webhook")

    for ch_name in channels:
        if ch_name == "slack" and settings.slack_webhook_url:
            router.register(SlackChannel(settings.slack_webhook_url))
        elif ch_name == "teams" and settings.teams_webhook_url:
            router.register(TeamsChannel(settings.teams_webhook_url))
        elif ch_name == "pagerduty" and settings.pagerduty_routing_key:
            router.register(
                PagerDutyChannel(settings.pagerduty_routing_key),
                verdicts=frozenset({"MALICIOUS", "SUSPICIOUS"}),
            )
        elif ch_name == "email" and settings.smtp_host:
            router.register(
                EmailChannel(
                    smtp_host=settings.smtp_host,
                    smtp_port=settings.smtp_port,
                    smtp_user=settings.smtp_user,
                    smtp_password=settings.smtp_password,
                    smtp_use_tls=settings.smtp_use_tls,
                    from_addr=settings.smtp_from,
                    to_addrs=settings.smtp_to,
                )
            )
        elif ch_name == "webhook":
            urls = list(settings.webhook_urls)
            if settings.webhook_url:
                urls.append(settings.webhook_url)
            for url in urls:
                router.register(
                    GenericWebhookChannel(url, secret=settings.webhook_secret),
                    verdicts=frozenset(settings.webhook_verdicts),
                )
        else:
            logger.warning(
                "Notification channel '%s' requested but not configured", ch_name
            )

    return router
