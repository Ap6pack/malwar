# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Notification dispatchers for scan results."""

from malwar.notifications.base import NotificationChannel
from malwar.notifications.email_channel import EmailChannel
from malwar.notifications.events import EventType, FindingSummary, NotificationEvent
from malwar.notifications.generic_webhook import GenericWebhookChannel
from malwar.notifications.pagerduty import PagerDutyChannel
from malwar.notifications.router import NotificationRouter
from malwar.notifications.slack import SlackChannel
from malwar.notifications.teams import TeamsChannel
from malwar.notifications.webhook import WebhookNotifier

__all__ = [
    "EmailChannel",
    "EventType",
    "FindingSummary",
    "GenericWebhookChannel",
    "NotificationChannel",
    "NotificationEvent",
    "NotificationRouter",
    "PagerDutyChannel",
    "SlackChannel",
    "TeamsChannel",
    "WebhookNotifier",
]
