# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Generic webhook notification channel for custom HTTP POST endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

import httpx

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import NotificationEvent

logger = logging.getLogger("malwar.notifications.generic_webhook")

_TIMEOUT_SECONDS = 10.0


def _compute_signature(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a payload."""
    return hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


class GenericWebhookChannel(NotificationChannel):
    """POST JSON notification events to a custom HTTP endpoint."""

    def __init__(
        self,
        url: str,
        *,
        secret: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url
        self._secret = secret
        self._extra_headers = headers or {}

    @property
    def name(self) -> str:
        return "webhook"

    def is_configured(self) -> bool:
        return bool(self._url)

    async def send(self, event: NotificationEvent) -> bool:
        if not self._url:
            logger.warning("Generic webhook URL not configured")
            return False

        payload = event.model_dump(mode="json")
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        headers.update(self._extra_headers)

        if self._secret:
            signature = _compute_signature(payload_bytes, self._secret)
            headers["X-Malwar-Signature"] = signature

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(self._url, json=payload, headers=headers)
                response.raise_for_status()
            logger.info("Generic webhook sent for scan %s to %s", event.scan_id, self._url)
            return True
        except Exception:
            logger.exception(
                "Failed to send generic webhook for scan %s to %s", event.scan_id, self._url
            )
            return False
