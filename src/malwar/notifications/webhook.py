# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Webhook notification dispatcher for scan results."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime

import httpx

from malwar.models.scan import ScanResult

logger = logging.getLogger("malwar.notifications.webhook")

_NOTIFY_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS"})
_TIMEOUT_SECONDS = 10.0
_MAX_TOP_FINDINGS = 5
_MAX_RETRIES = 3
_BACKOFF_BASE = 1  # seconds: 1, 2, 4


def _compute_signature(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a payload."""
    return hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


class WebhookNotifier:
    """Fire-and-forget webhook dispatcher for malicious/suspicious scan results."""

    def __init__(
        self,
        urls: list[str] | None = None,
        *,
        url: str = "",
        secret: str = "",
        verdicts: list[str] | None = None,
    ) -> None:
        # Support both legacy multi-URL interface and new single-URL interface
        self._urls: list[str] = []
        if urls:
            self._urls.extend(urls)
        if url:
            self._urls.append(url)
        self._secret = secret
        self._verdicts = frozenset(verdicts) if verdicts is not None else _NOTIFY_VERDICTS

    @property
    def urls(self) -> list[str]:
        return self._urls

    async def notify(self, scan_result: ScanResult) -> None:
        """POST a JSON payload to each configured webhook URL.

        Only fires for verdicts that match the configured verdicts list.
        Failures are logged but never raised so the scan pipeline is not blocked.
        Retries up to 3 times with exponential backoff (1s, 2s, 4s).
        """
        if not self._urls:
            return

        if scan_result.verdict not in self._verdicts:
            return

        payload = self._build_payload(scan_result)
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._secret:
            signature = _compute_signature(payload_bytes, self._secret)
            headers["X-Malwar-Signature"] = signature

        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            for url in self._urls:
                await self._deliver_with_retry(client, url, payload, headers)

    async def _deliver_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict[str, object],
        headers: dict[str, str],
    ) -> None:
        """Attempt delivery with exponential backoff retries."""
        for attempt in range(_MAX_RETRIES):
            try:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                logger.info(
                    "Webhook delivered to %s (status %s)", url, response.status_code
                )
                return
            except Exception:
                if attempt < _MAX_RETRIES - 1:
                    backoff = _BACKOFF_BASE * (2 ** attempt)
                    logger.warning(
                        "Webhook delivery attempt %d/%d failed for %s, retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        url,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    logger.exception(
                        "Webhook delivery failed for %s after %d attempts",
                        url,
                        _MAX_RETRIES,
                    )

    @staticmethod
    def _build_payload(scan_result: ScanResult) -> dict[str, object]:
        top_findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
            }
            for f in scan_result.findings[:_MAX_TOP_FINDINGS]
        ]

        return {
            "event": "scan.completed",
            "scan_id": scan_result.scan_id,
            "verdict": scan_result.verdict,
            "risk_score": scan_result.risk_score,
            "finding_count": len(scan_result.findings),
            "skill_name": scan_result.skill_name,
            "timestamp": datetime.now(UTC).isoformat(),
            "top_findings": top_findings,
        }
