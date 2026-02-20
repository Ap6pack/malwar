# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Webhook notification dispatcher for scan results."""

from __future__ import annotations

import logging

import httpx

from malwar.models.scan import ScanResult

logger = logging.getLogger("malwar.notifications.webhook")

_NOTIFY_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS"})
_TIMEOUT_SECONDS = 10.0
_MAX_TOP_FINDINGS = 5


class WebhookNotifier:
    """Fire-and-forget webhook dispatcher for malicious/suspicious scan results."""

    def __init__(self, urls: list[str]) -> None:
        self.urls = urls

    async def notify(self, scan_result: ScanResult) -> None:
        """POST a JSON payload to each configured webhook URL.

        Only fires for MALICIOUS or SUSPICIOUS verdicts.  Failures are
        logged but never raised so the scan pipeline is not blocked.
        """
        if not self.urls:
            return

        if scan_result.verdict not in _NOTIFY_VERDICTS:
            return

        payload = self._build_payload(scan_result)

        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            for url in self.urls:
                try:
                    response = await client.post(url, json=payload)
                    response.raise_for_status()
                    logger.info(
                        "Webhook delivered to %s (status %s)", url, response.status_code
                    )
                except Exception:
                    logger.exception("Webhook delivery failed for %s", url)

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
            "scan_id": scan_result.scan_id,
            "verdict": scan_result.verdict,
            "risk_score": scan_result.risk_score,
            "finding_count": len(scan_result.findings),
            "skill_name": scan_result.skill_name,
            "top_findings": top_findings,
        }
