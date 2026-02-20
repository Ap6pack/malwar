# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the webhook notification dispatcher."""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult
from malwar.notifications.webhook import WebhookNotifier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    verdict_risk: int = 80,
    skill_name: str = "evil-skill",
) -> ScanResult:
    """Create a ScanResult with enough findings to hit the desired risk score."""
    findings: list[Finding] = []
    if verdict_risk >= 75:
        findings.append(
            Finding(
                id="MALWAR-TEST-001",
                rule_id="rule-test-001",
                title="Obfuscated base64",
                description="Base64-encoded payload detected",
                severity=Severity.CRITICAL,
                confidence=1.0,
                category=ThreatCategory.OBFUSCATED_COMMAND,
                detector_layer=DetectorLayer.RULE_ENGINE,
                location=Location(line_start=10, snippet="echo base64..."),
                evidence=["base64 encoded command"],
            )
        )
    elif verdict_risk >= 40:
        findings.append(
            Finding(
                id="MALWAR-TEST-002",
                rule_id="rule-test-002",
                title="Suspicious curl",
                description="Downloads from unknown domain",
                severity=Severity.MEDIUM,
                confidence=1.0,
                category=ThreatCategory.SUSPICIOUS_COMMAND,
                detector_layer=DetectorLayer.RULE_ENGINE,
                location=Location(line_start=5, snippet="curl http://..."),
                evidence=["curl to unknown host"],
            )
        )
    return ScanResult(
        scan_id="scan-webhook-test-001",
        target="/tmp/SKILL.md",
        skill_sha256="abc123",
        skill_name=skill_name,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWebhookNotifier:
    """Tests for WebhookNotifier."""

    @respx.mock
    async def test_sends_post_to_configured_urls(self) -> None:
        """Webhook should POST JSON to each configured URL."""
        url1 = "https://hooks.example.com/a"
        url2 = "https://hooks.example.com/b"

        route1 = respx.post(url1).mock(return_value=httpx.Response(200))
        route2 = respx.post(url2).mock(return_value=httpx.Response(200))

        notifier = WebhookNotifier(urls=[url1, url2])
        result = _make_result(verdict_risk=80)
        await notifier.notify(result)

        assert route1.called
        assert route2.called

        # Verify payload shape
        payload = route1.calls[0].request.content
        import json

        body = json.loads(payload)
        assert body["scan_id"] == "scan-webhook-test-001"
        assert body["verdict"] == "MALICIOUS"
        assert body["risk_score"] >= 75
        assert body["skill_name"] == "evil-skill"
        assert body["finding_count"] == 1
        assert len(body["top_findings"]) == 1
        assert body["top_findings"][0]["rule_id"] == "rule-test-001"

    @respx.mock
    async def test_fires_for_suspicious_verdict(self) -> None:
        """Webhook should also fire for SUSPICIOUS verdicts."""
        url = "https://hooks.example.com/suspicious"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        notifier = WebhookNotifier(urls=[url])
        result = _make_result(verdict_risk=50)
        await notifier.notify(result)

        assert route.called

    @respx.mock
    async def test_does_not_fire_for_clean_verdict(self) -> None:
        """Webhook should NOT fire for CLEAN verdicts."""
        url = "https://hooks.example.com/clean"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        notifier = WebhookNotifier(urls=[url])
        result = _make_result(verdict_risk=0)
        await notifier.notify(result)

        assert not route.called

    @respx.mock
    async def test_does_not_fire_for_caution_verdict(self) -> None:
        """Webhook should NOT fire for CAUTION verdicts."""
        url = "https://hooks.example.com/caution"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        notifier = WebhookNotifier(urls=[url])
        # risk_score 25 => CAUTION
        result = ScanResult(
            scan_id="scan-caution",
            target="/tmp/SKILL.md",
            skill_sha256="abc",
            findings=[
                Finding(
                    id="MALWAR-TEST-003",
                    rule_id="rule-test-003",
                    title="Minor issue",
                    description="Low concern",
                    severity=Severity.LOW,
                    confidence=1.0,
                    category=ThreatCategory.SUSPICIOUS_COMMAND,
                    detector_layer=DetectorLayer.RULE_ENGINE,
                    evidence=["minor"],
                )
            ],
        )
        await notifier.notify(result)

        assert not route.called

    async def test_empty_urls_is_noop(self) -> None:
        """Empty webhook_urls list should be a no-op (no HTTP calls)."""
        notifier = WebhookNotifier(urls=[])
        result = _make_result(verdict_risk=80)
        # Should complete without error and without making any HTTP calls
        await notifier.notify(result)

    @respx.mock
    async def test_failure_is_logged_not_raised(self, caplog: pytest.LogCaptureFixture) -> None:
        """HTTP failures should be logged but not propagated as exceptions."""
        url = "https://hooks.example.com/fail"
        respx.post(url).mock(return_value=httpx.Response(500))

        notifier = WebhookNotifier(urls=[url])
        result = _make_result(verdict_risk=80)

        with caplog.at_level(logging.ERROR, logger="malwar.notifications.webhook"):
            # Should NOT raise
            await notifier.notify(result)

        assert any("Webhook delivery failed" in record.message for record in caplog.records)

    @respx.mock
    async def test_connection_error_is_logged_not_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Connection errors should be logged but not propagated."""
        url = "https://hooks.example.com/timeout"
        respx.post(url).mock(side_effect=httpx.ConnectError("Connection refused"))

        notifier = WebhookNotifier(urls=[url])
        result = _make_result(verdict_risk=80)

        with caplog.at_level(logging.ERROR, logger="malwar.notifications.webhook"):
            await notifier.notify(result)

        assert any("Webhook delivery failed" in record.message for record in caplog.records)

    @respx.mock
    async def test_partial_failure_continues_to_remaining_urls(self) -> None:
        """If one webhook URL fails, the others should still be attempted."""
        url_fail = "https://hooks.example.com/fail"
        url_ok = "https://hooks.example.com/ok"

        respx.post(url_fail).mock(return_value=httpx.Response(503))
        route_ok = respx.post(url_ok).mock(return_value=httpx.Response(200))

        notifier = WebhookNotifier(urls=[url_fail, url_ok])
        result = _make_result(verdict_risk=80)
        await notifier.notify(result)

        assert route_ok.called
