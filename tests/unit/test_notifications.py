# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for notification channels, router, and event formatting."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult
from malwar.notifications.base import NotificationChannel
from malwar.notifications.email_channel import EmailChannel, _build_html
from malwar.notifications.events import EventType, FindingSummary, NotificationEvent
from malwar.notifications.factory import build_router
from malwar.notifications.generic_webhook import GenericWebhookChannel
from malwar.notifications.pagerduty import PagerDutyChannel
from malwar.notifications.router import NotificationRouter
from malwar.notifications.slack import SlackChannel, _build_blocks
from malwar.notifications.teams import TeamsChannel, _build_adaptive_card

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_scan_result(
    verdict_risk: int = 80,
    skill_name: str = "evil-skill",
    status: str = "completed",
) -> ScanResult:
    """Create a ScanResult with enough findings to reach the desired risk score."""
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
        scan_id="scan-notify-test-001",
        target="/tmp/SKILL.md",
        skill_sha256="abc123",
        skill_name=skill_name,
        findings=findings,
        status=status,
    )


def _make_event(
    event_type: EventType = EventType.THREAT_FOUND,
    verdict: str = "MALICIOUS",
    risk_score: int = 85,
    finding_count: int = 1,
) -> NotificationEvent:
    """Create a notification event for testing."""
    return NotificationEvent(
        event_type=event_type,
        scan_id="scan-test-001",
        target="/tmp/SKILL.md",
        verdict=verdict,
        risk_score=risk_score,
        finding_count=finding_count,
        findings_summary=[
            FindingSummary(
                rule_id="rule-test-001",
                title="Obfuscated base64",
                severity="critical",
                confidence=1.0,
                category="obfuscated_command",
            )
        ],
        skill_name="evil-skill",
        overall_severity="critical",
        timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# NotificationEvent tests
# ---------------------------------------------------------------------------


class TestNotificationEvent:
    """Tests for NotificationEvent model and factory method."""

    def test_from_scan_result_threat_found(self) -> None:
        """Malicious scan result should produce THREAT_FOUND event."""
        result = _make_scan_result(verdict_risk=80)
        event = NotificationEvent.from_scan_result(result)

        assert event.event_type == EventType.THREAT_FOUND
        assert event.scan_id == "scan-notify-test-001"
        assert event.target == "/tmp/SKILL.md"
        assert event.verdict == "MALICIOUS"
        assert event.risk_score >= 75
        assert event.finding_count == 1
        assert len(event.findings_summary) == 1
        assert event.findings_summary[0].rule_id == "rule-test-001"
        assert event.skill_name == "evil-skill"

    def test_from_scan_result_scan_complete(self) -> None:
        """Clean scan result should produce SCAN_COMPLETE event."""
        result = _make_scan_result(verdict_risk=0)
        event = NotificationEvent.from_scan_result(result)

        assert event.event_type == EventType.SCAN_COMPLETE
        assert event.verdict == "CLEAN"
        assert event.risk_score == 0
        assert event.finding_count == 0

    def test_from_scan_result_suspicious(self) -> None:
        """Suspicious scan result should produce THREAT_FOUND event."""
        result = _make_scan_result(verdict_risk=50)
        event = NotificationEvent.from_scan_result(result)

        assert event.event_type == EventType.THREAT_FOUND
        assert event.verdict == "SUSPICIOUS"

    def test_from_scan_result_failed(self) -> None:
        """Failed scan should produce SCAN_FAILED event."""
        result = _make_scan_result(verdict_risk=0, status="failed")
        event = NotificationEvent.from_scan_result(result)

        assert event.event_type == EventType.SCAN_FAILED

    def test_timestamp_auto_populated(self) -> None:
        """Timestamp should be auto-populated."""
        event = _make_event()
        assert event.timestamp is not None

    def test_findings_summary_limited_to_10(self) -> None:
        """Findings summary should be limited to 10 entries."""
        findings = [
            Finding(
                id=f"MALWAR-TEST-{i:03d}",
                rule_id=f"rule-test-{i:03d}",
                title=f"Finding {i}",
                description=f"Description {i}",
                severity=Severity.LOW,
                confidence=0.5,
                category=ThreatCategory.SUSPICIOUS_COMMAND,
                detector_layer=DetectorLayer.RULE_ENGINE,
            )
            for i in range(15)
        ]
        result = ScanResult(
            scan_id="scan-many",
            target="/tmp/SKILL.md",
            skill_sha256="abc",
            findings=findings,
        )
        event = NotificationEvent.from_scan_result(result)
        assert len(event.findings_summary) == 10


# ---------------------------------------------------------------------------
# SlackChannel tests
# ---------------------------------------------------------------------------


class TestSlackChannel:
    """Tests for the Slack notification channel."""

    @respx.mock
    async def test_send_success(self) -> None:
        """Slack channel should POST blocks to webhook URL."""
        url = "https://hooks.slack.com/services/T00/B00/abc123"
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))

        channel = SlackChannel(webhook_url=url)
        event = _make_event()
        result = await channel.send(event)

        assert result is True
        assert route.called

        request = route.calls[0].request
        body = json.loads(request.content)
        assert "blocks" in body
        # Verify Block Kit structure
        assert body["blocks"][0]["type"] == "header"
        assert "Threat Detected" in body["blocks"][0]["text"]["text"]

    @respx.mock
    async def test_send_failure_returns_false(self) -> None:
        """HTTP failure should return False, not raise."""
        url = "https://hooks.slack.com/services/T00/B00/fail"
        respx.post(url).mock(return_value=httpx.Response(500))

        channel = SlackChannel(webhook_url=url)
        event = _make_event()
        result = await channel.send(event)

        assert result is False

    async def test_unconfigured_returns_false(self) -> None:
        """Empty webhook URL should return False."""
        channel = SlackChannel(webhook_url="")
        assert channel.is_configured() is False
        result = await channel.send(_make_event())
        assert result is False

    def test_name(self) -> None:
        """Channel name should be 'slack'."""
        channel = SlackChannel(webhook_url="https://example.com")
        assert channel.name == "slack"

    def test_block_kit_structure(self) -> None:
        """Verify Slack Block Kit blocks contain expected sections."""
        event = _make_event()
        blocks = _build_blocks(event)

        # Header, fields section, skill section, findings section, context
        block_types = [b["type"] for b in blocks]
        assert "header" in block_types
        assert "section" in block_types
        assert "context" in block_types

    def test_block_kit_clean_verdict(self) -> None:
        """Clean verdict should show check mark emoji in blocks."""
        event = _make_event(
            event_type=EventType.SCAN_COMPLETE,
            verdict="CLEAN",
            risk_score=0,
            finding_count=0,
        )
        blocks = _build_blocks(event)
        header_text = blocks[0]["text"]["text"]
        assert ":white_check_mark:" in header_text


# ---------------------------------------------------------------------------
# TeamsChannel tests
# ---------------------------------------------------------------------------


class TestTeamsChannel:
    """Tests for the Microsoft Teams notification channel."""

    @respx.mock
    async def test_send_success(self) -> None:
        """Teams channel should POST Adaptive Card to webhook URL."""
        url = "https://outlook.office.com/webhook/abc123"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        channel = TeamsChannel(webhook_url=url)
        event = _make_event()
        result = await channel.send(event)

        assert result is True
        assert route.called

        request = route.calls[0].request
        body = json.loads(request.content)
        assert body["type"] == "message"
        assert len(body["attachments"]) == 1
        card = body["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"

    @respx.mock
    async def test_send_failure_returns_false(self) -> None:
        """HTTP failure should return False."""
        url = "https://outlook.office.com/webhook/fail"
        respx.post(url).mock(return_value=httpx.Response(500))

        channel = TeamsChannel(webhook_url=url)
        result = await channel.send(_make_event())
        assert result is False

    async def test_unconfigured_returns_false(self) -> None:
        """Empty webhook URL should return False."""
        channel = TeamsChannel(webhook_url="")
        assert channel.is_configured() is False
        result = await channel.send(_make_event())
        assert result is False

    def test_name(self) -> None:
        """Channel name should be 'teams'."""
        channel = TeamsChannel(webhook_url="https://example.com")
        assert channel.name == "teams"

    def test_adaptive_card_structure(self) -> None:
        """Verify Adaptive Card payload structure."""
        event = _make_event()
        payload = _build_adaptive_card(event)

        assert payload["type"] == "message"
        card = payload["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.4"
        assert len(card["body"]) > 0

        # Should have a FactSet with scan details
        fact_set = [b for b in card["body"] if b.get("type") == "FactSet"]
        assert len(fact_set) == 1
        facts = fact_set[0]["facts"]
        fact_titles = {f["title"] for f in facts}
        assert "Verdict" in fact_titles
        assert "Risk Score" in fact_titles
        assert "Scan ID" in fact_titles


# ---------------------------------------------------------------------------
# PagerDutyChannel tests
# ---------------------------------------------------------------------------


class TestPagerDutyChannel:
    """Tests for the PagerDuty notification channel."""

    @respx.mock
    async def test_send_success_for_malicious(self) -> None:
        """PagerDuty should create incident for MALICIOUS verdict."""
        route = respx.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"status": "success"})
        )

        channel = PagerDutyChannel(routing_key="test-routing-key-123")
        event = _make_event(verdict="MALICIOUS")
        result = await channel.send(event)

        assert result is True
        assert route.called

        body = json.loads(route.calls[0].request.content)
        assert body["routing_key"] == "test-routing-key-123"
        assert body["event_action"] == "trigger"
        assert body["payload"]["severity"] == "critical"
        assert "malwar" in body["payload"]["summary"]

    @respx.mock
    async def test_send_success_for_suspicious(self) -> None:
        """PagerDuty should create incident for SUSPICIOUS verdict."""
        route = respx.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"status": "success"})
        )

        channel = PagerDutyChannel(routing_key="test-key")
        event = _make_event(verdict="SUSPICIOUS", risk_score=50)
        result = await channel.send(event)

        assert result is True
        assert route.called

    async def test_skips_clean_verdict(self) -> None:
        """PagerDuty should skip CLEAN verdicts (returns True, no HTTP)."""
        channel = PagerDutyChannel(routing_key="test-key")
        event = _make_event(
            event_type=EventType.SCAN_COMPLETE,
            verdict="CLEAN",
            risk_score=0,
        )
        result = await channel.send(event)
        assert result is True  # Not an error, just filtered

    async def test_skips_caution_verdict(self) -> None:
        """PagerDuty should skip CAUTION verdicts."""
        channel = PagerDutyChannel(routing_key="test-key")
        event = _make_event(verdict="CAUTION", risk_score=25)
        result = await channel.send(event)
        assert result is True

    @respx.mock
    async def test_send_failure_returns_false(self) -> None:
        """HTTP failure should return False."""
        respx.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(500)
        )
        channel = PagerDutyChannel(routing_key="test-key")
        event = _make_event(verdict="MALICIOUS")
        result = await channel.send(event)
        assert result is False

    async def test_unconfigured_returns_false(self) -> None:
        """Empty routing key should return False."""
        channel = PagerDutyChannel(routing_key="")
        assert channel.is_configured() is False
        result = await channel.send(_make_event())
        assert result is False

    def test_name(self) -> None:
        """Channel name should be 'pagerduty'."""
        channel = PagerDutyChannel(routing_key="key")
        assert channel.name == "pagerduty"

    @respx.mock
    async def test_dedup_key_uses_scan_id(self) -> None:
        """Dedup key should incorporate the scan ID."""
        route = respx.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"status": "success"})
        )
        channel = PagerDutyChannel(routing_key="test-key")
        event = _make_event(verdict="MALICIOUS")
        await channel.send(event)

        body = json.loads(route.calls[0].request.content)
        assert body["dedup_key"] == f"malwar-scan-{event.scan_id}"


# ---------------------------------------------------------------------------
# EmailChannel tests
# ---------------------------------------------------------------------------


class TestEmailChannel:
    """Tests for the Email notification channel."""

    @patch("malwar.notifications.email_channel.smtplib.SMTP")
    async def test_send_success(self, mock_smtp_class: MagicMock) -> None:
        """Email channel should send via SMTP."""
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        channel = EmailChannel(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user@example.com",
            smtp_password="password",  # noqa: S106
            smtp_use_tls=True,
            from_addr="malwar@example.com",
            to_addrs=["security@example.com"],
        )
        event = _make_event()
        result = await channel.send(event)

        assert result is True
        mock_smtp_class.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@example.com", "password")
        mock_server.sendmail.assert_called_once()

    @patch("malwar.notifications.email_channel.smtplib.SMTP")
    async def test_send_without_tls(self, mock_smtp_class: MagicMock) -> None:
        """Email channel should work without TLS."""
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        channel = EmailChannel(
            smtp_host="smtp.example.com",
            smtp_port=25,
            smtp_use_tls=False,
            from_addr="malwar@example.com",
            to_addrs=["security@example.com"],
        )
        result = await channel.send(_make_event())

        assert result is True
        mock_server.starttls.assert_not_called()

    @patch("malwar.notifications.email_channel.smtplib.SMTP")
    async def test_send_failure_returns_false(self, mock_smtp_class: MagicMock) -> None:
        """SMTP error should return False."""
        mock_smtp_class.side_effect = ConnectionRefusedError("Connection refused")

        channel = EmailChannel(
            smtp_host="smtp.example.com",
            to_addrs=["security@example.com"],
        )
        result = await channel.send(_make_event())
        assert result is False

    async def test_unconfigured_returns_false(self) -> None:
        """Missing host or recipients should return False."""
        channel = EmailChannel(smtp_host="", to_addrs=[])
        assert channel.is_configured() is False
        result = await channel.send(_make_event())
        assert result is False

    async def test_unconfigured_missing_recipients(self) -> None:
        """Host without recipients should be unconfigured."""
        channel = EmailChannel(smtp_host="smtp.example.com", to_addrs=[])
        assert channel.is_configured() is False

    def test_name(self) -> None:
        """Channel name should be 'email'."""
        channel = EmailChannel(smtp_host="smtp.example.com", to_addrs=["a@b.com"])
        assert channel.name == "email"

    def test_html_template_contains_verdict(self) -> None:
        """HTML template should contain scan details."""
        event = _make_event()
        html = _build_html(event)
        assert "MALICIOUS" in html
        assert "scan-test-001" in html
        assert "evil-skill" in html
        assert "rule-test-001" in html
        assert "<!DOCTYPE html>" in html


# ---------------------------------------------------------------------------
# GenericWebhookChannel tests
# ---------------------------------------------------------------------------


class TestGenericWebhookChannel:
    """Tests for the generic webhook notification channel."""

    @respx.mock
    async def test_send_success(self) -> None:
        """Generic webhook should POST JSON payload."""
        url = "https://hooks.example.com/notify"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        channel = GenericWebhookChannel(url=url)
        event = _make_event()
        result = await channel.send(event)

        assert result is True
        assert route.called

        body = json.loads(route.calls[0].request.content)
        assert body["event_type"] == "threat_found"
        assert body["scan_id"] == "scan-test-001"
        assert body["verdict"] == "MALICIOUS"

    @respx.mock
    async def test_send_with_hmac_signature(self) -> None:
        """When secret is set, X-Malwar-Signature header should be present."""
        url = "https://hooks.example.com/signed"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        channel = GenericWebhookChannel(url=url, secret="my-secret")  # noqa: S106
        await channel.send(_make_event())

        request = route.calls[0].request
        assert "X-Malwar-Signature" in request.headers
        assert len(request.headers["X-Malwar-Signature"]) == 64  # SHA256 hex

    @respx.mock
    async def test_no_signature_without_secret(self) -> None:
        """Without a secret, no signature header should be present."""
        url = "https://hooks.example.com/unsigned"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        channel = GenericWebhookChannel(url=url)
        await channel.send(_make_event())

        request = route.calls[0].request
        assert "X-Malwar-Signature" not in request.headers

    @respx.mock
    async def test_extra_headers_included(self) -> None:
        """Custom headers should be included in the request."""
        url = "https://hooks.example.com/custom"
        route = respx.post(url).mock(return_value=httpx.Response(200))

        channel = GenericWebhookChannel(
            url=url,
            headers={"Authorization": "Bearer token123"},
        )
        await channel.send(_make_event())

        request = route.calls[0].request
        assert request.headers.get("Authorization") == "Bearer token123"

    @respx.mock
    async def test_send_failure_returns_false(self) -> None:
        """HTTP error should return False."""
        url = "https://hooks.example.com/fail"
        respx.post(url).mock(return_value=httpx.Response(500))

        channel = GenericWebhookChannel(url=url)
        result = await channel.send(_make_event())
        assert result is False

    async def test_unconfigured_returns_false(self) -> None:
        """Empty URL should return False."""
        channel = GenericWebhookChannel(url="")
        assert channel.is_configured() is False
        result = await channel.send(_make_event())
        assert result is False

    def test_name(self) -> None:
        """Channel name should be 'webhook'."""
        channel = GenericWebhookChannel(url="https://example.com")
        assert channel.name == "webhook"


# ---------------------------------------------------------------------------
# NotificationRouter tests
# ---------------------------------------------------------------------------


class TestNotificationRouter:
    """Tests for the NotificationRouter dispatcher."""

    @respx.mock
    async def test_dispatch_to_all_matching_channels(self) -> None:
        """Router should dispatch to all channels that match filters."""
        url1 = "https://hooks.slack.com/services/T00/B00/abc"
        url2 = "https://hooks.example.com/notify"
        respx.post(url1).mock(return_value=httpx.Response(200, text="ok"))
        respx.post(url2).mock(return_value=httpx.Response(200))

        router = NotificationRouter()
        router.register(SlackChannel(webhook_url=url1))
        router.register(GenericWebhookChannel(url=url2))

        event = _make_event()
        results = await router.dispatch(event)

        assert results["slack"] is True
        assert results["webhook"] is True

    @respx.mock
    async def test_verdict_filter(self) -> None:
        """Channels with verdict filter should only receive matching events."""
        url = "https://hooks.slack.com/services/T00/B00/abc"
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))

        router = NotificationRouter()
        router.register(
            SlackChannel(webhook_url=url),
            verdicts=frozenset({"MALICIOUS"}),
        )

        # CLEAN event should be filtered out
        event = _make_event(
            event_type=EventType.SCAN_COMPLETE,
            verdict="CLEAN",
            risk_score=0,
        )
        results = await router.dispatch(event)
        assert len(results) == 0
        assert not route.called

    @respx.mock
    async def test_min_risk_score_filter(self) -> None:
        """Channels with min_risk_score filter should skip low-risk events."""
        url = "https://hooks.slack.com/services/T00/B00/abc"
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))

        router = NotificationRouter()
        router.register(
            SlackChannel(webhook_url=url),
            min_risk_score=50,
        )

        # Low-risk event should be filtered
        event = _make_event(risk_score=30, verdict="CAUTION")
        results = await router.dispatch(event)
        assert len(results) == 0
        assert not route.called

    @respx.mock
    async def test_event_type_filter(self) -> None:
        """Channels with event_type filter should only receive matching types."""
        url = "https://hooks.slack.com/services/T00/B00/abc"
        respx.post(url).mock(return_value=httpx.Response(200, text="ok"))

        router = NotificationRouter()
        router.register(
            SlackChannel(webhook_url=url),
            event_types=frozenset({EventType.THREAT_FOUND}),
        )

        # SCAN_COMPLETE should be filtered out
        event = _make_event(
            event_type=EventType.SCAN_COMPLETE,
            verdict="CLEAN",
            risk_score=0,
        )
        results = await router.dispatch(event)
        assert len(results) == 0

    @respx.mock
    async def test_partial_failure(self) -> None:
        """If one channel fails, others should still succeed."""
        url_ok = "https://hooks.slack.com/services/T00/B00/ok"
        url_fail = "https://hooks.example.com/fail"
        respx.post(url_ok).mock(return_value=httpx.Response(200, text="ok"))
        respx.post(url_fail).mock(return_value=httpx.Response(500))

        router = NotificationRouter()
        router.register(SlackChannel(webhook_url=url_ok))
        router.register(GenericWebhookChannel(url=url_fail))

        event = _make_event()
        results = await router.dispatch(event)

        assert results["slack"] is True
        assert results["webhook"] is False

    def test_get_channel_status(self) -> None:
        """get_channel_status should return info for all registered channels."""
        router = NotificationRouter()
        router.register(
            SlackChannel(webhook_url="https://hooks.slack.com/abc"),
            verdicts=frozenset({"MALICIOUS"}),
            min_risk_score=40,
        )
        router.register(PagerDutyChannel(routing_key="key"))

        statuses = router.get_channel_status()
        assert len(statuses) == 2

        slack_status = statuses[0]
        assert slack_status["name"] == "slack"
        assert slack_status["configured"] is True
        assert "MALICIOUS" in slack_status["verdicts"]
        assert slack_status["min_risk_score"] == 40

    def test_channels_property(self) -> None:
        """channels property should return all registered channel objects."""
        router = NotificationRouter()
        slack = SlackChannel(webhook_url="https://hooks.slack.com/abc")
        teams = TeamsChannel(webhook_url="https://outlook.office.com/webhook/abc")
        router.register(slack)
        router.register(teams)

        channels = router.channels
        assert len(channels) == 2
        assert slack in channels
        assert teams in channels

    async def test_empty_router_dispatch(self) -> None:
        """Router with no channels should return empty results."""
        router = NotificationRouter()
        event = _make_event()
        results = await router.dispatch(event)
        assert results == {}

    @respx.mock
    async def test_unhandled_exception_in_channel(self) -> None:
        """Unhandled exception in channel.send() should be caught."""

        class BrokenChannel(NotificationChannel):
            @property
            def name(self) -> str:
                return "broken"

            async def send(self, event: NotificationEvent) -> bool:
                raise RuntimeError("unexpected")

        router = NotificationRouter()
        router.register(BrokenChannel())

        event = _make_event()
        results = await router.dispatch(event)
        assert results["broken"] is False


# ---------------------------------------------------------------------------
# Factory tests
# ---------------------------------------------------------------------------


class TestBuildRouter:
    """Tests for the notification router factory."""

    def test_auto_detect_slack(self) -> None:
        """Factory should auto-detect Slack when URL is set."""
        from malwar.core.config import Settings

        settings = Settings(
            slack_webhook_url="https://hooks.slack.com/services/T00/B00/abc",
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "slack" in names

    def test_auto_detect_teams(self) -> None:
        """Factory should auto-detect Teams when URL is set."""
        from malwar.core.config import Settings

        settings = Settings(
            teams_webhook_url="https://outlook.office.com/webhook/abc",
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "teams" in names

    def test_auto_detect_pagerduty(self) -> None:
        """Factory should auto-detect PagerDuty when routing key is set."""
        from malwar.core.config import Settings

        settings = Settings(
            pagerduty_routing_key="test-routing-key",
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "pagerduty" in names

    def test_auto_detect_email(self) -> None:
        """Factory should auto-detect email when SMTP host and recipients are set."""
        from malwar.core.config import Settings

        settings = Settings(
            smtp_host="smtp.example.com",
            smtp_to=["security@example.com"],
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "email" in names

    def test_auto_detect_webhook(self) -> None:
        """Factory should auto-detect generic webhook when URL is set."""
        from malwar.core.config import Settings

        settings = Settings(
            webhook_url="https://hooks.example.com/notify",
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "webhook" in names

    def test_explicit_channels_list(self) -> None:
        """Factory should only build channels specified in notification_channels."""
        from malwar.core.config import Settings

        settings = Settings(
            notification_channels=["slack"],
            slack_webhook_url="https://hooks.slack.com/services/T00/B00/abc",
            teams_webhook_url="https://outlook.office.com/webhook/abc",
            _env_file=None,
        )
        router = build_router(settings)
        names = [ch.name for ch in router.channels]
        assert "slack" in names
        assert "teams" not in names

    def test_no_channels_configured(self) -> None:
        """Factory should return empty router when nothing is configured."""
        from malwar.core.config import Settings

        settings = Settings(_env_file=None)
        router = build_router(settings)
        assert len(router.channels) == 0

    def test_unconfigured_channel_in_list_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Factory should warn when a requested channel lacks config."""
        from malwar.core.config import Settings

        settings = Settings(
            notification_channels=["slack"],
            # No slack_webhook_url set
            _env_file=None,
        )
        with caplog.at_level(logging.WARNING, logger="malwar.notifications.factory"):
            router = build_router(settings)

        assert len(router.channels) == 0
        assert any("not configured" in record.message for record in caplog.records)

    def test_multiple_webhook_urls(self) -> None:
        """Factory should create a webhook channel for each URL."""
        from malwar.core.config import Settings

        settings = Settings(
            webhook_urls=["https://a.example.com", "https://b.example.com"],
            _env_file=None,
        )
        router = build_router(settings)
        webhook_channels = [ch for ch in router.channels if ch.name == "webhook"]
        assert len(webhook_channels) == 2
