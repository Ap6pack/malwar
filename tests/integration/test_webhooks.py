# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for end-to-end webhook notification wiring."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.storage.database import close_db, init_db

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def webhook_url():
    return "https://hooks.example.com/malwar-webhook"


@pytest.fixture
def webhook_secret():
    return "test-webhook-secret-key"


@pytest.fixture
def webhook_app(tmp_path, monkeypatch, webhook_url, webhook_secret):
    """Create a FastAPI app with webhook configuration."""
    db_path = tmp_path / "test_webhook.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    monkeypatch.setenv("MALWAR_WEBHOOK_URL", webhook_url)
    monkeypatch.setenv("MALWAR_WEBHOOK_SECRET", webhook_secret)
    monkeypatch.setenv("MALWAR_WEBHOOK_VERDICTS", '["MALICIOUS","SUSPICIOUS"]')
    return create_app()


@pytest.fixture
def no_webhook_app(tmp_path, monkeypatch):
    """Create a FastAPI app without webhook configuration."""
    db_path = tmp_path / "test_no_webhook.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    monkeypatch.setenv("MALWAR_WEBHOOK_URL", "")
    monkeypatch.setenv("MALWAR_WEBHOOK_SECRET", "")
    return create_app()


@pytest.fixture
async def webhook_client(webhook_app, tmp_path):
    """Provide an async HTTP client bound to the webhook-enabled app."""
    db_path = tmp_path / "test_webhook.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=webhook_app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


@pytest.fixture
async def no_webhook_client(no_webhook_app, tmp_path):
    """Provide an async HTTP client bound to the app without webhooks."""
    db_path = tmp_path / "test_no_webhook.db"
    await init_db(db_path)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=no_webhook_app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWebhookFiresOnMalicious:
    """Webhook fires when a scan returns a MALICIOUS verdict."""

    @respx.mock
    async def test_webhook_fires_on_malicious_verdict(
        self, webhook_client, webhook_url
    ) -> None:
        """Submitting a malicious skill should trigger a webhook POST."""
        route = respx.post(webhook_url).mock(return_value=httpx.Response(200))

        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "MALICIOUS"

        # Give background task time to complete
        await asyncio.sleep(0.1)

        assert route.called
        request_body = json.loads(route.calls[0].request.content)
        assert request_body["event"] == "scan.completed"
        assert request_body["scan_id"] == data["scan_id"]
        assert request_body["verdict"] == "MALICIOUS"
        assert request_body["risk_score"] >= 75
        assert request_body["finding_count"] > 0
        assert "timestamp" in request_body
        assert "skill_name" in request_body


class TestWebhookDoesNotFireOnClean:
    """Webhook should NOT fire when a scan returns a CLEAN verdict."""

    @respx.mock
    async def test_webhook_does_not_fire_on_clean_verdict(
        self, webhook_client, webhook_url
    ) -> None:
        """Submitting a benign skill should NOT trigger a webhook POST."""
        route = respx.post(webhook_url).mock(return_value=httpx.Response(200))

        content = (BENIGN_DIR / "hello_world.md").read_text()
        resp = await webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "CLEAN"

        # Give background task time to complete (it shouldn't fire)
        await asyncio.sleep(0.1)

        assert not route.called


class TestWebhookHmacSignature:
    """Webhook includes a valid HMAC-SHA256 signature in the X-Malwar-Signature header."""

    @respx.mock
    async def test_webhook_includes_hmac_signature(
        self, webhook_client, webhook_url, webhook_secret
    ) -> None:
        """The webhook request should include a valid HMAC-SHA256 signature."""
        route = respx.post(webhook_url).mock(return_value=httpx.Response(200))

        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        assert resp.json()["verdict"] == "MALICIOUS"

        # Give background task time to complete
        await asyncio.sleep(0.1)

        assert route.called
        request = route.calls[0].request
        assert "X-Malwar-Signature" in request.headers

        # Verify the signature is a valid hex-encoded SHA-256 digest
        signature = request.headers["X-Malwar-Signature"]
        assert len(signature) == 64  # SHA-256 hex digest length

        # Verify the signature matches the payload
        payload_body = json.loads(request.content)
        payload_bytes = json.dumps(
            payload_body, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        expected_sig = hmac.new(
            webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        assert signature == expected_sig


class TestWebhookRetriesOnFailure:
    """Webhook retries on transient failures with exponential backoff."""

    @respx.mock
    @patch("malwar.notifications.webhook.asyncio.sleep", new_callable=AsyncMock)
    async def test_webhook_retries_on_failure(
        self, mock_sleep, webhook_client, webhook_url
    ) -> None:
        """Webhook should retry up to 3 times when the endpoint fails."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return httpx.Response(503)
            return httpx.Response(200)

        respx.post(webhook_url).mock(side_effect=side_effect)

        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        assert resp.json()["verdict"] == "MALICIOUS"

        # Give background task time to complete retries
        await asyncio.sleep(0.1)

        # Should have been called 3 times (2 failures + 1 success)
        assert call_count == 3
        # Verify exponential backoff was used (1s and 2s delays)
        mock_sleep.assert_any_call(1)  # First retry: 1s
        mock_sleep.assert_any_call(2)  # Second retry: 2s


class TestNoWebhookWhenNotConfigured:
    """No webhook fires when the webhook URL is not configured."""

    @respx.mock
    async def test_no_webhook_when_url_not_configured(
        self, no_webhook_client
    ) -> None:
        """When webhook_url is empty, no HTTP calls should be made."""
        # Set up a catch-all route to detect any outgoing POST
        catch_all = respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(200)
        )

        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await no_webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200
        assert resp.json()["verdict"] == "MALICIOUS"

        # Give background task time to complete (it shouldn't fire)
        await asyncio.sleep(0.1)

        assert not catch_all.called


class TestWebhookPayloadSchema:
    """Verify the webhook payload matches the documented schema."""

    @respx.mock
    async def test_payload_schema(
        self, webhook_client, webhook_url
    ) -> None:
        """Webhook payload should contain all required fields."""
        route = respx.post(webhook_url).mock(return_value=httpx.Response(200))

        content = (MALICIOUS_DIR / "prompt_injection_basic.md").read_text()
        resp = await webhook_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "prompt_injection_basic.md",
                "layers": ["rule_engine", "threat_intel"],
                "use_llm": False,
            },
        )

        assert resp.status_code == 200

        # Give background task time to complete
        await asyncio.sleep(0.1)

        assert route.called
        payload = json.loads(route.calls[0].request.content)

        # Verify all required fields per the schema
        required_fields = {
            "event",
            "scan_id",
            "verdict",
            "risk_score",
            "finding_count",
            "skill_name",
            "timestamp",
        }
        assert required_fields.issubset(set(payload.keys()))
        assert payload["event"] == "scan.completed"
        assert isinstance(payload["risk_score"], int)
        assert isinstance(payload["finding_count"], int)
        assert isinstance(payload["timestamp"], str)
