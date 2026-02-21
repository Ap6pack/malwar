# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for the audit log API endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.audit.events import AuditEvent, AuditEventType
from malwar.audit.logger import AuditLogger, set_audit_logger
from malwar.audit.store import AuditStore
from malwar.storage.database import close_db, init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database."""
    db_path = tmp_path / "test_audit_api.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    return create_app()


@pytest.fixture
async def client(app, tmp_path):
    """Provide an async HTTP client bound to the test app, with DB initialized."""
    db_path = tmp_path / "test_audit_api.db"
    await init_db(db_path)

    # Configure audit logger to use the test DB
    logger = AuditLogger(log_dir=tmp_path / "audit_logs")
    set_audit_logger(logger)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac
    finally:
        await close_db()


async def _seed_audit_events(count: int = 5) -> list[str]:
    """Insert test audit events and return their event IDs."""
    from malwar.storage.database import get_db

    db = await get_db()
    store = AuditStore(db)
    event_ids = []

    for i in range(count):
        event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="test-actor",
            resource_type="scan",
            resource_id=f"scan-{i}",
            action=f"Scan {i} completed",
            details={"index": i},
        )
        await store.insert(event)
        event_ids.append(event.event_id)

    return event_ids


# ---------------------------------------------------------------------------
# GET /api/v1/audit
# ---------------------------------------------------------------------------


class TestListAuditEvents:
    """Tests for the audit event listing endpoint."""

    async def test_list_audit_events_empty(self, client) -> None:
        """Empty database returns empty list."""
        resp = await client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["events"] == []

    async def test_list_audit_events_returns_seeded(self, client) -> None:
        """Seeded events are returned in the listing."""
        event_ids = await _seed_audit_events(3)

        resp = await client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["events"]) == 3

        returned_ids = {e["event_id"] for e in data["events"]}
        for eid in event_ids:
            assert eid in returned_ids

    async def test_list_audit_events_filter_by_event_type(self, client) -> None:
        """Filtering by event_type returns only matching events."""
        from malwar.storage.database import get_db

        db = await get_db()
        store = AuditStore(db)

        await store.insert(AuditEvent(
            event_type=AuditEventType.SCAN_STARTED,
            actor="test",
            resource_id="s1",
        ))
        await store.insert(AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="test",
            resource_id="s1",
        ))

        resp = await client.get("/api/v1/audit?event_type=scan_started")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["event_type"] == "scan_started"

    async def test_list_audit_events_filter_by_actor(self, client) -> None:
        """Filtering by actor returns only matching events."""
        from malwar.storage.database import get_db

        db = await get_db()
        store = AuditStore(db)

        await store.insert(AuditEvent(
            event_type=AuditEventType.API_REQUEST,
            actor="alice",
        ))
        await store.insert(AuditEvent(
            event_type=AuditEventType.API_REQUEST,
            actor="bob",
        ))

        resp = await client.get("/api/v1/audit?actor=alice")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["events"][0]["actor"] == "alice"

    async def test_list_audit_events_pagination(self, client) -> None:
        """Pagination with limit and offset works correctly."""
        await _seed_audit_events(10)

        # Filter by event_type to avoid interference from middleware-generated
        # api_request events that are added by the audit middleware itself.
        base = "/api/v1/audit?event_type=scan_completed"

        resp_page1 = await client.get(f"{base}&limit=3&offset=0")
        assert resp_page1.status_code == 200
        page1 = resp_page1.json()
        assert len(page1["events"]) == 3
        assert page1["total"] == 10

        resp_page2 = await client.get(f"{base}&limit=3&offset=3")
        assert resp_page2.status_code == 200
        page2 = resp_page2.json()
        assert len(page2["events"]) == 3

        # Ensure no overlap
        ids1 = {e["event_id"] for e in page1["events"]}
        ids2 = {e["event_id"] for e in page2["events"]}
        assert ids1.isdisjoint(ids2)

    async def test_list_audit_events_response_structure(self, client) -> None:
        """Verify the full response structure matches AuditEventResponse."""
        await _seed_audit_events(1)

        resp = await client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        event = data["events"][0]

        required_fields = {
            "event_id",
            "timestamp",
            "event_type",
            "actor",
            "resource_type",
            "resource_id",
            "action",
            "details",
            "ip_address",
        }
        assert required_fields.issubset(set(event.keys()))


# ---------------------------------------------------------------------------
# GET /api/v1/audit/{event_id}
# ---------------------------------------------------------------------------


class TestGetAuditEvent:
    """Tests for the single audit event retrieval endpoint."""

    async def test_get_audit_event_by_id(self, client) -> None:
        """Retrieve a specific audit event by its ID."""
        event_ids = await _seed_audit_events(1)
        event_id = event_ids[0]

        resp = await client.get(f"/api/v1/audit/{event_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id
        assert data["event_type"] == "scan_completed"
        assert data["actor"] == "test-actor"

    async def test_get_audit_event_not_found(self, client) -> None:
        """Non-existent event ID returns 404."""
        resp = await client.get("/api/v1/audit/nonexistent-id")
        assert resp.status_code == 404

    async def test_get_audit_event_details_parsed(self, client) -> None:
        """Event details JSON is correctly parsed in the response."""
        event_ids = await _seed_audit_events(1)
        event_id = event_ids[0]

        resp = await client.get(f"/api/v1/audit/{event_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["details"], dict)
        assert "index" in data["details"]


# ---------------------------------------------------------------------------
# Audit middleware integration
# ---------------------------------------------------------------------------


class TestAuditMiddleware:
    """Tests verifying the audit middleware captures API requests."""

    async def test_api_request_generates_audit_event(self, client) -> None:
        """Making an API request should create an audit event via middleware."""
        # Make a request to a non-audit endpoint
        await client.get("/api/v1/scans")

        # The audit middleware should have logged the request
        resp = await client.get("/api/v1/audit?event_type=api_request")
        assert resp.status_code == 200
        data = resp.json()
        # There should be at least one api_request event (from the /scans call)
        # Note: the /audit calls themselves might also generate events depending
        # on middleware config, so we just check for >= 1
        assert data["total"] >= 1

    async def test_health_endpoint_not_audited(self, client) -> None:
        """Health check requests should be excluded from audit logging."""
        await client.get("/api/v1/health")

        resp = await client.get("/api/v1/audit?event_type=api_request")
        data = resp.json()
        # Health endpoint should be skipped by audit middleware
        health_events = [
            e for e in data["events"]
            if e.get("resource_id") == "/api/v1/health"
        ]
        assert len(health_events) == 0
