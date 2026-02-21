# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the audit logging module."""

from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite
import pytest

from malwar.audit.events import AuditEvent, AuditEventType
from malwar.audit.logger import AuditLogger, hash_api_key, set_audit_logger
from malwar.audit.store import AuditStore
from malwar.storage.migrations import run_migrations

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def audit_db(tmp_path):
    """Create a temporary SQLite database with audit_log table."""
    db_path = tmp_path / "test_audit.db"
    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await run_migrations(db)
    yield db
    await db.close()


@pytest.fixture
def sample_event() -> AuditEvent:
    """Create a sample audit event for testing."""
    return AuditEvent(
        event_type=AuditEventType.SCAN_COMPLETED,
        actor="cli",
        resource_type="scan",
        resource_id="abc123",
        action="Scan completed: verdict=CLEAN",
        details={"verdict": "CLEAN", "risk_score": 0, "finding_count": 0},
        ip_address="",
    )


# ---------------------------------------------------------------------------
# AuditEvent model tests
# ---------------------------------------------------------------------------


class TestAuditEvent:
    """Tests for the AuditEvent data model."""

    def test_event_has_auto_generated_id(self) -> None:
        event = AuditEvent(event_type=AuditEventType.SCAN_STARTED)
        assert event.event_id
        assert len(event.event_id) == 32  # hex UUID

    def test_event_has_auto_generated_timestamp(self) -> None:
        event = AuditEvent(event_type=AuditEventType.SCAN_STARTED)
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None

    def test_event_type_enum_values(self) -> None:
        assert AuditEventType.SCAN_STARTED == "scan_started"
        assert AuditEventType.SCAN_COMPLETED == "scan_completed"
        assert AuditEventType.FINDING_DETECTED == "finding_detected"
        assert AuditEventType.API_KEY_USED == "api_key_used"
        assert AuditEventType.CONFIG_CHANGED == "config_changed"
        assert AuditEventType.SIGNATURE_CREATED == "signature_created"
        assert AuditEventType.SIGNATURE_UPDATED == "signature_updated"
        assert AuditEventType.SIGNATURE_DELETED == "signature_deleted"
        assert AuditEventType.API_REQUEST == "api_request"

    def test_event_serialization(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="cli",
            resource_type="scan",
            resource_id="test-scan-1",
            action="Scan completed",
            details={"verdict": "CLEAN"},
        )
        data = event.model_dump(mode="json")
        assert data["event_type"] == "scan_completed"
        assert data["actor"] == "cli"
        assert data["details"]["verdict"] == "CLEAN"

    def test_event_defaults(self) -> None:
        event = AuditEvent(event_type=AuditEventType.API_REQUEST)
        assert event.actor == "cli"
        assert event.resource_type == ""
        assert event.resource_id == ""
        assert event.action == ""
        assert event.details == {}
        assert event.ip_address == ""


# ---------------------------------------------------------------------------
# AuditStore tests
# ---------------------------------------------------------------------------


class TestAuditStore:
    """Tests for the AuditStore repository."""

    async def test_insert_and_retrieve(self, audit_db, sample_event) -> None:
        store = AuditStore(audit_db)
        await store.insert(sample_event)

        result = await store.get_by_id(sample_event.event_id)
        assert result is not None
        assert result["event_id"] == sample_event.event_id
        assert result["event_type"] == "scan_completed"
        assert result["actor"] == "cli"
        assert result["resource_type"] == "scan"
        assert result["resource_id"] == "abc123"

    async def test_get_by_id_not_found(self, audit_db) -> None:
        store = AuditStore(audit_db)
        result = await store.get_by_id("nonexistent")
        assert result is None

    async def test_list_events_returns_all(self, audit_db) -> None:
        store = AuditStore(audit_db)

        for i in range(5):
            event = AuditEvent(
                event_type=AuditEventType.SCAN_COMPLETED,
                actor="cli",
                resource_id=f"scan-{i}",
            )
            await store.insert(event)

        results = await store.list_events()
        assert len(results) == 5

    async def test_list_events_filter_by_event_type(self, audit_db) -> None:
        store = AuditStore(audit_db)

        await store.insert(AuditEvent(
            event_type=AuditEventType.SCAN_STARTED,
            resource_id="scan-1",
        ))
        await store.insert(AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            resource_id="scan-1",
        ))
        await store.insert(AuditEvent(
            event_type=AuditEventType.FINDING_DETECTED,
            resource_id="scan-1/rule-1",
        ))

        results = await store.list_events(event_type="scan_started")
        assert len(results) == 1
        assert results[0]["event_type"] == "scan_started"

    async def test_list_events_filter_by_actor(self, audit_db) -> None:
        store = AuditStore(audit_db)

        await store.insert(AuditEvent(
            event_type=AuditEventType.API_REQUEST,
            actor="user-a",
        ))
        await store.insert(AuditEvent(
            event_type=AuditEventType.API_REQUEST,
            actor="user-b",
        ))

        results = await store.list_events(actor="user-a")
        assert len(results) == 1
        assert results[0]["actor"] == "user-a"

    async def test_list_events_filter_by_date_range(self, audit_db) -> None:
        store = AuditStore(audit_db)

        # Insert events with explicit timestamps
        old_event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            resource_id="old-scan",
        )
        new_event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            timestamp=datetime(2026, 2, 15, tzinfo=UTC),
            resource_id="new-scan",
        )
        await store.insert(old_event)
        await store.insert(new_event)

        results = await store.list_events(start_date="2026-02-01")
        assert len(results) == 1
        assert results[0]["resource_id"] == "new-scan"

    async def test_list_events_with_limit_and_offset(self, audit_db) -> None:
        store = AuditStore(audit_db)

        for i in range(10):
            await store.insert(AuditEvent(
                event_type=AuditEventType.API_REQUEST,
                resource_id=f"req-{i}",
            ))

        results = await store.list_events(limit=3, offset=0)
        assert len(results) == 3

        results_page2 = await store.list_events(limit=3, offset=3)
        assert len(results_page2) == 3
        # Pages should not overlap
        ids_page1 = {r["event_id"] for r in results}
        ids_page2 = {r["event_id"] for r in results_page2}
        assert ids_page1.isdisjoint(ids_page2)

    async def test_count_events(self, audit_db) -> None:
        store = AuditStore(audit_db)

        for _ in range(7):
            await store.insert(AuditEvent(
                event_type=AuditEventType.SCAN_COMPLETED,
            ))

        count = await store.count_events()
        assert count == 7

    async def test_count_events_with_filter(self, audit_db) -> None:
        store = AuditStore(audit_db)

        await store.insert(AuditEvent(event_type=AuditEventType.SCAN_STARTED))
        await store.insert(AuditEvent(event_type=AuditEventType.SCAN_COMPLETED))
        await store.insert(AuditEvent(event_type=AuditEventType.SCAN_COMPLETED))

        count = await store.count_events(event_type="scan_completed")
        assert count == 2

    async def test_details_json_round_trip(self, audit_db) -> None:
        store = AuditStore(audit_db)

        event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            details={"verdict": "MALICIOUS", "risk_score": 95, "nested": {"key": "value"}},
        )
        await store.insert(event)

        result = await store.get_by_id(event.event_id)
        assert result["details"]["verdict"] == "MALICIOUS"
        assert result["details"]["risk_score"] == 95
        assert result["details"]["nested"]["key"] == "value"

    async def test_list_events_ordered_by_timestamp_desc(self, audit_db) -> None:
        store = AuditStore(audit_db)

        early = AuditEvent(
            event_type=AuditEventType.SCAN_STARTED,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        )
        late = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            timestamp=datetime(2026, 2, 1, tzinfo=UTC),
        )
        await store.insert(early)
        await store.insert(late)

        results = await store.list_events()
        assert len(results) == 2
        # Latest should come first
        assert results[0]["event_id"] == late.event_id
        assert results[1]["event_id"] == early.event_id


# ---------------------------------------------------------------------------
# AuditLogger tests
# ---------------------------------------------------------------------------


class TestAuditLogger:
    """Tests for the AuditLogger class."""

    async def test_log_writes_json_file(self, tmp_path, audit_db, sample_event) -> None:
        """Logger should create daily JSONL log files."""
        from malwar.storage import database as db_module

        # Temporarily replace the module-level _db
        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            await logger.log(sample_event)

            # Check that a .jsonl file was created
            log_files = list((tmp_path / "audit_logs").glob("audit-*.jsonl"))
            assert len(log_files) == 1

            content = log_files[0].read_text()
            assert sample_event.event_id in content
            assert "scan_completed" in content
        finally:
            db_module._db = original_db

    async def test_log_scan_started(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_scan_started(
                scan_id="test-scan-1",
                target="SKILL.md",
                actor="cli",
                layers=["rule_engine"],
            )

            assert event.event_type == AuditEventType.SCAN_STARTED
            assert event.resource_type == "scan"
            assert event.resource_id == "test-scan-1"
            assert event.details["target"] == "SKILL.md"
            assert event.details["layers"] == ["rule_engine"]

            # Verify persisted to DB
            store = AuditStore(audit_db)
            result = await store.get_by_id(event.event_id)
            assert result is not None
        finally:
            db_module._db = original_db

    async def test_log_scan_completed(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_scan_completed(
                scan_id="test-scan-1",
                verdict="MALICIOUS",
                risk_score=95,
                finding_count=3,
                duration_ms=150,
            )

            assert event.event_type == AuditEventType.SCAN_COMPLETED
            assert event.details["verdict"] == "MALICIOUS"
            assert event.details["risk_score"] == 95
            assert event.details["finding_count"] == 3
        finally:
            db_module._db = original_db

    async def test_log_finding(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_finding(
                scan_id="test-scan-1",
                rule_id="MALWAR-PI-001",
                severity="critical",
                title="Prompt Injection Detected",
            )

            assert event.event_type == AuditEventType.FINDING_DETECTED
            assert event.resource_type == "finding"
            assert "MALWAR-PI-001" in event.resource_id
            assert event.details["rule_id"] == "MALWAR-PI-001"
            assert event.details["severity"] == "critical"
        finally:
            db_module._db = original_db

    async def test_log_signature_change(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_signature_change(
                AuditEventType.SIGNATURE_CREATED,
                "sig-abc123",
                details={"name": "Test Signature"},
            )

            assert event.event_type == AuditEventType.SIGNATURE_CREATED
            assert event.resource_type == "signature"
            assert event.resource_id == "sig-abc123"
        finally:
            db_module._db = original_db

    async def test_log_api_key_used(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_api_key_used(
                api_key="secret-key-123",
                endpoint="/api/v1/scan",
                method="POST",
                ip_address="192.168.1.1",
                status_code=200,
            )

            assert event.event_type == AuditEventType.API_KEY_USED
            # API key should be hashed, not stored in plain text
            assert "secret-key-123" not in event.actor
            assert event.actor.startswith("sha256:")
        finally:
            db_module._db = original_db

    async def test_log_api_request(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_api_request(
                method="GET",
                path="/api/v1/scans",
                status_code=200,
                actor="anonymous",
                ip_address="10.0.0.1",
                duration_ms=42.5,
            )

            assert event.event_type == AuditEventType.API_REQUEST
            assert event.details["method"] == "GET"
            assert event.details["path"] == "/api/v1/scans"
            assert event.details["status_code"] == 200
            assert event.details["duration_ms"] == 42.5
        finally:
            db_module._db = original_db

    async def test_log_config_change(self, tmp_path, audit_db) -> None:
        from malwar.storage import database as db_module

        original_db = db_module._db
        db_module._db = audit_db

        try:
            logger = AuditLogger(log_dir=tmp_path / "audit_logs")
            set_audit_logger(logger)

            event = await logger.log_config_change(
                "llm_model",
                details={"old": "claude-sonnet-4-6", "new": "claude-opus-4-6"},
            )

            assert event.event_type == AuditEventType.CONFIG_CHANGED
            assert event.resource_type == "config"
            assert event.resource_id == "llm_model"
        finally:
            db_module._db = original_db

    async def test_logger_gracefully_handles_db_failure(self, tmp_path) -> None:
        """Logger should not raise even if the database is unavailable."""
        logger = AuditLogger(log_dir=tmp_path / "audit_logs")

        # This should not raise, even though no DB is initialized
        event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="cli",
        )
        result = await logger.log(event)
        # Still returns the event
        assert result.event_id == event.event_id


# ---------------------------------------------------------------------------
# hash_api_key tests
# ---------------------------------------------------------------------------


class TestHashApiKey:
    """Tests for the hash_api_key utility."""

    def test_hash_regular_key(self) -> None:
        result = hash_api_key("my-secret-key")
        assert result.startswith("sha256:")
        assert "my-secret-key" not in result
        assert len(result) == len("sha256:") + 16

    def test_hash_is_deterministic(self) -> None:
        assert hash_api_key("key-1") == hash_api_key("key-1")

    def test_hash_different_keys_differ(self) -> None:
        assert hash_api_key("key-1") != hash_api_key("key-2")

    def test_hash_empty_string(self) -> None:
        assert hash_api_key("") == "anonymous"

    def test_hash_anonymous(self) -> None:
        assert hash_api_key("anonymous") == "anonymous"

    def test_hash_cli(self) -> None:
        assert hash_api_key("cli") == "cli"
