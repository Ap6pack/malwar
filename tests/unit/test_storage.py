# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the SQLite storage layer: database, migrations, and repositories."""

from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite
import pytest

from malwar.core.constants import DetectorLayer, ScanStatus, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.models.scan import ScanResult
from malwar.storage.database import close_db, init_db
from malwar.storage.repositories.campaigns import CampaignRepository
from malwar.storage.repositories.findings import FindingRepository
from malwar.storage.repositories.publishers import PublisherRepository
from malwar.storage.repositories.scans import ScanRepository
from malwar.storage.repositories.signatures import SignatureRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    """Create an in-memory database, run migrations, yield, then close."""
    # Reset the module-level _db so init_db creates a fresh connection
    import malwar.storage.database as db_mod

    db_mod._db = None

    conn = await init_db(":memory:")
    yield conn
    await close_db()


@pytest.fixture
def scan_repo(db: aiosqlite.Connection) -> ScanRepository:
    return ScanRepository(db)


@pytest.fixture
def finding_repo(db: aiosqlite.Connection) -> FindingRepository:
    return FindingRepository(db)


@pytest.fixture
def signature_repo(db: aiosqlite.Connection) -> SignatureRepository:
    return SignatureRepository(db)


@pytest.fixture
def campaign_repo(db: aiosqlite.Connection) -> CampaignRepository:
    return CampaignRepository(db)


@pytest.fixture
def publisher_repo(db: aiosqlite.Connection) -> PublisherRepository:
    return PublisherRepository(db)


def _make_scan_result(
    scan_id: str = "scan-001",
    target: str = "/tmp/test-skill/SKILL.md",
    status: ScanStatus = ScanStatus.COMPLETED,
    findings: list[Finding] | None = None,
) -> ScanResult:
    """Helper to create a ScanResult for testing."""
    return ScanResult(
        scan_id=scan_id,
        target=target,
        status=status,
        started_at=datetime(2026, 2, 20, 12, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 20, 12, 0, 5, tzinfo=UTC),
        duration_ms=5000,
        skill_name="test-skill",
        skill_author="testauthor",
        skill_sha256="abc123def456",
        layers_executed=["rule_engine", "url_crawler"],
        errors=[],
        findings=findings or [],
    )


def _make_finding(
    finding_id: str = "MALWAR-TEST-001",
    rule_id: str = "rule-test-001",
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Helper to create a Finding for testing."""
    return Finding(
        id=finding_id,
        rule_id=rule_id,
        title="Test Finding",
        description="A test finding for unit tests",
        severity=severity,
        confidence=0.9,
        category=ThreatCategory.SUSPICIOUS_COMMAND,
        detector_layer=DetectorLayer.RULE_ENGINE,
        location=Location(line_start=10, line_end=15, snippet="curl http://evil.com"),
        evidence=["matched pattern: curl"],
        ioc_values=["http://evil.com"],
        remediation="Remove the suspicious command",
    )


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------


class TestDatabaseInit:
    """Tests for database initialization and migrations."""

    async def test_init_creates_all_tables(self, db: aiosqlite.Connection):
        """All six tables must exist after init_db."""
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        rows = await cursor.fetchall()
        table_names = sorted(row[0] for row in rows)

        expected = sorted([
            "campaigns",
            "findings",
            "publishers",
            "scans",
            "signatures",
            "url_analysis",
        ])
        assert table_names == expected

    async def test_indexes_created(self, db: aiosqlite.Connection):
        """Key indexes should exist after migration."""
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
        rows = await cursor.fetchall()
        index_names = {row[0] for row in rows}

        expected_indexes = {
            "idx_scans_target",
            "idx_scans_skill_sha256",
            "idx_scans_verdict",
            "idx_scans_created_at",
            "idx_findings_scan_id",
            "idx_findings_rule_id",
            "idx_findings_severity",
            "idx_findings_category",
        }
        assert expected_indexes.issubset(index_names)

    async def test_foreign_keys_enabled(self, db: aiosqlite.Connection):
        """PRAGMA foreign_keys should be ON."""
        cursor = await db.execute("PRAGMA foreign_keys")
        row = await cursor.fetchone()
        assert row[0] == 1


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------


class TestSeedData:
    """Verify seed data from migrations."""

    async def test_clawhavoc_campaign_seeded(self, db: aiosqlite.Connection):
        """The ClawHavoc campaign should be present."""
        cursor = await db.execute(
            "SELECT * FROM campaigns WHERE id = 'campaign-clawhavoc-001'"
        )
        row = await cursor.fetchone()
        assert row is not None
        data = dict(row)
        assert data["name"] == "ClawHavoc"
        assert data["status"] == "active"
        assert "AMOS infostealer" in data["description"]

    async def test_ioc_signatures_seeded(self, db: aiosqlite.Connection):
        """Four ClawHavoc IOC signatures should be seeded."""
        cursor = await db.execute(
            "SELECT * FROM signatures WHERE campaign_id = 'campaign-clawhavoc-001'"
        )
        rows = await cursor.fetchall()
        assert len(rows) == 4

        sig_ids = {dict(r)["id"] for r in rows}
        assert sig_ids == {
            "sig-clawhavoc-c2-ip",
            "sig-clawhavoc-glot",
            "sig-clawhavoc-github",
            "sig-clawhavoc-domain",
        }

        # All should be critical
        for row in rows:
            assert dict(row)["severity"] == "critical"

    async def test_threat_actor_publishers_seeded(self, db: aiosqlite.Connection):
        """Six known threat actor publishers should be seeded."""
        cursor = await db.execute(
            "SELECT * FROM publishers WHERE is_known_threat_actor = 1"
        )
        rows = await cursor.fetchall()
        assert len(rows) == 6

        publisher_ids = {dict(r)["id"] for r in rows}
        assert publisher_ids == {
            "zaycv",
            "Ddoy233",
            "hightower6eu",
            "clawdhub1",
            "Aslaep123",
            "moonshine-100rze",
        }

        for row in rows:
            assert dict(row)["reputation_score"] == 0.0

    async def test_migrations_are_idempotent(self, db: aiosqlite.Connection):
        """Running migrations twice should not raise or duplicate data."""
        from malwar.storage.migrations import run_migrations

        await run_migrations(db)  # second run
        cursor = await db.execute("SELECT COUNT(*) FROM campaigns")
        row = await cursor.fetchone()
        assert row[0] == 1  # still one campaign


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------


class TestScanRepository:
    """Tests for ScanRepository."""

    async def test_create_and_get(self, scan_repo: ScanRepository):
        """Create a scan and retrieve it by ID."""
        scan = _make_scan_result()
        await scan_repo.create(scan)

        retrieved = await scan_repo.get("scan-001")
        assert retrieved is not None
        assert retrieved.scan_id == "scan-001"
        assert retrieved.target == "/tmp/test-skill/SKILL.md"
        assert retrieved.skill_name == "test-skill"
        assert retrieved.skill_author == "testauthor"
        assert retrieved.skill_sha256 == "abc123def456"
        assert str(retrieved.status) == "completed"
        assert retrieved.duration_ms == 5000
        assert retrieved.layers_executed == ["rule_engine", "url_crawler"]

    async def test_get_nonexistent(self, scan_repo: ScanRepository):
        """Getting a nonexistent scan returns None."""
        result = await scan_repo.get("does-not-exist")
        assert result is None

    async def test_list_recent(self, scan_repo: ScanRepository):
        """list_recent returns scans ordered by created_at desc."""
        for i in range(5):
            scan = _make_scan_result(scan_id=f"scan-{i:03d}")
            await scan_repo.create(scan)

        results = await scan_repo.list_recent(limit=3)
        assert len(results) == 3
        # Most recent first
        assert results[0]["id"] == "scan-004"

    async def test_update_status(self, scan_repo: ScanRepository):
        """update_status modifies the scan's status and optional fields."""
        scan = _make_scan_result(status=ScanStatus.RUNNING)
        await scan_repo.create(scan)

        await scan_repo.update_status(
            "scan-001",
            "completed",
            risk_score=85,
            verdict="MALICIOUS",
            overall_severity="critical",
            duration_ms=7500,
            layers_executed=["rule_engine", "url_crawler", "llm_analyzer"],
        )

        updated = await scan_repo.get("scan-001")
        assert updated is not None
        assert str(updated.status) == "completed"
        assert updated.duration_ms == 7500
        assert updated.layers_executed == ["rule_engine", "url_crawler", "llm_analyzer"]


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------


class TestFindingRepository:
    """Tests for FindingRepository."""

    async def test_create_many_and_get_by_scan(
        self,
        scan_repo: ScanRepository,
        finding_repo: FindingRepository,
    ):
        """Bulk-insert findings and retrieve them by scan ID."""
        scan = _make_scan_result()
        await scan_repo.create(scan)

        findings = [
            _make_finding(finding_id=f"MALWAR-TEST-{i:03d}", rule_id=f"rule-{i:03d}")
            for i in range(3)
        ]
        await finding_repo.create_many("scan-001", findings)

        rows = await finding_repo.get_by_scan("scan-001")
        assert len(rows) == 3
        assert all(r["scan_id"] == "scan-001" for r in rows)

    async def test_get_by_severity(
        self,
        scan_repo: ScanRepository,
        finding_repo: FindingRepository,
    ):
        """Retrieve findings filtered by severity."""
        scan = _make_scan_result()
        await scan_repo.create(scan)

        findings = [
            _make_finding(finding_id="MALWAR-H-001", severity=Severity.HIGH),
            _make_finding(finding_id="MALWAR-C-001", rule_id="rule-crit", severity=Severity.CRITICAL),
            _make_finding(finding_id="MALWAR-H-002", rule_id="rule-high2", severity=Severity.HIGH),
        ]
        await finding_repo.create_many("scan-001", findings)

        high = await finding_repo.get_by_severity("high")
        assert len(high) == 2

        critical = await finding_repo.get_by_severity("critical")
        assert len(critical) == 1
        assert critical[0]["id"] == "MALWAR-C-001"

    async def test_cascade_delete(
        self,
        db: aiosqlite.Connection,
        scan_repo: ScanRepository,
        finding_repo: FindingRepository,
    ):
        """Findings should be deleted when their parent scan is deleted."""
        scan = _make_scan_result()
        await scan_repo.create(scan)

        findings = [_make_finding()]
        await finding_repo.create_many("scan-001", findings)

        # Delete the scan
        await db.execute("DELETE FROM scans WHERE id = 'scan-001'")
        await db.commit()

        rows = await finding_repo.get_by_scan("scan-001")
        assert len(rows) == 0


# ---------------------------------------------------------------------------
# Signature queries
# ---------------------------------------------------------------------------


class TestSignatureRepository:
    """Tests for SignatureRepository."""

    async def test_get_all_enabled(self, signature_repo: SignatureRepository):
        """All seeded signatures should be enabled."""
        sigs = await signature_repo.get_all_enabled()
        assert len(sigs) >= 4  # at least the 4 seeded ones
        assert all(s["enabled"] == 1 for s in sigs)

    async def test_get_by_campaign(self, signature_repo: SignatureRepository):
        """Retrieve signatures by campaign ID."""
        sigs = await signature_repo.get_by_campaign("campaign-clawhavoc-001")
        assert len(sigs) == 4

    async def test_create_signature(self, signature_repo: SignatureRepository):
        """Create a new signature and verify it appears in enabled list."""
        new_sig = {
            "id": "sig-test-custom",
            "name": "Custom Test Sig",
            "description": "A custom test signature",
            "severity": "high",
            "category": "suspicious_command",
            "pattern_type": "regex",
            "pattern_value": r"rm\s+-rf\s+/",
            "ioc_type": None,
            "campaign_id": None,
            "source": "manual",
            "enabled": True,
        }
        await signature_repo.create(new_sig)

        sigs = await signature_repo.get_all_enabled()
        ids = {s["id"] for s in sigs}
        assert "sig-test-custom" in ids

    async def test_update_signature(self, signature_repo: SignatureRepository):
        """Update a signature's fields."""
        await signature_repo.update(
            "sig-clawhavoc-c2-ip", {"description": "Updated description"}
        )
        sigs = await signature_repo.get_by_campaign("campaign-clawhavoc-001")
        updated = next(s for s in sigs if s["id"] == "sig-clawhavoc-c2-ip")
        assert updated["description"] == "Updated description"


# ---------------------------------------------------------------------------
# Campaign queries
# ---------------------------------------------------------------------------


class TestCampaignRepository:
    """Tests for CampaignRepository."""

    async def test_get_campaign(self, campaign_repo: CampaignRepository):
        """Retrieve the seeded ClawHavoc campaign."""
        campaign = await campaign_repo.get("campaign-clawhavoc-001")
        assert campaign is not None
        assert campaign["name"] == "ClawHavoc"

    async def test_get_nonexistent_campaign(self, campaign_repo: CampaignRepository):
        """Getting a nonexistent campaign returns None."""
        result = await campaign_repo.get("does-not-exist")
        assert result is None

    async def test_list_active(self, campaign_repo: CampaignRepository):
        """list_active should return the seeded active campaign."""
        active = await campaign_repo.list_active()
        assert len(active) >= 1
        assert any(c["id"] == "campaign-clawhavoc-001" for c in active)


# ---------------------------------------------------------------------------
# Publisher queries
# ---------------------------------------------------------------------------


class TestPublisherRepository:
    """Tests for PublisherRepository."""

    async def test_get_publisher(self, publisher_repo: PublisherRepository):
        """Retrieve a seeded publisher."""
        pub = await publisher_repo.get("zaycv")
        assert pub is not None
        assert pub["is_known_threat_actor"] == 1
        assert pub["reputation_score"] == 0.0

    async def test_is_known_threat_actor_true(self, publisher_repo: PublisherRepository):
        """Seeded threat actors return True."""
        assert await publisher_repo.is_known_threat_actor("Ddoy233") is True
        assert await publisher_repo.is_known_threat_actor("hightower6eu") is True

    async def test_is_known_threat_actor_false(self, publisher_repo: PublisherRepository):
        """Unknown publisher returns False."""
        assert await publisher_repo.is_known_threat_actor("innocent-dev") is False

    async def test_update_reputation(self, publisher_repo: PublisherRepository):
        """Update a publisher's reputation score."""
        await publisher_repo.update_reputation("zaycv", 0.1)
        pub = await publisher_repo.get("zaycv")
        assert pub is not None
        assert pub["reputation_score"] == 0.1
