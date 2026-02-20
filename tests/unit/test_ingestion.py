# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the campaign ingestion system."""

from __future__ import annotations

import json
import textwrap

import aiosqlite
import pytest
from pydantic import ValidationError

from malwar.ingestion.importer import CampaignImporter, ImportResult
from malwar.ingestion.sources import (
    CsvFileSource,
    CsvStringSource,
    JsonFileSource,
    JsonStringSource,
    StixBundleSource,
    StixStringSource,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_JSON = json.dumps(
    {
        "campaigns": [
            {
                "name": "TestCampaign",
                "attributed_to": "APT-Test",
                "first_seen": "2026-01-15",
                "iocs": [
                    {"type": "domain", "value": "evil-test.com"},
                    {"type": "ip", "value": "10.0.0.1"},
                ],
                "signatures": [
                    {
                        "pattern_type": "exact",
                        "pattern_value": "evil-test.com",
                        "ioc_type": "domain",
                        "severity": "critical",
                    },
                    {
                        "pattern_type": "exact",
                        "pattern_value": "10.0.0.1",
                        "ioc_type": "ip",
                        "severity": "high",
                    },
                ],
            }
        ]
    }
)

SAMPLE_CSV = textwrap.dedent("""\
    campaign,ioc_type,ioc_value,severity
    TestCSV,domain,bad-domain.com,critical
    TestCSV,ip,192.168.1.1,high
    OtherCampaign,url,http://evil.example.com,medium
""")

SAMPLE_STIX = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--test-001",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--test-001",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "name": "Test",
                "identity_class": "system",
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--test-001",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "TestActor",
                "threat_actor_types": ["unknown"],
                "first_seen": "2026-01-15T00:00:00.000Z",
                "last_seen": "2026-02-01T00:00:00.000Z",
            },
            {
                "type": "campaign",
                "spec_version": "2.1",
                "id": "campaign--test-001",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "StixCampaign",
                "description": "A test STIX campaign",
                "first_seen": "2026-01-15T00:00:00.000Z",
                "last_seen": "2026-02-01T00:00:00.000Z",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--test-attr",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "relationship_type": "attributed-to",
                "source_ref": "campaign--test-001",
                "target_ref": "threat-actor--test-001",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--test-001",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "Evil Domain",
                "indicator_types": ["malicious-activity"],
                "pattern": "[domain-name:value = 'stix-evil.com']",
                "pattern_type": "stix",
                "valid_from": "2026-01-15T00:00:00.000Z",
                "labels": ["severity:critical"],
                "confidence": 90,
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--test-002",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "name": "Evil IP",
                "indicator_types": ["malicious-activity"],
                "pattern": "[ipv4-addr:value = '10.20.30.40']",
                "pattern_type": "stix",
                "valid_from": "2026-01-15T00:00:00.000Z",
                "labels": ["severity:high"],
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--test-ind1",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--test-001",
                "target_ref": "campaign--test-001",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--test-ind2",
                "created": "2026-01-15T00:00:00.000Z",
                "modified": "2026-01-15T00:00:00.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--test-002",
                "target_ref": "campaign--test-001",
            },
        ],
    }
)


@pytest.fixture
async def db(tmp_path):
    """Create a temporary in-memory-like database with the required schema."""
    db_path = tmp_path / "test_ingest.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute(
            """
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                attributed_to TEXT,
                iocs TEXT DEFAULT '[]',
                total_skills_affected INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE signatures (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                pattern_value TEXT NOT NULL,
                ioc_type TEXT,
                campaign_id TEXT REFERENCES campaigns(id),
                source TEXT NOT NULL DEFAULT 'manual',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await conn.commit()
        yield conn


# =========================================================================
# JSON source tests
# =========================================================================


class TestJsonFileSource:
    """Tests for JsonFileSource and JsonStringSource."""

    async def test_json_string_source_parses_campaigns(self) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        campaigns = await source.fetch()
        assert len(campaigns) == 1
        assert campaigns[0].name == "TestCampaign"

    async def test_json_string_source_parses_iocs(self) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        campaigns = await source.fetch()
        assert len(campaigns[0].iocs) == 2
        assert campaigns[0].iocs[0].type == "domain"
        assert campaigns[0].iocs[0].value == "evil-test.com"

    async def test_json_string_source_parses_signatures(self) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        campaigns = await source.fetch()
        assert len(campaigns[0].signatures) == 2
        assert campaigns[0].signatures[0].severity == "critical"

    async def test_json_file_source_reads_file(self, tmp_path) -> None:
        json_file = tmp_path / "threat.json"
        json_file.write_text(SAMPLE_JSON)
        source = JsonFileSource(json_file)
        campaigns = await source.fetch()
        assert len(campaigns) == 1
        assert campaigns[0].attributed_to == "APT-Test"

    async def test_json_source_invalid_json_raises(self) -> None:
        source = JsonStringSource("not valid json")
        with pytest.raises(ValidationError):
            await source.fetch()

    async def test_json_source_missing_campaigns_key_raises(self) -> None:
        source = JsonStringSource('{"data": []}')
        with pytest.raises(ValidationError):
            await source.fetch()

    async def test_json_source_empty_campaigns_raises(self) -> None:
        source = JsonStringSource('{"campaigns": []}')
        with pytest.raises(ValidationError):
            await source.fetch()

    async def test_json_source_name_attribute(self, tmp_path) -> None:
        json_file = tmp_path / "feed.json"
        json_file.write_text(SAMPLE_JSON)
        source = JsonFileSource(json_file)
        assert source.name == "json:feed.json"

    async def test_json_string_source_name(self) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        assert source.name == "json:api"


# =========================================================================
# CSV source tests
# =========================================================================


class TestCsvFileSource:
    """Tests for CsvFileSource and CsvStringSource."""

    async def test_csv_string_source_groups_by_campaign(self) -> None:
        source = CsvStringSource(SAMPLE_CSV)
        campaigns = await source.fetch()
        names = {c.name for c in campaigns}
        assert names == {"TestCSV", "OtherCampaign"}

    async def test_csv_source_creates_iocs_and_signatures(self) -> None:
        source = CsvStringSource(SAMPLE_CSV)
        campaigns = await source.fetch()
        test_csv = next(c for c in campaigns if c.name == "TestCSV")
        assert len(test_csv.iocs) == 2
        assert len(test_csv.signatures) == 2

    async def test_csv_source_preserves_severity(self) -> None:
        source = CsvStringSource(SAMPLE_CSV)
        campaigns = await source.fetch()
        test_csv = next(c for c in campaigns if c.name == "TestCSV")
        severities = {s.severity for s in test_csv.signatures}
        assert "critical" in severities
        assert "high" in severities

    async def test_csv_file_source_reads_file(self, tmp_path) -> None:
        csv_file = tmp_path / "threats.csv"
        csv_file.write_text(SAMPLE_CSV)
        source = CsvFileSource(csv_file)
        campaigns = await source.fetch()
        assert len(campaigns) == 2

    async def test_csv_source_missing_columns_raises(self) -> None:
        bad_csv = "name,type\nfoo,bar\n"
        source = CsvStringSource(bad_csv)
        with pytest.raises(ValueError, match="missing required columns"):
            await source.fetch()

    async def test_csv_source_empty_raises(self) -> None:
        source = CsvStringSource("")
        with pytest.raises(ValueError, match="empty"):
            await source.fetch()


# =========================================================================
# STIX bundle source tests
# =========================================================================


class TestStixBundleSource:
    """Tests for StixBundleSource and StixStringSource."""

    async def test_stix_string_source_parses_campaign(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        assert len(campaigns) == 1
        assert campaigns[0].name == "StixCampaign"

    async def test_stix_source_extracts_attribution(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        assert campaigns[0].attributed_to == "TestActor"

    async def test_stix_source_extracts_iocs(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        assert len(campaigns[0].iocs) == 2
        values = {ioc.value for ioc in campaigns[0].iocs}
        assert "stix-evil.com" in values
        assert "10.20.30.40" in values

    async def test_stix_source_extracts_signatures(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        assert len(campaigns[0].signatures) == 2

    async def test_stix_source_extracts_severity_from_labels(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        sigs = campaigns[0].signatures
        domain_sig = next(s for s in sigs if s.pattern_value == "stix-evil.com")
        assert domain_sig.severity == "critical"

    async def test_stix_source_extracts_confidence(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        sigs = campaigns[0].signatures
        domain_sig = next(s for s in sigs if s.pattern_value == "stix-evil.com")
        assert domain_sig.confidence == pytest.approx(0.9)

    async def test_stix_file_source_reads_file(self, tmp_path) -> None:
        stix_file = tmp_path / "bundle.json"
        stix_file.write_text(SAMPLE_STIX)
        source = StixBundleSource(stix_file)
        campaigns = await source.fetch()
        assert len(campaigns) == 1

    async def test_stix_source_not_a_bundle_raises(self) -> None:
        source = StixStringSource('{"type": "something-else"}')
        with pytest.raises(ValueError, match=r"not a STIX 2\.1 bundle"):
            await source.fetch()

    async def test_stix_source_extracts_first_seen(self) -> None:
        source = StixStringSource(SAMPLE_STIX)
        campaigns = await source.fetch()
        assert campaigns[0].first_seen == "2026-01-15"


# =========================================================================
# HTTP feed source tests
# =========================================================================


class TestHttpFeedSource:
    """Tests for HttpFeedSource with mocked HTTP responses."""

    async def test_http_json_feed(self, monkeypatch) -> None:
        """Test fetching a JSON feed via HTTP."""
        import httpx

        from malwar.ingestion.sources import HttpFeedSource

        class MockResponse:
            status_code = 200
            text = SAMPLE_JSON
            headers = {"etag": '"abc123"'}

            def raise_for_status(self):
                pass

        class MockClient:
            async def get(self, url, **kwargs):
                return MockResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockClient())

        source = HttpFeedSource("http://example.com/feed.json")
        campaigns = await source.fetch()
        assert len(campaigns) == 1
        assert campaigns[0].name == "TestCampaign"
        # ETag should be cached
        assert source._etag == '"abc123"'

    async def test_http_csv_feed(self, monkeypatch) -> None:
        """Test fetching a CSV feed via HTTP."""
        import httpx

        from malwar.ingestion.sources import HttpFeedSource

        class MockResponse:
            status_code = 200
            text = SAMPLE_CSV
            headers = {}

            def raise_for_status(self):
                pass

        class MockClient:
            async def get(self, url, **kwargs):
                return MockResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockClient())

        source = HttpFeedSource("http://example.com/feed.csv", format="csv")
        campaigns = await source.fetch()
        assert len(campaigns) == 2

    async def test_http_304_returns_empty(self, monkeypatch) -> None:
        """Test that a 304 Not Modified returns an empty list."""
        import httpx

        from malwar.ingestion.sources import HttpFeedSource

        class MockResponse:
            status_code = 304
            text = ""
            headers = {}

            def raise_for_status(self):
                pass

        class MockClient:
            async def get(self, url, **kwargs):
                return MockResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockClient())

        source = HttpFeedSource("http://example.com/feed.json")
        source._etag = '"old-etag"'
        campaigns = await source.fetch()
        assert campaigns == []


# =========================================================================
# Importer + deduplication tests
# =========================================================================


class TestCampaignImporter:
    """Tests for the CampaignImporter engine."""

    async def test_import_json_creates_campaign(self, db) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)

        assert result.campaigns_added == 1
        assert result.campaigns_updated == 0
        assert result.signatures_added == 2
        assert result.signatures_skipped == 0
        assert result.errors == []

    async def test_import_csv_creates_multiple_campaigns(self, db) -> None:
        source = CsvStringSource(SAMPLE_CSV)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)

        assert result.campaigns_added == 2
        assert result.signatures_added == 3

    async def test_deduplication_skips_existing_signatures(self, db) -> None:
        source = JsonStringSource(SAMPLE_JSON)
        importer = CampaignImporter(db)

        # First import
        result1 = await importer.import_from(source)
        assert result1.campaigns_added == 1
        assert result1.signatures_added == 2

        # Second import — same data
        result2 = await importer.import_from(source)
        assert result2.campaigns_added == 0
        assert result2.campaigns_updated == 1
        assert result2.signatures_added == 0
        assert result2.signatures_skipped == 2

    async def test_merge_mode_adds_new_iocs(self, db) -> None:
        """When merge=True, new IOCs are added to existing campaigns."""
        # Import initial campaign
        source1 = JsonStringSource(SAMPLE_JSON)
        importer = CampaignImporter(db, merge=True)
        await importer.import_from(source1)

        # Import same campaign with additional IOC
        updated = json.dumps(
            {
                "campaigns": [
                    {
                        "name": "TestCampaign",
                        "attributed_to": "APT-Test",
                        "first_seen": "2026-01-15",
                        "iocs": [
                            {"type": "domain", "value": "new-evil.com"},
                        ],
                        "signatures": [
                            {
                                "pattern_type": "exact",
                                "pattern_value": "new-evil.com",
                                "ioc_type": "domain",
                                "severity": "high",
                            }
                        ],
                    }
                ]
            }
        )
        source2 = JsonStringSource(updated)
        result = await importer.import_from(source2)

        assert result.campaigns_updated == 1
        assert result.signatures_added == 1

        # Verify IOCs were merged
        cursor = await db.execute(
            "SELECT iocs FROM campaigns WHERE name = 'TestCampaign'"
        )
        row = await cursor.fetchone()
        iocs = json.loads(row["iocs"])
        values = [ioc["value"] if isinstance(ioc, dict) else ioc for ioc in iocs]
        assert "evil-test.com" in values
        assert "new-evil.com" in values

    async def test_import_result_to_dict(self) -> None:
        result = ImportResult(
            campaigns_added=2,
            campaigns_updated=1,
            signatures_added=5,
            signatures_skipped=3,
            errors=["some error"],
        )
        d = result.to_dict()
        assert d["campaigns_added"] == 2
        assert d["signatures_skipped"] == 3
        assert d["errors"] == ["some error"]

    async def test_import_handles_fetch_error_gracefully(self, db) -> None:
        """If the source raises during fetch, errors are captured."""

        class BrokenSource:
            name = "broken"

            async def fetch(self):
                msg = "Connection refused"
                raise ConnectionError(msg)

        importer = CampaignImporter(db)
        result = await importer.import_from(BrokenSource())

        assert result.campaigns_added == 0
        assert len(result.errors) == 1
        assert "Connection refused" in result.errors[0]

    async def test_stix_import_creates_campaign_and_signatures(self, db) -> None:
        source = StixStringSource(SAMPLE_STIX)
        importer = CampaignImporter(db)
        result = await importer.import_from(source)

        assert result.campaigns_added == 1
        assert result.signatures_added == 2
        assert result.errors == []

    async def test_import_no_merge_does_not_update_iocs(self, db) -> None:
        """When merge=False, existing campaigns are not updated."""
        source = JsonStringSource(SAMPLE_JSON)
        importer = CampaignImporter(db, merge=False)
        await importer.import_from(source)

        # Import again with merge=False — campaign should not be updated
        result = await importer.import_from(source)
        assert result.campaigns_updated == 0
        assert result.signatures_skipped == 2


# =========================================================================
# Schema validation tests
# =========================================================================


class TestSchemaValidation:
    """Tests for the Pydantic import schema."""

    def test_valid_payload_parses(self) -> None:
        from malwar.ingestion.schema import ImportPayload

        payload = ImportPayload.model_validate_json(SAMPLE_JSON)
        assert len(payload.campaigns) == 1
        assert payload.campaigns[0].name == "TestCampaign"

    def test_missing_name_raises(self) -> None:
        from malwar.ingestion.schema import ImportPayload

        bad = json.dumps({"campaigns": [{"attributed_to": "test"}]})
        with pytest.raises(ValidationError):
            ImportPayload.model_validate_json(bad)

    def test_invalid_ioc_type_raises(self) -> None:
        from malwar.ingestion.schema import ImportPayload

        bad = json.dumps(
            {
                "campaigns": [
                    {
                        "name": "Test",
                        "iocs": [{"type": "invalid_type", "value": "x"}],
                    }
                ]
            }
        )
        with pytest.raises(ValidationError):
            ImportPayload.model_validate_json(bad)

    def test_default_severity(self) -> None:
        from malwar.ingestion.schema import ImportPayload

        data = json.dumps(
            {
                "campaigns": [
                    {
                        "name": "Test",
                        "signatures": [
                            {
                                "pattern_type": "exact",
                                "pattern_value": "evil.com",
                                "ioc_type": "domain",
                            }
                        ],
                    }
                ]
            }
        )
        payload = ImportPayload.model_validate_json(data)
        assert payload.campaigns[0].signatures[0].severity == "medium"
