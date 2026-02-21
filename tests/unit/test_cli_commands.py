# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for CLI commands — analytics, audit, cache, export."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

runner = CliRunner()


# ---------------------------------------------------------------------------
# analytics summary
# ---------------------------------------------------------------------------

class TestAnalyticsSummary:
    """Test the analytics summary CLI command."""

    def test_no_scan_data(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.analytics import app

        mock_db = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock):
            result = runner.invoke(app, [])
            assert result.exit_code == 0
            assert "No scan data found" in result.output

    def test_with_scan_data(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.analytics import app

        mock_db = AsyncMock()
        scan_rows = [("scan-1", "MALICIOUS", 85, "2026-01-15T10:00:00", 150, '["rule_engine"]')]
        finding_rows = [("f-1", "scan-1", "MALWAR-PI-001", "prompt_injection", "rule_engine", "critical")]
        mock_cursor_scans = AsyncMock()
        mock_cursor_scans.fetchall = AsyncMock(return_value=scan_rows)
        mock_cursor_findings = AsyncMock()
        mock_cursor_findings.fetchall = AsyncMock(return_value=finding_rows)
        mock_db.execute = AsyncMock(side_effect=[mock_cursor_scans, mock_cursor_findings])

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock):
            result = runner.invoke(app, [])
            assert result.exit_code == 0
            assert "Analytics Overview" in result.output

    def test_with_days_filter(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.analytics import app

        mock_db = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock):
            result = runner.invoke(app, ["--days", "7"])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# audit list
# ---------------------------------------------------------------------------

class TestAuditList:
    """Test the audit list CLI command."""

    def test_no_events(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.audit import app

        mock_db = AsyncMock()
        mock_store = MagicMock()
        mock_store.list_events = AsyncMock(return_value=[])

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock), \
             patch("malwar.audit.store.AuditStore", return_value=mock_store):
            result = runner.invoke(app, [])
            assert result.exit_code == 0
            assert "No audit events found" in result.output

    def test_with_events(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.audit import app

        mock_db = AsyncMock()
        mock_store = MagicMock()
        mock_store.list_events = AsyncMock(return_value=[
            {
                "event_id": "evt-123456789012",
                "timestamp": "2026-01-15T10:00:00",
                "event_type": "scan.completed",
                "actor": "api-key-1",
                "resource_type": "scan",
                "resource_id": "scan-1",
                "action": "complete",
            }
        ])

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock), \
             patch("malwar.audit.store.AuditStore", return_value=mock_store):
            result = runner.invoke(app, [])
            assert result.exit_code == 0
            assert "Audit Events" in result.output

    def test_with_filters(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.audit import app

        mock_db = AsyncMock()
        mock_store = MagicMock()
        mock_store.list_events = AsyncMock(return_value=[])

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock), \
             patch("malwar.audit.store.AuditStore", return_value=mock_store):
            result = runner.invoke(app, [
                "--type", "scan.completed",
                "--actor", "api-key-1", "--limit", "10",
            ])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# cache clear / stats
# ---------------------------------------------------------------------------

class TestCacheCommands:
    """Test cache CLI commands."""

    def test_cache_clear(self):
        from malwar.cli.commands.cache import app

        mock_mgr = MagicMock()
        mock_mgr.clear = AsyncMock(return_value=5)

        with patch("malwar.cache.manager.get_cache_manager", return_value=mock_mgr):
            result = runner.invoke(app, ["clear"])
            assert result.exit_code == 0
            assert "5 entries removed" in result.output

    def test_cache_stats(self):
        from malwar.cli.commands.cache import app

        mock_stats = MagicMock()
        mock_stats.hits = 10
        mock_stats.misses = 5
        mock_stats.total = 15
        mock_stats.hit_rate = 0.6667

        mock_mgr = MagicMock()
        mock_mgr.stats = mock_stats
        mock_mgr.size = AsyncMock(return_value=3)

        with patch("malwar.cache.manager.get_cache_manager", return_value=mock_mgr):
            result = runner.invoke(app, ["stats"])
            assert result.exit_code == 0
            assert "Cache Statistics" in result.output


# ---------------------------------------------------------------------------
# export stix
# ---------------------------------------------------------------------------

class TestExportStix:
    """Test the export stix CLI command."""

    def test_export_stix_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.export import app

        mock_db = AsyncMock()
        mock_campaign_repo = MagicMock()
        mock_campaign_repo.list_active = AsyncMock(return_value=[])
        mock_sig_repo = MagicMock()
        mock_sig_repo.get_all = AsyncMock(return_value=[])
        mock_scan_repo = MagicMock()
        mock_scan_repo.list_recent = AsyncMock(return_value=[])

        mock_bundle = {"type": "bundle", "objects": []}

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock), \
             patch("malwar.storage.repositories.campaigns.CampaignRepository", return_value=mock_campaign_repo), \
             patch("malwar.storage.repositories.signatures.SignatureRepository", return_value=mock_sig_repo), \
             patch("malwar.storage.repositories.scans.ScanRepository", return_value=mock_scan_repo), \
             patch("malwar.export.stix.build_stix_bundle", return_value=mock_bundle):
            result = runner.invoke(app, [])
            assert result.exit_code == 0
            assert "bundle" in result.output

    def test_export_stix_to_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.export import app

        mock_db = AsyncMock()
        mock_campaign_repo = MagicMock()
        mock_campaign_repo.list_active = AsyncMock(return_value=[])
        mock_sig_repo = MagicMock()
        mock_sig_repo.get_all = AsyncMock(return_value=[])
        mock_scan_repo = MagicMock()
        mock_scan_repo.list_recent = AsyncMock(return_value=[])

        mock_bundle = {"type": "bundle", "objects": []}
        out_file = tmp_path / "output.json"

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock), \
             patch("malwar.storage.repositories.campaigns.CampaignRepository", return_value=mock_campaign_repo), \
             patch("malwar.storage.repositories.signatures.SignatureRepository", return_value=mock_sig_repo), \
             patch("malwar.storage.repositories.scans.ScanRepository", return_value=mock_scan_repo), \
             patch("malwar.export.stix.build_stix_bundle", return_value=mock_bundle):
            result = runner.invoke(app, ["--output", str(out_file)])
            assert result.exit_code == 0
            assert out_file.exists()

    def test_export_campaign_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MALWAR_DB_PATH", str(tmp_path / "test.db"))
        from malwar.cli.commands.export import app

        mock_db = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        with patch("malwar.storage.database.init_db", return_value=mock_db), \
             patch("malwar.storage.database.close_db", new_callable=AsyncMock):
            result = runner.invoke(app, ["--campaign", "nonexistent"])
            assert result.exit_code == 1
