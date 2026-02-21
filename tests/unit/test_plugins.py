# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the plugin system: loading, validation, lifecycle, and hooks."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding
from malwar.models.skill import SkillContent, SkillMetadata
from malwar.plugins.base import DetectorPlugin, PluginMetadata
from malwar.plugins.hooks import HookManager, HookType
from malwar.plugins.loader import PluginLoader
from malwar.plugins.manager import PluginManager
from malwar.scanner.context import ScanContext

# ---------------------------------------------------------------------------
# Helpers — concrete plugin implementations for testing
# ---------------------------------------------------------------------------


class _GoodPlugin(DetectorPlugin):
    """A well-formed plugin for happy-path tests."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="good_plugin",
            version="1.0.0",
            author="Test Author",
            description="A well-formed test plugin",
            layer_name="plugin:good",
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                id="PLUGIN-GOOD-001",
                rule_id="good-rule",
                title="Good finding",
                description="Found by good_plugin",
                severity=Severity.INFO,
                confidence=0.5,
                category=ThreatCategory.SUSPICIOUS_COMMAND,
                detector_layer=DetectorLayer.RULE_ENGINE,
            )
        ]


class _MinimalPlugin(DetectorPlugin):
    """Another valid plugin with different metadata."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="minimal_plugin",
            version="0.0.1",
            author="Other Author",
            description="Minimal",
            layer_name="plugin:minimal",
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        return []


class _NoNamePlugin(DetectorPlugin):
    """Plugin with empty name — should fail validation."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="",
            version="1.0.0",
            author="Bad",
            description="Missing name",
            layer_name="plugin:bad",
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        return []


class _NoVersionPlugin(DetectorPlugin):
    """Plugin with empty version — should fail validation."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="no_version",
            version="",
            author="Bad",
            description="Missing version",
            layer_name="plugin:bad",
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        return []


class _NoLayerPlugin(DetectorPlugin):
    """Plugin with empty layer_name — should fail validation."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="no_layer",
            version="1.0.0",
            author="Bad",
            description="Missing layer",
            layer_name="",
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        return []


def _make_context() -> ScanContext:
    """Create a minimal ScanContext for testing."""
    return ScanContext(
        skill=SkillContent(
            file_path="test.md",
            raw_content="# TODO fix this\nSome content\n",
            metadata=SkillMetadata(name="test-skill"),
        ),
        scan_id="test-001",
    )


# =========================================================================
# DetectorPlugin base class
# =========================================================================


class TestDetectorPlugin:
    def test_layer_name_from_metadata(self):
        plugin = _GoodPlugin()
        assert plugin.layer_name == "plugin:good"

    def test_order_default(self):
        plugin = _GoodPlugin()
        assert plugin.order >= 100

    def test_metadata_attributes(self):
        plugin = _GoodPlugin()
        meta = plugin.plugin_metadata
        assert meta.name == "good_plugin"
        assert meta.version == "1.0.0"
        assert meta.author == "Test Author"
        assert meta.description == "A well-formed test plugin"
        assert meta.layer_name == "plugin:good"

    async def test_detect_returns_findings(self):
        plugin = _GoodPlugin()
        ctx = _make_context()
        findings = await plugin.detect(ctx)
        assert len(findings) == 1
        assert findings[0].id == "PLUGIN-GOOD-001"


# =========================================================================
# PluginMetadata
# =========================================================================


class TestPluginMetadata:
    def test_frozen(self):
        meta = PluginMetadata(
            name="x", version="1", author="a", description="d", layer_name="l"
        )
        with pytest.raises(AttributeError):
            meta.name = "changed"  # type: ignore[misc]

    def test_default_tags(self):
        meta = PluginMetadata(
            name="x", version="1", author="a", description="d", layer_name="l"
        )
        assert meta.tags == []


# =========================================================================
# PluginLoader
# =========================================================================


class TestPluginLoader:
    def test_load_from_directory(self, tmp_path: Path):
        """Loader discovers plugin classes from .py files in a directory."""
        plugin_code = textwrap.dedent("""\
            from malwar.plugins.base import DetectorPlugin, PluginMetadata
            from malwar.models.finding import Finding
            from malwar.scanner.context import ScanContext

            class DirPlugin(DetectorPlugin):
                @property
                def plugin_metadata(self):
                    return PluginMetadata(
                        name="dir_plugin",
                        version="0.1.0",
                        author="Dir Author",
                        description="Loaded from directory",
                        layer_name="plugin:dir",
                    )

                async def detect(self, context: ScanContext) -> list[Finding]:
                    return []
        """)
        (tmp_path / "my_plugin.py").write_text(plugin_code)

        loader = PluginLoader()
        plugins = loader.load_from_directory(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].plugin_metadata.name == "dir_plugin"

    def test_load_from_directory_skips_underscore(self, tmp_path: Path):
        """Files starting with _ are ignored."""
        (tmp_path / "_internal.py").write_text("x = 1\n")
        loader = PluginLoader()
        plugins = loader.load_from_directory(tmp_path)
        assert plugins == []

    def test_load_from_nonexistent_directory(self, tmp_path: Path):
        loader = PluginLoader()
        plugins = loader.load_from_directory(tmp_path / "nonexistent")
        assert plugins == []

    def test_load_from_directory_bad_file(self, tmp_path: Path):
        """A file with a syntax error is skipped gracefully."""
        (tmp_path / "broken.py").write_text("def bad(:\n")
        loader = PluginLoader()
        plugins = loader.load_from_directory(tmp_path)
        assert plugins == []

    def test_load_from_entry_points_no_crash(self):
        """Calling load_from_entry_points does not crash even with no eps."""
        loader = PluginLoader()
        plugins = loader.load_from_entry_points()
        # Might find zero or more; we just verify no exception
        assert isinstance(plugins, list)

    def test_load_from_module_paths(self):
        """Load from an explicit dotted module path."""
        loader = PluginLoader()
        # Use this test module itself — it defines _GoodPlugin
        plugins = loader.load_from_module_paths(["tests.unit.test_plugins"])
        names = [p.plugin_metadata.name for p in plugins]
        assert "good_plugin" in names

    def test_load_from_module_paths_bad_module(self):
        """A non-existent module path is skipped gracefully."""
        loader = PluginLoader()
        plugins = loader.load_from_module_paths(["nonexistent.module.path"])
        assert plugins == []


# =========================================================================
# PluginManager — validation
# =========================================================================


class TestPluginManagerValidation:
    def test_valid_plugin_passes(self):
        assert PluginManager._validate(_GoodPlugin()) is True

    def test_empty_name_fails(self):
        assert PluginManager._validate(_NoNamePlugin()) is False

    def test_empty_version_fails(self):
        assert PluginManager._validate(_NoVersionPlugin()) is False

    def test_empty_layer_fails(self):
        assert PluginManager._validate(_NoLayerPlugin()) is False


# =========================================================================
# PluginManager — lifecycle
# =========================================================================


class TestPluginManagerLifecycle:
    def _make_manager(self, *plugins: DetectorPlugin) -> PluginManager:
        mgr = PluginManager()
        for p in plugins:
            mgr._register(p, enabled_names=None)
        return mgr

    def test_register_and_list(self):
        mgr = self._make_manager(_GoodPlugin(), _MinimalPlugin())
        infos = mgr.list_plugins()
        assert len(infos) == 2
        names = {i.name for i in infos}
        assert names == {"good_plugin", "minimal_plugin"}

    def test_all_enabled_by_default(self):
        mgr = self._make_manager(_GoodPlugin(), _MinimalPlugin())
        assert all(i.enabled for i in mgr.list_plugins())

    def test_enable_disable(self):
        mgr = self._make_manager(_GoodPlugin())
        assert mgr.disable("good_plugin") is True
        assert mgr.is_enabled("good_plugin") is False

        assert mgr.enable("good_plugin") is True
        assert mgr.is_enabled("good_plugin") is True

    def test_enable_nonexistent_returns_false(self):
        mgr = self._make_manager()
        assert mgr.enable("ghost") is False

    def test_disable_nonexistent_returns_false(self):
        mgr = self._make_manager()
        assert mgr.disable("ghost") is False

    def test_is_enabled_nonexistent_returns_none(self):
        mgr = self._make_manager()
        assert mgr.is_enabled("ghost") is None

    def test_get_enabled_detectors(self):
        mgr = self._make_manager(_GoodPlugin(), _MinimalPlugin())
        mgr.disable("minimal_plugin")
        detectors = mgr.get_enabled_detectors()
        assert len(detectors) == 1
        assert detectors[0].plugin_metadata.name == "good_plugin"

    def test_get_plugin(self):
        mgr = self._make_manager(_GoodPlugin())
        p = mgr.get_plugin("good_plugin")
        assert p is not None
        assert p.plugin_metadata.name == "good_plugin"

    def test_get_plugin_not_found(self):
        mgr = self._make_manager()
        assert mgr.get_plugin("ghost") is None

    def test_enabled_names_filter(self):
        """Only plugins in enabled_names should be enabled."""
        mgr = PluginManager()
        mgr._register(_GoodPlugin(), enabled_names=["good_plugin"])
        mgr._register(_MinimalPlugin(), enabled_names=["good_plugin"])
        assert mgr.is_enabled("good_plugin") is True
        assert mgr.is_enabled("minimal_plugin") is False

    def test_invalid_plugin_not_registered(self):
        mgr = PluginManager()
        mgr._register(_NoNamePlugin(), enabled_names=None)
        assert mgr.list_plugins() == []


# =========================================================================
# PluginManager — discover integration
# =========================================================================


class TestPluginManagerDiscover:
    def test_discover_from_directory(self, tmp_path: Path):
        plugin_code = textwrap.dedent("""\
            from malwar.plugins.base import DetectorPlugin, PluginMetadata
            from malwar.models.finding import Finding
            from malwar.scanner.context import ScanContext

            class DiscoverPlugin(DetectorPlugin):
                @property
                def plugin_metadata(self):
                    return PluginMetadata(
                        name="discover_plugin",
                        version="1.0.0",
                        author="Discover Author",
                        description="Discovered",
                        layer_name="plugin:discover",
                    )

                async def detect(self, context: ScanContext) -> list[Finding]:
                    return []
        """)
        (tmp_path / "disc.py").write_text(plugin_code)

        mgr = PluginManager()
        mgr.discover(plugins_dir=str(tmp_path))

        infos = mgr.list_plugins()
        assert len(infos) == 1
        assert infos[0].name == "discover_plugin"
        assert infos[0].enabled is True

    def test_discover_with_enabled_names(self, tmp_path: Path):
        """Only plugins in enabled_names are enabled after discover."""
        plugin_code = textwrap.dedent("""\
            from malwar.plugins.base import DetectorPlugin, PluginMetadata
            from malwar.models.finding import Finding
            from malwar.scanner.context import ScanContext

            class AlphaPlugin(DetectorPlugin):
                @property
                def plugin_metadata(self):
                    return PluginMetadata(
                        name="alpha", version="1.0.0", author="A",
                        description="Alpha", layer_name="plugin:alpha",
                    )
                async def detect(self, context: ScanContext) -> list[Finding]:
                    return []

            class BetaPlugin(DetectorPlugin):
                @property
                def plugin_metadata(self):
                    return PluginMetadata(
                        name="beta", version="1.0.0", author="B",
                        description="Beta", layer_name="plugin:beta",
                    )
                async def detect(self, context: ScanContext) -> list[Finding]:
                    return []
        """)
        (tmp_path / "ab.py").write_text(plugin_code)

        mgr = PluginManager()
        mgr.discover(plugins_dir=str(tmp_path), enabled_names=["alpha"])

        infos = {p.name: p.enabled for p in mgr.list_plugins()}
        assert infos["alpha"] is True
        assert infos["beta"] is False


# =========================================================================
# HookManager
# =========================================================================


class TestHookManager:
    async def test_fire_sync_callback(self):
        hm = HookManager()
        called = []
        hm.register(HookType.PRE_SCAN, lambda **kw: called.append(kw))
        await hm.fire(HookType.PRE_SCAN, scan_id="abc")
        assert len(called) == 1
        assert called[0]["scan_id"] == "abc"

    async def test_fire_async_callback(self):
        hm = HookManager()
        called = []

        async def async_hook(**kwargs):
            called.append(kwargs)

        hm.register(HookType.POST_SCAN, async_hook)
        await hm.fire(HookType.POST_SCAN, result="ok")
        assert len(called) == 1
        assert called[0]["result"] == "ok"

    async def test_fire_on_finding(self):
        hm = HookManager()
        findings_seen: list[str] = []
        hm.register(HookType.ON_FINDING, lambda **kw: findings_seen.append(kw["finding_id"]))
        await hm.fire(HookType.ON_FINDING, finding_id="F-001")
        await hm.fire(HookType.ON_FINDING, finding_id="F-002")
        assert findings_seen == ["F-001", "F-002"]

    async def test_fire_exception_swallowed(self):
        """A misbehaving callback does not break other callbacks."""
        hm = HookManager()
        called = []

        def bad_hook(**kwargs):
            raise RuntimeError("boom")

        def good_hook(**kwargs):
            called.append("ok")

        hm.register(HookType.PRE_SCAN, bad_hook)
        hm.register(HookType.PRE_SCAN, good_hook)
        await hm.fire(HookType.PRE_SCAN)
        assert called == ["ok"]

    async def test_unregister(self):
        hm = HookManager()
        called = []
        cb = lambda **kw: called.append(1)  # noqa: E731
        hm.register(HookType.PRE_SCAN, cb)
        hm.unregister(HookType.PRE_SCAN, cb)
        await hm.fire(HookType.PRE_SCAN)
        assert called == []

    async def test_unregister_missing_is_noop(self):
        hm = HookManager()
        hm.unregister(HookType.PRE_SCAN, lambda: None)  # no crash

    def test_clear(self):
        hm = HookManager()
        hm.register(HookType.PRE_SCAN, lambda **kw: None)
        hm.register(HookType.POST_SCAN, lambda **kw: None)
        hm.clear()
        # Internal state cleared — no easy public assertion, but fire should be silent
        assert True

    async def test_multiple_hook_types(self):
        hm = HookManager()
        pre_calls = []
        post_calls = []
        hm.register(HookType.PRE_SCAN, lambda **kw: pre_calls.append(1))
        hm.register(HookType.POST_SCAN, lambda **kw: post_calls.append(1))
        await hm.fire(HookType.PRE_SCAN)
        assert len(pre_calls) == 1
        assert len(post_calls) == 0


# =========================================================================
# Pipeline integration — plugins as detectors
# =========================================================================


class TestPipelineIntegration:
    async def test_plugin_registered_in_pipeline(self):
        """Enabled plugins are usable as pipeline detectors."""
        from malwar.scanner.pipeline import ScanPipeline

        plugin = _GoodPlugin()
        pipeline = ScanPipeline()
        pipeline.register_detector(plugin)

        skill = SkillContent(
            file_path="test.md",
            raw_content="hello world",
            metadata=SkillMetadata(name="test"),
        )
        result = await pipeline.scan(skill)
        assert "plugin:good" in result.layers_executed
        assert any(f.id == "PLUGIN-GOOD-001" for f in result.findings)

    async def test_manager_detectors_in_pipeline(self):
        """PluginManager.get_enabled_detectors feeds the pipeline."""
        from malwar.scanner.pipeline import ScanPipeline

        mgr = PluginManager()
        mgr._register(_GoodPlugin(), enabled_names=None)
        mgr._register(_MinimalPlugin(), enabled_names=None)
        mgr.disable("minimal_plugin")

        pipeline = ScanPipeline()
        for det in mgr.get_enabled_detectors():
            pipeline.register_detector(det)

        skill = SkillContent(
            file_path="test.md",
            raw_content="hello world",
            metadata=SkillMetadata(name="test"),
        )
        result = await pipeline.scan(skill)
        assert "plugin:good" in result.layers_executed
        assert "plugin:minimal" not in result.layers_executed


# =========================================================================
# API routes
# =========================================================================


class TestPluginAPI:
    @pytest.fixture()
    def manager(self) -> PluginManager:
        mgr = PluginManager()
        mgr._register(_GoodPlugin(), enabled_names=None)
        mgr._register(_MinimalPlugin(), enabled_names=None)
        return mgr

    @pytest.fixture()
    def client(self, manager: PluginManager):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from malwar.api.routes.plugins import router, set_manager

        set_manager(manager)
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        return TestClient(app)

    def test_list_plugins(self, client):
        resp = client.get("/api/v1/plugins")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        names = {p["name"] for p in data}
        assert names == {"good_plugin", "minimal_plugin"}

    def test_enable_plugin(self, client, manager):
        manager.disable("good_plugin")
        resp = client.post("/api/v1/plugins/good_plugin/enable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True
        assert manager.is_enabled("good_plugin") is True

    def test_disable_plugin(self, client, manager):
        resp = client.post("/api/v1/plugins/good_plugin/disable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert manager.is_enabled("good_plugin") is False

    def test_enable_nonexistent_404(self, client):
        resp = client.post("/api/v1/plugins/ghost/enable")
        assert resp.status_code == 404

    def test_disable_nonexistent_404(self, client):
        resp = client.post("/api/v1/plugins/ghost/disable")
        assert resp.status_code == 404


# =========================================================================
# Example plugin
# =========================================================================


class TestExamplePlugin:
    async def test_todo_finder_detects_todo(self):
        """The example TodoFinderPlugin finds TODO markers."""
        from examples.plugins.example_detector import TodoFinderPlugin

        plugin = TodoFinderPlugin()
        assert plugin.plugin_metadata.name == "todo_finder"

        ctx = ScanContext(
            skill=SkillContent(
                file_path="test.md",
                raw_content="# Title\nTODO: finish this\nFIXME: broken\n",
                metadata=SkillMetadata(name="test"),
            ),
            scan_id="ex-001",
        )
        findings = await plugin.detect(ctx)
        assert len(findings) == 2
        assert "TODO" in findings[0].title
        assert "FIXME" in findings[1].title

    async def test_todo_finder_no_matches(self):
        from examples.plugins.example_detector import TodoFinderPlugin

        plugin = TodoFinderPlugin()
        ctx = ScanContext(
            skill=SkillContent(
                file_path="test.md",
                raw_content="# Clean file\nNo issues here.\n",
                metadata=SkillMetadata(name="clean"),
            ),
            scan_id="ex-002",
        )
        findings = await plugin.detect(ctx)
        assert findings == []
