# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Example detector plugin demonstrating the malwar plugin interface.

This plugin scans SKILL.md files for the presence of ``TODO`` or ``FIXME``
comments, which may indicate unfinished or untested sections in a skill
definition.  It is intentionally simplistic — its purpose is to serve as a
reference implementation for third-party plugin authors.

Installation
------------
Copy this file into the directory configured via ``MALWAR_PLUGINS_DIR``, or
register it as a ``malwar.detectors`` entry point in your package's
``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."malwar.detectors"]
    todo_finder = "my_package.todo_finder:TodoFinderPlugin"
"""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.models.finding import Finding, Location
from malwar.plugins.base import DetectorPlugin, PluginMetadata
from malwar.scanner.context import ScanContext

_TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)


class TodoFinderPlugin(DetectorPlugin):
    """Flags TODO/FIXME markers in skill files as informational findings."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="todo_finder",
            version="0.1.0",
            author="Malwar Examples",
            description="Detects TODO/FIXME comments that may indicate incomplete skill definitions",
            layer_name="plugin:todo_finder",
            tags=["example", "quality"],
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        raw_content = context.skill.raw_content

        for line_num, line in enumerate(raw_content.splitlines(), start=1):
            match = _TODO_RE.search(line)
            if match:
                findings.append(
                    Finding(
                        id=f"PLUGIN-TODO-{line_num:04d}",
                        rule_id="plugin-todo-finder",
                        title=f"{match.group()} marker found",
                        description=(
                            f"Line {line_num} contains a '{match.group()}' marker, "
                            "which may indicate an unfinished or untested section."
                        ),
                        severity=Severity.INFO,
                        confidence=1.0,
                        category=ThreatCategory.SUSPICIOUS_COMMAND,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:120],
                        ),
                    )
                )

        return findings
