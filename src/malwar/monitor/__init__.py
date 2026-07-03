# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Continuous registry monitoring — snapshot the whole ClawHub registry and
diff it over time to surface newly-published or newly-malicious skills."""

from __future__ import annotations

from malwar.monitor.diff import diff_snapshots
from malwar.monitor.models import (
    RegistrySnapshot,
    SkillChange,
    SkillRecord,
    SnapshotDiff,
)
from malwar.monitor.report import render_digest, render_tweet
from malwar.monitor.snapshot import SnapshotStore, build_snapshot

__all__ = [
    "RegistrySnapshot",
    "SkillChange",
    "SkillRecord",
    "SnapshotDiff",
    "SnapshotStore",
    "build_snapshot",
    "diff_snapshots",
    "render_digest",
    "render_tweet",
]
