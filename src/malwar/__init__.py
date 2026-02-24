# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""malwar - Malware detection engine for agentic skills."""

__version__ = "0.3.1"

from malwar.integrations.exceptions import MalwarBlockedError
from malwar.integrations.langchain import (
    MalwarCallbackHandler,
    MalwarGuard,
    MalwarScanTool,
)
from malwar.sdk import diff, diff_sync, scan, scan_batch, scan_file, scan_file_sync, scan_sync

__all__ = [
    "MalwarBlockedError",
    "MalwarCallbackHandler",
    "MalwarGuard",
    "MalwarScanTool",
    "__version__",
    "diff",
    "diff_sync",
    "scan",
    "scan_batch",
    "scan_file",
    "scan_file_sync",
    "scan_sync",
]
