# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""malwar - Malware detection engine for agentic skills."""

__version__ = "0.1.0"

from malwar.sdk import scan, scan_batch, scan_file, scan_file_sync, scan_sync

__all__ = [
    "__version__",
    "scan",
    "scan_batch",
    "scan_file",
    "scan_file_sync",
    "scan_sync",
]
