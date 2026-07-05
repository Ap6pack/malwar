"""malwar - Malware detection engine for agentic skills."""

__version__ = "0.4.0"

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
