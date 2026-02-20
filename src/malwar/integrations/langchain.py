# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""LangChain-compatible integration for Malwar.

This module provides three integration points:

* **MalwarScanTool** -- a LangChain-compatible tool that agents can invoke
  to scan arbitrary content for threats.
* **MalwarGuard** -- standalone middleware that wraps any function with a
  scan-before-execute check.
* **MalwarCallbackHandler** -- a callback-style handler that intercepts tool
  execution events and scans tool inputs before they run.

All classes work **standalone** without LangChain installed.  When LangChain
*is* available they are compatible with its tool and callback interfaces.

Usage::

    from malwar.integrations.langchain import MalwarGuard

    guard = MalwarGuard(block_on="SUSPICIOUS")
    result = guard.check(content, file_name="SKILL.md")
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from malwar.integrations.exceptions import MalwarBlockedError
from malwar.models.scan import ScanResult

logger = logging.getLogger("malwar.integrations.langchain")

F = TypeVar("F", bound=Callable[..., Any])

# Verdict severity ordering used for threshold comparisons.
_VERDICT_LEVELS: dict[str, int] = {
    "CLEAN": 0,
    "CAUTION": 1,
    "SUSPICIOUS": 2,
    "MALICIOUS": 3,
}


def _verdict_meets_threshold(verdict: str, block_on: str) -> bool:
    """Return ``True`` if *verdict* is at or above the *block_on* level."""
    return _VERDICT_LEVELS.get(verdict, 0) >= _VERDICT_LEVELS.get(block_on, 3)


def _raise_if_blocked(result: ScanResult, block_on: str) -> None:
    """Raise :class:`MalwarBlockedError` if the scan result meets the threshold."""
    if _verdict_meets_threshold(result.verdict, block_on):
        raise MalwarBlockedError(
            f"Content blocked: verdict={result.verdict} "
            f"risk_score={result.risk_score} (threshold={block_on})",
            verdict=result.verdict,
            risk_score=result.risk_score,
            findings=result.findings,
            scan_id=result.scan_id,
        )


# ---------------------------------------------------------------------------
# MalwarScanTool
# ---------------------------------------------------------------------------


class MalwarScanTool:
    """A LangChain-compatible tool for scanning content with Malwar.

    When LangChain is installed this class can be used directly as a tool
    in an agent's tool list.  It also works perfectly fine standalone.

    Parameters
    ----------
    use_llm : bool
        Whether to enable the LLM analyzer layer (default ``False``).
    use_urls : bool
        Whether to enable the URL crawler layer (default ``False``).

    Example::

        tool = MalwarScanTool()
        output = tool.run("potentially dangerous content")
    """

    name: str = "malwar_scan"
    description: str = (
        "Scan content (e.g. a SKILL.md file) for malware, prompt injection, "
        "and other threats.  Returns a verdict (CLEAN / CAUTION / SUSPICIOUS / "
        "MALICIOUS) along with a risk score and findings."
    )

    def __init__(
        self,
        *,
        use_llm: bool = False,
        use_urls: bool = False,
    ) -> None:
        self.use_llm = use_llm
        self.use_urls = use_urls

    # -- sync interface -----------------------------------------------------

    def run(self, content: str, *, file_name: str = "SKILL.md") -> dict[str, Any]:
        """Scan *content* synchronously and return a summary dict.

        Returns
        -------
        dict
            Keys: ``verdict``, ``risk_score``, ``findings_count``,
            ``findings_summary``, ``scan_id``.
        """
        from malwar.sdk import scan_sync

        result = scan_sync(
            content,
            file_name=file_name,
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        return self._format_output(result)

    # -- async interface ----------------------------------------------------

    async def arun(self, content: str, *, file_name: str = "SKILL.md") -> dict[str, Any]:
        """Scan *content* asynchronously and return a summary dict."""
        from malwar.sdk import scan as scan_async

        result = await scan_async(
            content,
            file_name=file_name,
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        return self._format_output(result)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _format_output(result: ScanResult) -> dict[str, Any]:
        """Convert a :class:`ScanResult` into a concise summary dict."""
        findings_summary = [
            {
                "id": f.id,
                "title": f.title,
                "severity": str(f.severity),
                "category": str(f.category),
                "confidence": f.confidence,
            }
            for f in result.findings
        ]
        return {
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "findings_count": len(result.findings),
            "findings_summary": findings_summary,
            "scan_id": result.scan_id,
        }


# ---------------------------------------------------------------------------
# MalwarGuard
# ---------------------------------------------------------------------------


class MalwarGuard:
    """Middleware that scans content before allowing execution.

    Parameters
    ----------
    block_on : str
        Minimum verdict that triggers a block.  One of ``"CAUTION"``,
        ``"SUSPICIOUS"``, or ``"MALICIOUS"`` (default).
    use_llm : bool
        Whether to enable the LLM analyzer layer (default ``False``).
    use_urls : bool
        Whether to enable the URL crawler layer (default ``False``).

    Example::

        guard = MalwarGuard(block_on="SUSPICIOUS")

        # Direct check
        result = guard.check(content)

        # Decorator
        @guard.wrap
        def execute_skill(content: str) -> str:
            return eval(content)  # noqa: S307
    """

    def __init__(
        self,
        *,
        block_on: str = "MALICIOUS",
        use_llm: bool = False,
        use_urls: bool = False,
    ) -> None:
        if block_on not in _VERDICT_LEVELS:
            msg = (
                f"Invalid block_on value: {block_on!r}. "
                f"Must be one of {list(_VERDICT_LEVELS.keys())}"
            )
            raise ValueError(msg)
        self.block_on = block_on
        self.use_llm = use_llm
        self.use_urls = use_urls

    # -- sync interface -----------------------------------------------------

    def check(self, content: str, file_name: str = "SKILL.md") -> ScanResult:
        """Scan *content* synchronously.

        Returns the :class:`ScanResult`.  Raises :class:`MalwarBlockedError`
        if the verdict meets or exceeds :attr:`block_on`.
        """
        from malwar.sdk import scan_sync

        result = scan_sync(
            content,
            file_name=file_name,
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        logger.info(
            "MalwarGuard.check: verdict=%s risk_score=%s scan_id=%s",
            result.verdict,
            result.risk_score,
            result.scan_id,
        )
        _raise_if_blocked(result, self.block_on)
        return result

    # -- async interface ----------------------------------------------------

    async def acheck(self, content: str, file_name: str = "SKILL.md") -> ScanResult:
        """Scan *content* asynchronously.

        Returns the :class:`ScanResult`.  Raises :class:`MalwarBlockedError`
        if the verdict meets or exceeds :attr:`block_on`.
        """
        from malwar.sdk import scan as scan_async

        result = await scan_async(
            content,
            file_name=file_name,
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        logger.info(
            "MalwarGuard.acheck: verdict=%s risk_score=%s scan_id=%s",
            result.verdict,
            result.risk_score,
            result.scan_id,
        )
        _raise_if_blocked(result, self.block_on)
        return result

    # -- decorator ----------------------------------------------------------

    def wrap(self, func: F) -> F:
        """Decorator that scans the first string argument before executing *func*.

        Works with both sync and async functions.  The first positional
        argument (which must be a ``str``) is scanned.  If the verdict meets
        the threshold, :class:`MalwarBlockedError` is raised and *func* is
        never called.
        """
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                content = _extract_content(args, kwargs)
                await self.acheck(content)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            content = _extract_content(args, kwargs)
            self.check(content)
            return func(*args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]


def _extract_content(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Extract the first string argument from *args* or *kwargs*."""
    for arg in args:
        if isinstance(arg, str):
            return arg
    for value in kwargs.values():
        if isinstance(value, str):
            return value
    msg = "No string argument found to scan"
    raise TypeError(msg)


# ---------------------------------------------------------------------------
# MalwarCallbackHandler
# ---------------------------------------------------------------------------


class MalwarCallbackHandler:
    """Callback handler that intercepts tool executions and scans inputs.

    Compatible with LangChain's ``BaseCallbackHandler`` pattern but does
    **not** require LangChain as a dependency.

    Parameters
    ----------
    block_on : str
        Minimum verdict that triggers a block (default ``"MALICIOUS"``).
    use_llm : bool
        Whether to enable the LLM analyzer layer (default ``False``).
    use_urls : bool
        Whether to enable the URL crawler layer (default ``False``).

    Example::

        handler = MalwarCallbackHandler(block_on="SUSPICIOUS")
        result = handler.on_tool_start(
            tool_name="execute_skill",
            tool_input="some content to scan",
        )
    """

    def __init__(
        self,
        *,
        block_on: str = "MALICIOUS",
        use_llm: bool = False,
        use_urls: bool = False,
    ) -> None:
        if block_on not in _VERDICT_LEVELS:
            msg = (
                f"Invalid block_on value: {block_on!r}. "
                f"Must be one of {list(_VERDICT_LEVELS.keys())}"
            )
            raise ValueError(msg)
        self.block_on = block_on
        self.use_llm = use_llm
        self.use_urls = use_urls
        self.scan_log: list[dict[str, Any]] = []

    # -- sync callbacks -----------------------------------------------------

    def on_tool_start(
        self,
        tool_name: str,
        tool_input: str,
        **kwargs: Any,
    ) -> ScanResult:
        """Called before a tool executes.  Scans *tool_input*.

        Returns the :class:`ScanResult`.  Raises :class:`MalwarBlockedError`
        if the verdict meets or exceeds :attr:`block_on`.
        """
        from malwar.sdk import scan_sync

        result = scan_sync(
            tool_input,
            file_name=f"tool:{tool_name}",
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        self._log_scan(tool_name, result)
        _raise_if_blocked(result, self.block_on)
        return result

    # -- async callbacks ----------------------------------------------------

    async def aon_tool_start(
        self,
        tool_name: str,
        tool_input: str,
        **kwargs: Any,
    ) -> ScanResult:
        """Async variant of :meth:`on_tool_start`."""
        from malwar.sdk import scan as scan_async

        result = await scan_async(
            tool_input,
            file_name=f"tool:{tool_name}",
            use_llm=self.use_llm,
            use_urls=self.use_urls,
        )
        self._log_scan(tool_name, result)
        _raise_if_blocked(result, self.block_on)
        return result

    # -- helpers ------------------------------------------------------------

    def _log_scan(self, tool_name: str, result: ScanResult) -> None:
        """Append a scan event to the internal log."""
        entry = {
            "tool_name": tool_name,
            "scan_id": result.scan_id,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "findings_count": len(result.findings),
        }
        self.scan_log.append(entry)
        logger.info(
            "MalwarCallbackHandler: tool=%s verdict=%s risk_score=%s scan_id=%s",
            tool_name,
            result.verdict,
            result.risk_score,
            result.scan_id,
        )

    def get_scan_log(self) -> list[dict[str, Any]]:
        """Return all scan events recorded by this handler."""
        return list(self.scan_log)
