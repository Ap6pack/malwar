# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Public SDK interface for embedding malwar in other tools.

Usage::

    from malwar import scan, scan_sync

    # Synchronous (blocking)
    result = scan_sync(content, file_name="my_skill.md")
    print(result.verdict, result.risk_score)

    # Async
    result = await scan(content, use_llm=False)
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from malwar.core.config import Settings, get_settings
from malwar.detectors.llm_analyzer.detector import LlmAnalyzerDetector
from malwar.detectors.rule_engine.detector import RuleEngineDetector
from malwar.detectors.threat_intel.detector import ThreatIntelDetector
from malwar.detectors.url_crawler.detector import UrlCrawlerDetector
from malwar.models.scan import ScanResult
from malwar.parsers.skill_parser import parse_skill_content
from malwar.scanner.pipeline import ScanPipeline

logger = logging.getLogger("malwar.sdk")


def _build_pipeline(
    *,
    settings: Settings | None = None,
    use_llm: bool = True,
    use_urls: bool = True,
) -> ScanPipeline:
    """Construct a fully-wired scan pipeline.

    Parameters
    ----------
    settings:
        Optional ``Settings`` override; falls back to ``get_settings()``.
    use_llm:
        Whether to register the LLM analyzer detector.
    use_urls:
        Whether to register the URL crawler detector.
    """
    settings = settings or get_settings()
    pipeline = ScanPipeline(settings=settings)

    pipeline.register_detector(RuleEngineDetector())

    if use_urls:
        pipeline.register_detector(UrlCrawlerDetector())

    if use_llm:
        pipeline.register_detector(LlmAnalyzerDetector(settings=settings))

    pipeline.register_detector(ThreatIntelDetector())

    return pipeline


def _resolve_layers(
    *,
    layers: list[str] | None,
    use_llm: bool,
    use_urls: bool,
    settings: Settings,
) -> list[str] | None:
    """Resolve the effective layer list based on user flags.

    Returns ``None`` (meaning "run all registered detectors") when no
    filtering is needed, or an explicit list of layer names otherwise.
    """
    if layers is not None:
        return list(layers)

    effective = list(settings.scan_default_layers)
    if not use_llm and "llm_analyzer" in effective:
        effective.remove("llm_analyzer")
    if not use_urls and "url_crawler" in effective:
        effective.remove("url_crawler")

    return effective


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------


async def scan(
    content: str,
    *,
    file_name: str = "SKILL.md",
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> ScanResult:
    """Scan raw SKILL.md content and return a :class:`ScanResult`.

    Parameters
    ----------
    content:
        The full text of the SKILL.md file (including any frontmatter).
    file_name:
        A label used as the ``target`` in the result.
    use_llm:
        Set ``False`` to skip the LLM analysis layer.
    use_urls:
        Set ``False`` to skip URL crawling.
    layers:
        Explicit list of layer names to execute.  Overrides ``use_llm``
        and ``use_urls`` when provided.

    Returns
    -------
    ScanResult
        Fully populated scan result with findings, risk score, and verdict.
    """
    settings = get_settings()
    skill = parse_skill_content(content, file_path=file_name)

    pipeline = _build_pipeline(
        settings=settings,
        use_llm=use_llm,
        use_urls=use_urls,
    )

    effective_layers = _resolve_layers(
        layers=layers,
        use_llm=use_llm,
        use_urls=use_urls,
        settings=settings,
    )

    return await pipeline.scan(skill, layers=effective_layers)


async def scan_file(
    path: str | Path,
    *,
    file_name: str | None = None,
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> ScanResult:
    """Read a file from disk and scan its contents.

    Parameters
    ----------
    path:
        Filesystem path to the SKILL.md file.
    file_name:
        Optional override for the file label in the result; defaults to
        the resolved file name.
    use_llm:
        Set ``False`` to skip the LLM analysis layer.
    use_urls:
        Set ``False`` to skip URL crawling.
    layers:
        Explicit list of layer names to execute.

    Returns
    -------
    ScanResult
    """
    resolved = Path(path).resolve()
    content = resolved.read_text(encoding="utf-8")
    label = file_name or resolved.name
    return await scan(
        content,
        file_name=label,
        use_llm=use_llm,
        use_urls=use_urls,
        layers=layers,
    )


async def scan_batch(
    items: list[dict],
    *,
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> list[ScanResult]:
    """Scan multiple items in sequence.

    Parameters
    ----------
    items:
        Each dict must have a ``"content"`` key with the raw SKILL.md text.
        An optional ``"file_name"`` key overrides the default label.
    use_llm:
        Set ``False`` to skip the LLM analysis layer.
    use_urls:
        Set ``False`` to skip URL crawling.
    layers:
        Explicit list of layer names to execute.

    Returns
    -------
    list[ScanResult]
        One result per input item, in the same order.
    """
    results: list[ScanResult] = []
    for item in items:
        result = await scan(
            item["content"],
            file_name=item.get("file_name", "SKILL.md"),
            use_llm=use_llm,
            use_urls=use_urls,
            layers=layers,
        )
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Public sync wrappers
# ---------------------------------------------------------------------------


def scan_sync(
    content: str,
    *,
    file_name: str = "SKILL.md",
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> ScanResult:
    """Synchronous wrapper around :func:`scan`.

    Calls ``asyncio.run()`` internally, so it must **not** be called from
    within an already-running event loop.
    """
    return asyncio.run(
        scan(
            content,
            file_name=file_name,
            use_llm=use_llm,
            use_urls=use_urls,
            layers=layers,
        )
    )


def scan_file_sync(
    path: str | Path,
    *,
    file_name: str | None = None,
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> ScanResult:
    """Synchronous wrapper around :func:`scan_file`."""
    return asyncio.run(
        scan_file(
            path,
            file_name=file_name,
            use_llm=use_llm,
            use_urls=use_urls,
            layers=layers,
        )
    )
