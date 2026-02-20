# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Layer 2: URL crawler detection -- fetches and analyzes URLs found in skills."""

from __future__ import annotations

import logging

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.url_crawler.analyzer import analyze_fetch_result
from malwar.detectors.url_crawler.extractor import extract_urls
from malwar.detectors.url_crawler.fetcher import SafeFetcher
from malwar.detectors.url_crawler.reputation import check_domain_reputation
from malwar.models.finding import Finding
from malwar.scanner.base import BaseDetector
from malwar.scanner.context import ScanContext

logger = logging.getLogger("malwar.detectors.url_crawler")

# Reputation score threshold: URLs at or below this score get fetched
_REPUTATION_FETCH_THRESHOLD = 0.6


class UrlCrawlerDetector(BaseDetector):
    """Layer 2: Fetch and analyze URLs found in skill files."""

    def __init__(self, fetcher: SafeFetcher | None = None) -> None:
        self._fetcher = fetcher or SafeFetcher()

    @property
    def layer_name(self) -> str:
        return DetectorLayer.URL_CRAWLER

    @property
    def order(self) -> int:
        return 20

    async def detect(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # ---------------------------------------------------------------
        # Step 1: Extract all URLs from the skill content
        # ---------------------------------------------------------------
        urls = extract_urls(context.skill)
        logger.info(
            "Extracted %d unique URLs from %s", len(urls), context.skill.file_path
        )

        if not urls:
            return findings

        # ---------------------------------------------------------------
        # Step 2: Check domain reputation for every URL
        # ---------------------------------------------------------------
        reputation_map: dict[str, object] = {}
        urls_to_fetch: list[str] = []

        for url in urls:
            rep = check_domain_reputation(url)
            reputation_map[url] = {
                "domain": rep.domain,
                "score": rep.score,
                "reasons": rep.reasons,
            }

            # Emit finding for known-malicious
            if rep.score == 0.0:
                findings.append(
                    Finding(
                        id=f"MALWAR-URL-REP-{len(findings)+1:03d}",
                        rule_id="url_known_malicious",
                        title="Known-malicious domain",
                        description=(
                            f"URL {url} points to a known-malicious domain: {rep.domain}"
                        ),
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        category=ThreatCategory.MALICIOUS_URL,
                        detector_layer=DetectorLayer.URL_CRAWLER,
                        evidence=rep.reasons,
                        ioc_values=[url, rep.domain],
                        remediation="Remove this URL immediately. It points to a known malicious resource.",
                    )
                )

            # Queue suspicious / unknown URLs for fetching
            if rep.score <= _REPUTATION_FETCH_THRESHOLD:
                urls_to_fetch.append(url)

        logger.info(
            "%d / %d URLs queued for fetching (reputation <= %.1f)",
            len(urls_to_fetch),
            len(urls),
            _REPUTATION_FETCH_THRESHOLD,
        )

        # ---------------------------------------------------------------
        # Step 3: Fetch suspicious / unknown URLs
        # ---------------------------------------------------------------
        fetch_results = []
        if urls_to_fetch:
            try:
                fetch_results = await self._fetcher.fetch_urls(urls_to_fetch)
            except Exception as exc:
                error_msg = f"URL fetch batch failed: {exc}"
                logger.error(error_msg)
                context.errors.append(error_msg)

        # ---------------------------------------------------------------
        # Step 4: Analyze fetched content
        # ---------------------------------------------------------------
        fetch_analysis: dict[str, object] = {}
        for result in fetch_results:
            try:
                result_findings = analyze_fetch_result(result)
                findings.extend(result_findings)
                fetch_analysis[result.url] = {
                    "final_url": result.final_url,
                    "status_code": result.status_code,
                    "content_type": result.content_type,
                    "redirect_chain": result.redirect_chain,
                    "error": result.error,
                    "findings_count": len(result_findings),
                }
            except Exception as exc:
                error_msg = f"Analysis failed for {result.url}: {exc}"
                logger.error(error_msg)
                context.errors.append(error_msg)

        # ---------------------------------------------------------------
        # Step 5: Store enrichment data in context
        # ---------------------------------------------------------------
        context.url_analysis_results = {
            "urls_extracted": len(urls),
            "urls_fetched": len(fetch_results),
            "reputation": reputation_map,
            "fetch_analysis": fetch_analysis,
        }

        logger.info(
            "URL crawler produced %d findings for %s",
            len(findings),
            context.skill.file_path,
        )
        return findings
