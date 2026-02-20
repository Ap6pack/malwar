# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Async HTTP fetcher with safety bounds for URL analysis."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("malwar.detectors.url_crawler.fetcher")

# Content types we consider textual (worth fetching the body for)
_TEXT_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "text/css",
        "text/javascript",
        "application/json",
        "application/javascript",
        "application/x-javascript",
        "application/xml",
        "application/x-sh",
        "application/x-shellscript",
        "text/x-shellscript",
        "text/x-python",
        "text/x-script.python",
    }
)

# Binary / archive content types we flag but skip body download
_BINARY_CONTENT_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-executable",
        "application/x-mach-binary",
        "application/vnd.microsoft.portable-executable",
    }
)


@dataclass
class FetchResult:
    """Result of fetching a single URL."""

    url: str
    final_url: str
    status_code: int
    content_type: str
    content: str  # First N bytes of response body (text only)
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


class SafeFetcher:
    """Fetch URLs concurrently with configurable safety bounds.

    Parameters
    ----------
    max_urls:
        Maximum number of URLs to fetch in a single batch.
    timeout:
        Per-request timeout in seconds.
    max_redirects:
        Maximum number of HTTP redirects to follow per request.
    max_bytes:
        Maximum number of bytes to read from the response body.
    concurrency:
        Maximum number of concurrent HTTP requests.
    """

    def __init__(
        self,
        max_urls: int = 10,
        timeout: float = 5.0,
        max_redirects: int = 3,
        max_bytes: int = 1_048_576,
        concurrency: int = 5,
    ) -> None:
        self.max_urls = max_urls
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.concurrency = concurrency

    async def fetch_urls(self, urls: list[str]) -> list[FetchResult]:
        """Fetch multiple URLs concurrently with safety bounds."""
        # Enforce maximum URL count
        urls_to_fetch = urls[: self.max_urls]

        semaphore = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=self.max_redirects,
            timeout=httpx.Timeout(self.timeout),
        ) as client:
            tasks = [
                self._fetch_one(client, url, semaphore) for url in urls_to_fetch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)

    async def _fetch_one(
        self,
        client: httpx.AsyncClient,
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> FetchResult:
        """Fetch a single URL with safety checks."""
        async with semaphore:
            try:
                return await self._do_fetch(client, url)
            except httpx.TooManyRedirects:
                return FetchResult(
                    url=url,
                    final_url=url,
                    status_code=0,
                    content_type="",
                    content="",
                    error=f"Too many redirects (>{self.max_redirects})",
                )
            except httpx.TimeoutException:
                return FetchResult(
                    url=url,
                    final_url=url,
                    status_code=0,
                    content_type="",
                    content="",
                    error=f"Request timed out ({self.timeout}s)",
                )
            except Exception as exc:
                logger.debug("Fetch failed for %s: %s", url, exc)
                return FetchResult(
                    url=url,
                    final_url=url,
                    status_code=0,
                    content_type="",
                    content="",
                    error=str(exc),
                )

    async def _do_fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> FetchResult:
        """Perform the actual fetch with HEAD pre-check."""
        redirect_chain: list[str] = []

        # Attempt HEAD first to inspect content-type / size
        head_resp = await client.head(url)
        content_type_raw = head_resp.headers.get("content-type", "")
        content_type = content_type_raw.split(";")[0].strip().lower()

        # Build redirect chain from the response history
        for resp in head_resp.history:
            redirect_chain.append(str(resp.url))

        final_url = str(head_resp.url)

        # Check content-length to avoid huge downloads
        content_length = head_resp.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            return FetchResult(
                url=url,
                final_url=final_url,
                status_code=head_resp.status_code,
                content_type=content_type,
                content="",
                redirect_chain=redirect_chain,
                error=f"Content too large ({content_length} bytes)",
            )

        # Skip binary content
        if content_type in _BINARY_CONTENT_TYPES:
            return FetchResult(
                url=url,
                final_url=final_url,
                status_code=head_resp.status_code,
                content_type=content_type,
                content="",
                redirect_chain=redirect_chain,
                error=None,
            )

        # For text content, perform a GET to read the body
        is_text = any(content_type.startswith(t) for t in _TEXT_CONTENT_TYPES) or not content_type
        if not is_text:
            return FetchResult(
                url=url,
                final_url=final_url,
                status_code=head_resp.status_code,
                content_type=content_type,
                content="",
                redirect_chain=redirect_chain,
            )

        # GET request with body-size limit
        get_resp = await client.get(url)
        redirect_chain = [str(r.url) for r in get_resp.history]
        final_url = str(get_resp.url)

        body = get_resp.text[: self.max_bytes]

        return FetchResult(
            url=url,
            final_url=final_url,
            status_code=get_resp.status_code,
            content_type=content_type,
            content=body,
            redirect_chain=redirect_chain,
        )
