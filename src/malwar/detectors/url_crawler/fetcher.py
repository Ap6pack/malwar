"""Async HTTP fetcher with safety bounds for URL analysis."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from malwar.detectors.url_crawler.safety import Resolver, check_url, resolve_host

logger = logging.getLogger("malwar.detectors.url_crawler.fetcher")


class UnsafeURLError(Exception):
    """Raised when a URL (or a redirect target) must not be fetched."""

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
        resolver: Resolver = resolve_host,
    ) -> None:
        self.max_urls = max_urls
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.concurrency = concurrency
        # Injectable so tests pin DNS answers instead of depending on the
        # network; see safety.check_url.
        self.resolver = resolver

    async def fetch_urls(self, urls: list[str]) -> list[FetchResult]:
        """Fetch multiple URLs concurrently with safety bounds."""
        # Enforce maximum URL count
        urls_to_fetch = urls[: self.max_urls]

        semaphore = asyncio.Semaphore(self.concurrency)

        # Redirects are followed by hand in _request, not by httpx, so every
        # hop can be validated before it is fetched. Letting the transport
        # chase them means the first unsafe destination is already requested
        # by the time we could look at it.
        async with httpx.AsyncClient(
            follow_redirects=False,
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
            except UnsafeURLError as exc:
                # Refused before any request was sent. Surfaced as a result
                # rather than dropped, so a blocked fetch is visible in the
                # report instead of looking like a URL that simply had nothing
                # interesting at the other end.
                return FetchResult(
                    url=url,
                    final_url=url,
                    status_code=0,
                    content_type="",
                    content="",
                    error=f"Refused to fetch: {exc}",
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

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
    ) -> tuple[httpx.Response, list[str], str]:
        """Issue ``method`` against ``url``, following redirects by hand.

        Every hop is checked before it is requested, which is the whole point:
        a URL that passes on the first request can redirect to internal
        infrastructure on the second, so validating only the entry point is
        equivalent to validating nothing.

        Returns ``(response, redirect_chain, final_url)``.
        """
        chain: list[str] = []
        current = url
        for _ in range(self.max_redirects + 1):
            safe, reason = check_url(current, resolver=self.resolver)
            if not safe:
                raise UnsafeURLError(reason)
            resp = await client.request(method, current)
            location = resp.headers.get("location")
            if not (resp.is_redirect and location):
                return resp, chain, current
            chain.append(current)
            # Relative Location headers are legal and common.
            current = urljoin(current, location)
        raise httpx.TooManyRedirects(f"exceeded {self.max_redirects} redirects")

    async def _do_fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> FetchResult:
        """Perform the actual fetch with HEAD pre-check."""
        head_resp, redirect_chain, final_url = await self._request(client, "HEAD", url)
        content_type_raw = head_resp.headers.get("content-type", "")
        content_type = content_type_raw.split(";")[0].strip().lower()

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

        # GET request with body-size limit, redirects validated the same way.
        get_resp, redirect_chain, final_url = await self._request(client, "GET", url)

        body = get_resp.text[: self.max_bytes]

        return FetchResult(
            url=url,
            final_url=final_url,
            status_code=get_resp.status_code,
            content_type=content_type,
            content=body,
            redirect_chain=redirect_chain,
        )
