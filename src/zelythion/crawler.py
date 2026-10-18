"""
Zelythion passive same-origin crawler.

Performs bounded, breadth-first crawling of HTML pages within the
authorized scan scope. This crawler is entirely passive:

- It only follows links it discovers in HTML responses.
- It never submits forms, executes JavaScript, or sends POST requests.
- It never follows links outside the authorized scope.
- It enforces depth and page count limits from ScanConfig.
- It deduplicates URLs to avoid fetching the same resource twice.
- It normalizes URLs (strip fragments, normalize path) before comparison.

Design decisions:
- Link extraction uses stdlib html.parser — no extra dependencies.
- Only <a href>, <link href>, and canonical <link rel="canonical">
  are extracted. Script src and image src are not followed.
- Fragments (#section) are stripped before enqueuing a URL.
- Query parameters are preserved — different query strings may yield
  different responses and different header configurations.
- A URL that returns a non-HTML content-type is fetched once for
  header/cookie checks, but its body is not parsed for more links.
- crawl() is synchronous and single-threaded in Phase 4.
  Async multi-threaded crawling is Phase 8.
- robots.txt is not used to authorise or de-authorise scanning.
  Scope and authorization come from the operator, not the target.
"""

from __future__ import annotations

import logging
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Optional

from zelythion.config import ScanConfig
from zelythion.errors import HttpClientError, ZelythionError
from zelythion.http_client import BoundedHttpClient, HttpResponse
from zelythion.scope import ScopeSpec, ScopeValidator, ScopeError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Link extractor
# ---------------------------------------------------------------------------


class _LinkExtractor(HTMLParser):
    """
    Minimal HTML link extractor using stdlib html.parser.

    Extracts href values from:
      <a href="...">              Navigation links
      <link rel="canonical" href="...">   Canonical URL hints
      <link rel="next" href="...">        Pagination hints
      <link rel="prev" href="...">        Pagination hints

    Does NOT extract:
      <script src="...">          JavaScript — not followed
      <img src="...">             Images — not followed
      <form action="...">         Forms — not submitted (passive only)
    """

    def __init__(self) -> None:
        super().__init__()
        self._links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = {k.lower(): v for k, v in attrs}
        href = attr_dict.get("href")

        if not href or not isinstance(href, str):
            return

        href = href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            return

        if tag == "a":
            self._links.append(href)
        elif tag == "link":
            rel = (attr_dict.get("rel") or "").lower()
            if any(r in rel for r in ("canonical", "next", "prev", "alternate")):
                self._links.append(href)

    @property
    def links(self) -> list[str]:
        return list(self._links)


def extract_links(html: str, base_url: str) -> list[str]:
    """
    Extract and resolve all navigable links from an HTML document.

    Args:
        html: Raw HTML text.
        base_url: The URL the HTML was fetched from (for relative link resolution).

    Returns:
        List of absolute URLs with fragments stripped. May contain duplicates.
    """
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception as exc:
        logger.debug("Link extraction parse error for %s: %s", base_url, exc)

    resolved: list[str] = []
    for href in parser.links:
        try:
            absolute = urllib.parse.urljoin(base_url, href)
            # Strip fragment — fragments are client-side only.
            defragged = urllib.parse.urldefrag(absolute).url
            resolved.append(defragged)
        except Exception:
            continue

    return resolved


def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication purposes.

    - Strips fragment.
    - Lowercases scheme and host.
    - Removes trailing slash from paths (except root "/").
    - Does NOT sort query parameters (order may matter to the server).
    """
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        normalized = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.params,
            parsed.query,
            "",  # no fragment
        ))
        return normalized
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Crawl result
# ---------------------------------------------------------------------------


@dataclass
class CrawlResult:
    """Result returned by the crawler for a single page."""

    url: str
    response: HttpResponse
    depth: int
    links_found: int


@dataclass
class CrawlSummary:
    """Aggregated statistics from a completed crawl."""

    pages_crawled: int = 0
    urls_discovered: int = 0
    urls_skipped_scope: int = 0
    urls_skipped_depth: int = 0
    urls_skipped_budget: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class PassiveCrawler:
    """
    Breadth-first passive same-origin web crawler.

    Usage::

        config = ScanConfig(target="https://example.com", max_depth=2, max_pages=20)
        scope = ScopeValidator().build_scope_from_target(config.target)
        with BoundedHttpClient(config, scope) as client:
            crawler = PassiveCrawler(config=config, scope=scope, client=client)
            for result in crawler.crawl(start_url=config.target):
                run_checks(result.response)

    The crawler yields CrawlResult objects as pages are fetched.
    Iteration stops when max_pages is reached or the queue is empty.
    """

    def __init__(
        self,
        config: ScanConfig,
        scope: ScopeSpec,
        client: BoundedHttpClient,
        on_error: Optional[Callable[[str, Exception], None]] = None,
    ) -> None:
        self._config = config
        self._scope = scope
        self._client = client
        self._validator = ScopeValidator()
        self._on_error = on_error or (lambda url, exc: None)

    def crawl(self, start_url: str) -> "CrawlIterator":
        """
        Return an iterator that lazily crawls pages starting from start_url.

        Yields CrawlResult for each successfully fetched page.
        Stops when max_pages is reached or the queue is empty.
        """
        return CrawlIterator(
            start_url=start_url,
            config=self._config,
            scope=self._scope,
            client=self._client,
            validator=self._validator,
            on_error=self._on_error,
        )


class CrawlIterator:
    """
    Lazy BFS iterator over crawlable pages.

    Not thread-safe — Phase 4 is single-threaded.
    """

    def __init__(
        self,
        start_url: str,
        config: ScanConfig,
        scope: ScopeSpec,
        client: BoundedHttpClient,
        validator: ScopeValidator,
        on_error: Callable[[str, Exception], None],
    ) -> None:
        self._config = config
        self._scope = scope
        self._client = client
        self._validator = validator
        self._on_error = on_error

        # BFS queue: (url, depth)
        self._queue: deque[tuple[str, int]] = deque()
        self._queue.append((start_url, 0))

        # Visited set uses normalized URLs.
        self._visited: set[str] = set()

        self.summary = CrawlSummary()

    def __iter__(self) -> "CrawlIterator":
        return self

    def __next__(self) -> CrawlResult:
        while self._queue:
            url, depth = self._queue.popleft()
            norm = normalize_url(url)

            # Skip already visited.
            if norm in self._visited:
                continue

            # Depth limit.
            if depth > self._config.max_depth:
                self.summary.urls_skipped_depth += 1
                continue

            # Page budget.
            if self.summary.pages_crawled >= self._config.max_pages:
                self.summary.urls_skipped_budget += 1
                logger.debug("Page budget reached (%d), stopping crawl.", self._config.max_pages)
                raise StopIteration

            # Scope validation.
            try:
                validated_url = self._validator.validate_url_in_scope(url, self._scope)
            except ScopeError as exc:
                self.summary.urls_skipped_scope += 1
                logger.debug("Skipping out-of-scope URL %r: %s", url, exc)
                continue

            # Fetch.
            self._visited.add(norm)
            try:
                response = self._client.get(validated_url)
            except ZelythionError as exc:
                err_msg = f"Failed to fetch {validated_url!r}: {exc}"
                self.summary.errors.append(err_msg)
                self._on_error(validated_url, exc)
                logger.warning(err_msg)
                continue

            self.summary.pages_crawled += 1

            # Extract links if this is an HTML response.
            new_links: list[str] = []
            if response.is_html() and depth < self._config.max_depth:
                raw_links = extract_links(response.text, validated_url)
                self.summary.urls_discovered += len(raw_links)

                for link in raw_links:
                    link_norm = normalize_url(link)
                    if link_norm not in self._visited:
                        new_links.append(link)
                        self._queue.append((link, depth + 1))

            logger.info(
                "Crawled [%d/%d] depth=%d links=%d  %s",
                self.summary.pages_crawled,
                self._config.max_pages,
                depth,
                len(new_links),
                validated_url,
            )

            return CrawlResult(
                url=validated_url,
                response=response,
                depth=depth,
                links_found=len(new_links),
            )

        raise StopIteration
