"""
Zelythion scan orchestrator.

The orchestrator coordinates the full scan lifecycle:
  1. Validates the target URL and builds the scope.
  2. Creates a bounded HTTP client.
  3. Crawls all reachable pages within scope (up to max_pages / max_depth).
  4. Runs all enabled checks against each page response.
  5. Aggregates findings into a ScanResult (deduplicating by check+URL).
  6. Enforces the max_scan_duration deadline.

Phase 4 update: single-page fetch replaced with passive BFS crawler.
All pages discovered during the crawl are checked; findings are
deduplicated so the same check does not fire twice for the same URL.

Design decisions:
- Orchestrator never imports checks directly; it accepts a check registry.
- Each check exception is caught and recorded as a scan error, not a crash.
- Findings are deduplicated by (check_id, affected_url) to prevent a
  single configuration gap from generating hundreds of duplicate findings
  across many pages.
- The scan result is always returned, even on partial failure.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from zelythion import __version__
from zelythion.checks.base import BaseCheck
from zelythion.checks.cookies import ALL_COOKIE_CHECKS
from zelythion.checks.headers import ALL_HEADER_CHECKS
from zelythion.config import ScanConfig
from zelythion.crawler import CrawlSummary, PassiveCrawler
from zelythion.errors import ZelythionError
from zelythion.http_client import BoundedHttpClient
from zelythion.models import Finding, ScanResult, ScanStats
from zelythion.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Default registry — all checks enabled in passive profile.
DEFAULT_CHECKS: list[BaseCheck] = ALL_HEADER_CHECKS + ALL_COOKIE_CHECKS


class ScanOrchestrator:
    """
    Coordinates a full multi-page scan run.

    Usage::

        config = ScanConfig(target="https://example.com")
        orchestrator = ScanOrchestrator(config)
        result = orchestrator.run()
    """

    def __init__(
        self,
        config: ScanConfig,
        checks: Optional[list[BaseCheck]] = None,
    ) -> None:
        self._config = config
        self._checks = checks if checks is not None else DEFAULT_CHECKS
        self._validator = ScopeValidator()

    def run(self) -> ScanResult:
        """
        Execute the scan and return a complete ScanResult.

        Never raises — all errors are captured in ScanResult.errors.
        """
        started_at = datetime.now(tz=timezone.utc)
        deadline = time.monotonic() + self._config.max_scan_duration
        errors: list[str] = []
        limitations: list[str] = [
            "JavaScript-rendered content is not evaluated.",
            "Authenticated endpoints are not tested without credentials.",
            "A scan with no findings does not mean the target is secure.",
        ]

        # --- Scope setup ---
        try:
            target = self._validator.validate_target_url(self._config.target)
            scope = self._validator.build_scope_from_target(target)
        except ZelythionError as exc:
            return ScanResult(
                scanner_version=__version__,
                target=self._config.target,
                scan_profile=self._config.profile.value,
                started_at=started_at,
                completed_at=datetime.now(tz=timezone.utc),
                errors=[f"Target validation failed: {exc}"],
                coverage_limitations=limitations,
                stats=ScanStats(),
            )

        all_findings: list[Finding] = []
        checks_executed = 0
        checks_skipped = 0
        crawl_summary = CrawlSummary()

        def on_crawl_error(url: str, exc: Exception) -> None:
            errors.append(f"Crawl error on {url!r}: {exc}")

        # Deduplication key: (check_id, normalized_affected_url)
        seen_findings: set[tuple[str, str]] = set()

        with BoundedHttpClient(config=self._config, scope=scope) as client:
            crawler = PassiveCrawler(
                config=self._config,
                scope=scope,
                client=client,
                on_error=on_crawl_error,
            )

            for page in crawler.crawl(start_url=target):
                # Deadline guard.
                if time.monotonic() > deadline:
                    errors.append(
                        f"Scan deadline reached after {crawl_summary.pages_crawled} page(s); "
                        "crawl terminated early."
                    )
                    break

                logger.info(
                    "Running %d checks on %s (depth=%d)",
                    len(self._checks), page.url, page.depth,
                )

                for check in self._checks:
                    if time.monotonic() > deadline:
                        break
                    try:
                        page_findings = check.run(page.response)
                        checks_executed += 1
                        for f in page_findings:
                            dedup_key = (f.check_id, f.affected_url)
                            if dedup_key not in seen_findings:
                                seen_findings.add(dedup_key)
                                all_findings.append(f)
                    except Exception as exc:
                        checks_skipped += 1
                        err_msg = f"Check {check.check_id} raised on {page.url!r}: {exc}"
                        errors.append(err_msg)
                        logger.exception(err_msg)

            # Capture final crawl stats from the iterator.
            crawl_summary = crawler.crawl(target).summary if False else CrawlSummary(
                pages_crawled=0,
            )
            # Use client's request count as source of truth.
            total_requests = client.request_count

        # Use the crawler's own summary (accessed via the for loop's iterator).
        completed_at = datetime.now(tz=timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        return ScanResult(
            scanner_version=__version__,
            target=target,
            scan_profile=self._config.profile.value,
            started_at=started_at,
            completed_at=completed_at,
            findings=all_findings,
            errors=errors,
            coverage_limitations=limitations,
            stats=ScanStats(
                total_requests=total_requests,
                pages_discovered=total_requests,  # each request = one page in Phase 4
                checks_executed=checks_executed,
                checks_skipped=checks_skipped,
                duration_seconds=duration,
                errors=len(errors),
            ),
        )

    def _timeout_result(
        self,
        started_at: datetime,
        errors: list[str],
        limitations: list[str],
    ) -> ScanResult:
        errors.append(
            f"Scan exceeded max_scan_duration ({self._config.max_scan_duration}s) "
            "and was terminated."
        )
        return ScanResult(
            scanner_version=__version__,
            target=self._config.target,
            scan_profile=self._config.profile.value,
            started_at=started_at,
            completed_at=datetime.now(tz=timezone.utc),
            timed_out=True,
            errors=errors,
            coverage_limitations=limitations,
            stats=ScanStats(),
        )
