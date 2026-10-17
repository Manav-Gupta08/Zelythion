"""
Zelythion scan orchestrator.

The orchestrator coordinates the full scan lifecycle:
  1. Validates the target URL and builds the scope.
  2. Creates a bounded HTTP client.
  3. Fetches the target page.
  4. Runs all enabled checks against the response.
  5. Aggregates findings into a ScanResult.
  6. Enforces the max_scan_duration deadline.

This is Phase 1/2 implementation — single-page orchestration.
The crawler (Phase 4) will expand this to multi-page scanning.

Design decisions:
- Orchestrator never imports checks directly; it accepts a check registry.
  This keeps it decoupled and testable.
- Each check exception is caught and recorded as a scan error, not a crash.
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
from zelythion.errors import ZelythionError
from zelythion.http_client import BoundedHttpClient, HttpResponse
from zelythion.models import ScanResult, ScanStats
from zelythion.scope import ScopeValidator

logger = logging.getLogger(__name__)

# Default registry — all checks enabled in passive profile.
DEFAULT_CHECKS: list[BaseCheck] = ALL_HEADER_CHECKS + ALL_COOKIE_CHECKS


class ScanOrchestrator:
    """
    Coordinates a single scan run.

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
            "Only the initial target URL is scanned in Phase 1; multi-page crawling is Phase 4.",
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

        total_requests = 0
        findings = []
        checks_executed = 0
        checks_skipped = 0
        response: Optional[HttpResponse] = None

        with BoundedHttpClient(config=self._config, scope=scope) as client:
            # --- Fetch target ---
            try:
                if time.monotonic() > deadline:
                    return self._timeout_result(started_at, errors, limitations)

                logger.info("Fetching target: %s", target)
                response = client.get(target)
                total_requests = client.request_count
                logger.info(
                    "Response: HTTP %s (%d bytes, %.0fms)",
                    response.status_code,
                    len(response.body),
                    response.elapsed_ms,
                )
            except ZelythionError as exc:
                errors.append(f"Failed to fetch target: {exc}")
                logger.error("Failed to fetch %s: %s", target, exc)

            # --- Run checks ---
            if response is not None:
                for check in self._checks:
                    if time.monotonic() > deadline:
                        errors.append(
                            f"Scan deadline reached; {len(self._checks) - checks_executed} "
                            "checks were not executed."
                        )
                        break

                    try:
                        check_findings = check.run(response)
                        findings.extend(check_findings)
                        checks_executed += 1
                        if check_findings:
                            logger.debug(
                                "Check %s produced %d finding(s)", check.check_id, len(check_findings)
                            )
                    except Exception as exc:
                        checks_skipped += 1
                        err_msg = f"Check {check.check_id} raised an unexpected error: {exc}"
                        errors.append(err_msg)
                        logger.exception(err_msg)

        completed_at = datetime.now(tz=timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        return ScanResult(
            scanner_version=__version__,
            target=target,
            scan_profile=self._config.profile.value,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            errors=errors,
            coverage_limitations=limitations,
            stats=ScanStats(
                total_requests=total_requests,
                pages_discovered=1 if response is not None else 0,
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
