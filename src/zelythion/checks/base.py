"""
Zelythion base check interface.

Every security check is a callable that accepts an HttpResponse (and
optionally config) and returns a list of Finding objects.

Design rules for checks:
- A check MUST NOT make network requests directly — the HTTP client does that.
- A check receives pre-fetched response data and returns findings.
- A check MUST return an empty list (not raise) when nothing is detected.
- Severity and confidence must reflect actual evidence, not worst-case impact.
- Every finding must include an Evidence object with at least a summary.
- Check IDs must match the pattern [A-Z]{2,6}-[0-9]{3,5} and be stable.
- Checks must document their false-positive conditions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zelythion.http_client import HttpResponse
    from zelythion.models import Finding


class BaseCheck(ABC):
    """Abstract base class for all Zelythion security checks."""

    #: Stable check ID, e.g. "HDR-001". Must not change between releases.
    check_id: str

    #: Human-readable name shown in the checks list and reports.
    name: str

    #: One-line description of what this check detects.
    description: str

    @abstractmethod
    def run(self, response: "HttpResponse") -> list["Finding"]:
        """
        Execute this check against the given HTTP response.

        Args:
            response: Pre-fetched, sanitized HTTP response to inspect.

        Returns:
            List of Finding objects. Empty list means nothing detected.
            Must never raise — catch and log exceptions internally.
        """
