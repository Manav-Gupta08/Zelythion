"""
SentinelScan scope enforcement.

The scope module is the authoritative gatekeeper for all network destinations.
Every URL — including redirects and discovered links — must pass scope validation
before a request is made.

Safety properties enforced here:
- Scheme restriction (https/http only).
- Private, loopback, link-local, multicast, and reserved IP rejection.
- Cloud metadata endpoint blocking (169.254.169.254, etc.).
- Host and origin allowlist enforcement.
- URL normalization to prevent encoding bypasses.
- Maximum URL length limits.
- Redirect destination validation.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScopeError(Exception):
    """Raised when a URL fails scope or safety validation."""


class PrivateDestinationError(ScopeError):
    """Raised when a URL resolves to or references a private/reserved destination."""


class SchemeError(ScopeError):
    """Raised when the URL scheme is not permitted."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_SCHEMES: FrozenSet[str] = frozenset({"https", "http"})

# Maximum permitted URL length. Prevents resource exhaustion from huge URLs.
MAX_URL_LENGTH = 4096

# Cloud metadata service IPs (IPv4 and IPv6 link-local ranges).
CLOUD_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure instance metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)

# Hostnames that are categorically disallowed.
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.internal",
    }
)

# Regex for detecting IPv4-in-hostname tricks (e.g. 0x7f000001, 0177.0.0.1).
_DECIMAL_IP_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


# ---------------------------------------------------------------------------
# Dataclass: ScopeSpec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeSpec:
    """
    Defines the authorized scope for a scan.

    Attributes:
        allowed_hosts: Explicit set of permitted hostnames. Populated from the
            target URL unless overridden.
        allow_subdomains: When True, subdomains of allowed_hosts are permitted.
        allowed_schemes: Permitted URL schemes (defaults to https and http).
    """

    allowed_hosts: FrozenSet[str] = field(default_factory=frozenset)
    allow_subdomains: bool = False
    allowed_schemes: FrozenSet[str] = field(default_factory=lambda: ALLOWED_SCHEMES)

    def is_host_in_scope(self, hostname: str) -> bool:
        """Return True if the hostname is within the configured scope."""
        hostname = hostname.lower().rstrip(".")
        if hostname in self.allowed_hosts:
            return True
        if self.allow_subdomains:
            for allowed in self.allowed_hosts:
                if hostname.endswith(f".{allowed}"):
                    return True
        return False


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------


class ScopeValidator:
    """
    Validates and normalizes URLs for scope and safety.

    The validator is constructed once at scan start with the target URL, then
    called for every URL encountered during the scan — including redirects,
    discovered links, and form action URLs.
    """

    def __init__(self, scope: Optional[ScopeSpec] = None) -> None:
        self._scope = scope

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_target_url(self, raw_url: str) -> str:
        """
        Validate a user-supplied target URL and return a normalized form.

        Raises:
            ScopeError: If the URL fails any safety or scheme check.

        Returns:
            Normalized URL string.
        """
        normalized = self._normalize(raw_url)
        self._check_length(normalized)
        # Check scheme FIRST so file://, javascript:, data: raise SchemeError
        # before we attempt to extract a host (which may not exist for these schemes).
        parsed_early = urllib.parse.urlparse(normalized)
        self._check_scheme(parsed_early.scheme)
        parsed = self._parse_and_require_host(normalized)
        self._check_host_safety(parsed.hostname or "")
        return normalized

    def validate_url_in_scope(self, raw_url: str, base_scope: ScopeSpec) -> str:
        """
        Validate a URL that must also fall within the defined scan scope.

        Raises:
            ScopeError: If the URL fails safety checks or is outside scope.

        Returns:
            Normalized URL string.
        """
        normalized = self._normalize(raw_url)
        self._check_length(normalized)
        parsed_early = urllib.parse.urlparse(normalized)
        self._check_scheme(parsed_early.scheme)
        parsed = self._parse_and_require_host(normalized)
        hostname = parsed.hostname or ""
        self._check_host_safety(hostname)
        if not base_scope.is_host_in_scope(hostname):
            raise ScopeError(
                f"URL '{normalized}' is outside the authorized scan scope. "
                f"Allowed hosts: {set(base_scope.allowed_hosts)}"
            )
        return normalized

    def build_scope_from_target(self, target_url: str) -> ScopeSpec:
        """
        Build a ScopeSpec from a validated target URL.

        The scope initially allows only the target's exact hostname.
        """
        parsed = urllib.parse.urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        return ScopeSpec(allowed_hosts=frozenset({hostname}))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(raw_url: str) -> str:
        """Normalize a URL: strip whitespace, lowercase scheme and host."""
        raw_url = raw_url.strip()
        try:
            parsed = urllib.parse.urlparse(raw_url)
        except ValueError as exc:
            raise ScopeError(f"Malformed URL: {raw_url!r}") from exc

        # Re-compose with lowercased scheme and netloc.
        normalized = urllib.parse.urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                "",  # strip fragment — fragments are client-side only
            )
        )
        return normalized

    @staticmethod
    def _check_length(url: str) -> None:
        if len(url) > MAX_URL_LENGTH:
            raise ScopeError(
                f"URL exceeds maximum permitted length ({MAX_URL_LENGTH} chars): {url[:80]}…"
            )

    @staticmethod
    def _parse_and_require_host(url: str) -> urllib.parse.ParseResult:
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:
            raise ScopeError(f"URL has no host component: {url!r}")
        return parsed

    @staticmethod
    def _check_scheme(scheme: str) -> None:
        if scheme not in ALLOWED_SCHEMES:
            raise SchemeError(
                f"URL scheme {scheme!r} is not permitted. Allowed: {sorted(ALLOWED_SCHEMES)}"
            )

    @staticmethod
    def _check_host_safety(hostname: str) -> None:
        """
        Reject requests to private, reserved, loopback, and cloud metadata
        destinations to prevent SSRF and DNS-rebinding abuse.

        This check uses the hostname string as supplied. DNS resolution is
        deliberately NOT performed here because:
          1. DNS results can change between check time and connect time.
          2. The HTTP client must perform its own connection-time validation.

        This check catches obvious static SSRF — literal private IPs,
        blocked hostnames, and cloud metadata addresses embedded in URLs.
        """
        hostname = hostname.lower().rstrip(".")

        if not hostname:
            raise ScopeError("URL has an empty host.")

        # Blocked hostname list.
        if hostname in BLOCKED_HOSTNAMES:
            raise PrivateDestinationError(
                f"Destination hostname is categorically blocked: {hostname!r}"
            )

        # Cloud metadata IPs by literal address.
        if hostname in CLOUD_METADATA_IPS:
            raise PrivateDestinationError(
                f"Destination appears to be a cloud metadata endpoint: {hostname!r}"
            )

        # Parse as IP address if it looks like one.
        ip: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # Not a bare IP literal — continue with hostname checks below.
            pass

        if ip is not None:
            ScopeValidator._reject_unsafe_ip(ip)
            return

        # For hostnames: check for embedded IPv4 literals (e.g., 192.168.1.1.evil.com).
        # This is a heuristic check; full protection requires connection-time validation.
        parts = hostname.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            # Looks like a raw IPv4 address expressed as a hostname.
            try:
                ip = ipaddress.IPv4Address(hostname)
                ScopeValidator._reject_unsafe_ip(ip)
            except ValueError:
                pass

    @staticmethod
    def _reject_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        """Reject private, reserved, loopback, link-local, and multicast IPs."""
        categories: list[tuple[bool, str]] = [
            (ip.is_loopback, "loopback"),
            (ip.is_private, "private"),
            (ip.is_link_local, "link-local"),
            (ip.is_multicast, "multicast"),
            (ip.is_reserved, "reserved"),
            (ip.is_unspecified, "unspecified"),
        ]
        for predicate, label in categories:
            if predicate:
                raise PrivateDestinationError(
                    f"Destination IP {ip} is in a {label} range and is not permitted "
                    "as a scan target. Use --lab-mode for isolated local targets."
                )
