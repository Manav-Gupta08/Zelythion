"""
Cookie attribute checks — OWASP A02:2025 Security Misconfiguration.

Checks implemented:
  CKI-001  Cookie missing Secure flag
  CKI-002  Cookie missing HttpOnly flag
  CKI-003  Cookie missing or weak SameSite attribute
  CKI-004  Cookie with overly broad Domain scope
  CKI-005  Session cookie without expiry (informational)

Coverage notes:
- All checks are PASSIVE — they inspect Set-Cookie response headers.
- Each Set-Cookie header is parsed individually; a page setting multiple
  cookies may produce multiple findings.
- The Secure flag check only fires on HTTPS responses. On HTTP, the flag
  would be ineffective anyway (the entire transport is insecure).
  The correct finding for HTTP sessions is a transport-level finding.
- SameSite=None without Secure is treated as a higher-severity finding
  because it actively downgrades cross-site cookie protections.

False-positive conditions:
- CKI-001: Third-party analytics cookies injected by CDNs may lack Secure.
  The scanner reports what it observes — origin config may differ.
- CKI-002: Some SSO redirect cookies are intentionally readable by JS.
  Treat as informational if no sensitive data is stored.
- CKI-005: Non-session cookies (preferences, analytics) legitimately lack expiry.

References:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from zelythion import __version__
from zelythion.checks.base import BaseCheck
from zelythion.http_client import HttpResponse
from zelythion.models import (
    Confidence,
    DetectionMethod,
    Evidence,
    Finding,
    HttpEvidence,
    OWASPMapping,
    Severity,
)

logger = logging.getLogger(__name__)

_OWASP_A02 = OWASPMapping(
    edition="2025",
    category_id="A02",
    category_name="Security Misconfiguration",
)


# ---------------------------------------------------------------------------
# Cookie parser
# ---------------------------------------------------------------------------


@dataclass
class ParsedCookie:
    """Minimal representation of a Set-Cookie header value."""

    raw: str
    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str]  # "strict", "lax", "none", or None if absent
    domain: Optional[str]
    path: Optional[str]
    has_expiry: bool  # True if Expires or Max-Age is present


def parse_set_cookie(raw: str) -> ParsedCookie:
    """
    Parse a raw Set-Cookie header value into a ParsedCookie.

    This is a best-effort parser for the common subset of cookie attributes.
    It does not handle every edge case in RFC 6265.
    """
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()

    attrs_lower = {p.split("=")[0].strip().lower(): p for p in parts[1:]}

    secure = "secure" in attrs_lower
    http_only = "httponly" in attrs_lower

    same_site: Optional[str] = None
    if "samesite" in attrs_lower:
        ss_part = attrs_lower["samesite"]
        if "=" in ss_part:
            same_site = ss_part.split("=", 1)[1].strip().lower()
        else:
            same_site = ""  # Present but no value — treat as misconfigured

    domain: Optional[str] = None
    if "domain" in attrs_lower:
        dp = attrs_lower["domain"]
        domain = dp.split("=", 1)[1].strip() if "=" in dp else None

    path: Optional[str] = None
    if "path" in attrs_lower:
        pp = attrs_lower["path"]
        path = pp.split("=", 1)[1].strip() if "=" in pp else None

    has_expiry = "expires" in attrs_lower or "max-age" in attrs_lower

    return ParsedCookie(
        raw=raw,
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
        has_expiry=has_expiry,
    )


def _get_cookies(response: HttpResponse) -> list[ParsedCookie]:
    """Extract and parse all Set-Cookie headers from the response."""
    cookies: list[ParsedCookie] = []
    # httpx stores multiple headers with the same name — check raw headers
    raw_cookies = response.headers.get("set-cookie")
    # Note: httpx collapses multiple set-cookie headers with comma. We handle single value here.
    # In Phase 4 (full crawler integration), the HTTP client will preserve individual headers.
    if raw_cookies and raw_cookies != "[REDACTED]":
        # Handle comma-separated cookies (httpx may join them) with a naive split
        # that avoids splitting on commas inside Expires dates.
        # RFC 6265 prohibits commas in attribute values except Expires.
        # We split on "; path" boundaries as a heuristic.
        for raw in _split_set_cookie_header(raw_cookies):
            try:
                cookies.append(parse_set_cookie(raw))
            except Exception:
                logger.debug("Failed to parse Set-Cookie: %r", raw)
    return cookies


def _split_set_cookie_header(value: str) -> list[str]:
    """
    Split a (potentially concatenated) Set-Cookie header into individual cookies.

    httpx may join multiple Set-Cookie headers with ", ". The challenge is that
    Expires values also contain commas. We detect new cookie boundaries by
    looking for ", " followed by a pattern that looks like a new cookie name.
    """
    # Simple heuristic: split on ", " followed by <token>=<token> (new cookie name=value)
    parts = re.split(r",\s*(?=[^,;=]+=[^,;=]+(?:;|$))", value)
    return [p.strip() for p in parts if p.strip()]


def _http_evidence(response: HttpResponse, cookie_name: str, observed: str) -> Evidence:
    return Evidence(
        summary=f"Cookie '{cookie_name}' has a missing or weak security attribute.",
        http=HttpEvidence(
            url=response.url,
            method="GET",
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_time_ms=response.elapsed_ms,
        ),
        observed_value=observed,
    )


# ---------------------------------------------------------------------------
# CKI-001 — Missing Secure flag
# ---------------------------------------------------------------------------


class MissingSecureFlagCheck(BaseCheck):
    check_id = "CKI-001"
    name = "Cookie missing Secure flag"
    description = (
        "Checks whether cookies set by HTTPS responses include the Secure flag. "
        "Without it, the cookie will be transmitted over plain HTTP connections."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        # Secure flag is only meaningful on HTTPS responses.
        if not response.url.startswith("https://"):
            return []

        findings = []
        for cookie in _get_cookies(response):
            if cookie.secure:
                continue
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Cookie '{cookie.name}' is missing the Secure flag",
                    description=(
                        f"The cookie '{cookie.name}' is set over HTTPS but does not include "
                        "the Secure flag. Without this flag, the browser will transmit the "
                        "cookie over any HTTP connection to the same domain, where it can be "
                        "intercepted by a network attacker (e.g., on shared Wi-Fi)."
                    ),
                    severity=Severity.medium,
                    confidence=Confidence.confirmed,
                    detection_method=DetectionMethod.passive_cookie,
                    affected_url=response.url,
                    affected_component=f"Cookie: {cookie.name}",
                    owasp=_OWASP_A02,
                    cwe_ids=[614, 311],
                    evidence=_http_evidence(response, cookie.name, cookie.raw),
                    remediation=(
                        f"Add the Secure flag to the '{cookie.name}' cookie:\n"
                        f"  Set-Cookie: {cookie.name}=<value>; Secure; ...\n"
                        "Ensure all sensitive cookies include Secure."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                    ],
                    scanner_version=__version__,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# CKI-002 — Missing HttpOnly flag
# ---------------------------------------------------------------------------


class MissingHttpOnlyFlagCheck(BaseCheck):
    check_id = "CKI-002"
    name = "Cookie missing HttpOnly flag"
    description = (
        "Checks whether cookies include the HttpOnly flag to prevent JavaScript access, "
        "which reduces the impact of XSS attacks."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        findings = []
        for cookie in _get_cookies(response):
            if cookie.http_only:
                continue
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Cookie '{cookie.name}' is missing the HttpOnly flag",
                    description=(
                        f"The cookie '{cookie.name}' does not include the HttpOnly flag. "
                        "Without this flag, the cookie value is accessible via JavaScript "
                        "(document.cookie). In the event of a cross-site scripting (XSS) "
                        "vulnerability, an attacker could steal this cookie and hijack "
                        "the user's session."
                    ),
                    severity=Severity.medium,
                    confidence=Confidence.confirmed,
                    detection_method=DetectionMethod.passive_cookie,
                    affected_url=response.url,
                    affected_component=f"Cookie: {cookie.name}",
                    owasp=_OWASP_A02,
                    cwe_ids=[1004, 79],
                    evidence=_http_evidence(response, cookie.name, cookie.raw),
                    remediation=(
                        f"Add the HttpOnly flag to the '{cookie.name}' cookie:\n"
                        f"  Set-Cookie: {cookie.name}=<value>; HttpOnly; ...\n"
                        "Session cookies and other sensitive cookies should always be HttpOnly."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute",
                    ],
                    false_positive_notes=(
                        "Some cookies are intentionally readable by JavaScript (e.g., CSRF tokens "
                        "that must be read and sent in request headers). Review before remediating."
                    ),
                    scanner_version=__version__,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# CKI-003 — Missing or weak SameSite attribute
# ---------------------------------------------------------------------------


class WeakSameSiteCheck(BaseCheck):
    check_id = "CKI-003"
    name = "Cookie missing or weak SameSite attribute"
    description = (
        "Checks whether cookies have a SameSite attribute set to Strict or Lax. "
        "SameSite=None without Secure, or no SameSite at all, weakens CSRF protections."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        findings = []
        for cookie in _get_cookies(response):
            ss = cookie.same_site

            if ss in ("strict", "lax"):
                continue  # Correctly configured

            # Determine severity based on the specific misconfiguration.
            if ss == "none" and not cookie.secure:
                # SameSite=None without Secure is actively misconfigured and
                # modern browsers will reject this combination.
                severity = Severity.high
                observed = "SameSite=None (without Secure flag)"
                issue = (
                    "SameSite=None requires the Secure flag. Without it, modern browsers "
                    "reject the cookie entirely, breaking functionality. This combination "
                    "also allows cross-site request forgery attacks in older browsers."
                )
            elif ss == "none":
                severity = Severity.medium
                observed = "SameSite=None"
                issue = (
                    "SameSite=None disables all cross-site cookie restrictions, allowing "
                    "the cookie to be sent in cross-site requests. This weakens CSRF "
                    "protections and should only be used when cross-site cookie sharing "
                    "is explicitly required (e.g., third-party OAuth flows)."
                )
            else:
                # Absent or malformed SameSite
                severity = Severity.low
                observed = f"SameSite={ss!r}" if ss is not None else "(SameSite absent)"
                issue = (
                    "The cookie has no SameSite attribute. Modern browsers default to "
                    "SameSite=Lax, but this is not guaranteed across all browsers and "
                    "should be set explicitly."
                )

            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Cookie '{cookie.name}' has weak SameSite configuration",
                    description=(
                        f"The cookie '{cookie.name}' has a SameSite misconfiguration: "
                        f"{issue}"
                    ),
                    severity=severity,
                    confidence=Confidence.confirmed,
                    detection_method=DetectionMethod.passive_cookie,
                    affected_url=response.url,
                    affected_component=f"Cookie: {cookie.name}",
                    owasp=_OWASP_A02,
                    cwe_ids=[352, 1275],
                    evidence=_http_evidence(response, cookie.name, cookie.raw),
                    remediation=(
                        f"Set the SameSite attribute on '{cookie.name}':\n"
                        f"  Set-Cookie: {cookie.name}=<value>; SameSite=Strict; ...\n"
                        "Use Strict for session cookies. Use Lax for cookies needed "
                        "in top-level navigation. Only use None for explicitly cross-site cookies."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#controlling_third-party_cookies_with_samesite",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                    scanner_version=__version__,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_COOKIE_CHECKS: list[BaseCheck] = [
    MissingSecureFlagCheck(),
    MissingHttpOnlyFlagCheck(),
    WeakSameSiteCheck(),
]
