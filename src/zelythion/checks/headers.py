"""
Security header checks — OWASP A02:2025 Security Misconfiguration.

Checks implemented:
  HDR-001  Missing Content-Security-Policy
  HDR-002  Missing X-Content-Type-Options
  HDR-003  Missing X-Frame-Options (or equivalent CSP frame-ancestors)
  HDR-004  Missing Strict-Transport-Security (HSTS)
  HDR-005  Missing Referrer-Policy
  HDR-006  Missing Permissions-Policy
  HDR-007  Server header version disclosure

Coverage notes:
- All checks are PASSIVE — they inspect response headers only.
- Checks only fire on HTML responses (200 status) where relevant.
  A 404 page missing CSP is significantly lower priority.
- HSTS check only fires on HTTPS responses; flagging it on HTTP would
  be misleading (HTTP cannot serve HSTS).
- Severity is assigned conservatively. A missing header is not a
  confirmed exploit — it is a defence-in-depth gap.
- HDR-001 through HDR-006: Confidence is CONFIRMED because the absence
  of a header is an objective, unambiguous observation.
- HDR-007: Confidence is TENTATIVE — the Server header content is
  information disclosure but not directly exploitable.

False-positive conditions:
- HDR-004: Will not fire if the target is HTTP (HSTS requires HTTPS).
- HDR-003: Will not fire if CSP header contains 'frame-ancestors'.
- All: Intermediate proxies may add headers not present at origin;
  results reflect what the scanner observed, not necessarily origin config.

References:
  https://owasp.org/www-project-secure-headers/
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
  https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
"""

from __future__ import annotations

import logging
import re

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

_OWASP_A04 = OWASPMapping(
    edition="2025",
    category_id="A04",
    category_name="Cryptographic Failures",
)


def _http_evidence(response: HttpResponse) -> HttpEvidence:
    return HttpEvidence(
        url=response.url,
        method="GET",
        status_code=response.status_code,
        response_headers=dict(response.headers),
        response_time_ms=response.elapsed_ms,
    )


def _is_html_200(response: HttpResponse) -> bool:
    return response.status_code == 200 and response.is_html()


# ---------------------------------------------------------------------------
# HDR-001 — Missing Content-Security-Policy
# ---------------------------------------------------------------------------


class MissingCSPCheck(BaseCheck):
    check_id = "HDR-001"
    name = "Missing Content-Security-Policy"
    description = (
        "Checks whether the response includes a Content-Security-Policy header. "
        "Without CSP, browsers apply no restrictions on resource origins, "
        "increasing XSS exploitability."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        if not _is_html_200(response):
            return []

        csp = response.header("content-security-policy")
        if csp is not None:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Missing Content-Security-Policy header",
                description=(
                    "The response does not include a Content-Security-Policy (CSP) header. "
                    "CSP is a browser security mechanism that helps mitigate cross-site scripting "
                    "(XSS) attacks by allowing the server to declare which content sources "
                    "browsers should consider legitimate. Without a CSP, browsers impose no "
                    "restrictions on resource loading, making XSS exploits more impactful."
                ),
                severity=Severity.medium,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="Content-Security-Policy",
                owasp=_OWASP_A02,
                cwe_ids=[693, 1021],
                evidence=Evidence(
                    summary="Content-Security-Policy header is absent from the response.",
                    http=_http_evidence(response),
                    observed_value="(header absent)",
                    expected_value="Content-Security-Policy: default-src 'self'; ...",
                ),
                remediation=(
                    "Add a Content-Security-Policy header to all HTML responses. "
                    "Start with a strict policy: "
                    "  Content-Security-Policy: default-src 'self'\n"
                    "Use 'Content-Security-Policy-Report-Only' to test without enforcement first. "
                    "Avoid 'unsafe-inline' and 'unsafe-eval' in production policies."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://csp.withgoogle.com/docs/strict-csp.html",
                    "https://owasp.org/www-project-secure-headers/#content-security-policy",
                ],
                false_positive_notes=(
                    "This check may fire on pages served through CDNs or reverse proxies "
                    "that strip headers. Verify at the origin server."
                ),
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-002 — Missing X-Content-Type-Options
# ---------------------------------------------------------------------------


class MissingXContentTypeOptionsCheck(BaseCheck):
    check_id = "HDR-002"
    name = "Missing X-Content-Type-Options"
    description = (
        "Checks whether the response includes 'X-Content-Type-Options: nosniff'. "
        "Without it, browsers may MIME-sniff responses and execute uploaded files "
        "as scripts."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        if response.status_code not in (200, 201):
            return []

        value = response.header("x-content-type-options")
        if value is not None and "nosniff" in value.lower():
            return []

        observed = value if value is not None else "(header absent)"
        return [
            Finding(
                check_id=self.check_id,
                title="Missing or incorrect X-Content-Type-Options header",
                description=(
                    "The response is missing 'X-Content-Type-Options: nosniff' or the header "
                    "is present with an incorrect value. Without this header, browsers may "
                    "MIME-sniff the response and treat a file uploaded as text/plain as "
                    "text/html, enabling script injection via file upload features."
                ),
                severity=Severity.low,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="X-Content-Type-Options",
                owasp=_OWASP_A02,
                cwe_ids=[693],
                evidence=Evidence(
                    summary="X-Content-Type-Options: nosniff is absent or incorrectly set.",
                    http=_http_evidence(response),
                    observed_value=observed,
                    expected_value="X-Content-Type-Options: nosniff",
                ),
                remediation=(
                    "Add the following header to all responses:\n"
                    "  X-Content-Type-Options: nosniff\n"
                    "This is a one-line change in most web server and framework configurations."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    "https://owasp.org/www-project-secure-headers/#x-content-type-options",
                ],
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-003 — Missing X-Frame-Options
# ---------------------------------------------------------------------------


class MissingXFrameOptionsCheck(BaseCheck):
    check_id = "HDR-003"
    name = "Missing X-Frame-Options"
    description = (
        "Checks whether the response includes X-Frame-Options or a CSP frame-ancestors "
        "directive to prevent clickjacking."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        if not _is_html_200(response):
            return []

        # X-Frame-Options OR CSP frame-ancestors both satisfy this control.
        xfo = response.header("x-frame-options")
        csp = response.header("content-security-policy") or ""

        if xfo is not None:
            return []
        if "frame-ancestors" in csp.lower():
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                description=(
                    "The response does not include X-Frame-Options or a CSP frame-ancestors "
                    "directive. Without these controls, the page can be embedded in an iframe "
                    "on an attacker-controlled site to perform clickjacking attacks, where "
                    "users are tricked into clicking UI elements they cannot see."
                ),
                severity=Severity.medium,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="X-Frame-Options",
                owasp=_OWASP_A02,
                cwe_ids=[1021],
                evidence=Evidence(
                    summary="X-Frame-Options absent and CSP has no frame-ancestors directive.",
                    http=_http_evidence(response),
                    observed_value="(X-Frame-Options absent, no frame-ancestors in CSP)",
                    expected_value="X-Frame-Options: DENY  or  CSP: frame-ancestors 'none'",
                ),
                remediation=(
                    "Add one of the following to all HTML responses:\n"
                    "  X-Frame-Options: DENY\n"
                    "  X-Frame-Options: SAMEORIGIN\n"
                    "Or use the modern CSP equivalent:\n"
                    "  Content-Security-Policy: frame-ancestors 'none'\n"
                    "Prefer the CSP approach for new deployments."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                ],
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-004 — Missing Strict-Transport-Security (HSTS)
# ---------------------------------------------------------------------------


class MissingHSTSCheck(BaseCheck):
    check_id = "HDR-004"
    name = "Missing Strict-Transport-Security (HSTS)"
    description = (
        "Checks whether HTTPS responses include a Strict-Transport-Security header "
        "to prevent protocol downgrade attacks."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        # HSTS only applies to HTTPS — do not flag on HTTP responses.
        if not response.url.startswith("https://"):
            return []
        if not _is_html_200(response):
            return []

        hsts = response.header("strict-transport-security")
        if hsts is not None:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Missing Strict-Transport-Security (HSTS) header",
                description=(
                    "The HTTPS response does not include a Strict-Transport-Security (HSTS) "
                    "header. Without HSTS, browsers will not automatically upgrade future "
                    "requests to HTTPS, leaving users vulnerable to SSL stripping and "
                    "protocol downgrade attacks on subsequent visits."
                ),
                severity=Severity.medium,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="Strict-Transport-Security",
                owasp=_OWASP_A04,
                cwe_ids=[319, 523],
                evidence=Evidence(
                    summary="Strict-Transport-Security header is absent from the HTTPS response.",
                    http=_http_evidence(response),
                    observed_value="(header absent)",
                    expected_value="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                ),
                remediation=(
                    "Add the Strict-Transport-Security header to all HTTPS responses:\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "Consider adding 'preload' and submitting to the HSTS preload list "
                    "at https://hstspreload.org for maximum protection."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    "https://hstspreload.org",
                ],
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-005 — Missing Referrer-Policy
# ---------------------------------------------------------------------------


class MissingReferrerPolicyCheck(BaseCheck):
    check_id = "HDR-005"
    name = "Missing Referrer-Policy"
    description = (
        "Checks whether the response includes a Referrer-Policy header to control "
        "how much referrer information is included with requests."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        if not _is_html_200(response):
            return []

        rp = response.header("referrer-policy")
        if rp is not None:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Missing Referrer-Policy header",
                description=(
                    "The response does not include a Referrer-Policy header. Without it, "
                    "browsers use their default referrer policy (typically 'strict-origin-when-"
                    "cross-origin' in modern browsers, but older browsers may send full URLs). "
                    "This can expose sensitive URL parameters (session tokens, user IDs) in "
                    "the Referer header when users navigate to external sites."
                ),
                severity=Severity.low,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="Referrer-Policy",
                owasp=_OWASP_A02,
                cwe_ids=[116],
                evidence=Evidence(
                    summary="Referrer-Policy header is absent from the response.",
                    http=_http_evidence(response),
                    observed_value="(header absent)",
                    expected_value="Referrer-Policy: strict-origin-when-cross-origin",
                ),
                remediation=(
                    "Add a Referrer-Policy header to HTML responses:\n"
                    "  Referrer-Policy: strict-origin-when-cross-origin\n"
                    "Use 'no-referrer' for sensitive pages such as login or account pages."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    "https://owasp.org/www-project-secure-headers/#referrer-policy",
                ],
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-006 — Missing Permissions-Policy
# ---------------------------------------------------------------------------


class MissingPermissionsPolicyCheck(BaseCheck):
    check_id = "HDR-006"
    name = "Missing Permissions-Policy"
    description = (
        "Checks whether the response includes a Permissions-Policy header to control "
        "access to browser features (camera, microphone, geolocation, etc.)."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        if not _is_html_200(response):
            return []

        pp = response.header("permissions-policy")
        # Also accept legacy Feature-Policy header.
        fp = response.header("feature-policy")
        if pp is not None or fp is not None:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Missing Permissions-Policy header",
                description=(
                    "The response does not include a Permissions-Policy (formerly Feature-Policy) "
                    "header. Without it, embedded third-party scripts or iframes may access "
                    "browser features such as the camera, microphone, and geolocation without "
                    "explicit permission. This is a defence-in-depth gap rather than an "
                    "immediately exploitable vulnerability."
                ),
                severity=Severity.info,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="Permissions-Policy",
                owasp=_OWASP_A02,
                cwe_ids=[693],
                evidence=Evidence(
                    summary="Permissions-Policy header is absent from the response.",
                    http=_http_evidence(response),
                    observed_value="(header absent)",
                    expected_value="Permissions-Policy: camera=(), microphone=(), geolocation=()",
                ),
                remediation=(
                    "Add a Permissions-Policy header to restrict feature access:\n"
                    "  Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
                    "Adjust the policy to allow only the features your application requires."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    "https://owasp.org/www-project-secure-headers/#permissions-policy",
                ],
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# HDR-007 — Server header version disclosure
# ---------------------------------------------------------------------------

# Version-number patterns commonly found in Server headers.
_VERSION_PATTERN = re.compile(
    r"(apache|nginx|iis|lighttpd|gunicorn|caddy|openresty)[/\s][\d.]+",
    re.IGNORECASE,
)


class ServerVersionDisclosureCheck(BaseCheck):
    check_id = "HDR-007"
    name = "Server version disclosure via Server header"
    description = (
        "Checks whether the Server response header discloses software name and version, "
        "which aids targeted vulnerability research by attackers."
    )

    def run(self, response: HttpResponse) -> list[Finding]:
        server = response.header("server")
        if not server:
            return []

        match = _VERSION_PATTERN.search(server)
        if not match:
            # Server header present but no recognizable version — informational only.
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Server software version disclosed in response header",
                description=(
                    f"The Server header discloses the web server software and version: "
                    f"'{server}'. Attackers can use this information to identify known "
                    "vulnerabilities for the specific version and prioritize exploitation."
                ),
                severity=Severity.info,
                confidence=Confidence.confirmed,
                detection_method=DetectionMethod.passive_header,
                affected_url=response.url,
                affected_component="Server",
                owasp=_OWASP_A02,
                cwe_ids=[200],
                evidence=Evidence(
                    summary=f"Server header reveals software version: '{server}'.",
                    http=_http_evidence(response),
                    observed_value=server,
                    expected_value="Server: (no version information)",
                ),
                remediation=(
                    "Configure your web server to suppress or genericise the Server header.\n"
                    "Apache: ServerTokens Prod\n"
                    "Nginx:  server_tokens off;\n"
                    "IIS:    Remove-WebConfigurationProperty system.webServer/security/requestFiltering -name allowDoubleEscaping"
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    "https://owasp.org/www-project-secure-headers/#server",
                ],
                false_positive_notes=(
                    "This check fires whenever a version number is detected in the Server header. "
                    "Some organisations intentionally expose this in staging environments."
                ),
                scanner_version=__version__,
            )
        ]


# ---------------------------------------------------------------------------
# Registry — all header checks exported
# ---------------------------------------------------------------------------

ALL_HEADER_CHECKS: list[BaseCheck] = [
    MissingCSPCheck(),
    MissingXContentTypeOptionsCheck(),
    MissingXFrameOptionsCheck(),
    MissingHSTSCheck(),
    MissingReferrerPolicyCheck(),
    MissingPermissionsPolicyCheck(),
    ServerVersionDisclosureCheck(),
]
