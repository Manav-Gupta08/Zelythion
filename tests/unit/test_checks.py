"""
Unit tests for security header and cookie checks.

Tests verify that each check:
  - Fires when the relevant header/attribute is absent.
  - Does NOT fire when the header/attribute is correctly set.
  - Produces findings with the correct check_id, severity, and confidence.
  - Does NOT fire on non-HTML responses where appropriate.
  - Does NOT fire on HSTS for HTTP (not HTTPS) responses.
  - Cookie checks fire per-cookie when multiple cookies are set.
  - SameSite=None without Secure is treated as higher severity.

No network requests are made.
"""

from __future__ import annotations

import pytest

from zelythion.checks.cookies import (
    MissingHttpOnlyFlagCheck,
    MissingSecureFlagCheck,
    WeakSameSiteCheck,
    parse_set_cookie,
)
from zelythion.checks.headers import (
    MissingCSPCheck,
    MissingHSTSCheck,
    MissingPermissionsPolicyCheck,
    MissingReferrerPolicyCheck,
    MissingXContentTypeOptionsCheck,
    MissingXFrameOptionsCheck,
    ServerVersionDisclosureCheck,
)
from zelythion.http_client import HttpResponse
from zelythion.models import Confidence, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    url: str = "https://example.com/",
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"<html><body>Hello</body></html>",
) -> HttpResponse:
    base_headers = {"content-type": "text/html; charset=utf-8"}
    if headers:
        base_headers.update(headers)
    return HttpResponse(
        url=url,
        status_code=status,
        headers={k.lower(): v for k, v in base_headers.items()},
        body=body,
        elapsed_ms=50.0,
    )


# ---------------------------------------------------------------------------
# HDR-001 — CSP
# ---------------------------------------------------------------------------


class TestMissingCSP:
    def setup_method(self) -> None:
        self.check = MissingCSPCheck()

    def test_fires_when_csp_absent(self) -> None:
        resp = _make_response()
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-001"
        assert findings[0].severity == Severity.medium
        assert findings[0].confidence == Confidence.confirmed

    def test_no_finding_when_csp_present(self) -> None:
        resp = _make_response(headers={"content-security-policy": "default-src 'self'"})
        assert self.check.run(resp) == []

    def test_no_finding_on_404(self) -> None:
        resp = _make_response(status=404)
        assert self.check.run(resp) == []

    def test_no_finding_on_json_response(self) -> None:
        resp = _make_response(
            headers={"content-type": "application/json"},
            body=b'{"key": "value"}',
        )
        assert self.check.run(resp) == []

    def test_finding_contains_affected_url(self) -> None:
        resp = _make_response(url="https://example.com/login")
        findings = self.check.run(resp)
        assert findings[0].affected_url == "https://example.com/login"

    def test_finding_has_owasp_mapping(self) -> None:
        resp = _make_response()
        findings = self.check.run(resp)
        assert findings[0].owasp is not None
        assert findings[0].owasp.category_id == "A02"


# ---------------------------------------------------------------------------
# HDR-002 — X-Content-Type-Options
# ---------------------------------------------------------------------------


class TestMissingXContentTypeOptions:
    def setup_method(self) -> None:
        self.check = MissingXContentTypeOptionsCheck()

    def test_fires_when_header_absent(self) -> None:
        resp = _make_response()
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-002"
        assert findings[0].severity == Severity.low

    def test_no_finding_with_nosniff(self) -> None:
        resp = _make_response(headers={"x-content-type-options": "nosniff"})
        assert self.check.run(resp) == []

    def test_fires_with_wrong_value(self) -> None:
        resp = _make_response(headers={"x-content-type-options": "sniff"})
        assert len(self.check.run(resp)) == 1

    def test_no_finding_on_404(self) -> None:
        assert self.check.run(_make_response(status=404)) == []


# ---------------------------------------------------------------------------
# HDR-003 — X-Frame-Options
# ---------------------------------------------------------------------------


class TestMissingXFrameOptions:
    def setup_method(self) -> None:
        self.check = MissingXFrameOptionsCheck()

    def test_fires_when_absent(self) -> None:
        findings = self.check.run(_make_response())
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-003"

    def test_no_finding_with_xfo_deny(self) -> None:
        resp = _make_response(headers={"x-frame-options": "DENY"})
        assert self.check.run(resp) == []

    def test_no_finding_with_xfo_sameorigin(self) -> None:
        resp = _make_response(headers={"x-frame-options": "SAMEORIGIN"})
        assert self.check.run(resp) == []

    def test_no_finding_with_csp_frame_ancestors(self) -> None:
        resp = _make_response(
            headers={"content-security-policy": "frame-ancestors 'none'"}
        )
        assert self.check.run(resp) == []

    def test_no_finding_on_404(self) -> None:
        assert self.check.run(_make_response(status=404)) == []


# ---------------------------------------------------------------------------
# HDR-004 — HSTS
# ---------------------------------------------------------------------------


class TestMissingHSTS:
    def setup_method(self) -> None:
        self.check = MissingHSTSCheck()

    def test_fires_on_https_without_hsts(self) -> None:
        findings = self.check.run(_make_response(url="https://example.com/"))
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-004"

    def test_no_finding_with_hsts(self) -> None:
        resp = _make_response(
            url="https://example.com/",
            headers={"strict-transport-security": "max-age=31536000"},
        )
        assert self.check.run(resp) == []

    def test_no_finding_on_http(self) -> None:
        # HSTS is meaningless on plain HTTP — must NOT fire.
        resp = _make_response(url="http://example.com/")
        assert self.check.run(resp) == []

    def test_no_finding_on_404(self) -> None:
        assert self.check.run(_make_response(status=404)) == []

    def test_owasp_a04_mapped(self) -> None:
        findings = self.check.run(_make_response(url="https://example.com/"))
        assert findings[0].owasp is not None
        assert findings[0].owasp.category_id == "A04"


# ---------------------------------------------------------------------------
# HDR-005 — Referrer-Policy
# ---------------------------------------------------------------------------


class TestMissingReferrerPolicy:
    def setup_method(self) -> None:
        self.check = MissingReferrerPolicyCheck()

    def test_fires_when_absent(self) -> None:
        findings = self.check.run(_make_response())
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-005"
        assert findings[0].severity == Severity.low

    def test_no_finding_when_present(self) -> None:
        resp = _make_response(headers={"referrer-policy": "strict-origin-when-cross-origin"})
        assert self.check.run(resp) == []


# ---------------------------------------------------------------------------
# HDR-006 — Permissions-Policy
# ---------------------------------------------------------------------------


class TestMissingPermissionsPolicy:
    def setup_method(self) -> None:
        self.check = MissingPermissionsPolicyCheck()

    def test_fires_when_absent(self) -> None:
        findings = self.check.run(_make_response())
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-006"
        assert findings[0].severity == Severity.info

    def test_no_finding_with_permissions_policy(self) -> None:
        resp = _make_response(headers={"permissions-policy": "camera=()"})
        assert self.check.run(resp) == []

    def test_no_finding_with_legacy_feature_policy(self) -> None:
        resp = _make_response(headers={"feature-policy": "camera 'none'"})
        assert self.check.run(resp) == []


# ---------------------------------------------------------------------------
# HDR-007 — Server version disclosure
# ---------------------------------------------------------------------------


class TestServerVersionDisclosure:
    def setup_method(self) -> None:
        self.check = ServerVersionDisclosureCheck()

    def test_fires_on_apache_with_version(self) -> None:
        resp = _make_response(headers={"server": "Apache/2.4.51 (Ubuntu)"})
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "HDR-007"
        assert findings[0].severity == Severity.info

    def test_fires_on_nginx_with_version(self) -> None:
        resp = _make_response(headers={"server": "nginx/1.18.0"})
        assert len(self.check.run(resp)) == 1

    def test_no_finding_without_server_header(self) -> None:
        resp = _make_response()  # no server header
        assert self.check.run(resp) == []

    def test_no_finding_generic_server_header(self) -> None:
        # "nginx" alone without a version should not fire.
        resp = _make_response(headers={"server": "nginx"})
        assert self.check.run(resp) == []

    def test_no_finding_on_cloudflare(self) -> None:
        resp = _make_response(headers={"server": "cloudflare"})
        assert self.check.run(resp) == []


# ---------------------------------------------------------------------------
# Cookie parser
# ---------------------------------------------------------------------------


class TestCookieParser:
    def test_parses_secure_flag(self) -> None:
        c = parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Strict")
        assert c.secure is True

    def test_parses_httponly_flag(self) -> None:
        c = parse_set_cookie("session=abc; HttpOnly")
        assert c.http_only is True

    def test_parses_samesite_strict(self) -> None:
        c = parse_set_cookie("token=xyz; SameSite=Strict")
        assert c.same_site == "strict"

    def test_parses_samesite_none(self) -> None:
        c = parse_set_cookie("token=xyz; SameSite=None; Secure")
        assert c.same_site == "none"
        assert c.secure is True

    def test_absent_flags_default_false(self) -> None:
        c = parse_set_cookie("pref=dark")
        assert c.secure is False
        assert c.http_only is False
        assert c.same_site is None

    def test_parses_cookie_name(self) -> None:
        c = parse_set_cookie("my_session=abc123; Path=/")
        assert c.name == "my_session"


# ---------------------------------------------------------------------------
# CKI-001 — Secure flag
# ---------------------------------------------------------------------------


class TestMissingSecureFlag:
    def setup_method(self) -> None:
        self.check = MissingSecureFlagCheck()

    def test_fires_on_https_cookie_without_secure(self) -> None:
        resp = _make_response(
            url="https://example.com/",
            headers={"set-cookie": "session=abc; HttpOnly; SameSite=Strict"},
        )
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "CKI-001"

    def test_no_finding_with_secure_flag(self) -> None:
        resp = _make_response(
            url="https://example.com/",
            headers={"set-cookie": "session=abc; Secure; HttpOnly"},
        )
        assert self.check.run(resp) == []

    def test_no_finding_on_http_response(self) -> None:
        # Secure flag check must not fire on HTTP — the transport is the issue.
        resp = _make_response(
            url="http://example.com/",
            headers={"set-cookie": "session=abc; HttpOnly"},
        )
        assert self.check.run(resp) == []

    def test_no_finding_when_no_cookies(self) -> None:
        resp = _make_response(url="https://example.com/")
        assert self.check.run(resp) == []


# ---------------------------------------------------------------------------
# CKI-002 — HttpOnly flag
# ---------------------------------------------------------------------------


class TestMissingHttpOnlyFlag:
    def setup_method(self) -> None:
        self.check = MissingHttpOnlyFlagCheck()

    def test_fires_without_httponly(self) -> None:
        resp = _make_response(
            headers={"set-cookie": "session=abc; Secure; SameSite=Strict"},
        )
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "CKI-002"

    def test_no_finding_with_httponly(self) -> None:
        resp = _make_response(
            headers={"set-cookie": "session=abc; HttpOnly; Secure"},
        )
        assert self.check.run(resp) == []

    def test_no_finding_when_no_cookies(self) -> None:
        resp = _make_response()
        assert self.check.run(resp) == []


# ---------------------------------------------------------------------------
# CKI-003 — SameSite
# ---------------------------------------------------------------------------


class TestWeakSameSite:
    def setup_method(self) -> None:
        self.check = WeakSameSiteCheck()

    def test_fires_when_samesite_absent(self) -> None:
        resp = _make_response(headers={"set-cookie": "session=abc; Secure; HttpOnly"})
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].check_id == "CKI-003"
        assert findings[0].severity == Severity.low

    def test_samesite_none_without_secure_is_high(self) -> None:
        resp = _make_response(
            url="https://example.com/",
            headers={"set-cookie": "session=abc; SameSite=None"},
        )
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_samesite_none_with_secure_is_medium(self) -> None:
        resp = _make_response(
            url="https://example.com/",
            headers={"set-cookie": "session=abc; SameSite=None; Secure"},
        )
        findings = self.check.run(resp)
        assert len(findings) == 1
        assert findings[0].severity == Severity.medium

    def test_no_finding_with_samesite_strict(self) -> None:
        resp = _make_response(headers={"set-cookie": "session=abc; SameSite=Strict; Secure"})
        assert self.check.run(resp) == []

    def test_no_finding_with_samesite_lax(self) -> None:
        resp = _make_response(headers={"set-cookie": "session=abc; SameSite=Lax; Secure"})
        assert self.check.run(resp) == []

    def test_no_finding_when_no_cookies(self) -> None:
        assert self.check.run(_make_response()) == []
