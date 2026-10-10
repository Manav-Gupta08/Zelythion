"""
Unit tests for SentinelScan scope enforcement.

These tests verify that the ScopeValidator correctly:
- Accepts valid public HTTPS targets.
- Rejects private, loopback, and reserved IP ranges.
- Rejects cloud metadata endpoints.
- Rejects blocked hostnames.
- Rejects disallowed URL schemes.
- Normalizes URLs consistently.
- Enforces scope boundaries for in-scan URL validation.
- Rejects URLs that are too long.

No network requests are made in these tests.
"""

from __future__ import annotations

import pytest

from sentinelscan.scope import (
    ScopeValidator,
    ScopeSpec,
    ScopeError,
    PrivateDestinationError,
    SchemeError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def validator() -> ScopeValidator:
    return ScopeValidator()


# ---------------------------------------------------------------------------
# Valid targets
# ---------------------------------------------------------------------------


class TestValidTargets:
    def test_https_target_accepted(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("https://example.com")
        assert url == "https://example.com"

    def test_http_target_accepted(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("http://example.com")
        assert url == "http://example.com"

    def test_https_with_path(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("https://example.com/path/to/resource")
        assert "example.com" in url

    def test_https_with_port(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("https://example.com:8443/")
        assert "8443" in url

    def test_scheme_normalised_to_lowercase(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("HTTPS://example.com")
        assert url.startswith("https://")

    def test_host_normalised_to_lowercase(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("https://EXAMPLE.COM")
        assert "example.com" in url.lower()

    def test_fragment_stripped(self, validator: ScopeValidator) -> None:
        url = validator.validate_target_url("https://example.com/page#section")
        assert "#" not in url


# ---------------------------------------------------------------------------
# Scheme rejection
# ---------------------------------------------------------------------------


class TestSchemeRejection:
    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<h1>test</h1>",
            "ssh://example.com",
            "ldap://example.com",
            "dict://example.com",
            "gopher://example.com",
        ],
    )
    def test_disallowed_scheme_rejected(self, validator: ScopeValidator, bad_url: str) -> None:
        with pytest.raises(SchemeError):
            validator.validate_target_url(bad_url)


# ---------------------------------------------------------------------------
# Loopback rejection
# ---------------------------------------------------------------------------


class TestLoopbackRejection:
    @pytest.mark.parametrize(
        "loopback_url",
        [
            "https://127.0.0.1",
            "https://127.0.0.1:8080",
            "https://127.1.1.1",
            "https://[::1]",
            "https://localhost",
        ],
    )
    def test_loopback_rejected(self, validator: ScopeValidator, loopback_url: str) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url(loopback_url)


# ---------------------------------------------------------------------------
# Private IP rejection
# ---------------------------------------------------------------------------


class TestPrivateIPRejection:
    @pytest.mark.parametrize(
        "private_url",
        [
            "https://10.0.0.1",
            "https://10.255.255.255",
            "https://172.16.0.1",
            "https://172.31.255.255",
            "https://192.168.0.1",
            "https://192.168.100.200",
            "https://[fc00::1]",
            "https://[fd00::1]",
        ],
    )
    def test_private_ip_rejected(self, validator: ScopeValidator, private_url: str) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url(private_url)


# ---------------------------------------------------------------------------
# Link-local and reserved rejection
# ---------------------------------------------------------------------------


class TestLinkLocalRejection:
    @pytest.mark.parametrize(
        "link_local_url",
        [
            "https://169.254.0.1",
            "https://169.254.169.254",  # AWS / GCP metadata
            "https://[fe80::1]",
        ],
    )
    def test_link_local_rejected(self, validator: ScopeValidator, link_local_url: str) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url(link_local_url)


# ---------------------------------------------------------------------------
# Cloud metadata rejection
# ---------------------------------------------------------------------------


class TestCloudMetadataRejection:
    def test_aws_metadata_ip_rejected(self, validator: ScopeValidator) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url("https://169.254.169.254")

    def test_gcp_metadata_hostname_rejected(self, validator: ScopeValidator) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url("https://metadata.google.internal")

    def test_alibaba_metadata_rejected(self, validator: ScopeValidator) -> None:
        with pytest.raises(PrivateDestinationError):
            validator.validate_target_url("https://100.100.100.200")


# ---------------------------------------------------------------------------
# Malformed URL rejection
# ---------------------------------------------------------------------------


class TestMalformedURLs:
    def test_url_without_scheme_rejected(self, validator: ScopeValidator) -> None:
        with pytest.raises(ScopeError):
            validator.validate_target_url("example.com")

    def test_url_without_host_rejected(self, validator: ScopeValidator) -> None:
        with pytest.raises(ScopeError):
            validator.validate_target_url("https://")

    def test_url_too_long_rejected(self, validator: ScopeValidator) -> None:
        long_url = "https://example.com/" + "a" * 4100
        with pytest.raises(ScopeError):
            validator.validate_target_url(long_url)


# ---------------------------------------------------------------------------
# Scope enforcement (in-scan URL validation)
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    def test_in_scope_url_accepted(self, validator: ScopeValidator) -> None:
        scope = ScopeSpec(allowed_hosts=frozenset({"example.com"}))
        result = validator.validate_url_in_scope("https://example.com/page", scope)
        assert "example.com" in result

    def test_out_of_scope_url_rejected(self, validator: ScopeValidator) -> None:
        scope = ScopeSpec(allowed_hosts=frozenset({"example.com"}))
        with pytest.raises(ScopeError):
            validator.validate_url_in_scope("https://evil.com/page", scope)

    def test_subdomain_rejected_without_flag(self, validator: ScopeValidator) -> None:
        scope = ScopeSpec(allowed_hosts=frozenset({"example.com"}), allow_subdomains=False)
        with pytest.raises(ScopeError):
            validator.validate_url_in_scope("https://sub.example.com/page", scope)

    def test_subdomain_accepted_with_flag(self, validator: ScopeValidator) -> None:
        scope = ScopeSpec(allowed_hosts=frozenset({"example.com"}), allow_subdomains=True)
        result = validator.validate_url_in_scope("https://sub.example.com/page", scope)
        assert "sub.example.com" in result

    def test_build_scope_from_target(self, validator: ScopeValidator) -> None:
        scope = validator.build_scope_from_target("https://example.com/path")
        assert "example.com" in scope.allowed_hosts

    def test_private_ip_rejected_even_in_scope(self, validator: ScopeValidator) -> None:
        """A private IP must be rejected even if it appears in the allowed_hosts set."""
        scope = ScopeSpec(allowed_hosts=frozenset({"192.168.1.1"}))
        with pytest.raises(PrivateDestinationError):
            validator.validate_url_in_scope("https://192.168.1.1/", scope)
