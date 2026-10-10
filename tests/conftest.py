"""
Shared test fixtures and configuration for Zelythion tests.
"""

from __future__ import annotations

import pytest

from zelythion.config import ScanConfig, ScanProfile, OutputFormat
from zelythion.scope import ScopeValidator, ScopeSpec
from zelythion.models import (
    Evidence,
    Finding,
    Confidence,
    Severity,
    DetectionMethod,
    FindingStatus,
    OWASPMapping,
    HttpEvidence,
)
from zelythion import __version__


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_config() -> ScanConfig:
    """Default scan config targeting a safe public test URL."""
    return ScanConfig(target="https://example.com")


@pytest.fixture()
def active_config() -> ScanConfig:
    """Active scan config for authorized testing."""
    return ScanConfig(
        target="https://example.com",
        profile=ScanProfile.active,
        timeout=15.0,
    )


# ---------------------------------------------------------------------------
# Scope fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def scope_validator() -> ScopeValidator:
    return ScopeValidator()


@pytest.fixture()
def example_scope() -> ScopeSpec:
    return ScopeSpec(allowed_hosts=frozenset({"example.com"}))


# ---------------------------------------------------------------------------
# Finding fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def minimal_evidence() -> Evidence:
    return Evidence(
        summary="Test evidence summary.",
        observed_value="missing",
        expected_value="present",
    )


@pytest.fixture()
def http_evidence() -> HttpEvidence:
    return HttpEvidence(
        url="https://example.com/",
        method="GET",
        status_code=200,
        response_headers={"content-type": "text/html"},
        response_time_ms=123.4,
    )


@pytest.fixture()
def sample_finding(minimal_evidence: Evidence) -> Finding:
    return Finding(
        check_id="HDR-001",
        title="Missing Content-Security-Policy header",
        description=(
            "The response does not include a Content-Security-Policy header. "
            "Without CSP, browsers cannot enforce restrictions on resource loading, "
            "which increases the risk of cross-site scripting (XSS) exploitation."
        ),
        severity=Severity.medium,
        confidence=Confidence.confirmed,
        detection_method=DetectionMethod.passive_header,
        affected_url="https://example.com/",
        affected_component="Content-Security-Policy",
        evidence=minimal_evidence,
        remediation=(
            "Add a Content-Security-Policy header to all HTTP responses. "
            "Start with a strict policy and relax as needed. "
            "Use 'Content-Security-Policy-Report-Only' to test without enforcement."
        ),
        references=[
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://csp.withgoogle.com/docs/strict-csp.html",
        ],
        owasp=OWASPMapping(
            edition="2025",
            category_id="A02",
            category_name="Security Misconfiguration",
        ),
        cwe_ids=[693, 1021],
        scanner_version=__version__,
    )
