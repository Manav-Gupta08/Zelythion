"""
Zelythion finding and scan result models.

Findings are the primary output of the scanner. Every finding must carry
sufficient evidence for an operator to independently verify the issue,
appropriate context for remediation, and honest confidence metadata.

Design principles:
- Evidence before conclusions: a finding is not confirmed unless evidence
  explicitly supports it.
- No fabricated data: severity, confidence, and CVSS are never assigned
  without documented rationale.
- Sensitive data redaction: request/response evidence is sanitized before
  inclusion in a finding.
- Stable identifiers: check IDs are stable across scanner versions so that
  findings can be tracked over time.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """
    Finding severity classification.

    Severity reflects the potential business impact of the issue, not the
    technical CVSS score. Assign conservatively — prefer lower severity
    when evidence is ambiguous.
    """

    critical = "critical"
    """Exploitable with likely severe business impact. Requires immediate action."""

    high = "high"
    """Exploitable or near-exploitable with significant impact."""

    medium = "medium"
    """Notable weakness that may be exploitable under specific conditions."""

    low = "low"
    """Minor weakness or defence-in-depth gap with limited direct impact."""

    info = "info"
    """Observation, best-practice note, or informational finding without direct risk."""


class Confidence(str, Enum):
    """
    Scanner confidence in the finding's accuracy.

    Confidence reflects how certain the scanner is that the finding
    accurately represents an actual security weakness — independent of
    its severity.
    """

    confirmed = "confirmed"
    """
    The scanner has high-confidence evidence directly supporting this finding.
    Example: A certificate is provably expired.
    """

    probable = "probable"
    """
    The scanner has reasonable evidence. Manual verification is recommended.
    Example: A header is missing from multiple observed responses.
    """

    tentative = "tentative"
    """
    The scanner observed a potential indicator. False positives are likely
    without additional investigation.
    Example: A single response lacked an optional header.
    """

    informational = "informational"
    """
    An observation with no direct security implication. Included for context.
    """


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""

    open = "open"
    """Newly identified; not yet reviewed."""

    confirmed = "confirmed"
    """Manually verified by a security engineer."""

    false_positive = "false_positive"
    """Determined to be a scanner false positive after investigation."""

    remediated = "remediated"
    """The underlying weakness has been addressed."""

    accepted = "accepted"
    """Risk accepted by an authorized decision maker."""

    wont_fix = "wont_fix"
    """Acknowledged but will not be remediated."""


class DetectionMethod(str, Enum):
    """How the finding was detected."""

    passive_header = "passive_header"
    passive_body = "passive_body"
    passive_cookie = "passive_cookie"
    passive_tls = "passive_tls"
    passive_redirect = "passive_redirect"
    active_probe = "active_probe"
    configuration_analysis = "configuration_analysis"
    dependency_analysis = "dependency_analysis"
    manual = "manual"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class HttpEvidence(BaseModel):
    """
    Sanitized HTTP request/response evidence for a finding.

    Sensitive headers (Authorization, Cookie, Set-Cookie values, etc.) are
    redacted before this model is populated. Never store raw session tokens
    or credentials here.
    """

    model_config = {"frozen": True}

    url: str = Field(description="The request URL (query parameters may be redacted).")
    method: str = Field(default="GET", description="HTTP method.")
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Sanitized request headers (sensitive values redacted).",
    )
    status_code: Optional[int] = Field(default=None, description="HTTP response status code.")
    response_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Sanitized response headers (sensitive values redacted).",
    )
    response_excerpt: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Short, relevant excerpt of the response body (sanitized).",
    )
    response_time_ms: Optional[float] = Field(
        default=None,
        description="Response time in milliseconds.",
    )

    @field_validator("method")
    @classmethod
    def method_uppercase(cls, v: str) -> str:
        return v.upper()


class Evidence(BaseModel):
    """
    Structured evidence supporting a finding.

    The evidence field is intentionally flexible to support different
    check types. Always include enough information for an operator to
    manually verify the finding without running the scanner again.
    """

    model_config = {"frozen": True}

    summary: str = Field(
        description="One-sentence summary of what the evidence shows.",
        max_length=500,
    )
    http: Optional[HttpEvidence] = Field(
        default=None,
        description="HTTP request/response evidence (if applicable).",
    )
    observed_value: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="The specific observed value that triggered this finding (e.g., a header value).",
    )
    expected_value: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="What a safe value or configuration would look like.",
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Check-specific additional evidence fields.",
    )


# ---------------------------------------------------------------------------
# OWASP mapping
# ---------------------------------------------------------------------------


class OWASPMapping(BaseModel):
    """Maps a finding to an OWASP Top 10 category."""

    model_config = {"frozen": True}

    edition: str = Field(
        default="2025",
        description="OWASP Top 10 edition year (e.g., '2021', '2025').",
    )
    category_id: str = Field(
        description="Category identifier (e.g., 'A02').",
    )
    category_name: str = Field(
        description="Human-readable category name (e.g., 'Security Misconfiguration').",
    )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single security finding produced by a scanner check.

    A finding must never be created without evidence. The confidence field
    must reflect the actual certainty of the detection, not the potential
    impact of the issue if real.
    """

    model_config = {"frozen": True}

    # --- Identity ---
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique finding ID for this scan run.",
    )
    check_id: str = Field(
        description=(
            "Stable check identifier (e.g., 'HDR-001'). "
            "Consistent across scanner versions for tracking purposes."
        ),
    )

    # --- Classification ---
    title: str = Field(description="Short, human-readable finding title.", max_length=200)
    description: str = Field(
        description="Detailed description of the weakness and its implications.",
        max_length=4000,
    )
    severity: Severity = Field(description="Finding severity.")
    confidence: Confidence = Field(description="Scanner confidence in this finding's accuracy.")
    status: FindingStatus = Field(
        default=FindingStatus.open,
        description="Finding lifecycle status.",
    )
    detection_method: DetectionMethod = Field(description="How this finding was detected.")

    # --- OWASP / CWE mapping ---
    owasp: Optional[OWASPMapping] = Field(
        default=None,
        description="OWASP Top 10 mapping.",
    )
    cwe_ids: list[int] = Field(
        default_factory=list,
        description="Relevant CWE identifiers.",
    )

    # --- Location ---
    affected_url: str = Field(description="URL of the affected resource.")
    affected_component: Optional[str] = Field(
        default=None,
        description="Specific component affected (e.g., header name, cookie name).",
    )

    # --- Evidence ---
    evidence: Evidence = Field(description="Evidence supporting this finding.")

    # --- Remediation ---
    remediation: str = Field(
        description="Concrete, actionable remediation guidance.",
        max_length=4000,
    )
    references: list[str] = Field(
        default_factory=list,
        description="Authoritative references (OWASP WSTG, MDN, RFC, etc.).",
    )

    # --- Metadata ---
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this finding was created.",
    )
    scanner_version: str = Field(
        description="Version of Zelythion that produced this finding.",
    )
    false_positive_notes: Optional[str] = Field(
        default=None,
        description="Notes on known false-positive conditions for this check.",
    )

    @field_validator("check_id")
    @classmethod
    def check_id_format(cls, v: str) -> str:
        """Enforce CHECK-NNN format (e.g., HDR-001, CKI-002)."""
        import re
        if not re.match(r"^[A-Z]{2,6}-\d{3,5}$", v):
            raise ValueError(
                f"check_id must match pattern [A-Z]{{2,6}}-[0-9]{{3,5}}, got: {v!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------


class ScanStats(BaseModel):
    """Aggregate statistics for a completed scan."""

    model_config = {"frozen": True}

    total_requests: int = Field(default=0, ge=0)
    pages_discovered: int = Field(default=0, ge=0)
    checks_executed: int = Field(default=0, ge=0)
    checks_skipped: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0.0)
    errors: int = Field(default=0, ge=0)


class ScanResult(BaseModel):
    """
    Complete result of a scan run.

    This is the root object serialized into JSON and HTML reports.
    It must not be modified after the scan completes.
    """

    model_config = {"frozen": True}

    # --- Identity ---
    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this scan run.",
    )
    scanner_version: str = Field(description="Zelythion version that produced this scan.")

    # --- Target ---
    target: str = Field(description="Normalized target URL.")
    scan_profile: str = Field(description="Scan profile used (passive or active).")

    # --- Timing ---
    started_at: datetime = Field(description="UTC scan start time.")
    completed_at: Optional[datetime] = Field(
        default=None,
        description="UTC scan completion time (None if scan did not complete normally).",
    )
    timed_out: bool = Field(
        default=False,
        description="True if the scan hit the maximum duration limit.",
    )
    cancelled: bool = Field(
        default=False,
        description="True if the scan was cancelled by the operator.",
    )

    # --- Results ---
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during the scan.",
    )
    stats: ScanStats = Field(default_factory=ScanStats)

    # --- Coverage notes ---
    coverage_limitations: list[str] = Field(
        default_factory=list,
        description=(
            "Documented reasons why certain checks or categories could not be "
            "fully evaluated. A scan with no findings is not proof of security."
        ),
    )

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Return findings grouped by severity."""
        groups: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for finding in self.findings:
            groups[finding.severity.value].append(finding)
        return groups

    def summary_counts(self) -> dict[str, int]:
        """Return counts of findings per severity."""
        return {
            severity: len(findings)
            for severity, findings in self.findings_by_severity().items()
        }
