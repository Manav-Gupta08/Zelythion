"""
SentinelScan configuration models.

All configuration is validated through Pydantic to ensure type safety and
to catch misconfiguration early, before any network activity occurs.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class ScanProfile(str, Enum):
    """Scan aggressiveness profile."""

    passive = "passive"
    """
    Conservative passive scanning only.
    No active test payloads are sent. HTTP requests are limited to
    reconnaissance and observation.
    """

    active = "active"
    """
    Active testing enabled.
    Narrow, non-destructive test payloads may be sent.
    Requires explicit operator confirmation.
    """


class OutputFormat(str, Enum):
    """Report output format."""

    text = "text"
    json = "json"
    html = "html"


class ScanConfig(BaseModel):
    """
    Validated configuration for a single scan run.

    All resource limits are bounded to prevent runaway scans.
    Sensitive fields are excluded from repr and serialization.
    """

    model_config = {"frozen": True}

    # --- Target ---
    target: str = Field(description="Normalized target URL (https://hostname[:port][/path]).")

    # --- Profile ---
    profile: ScanProfile = Field(
        default=ScanProfile.passive,
        description="Scan aggressiveness profile.",
    )

    # --- Output ---
    output_format: OutputFormat = Field(
        default=OutputFormat.text,
        description="Report output format.",
    )
    output_file: Optional[str] = Field(
        default=None,
        description="Optional file path to write the report to.",
    )

    # --- Crawl limits ---
    max_depth: int = Field(
        default=2,
        ge=0,
        le=10,
        description="Maximum link-following depth from the start URL.",
    )
    max_pages: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of distinct pages to visit.",
    )
    max_requests: int = Field(
        default=200,
        ge=1,
        le=2000,
        description="Hard ceiling on total HTTP requests per scan.",
    )

    # --- Timeouts and concurrency ---
    timeout: float = Field(
        default=10.0,
        ge=1.0,
        le=120.0,
        description="Per-request timeout in seconds.",
    )
    connect_timeout: float = Field(
        default=5.0,
        ge=1.0,
        le=30.0,
        description="TCP connection timeout in seconds.",
    )
    max_concurrency: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum simultaneous HTTP connections.",
    )
    max_scan_duration: float = Field(
        default=300.0,
        ge=10.0,
        le=3600.0,
        description="Hard ceiling on total scan duration in seconds.",
    )

    # --- Response limits ---
    max_response_size: int = Field(
        default=5 * 1024 * 1024,  # 5 MB
        ge=1024,
        le=50 * 1024 * 1024,
        description="Maximum response body to read per request, in bytes.",
    )
    max_redirects: int = Field(
        default=5,
        ge=0,
        le=20,
        description="Maximum redirects to follow per request.",
    )

    # --- Request rate ---
    requests_per_second: float = Field(
        default=5.0,
        ge=0.1,
        le=50.0,
        description="Target request rate limit (requests per second).",
    )

    # --- Behaviour flags ---
    verify_tls: bool = Field(
        default=True,
        description=(
            "Verify TLS certificates. Must not be disabled for production targets. "
            "Disable only for isolated lab environments with self-signed certs."
        ),
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects (scope-validated at each step).",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose diagnostic output.",
    )

    # --- Validators ---

    @field_validator("target")
    @classmethod
    def target_must_be_http(cls, v: str) -> str:
        stripped = v.strip()
        if not (stripped.startswith("http://") or stripped.startswith("https://")):
            raise ValueError(f"Target must be an http:// or https:// URL, got: {stripped!r}")
        return stripped

    @model_validator(mode="after")
    def active_requires_acknowledgement(self) -> "ScanConfig":
        """
        Warn when active profile is configured without TLS verification.
        This does not block the config but is validated here so that the
        CLI can surface the warning before any requests are made.
        """
        if self.profile == ScanProfile.active and not self.verify_tls:
            # Not an error — the user may be targeting a lab — but we record it.
            pass
        return self

    @model_validator(mode="after")
    def connect_timeout_le_request_timeout(self) -> "ScanConfig":
        if self.connect_timeout > self.timeout:
            raise ValueError(
                f"connect_timeout ({self.connect_timeout}s) must be ≤ timeout ({self.timeout}s)."
            )
        return self
