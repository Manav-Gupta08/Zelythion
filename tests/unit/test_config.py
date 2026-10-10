"""
Unit tests for SentinelScan configuration.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinelscan.config import ScanConfig, ScanProfile, OutputFormat


class TestScanConfig:
    def test_default_config(self) -> None:
        cfg = ScanConfig(target="https://example.com")
        assert cfg.target == "https://example.com"
        assert cfg.profile == ScanProfile.passive
        assert cfg.output_format == OutputFormat.text
        assert cfg.max_depth == 2
        assert cfg.max_pages == 50
        assert cfg.timeout == 10.0
        assert cfg.verify_tls is True
        assert cfg.verbose is False

    def test_active_profile(self) -> None:
        cfg = ScanConfig(target="https://example.com", profile=ScanProfile.active)
        assert cfg.profile == ScanProfile.active

    def test_target_must_have_scheme(self) -> None:
        with pytest.raises(ValidationError, match="http"):
            ScanConfig(target="example.com")

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig(target="ftp://example.com")

    def test_max_depth_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", max_depth=11)
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", max_depth=-1)

    def test_max_pages_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", max_pages=501)

    def test_timeout_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", timeout=0.5)
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", timeout=200.0)

    def test_connect_timeout_le_timeout(self) -> None:
        with pytest.raises(ValidationError, match="connect_timeout"):
            ScanConfig(
                target="https://example.com",
                timeout=5.0,
                connect_timeout=10.0,
            )

    def test_config_is_immutable(self) -> None:
        cfg = ScanConfig(target="https://example.com")
        with pytest.raises(Exception):
            cfg.target = "https://other.com"  # type: ignore[misc]

    def test_json_format_config(self) -> None:
        cfg = ScanConfig(
            target="https://example.com",
            output_format=OutputFormat.json,
        )
        assert cfg.output_format == OutputFormat.json

    def test_output_file_stored(self) -> None:
        cfg = ScanConfig(target="https://example.com", output_file="/tmp/report.json")
        assert cfg.output_file == "/tmp/report.json"

    def test_max_response_size_default(self) -> None:
        cfg = ScanConfig(target="https://example.com")
        assert cfg.max_response_size == 5 * 1024 * 1024

    def test_requests_per_second_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig(target="https://example.com", requests_per_second=100.0)
