"""
Unit tests for JSON report generation.

Tests verify:
  - Report structure contains all required top-level keys.
  - Findings are sorted by severity then check_id (most severe first).
  - Sensitive query parameters in URLs are redacted.
  - Sensitive response headers in evidence are redacted.
  - Timestamps are ISO-8601 UTC strings.
  - Summary counts match actual findings.
  - Empty scan produces valid, well-formed JSON.
  - Schema version is present.
  - File writing works correctly.
  - Report is valid JSON (parseable).
  - Float rounding to 2 decimal places.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from zelythion import __version__
from zelythion.models import (
    Confidence,
    DetectionMethod,
    Evidence,
    Finding,
    HttpEvidence,
    OWASPMapping,
    ScanResult,
    ScanStats,
    Severity,
)
from zelythion.reporting.json_report import (
    REPORT_SCHEMA_VERSION,
    generate_json_report,
    generate_json_report_to_file,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    check_id: str = "HDR-001",
    severity: Severity = Severity.medium,
    url: str = "https://example.com/",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test finding {check_id}",
        description="A test finding.",
        severity=severity,
        confidence=Confidence.confirmed,
        detection_method=DetectionMethod.passive_header,
        affected_url=url,
        evidence=Evidence(
            summary="Header absent.",
            http=HttpEvidence(
                url=url,
                method="GET",
                status_code=200,
                response_headers={"content-type": "text/html", "set-cookie": "session=abc"},
                response_time_ms=123.456,
            ),
            observed_value="(absent)",
            expected_value="present",
        ),
        owasp=OWASPMapping(edition="2025", category_id="A02", category_name="Security Misconfiguration"),
        cwe_ids=[693],
        remediation="Fix it.",
        references=["https://example.com/ref"],
        scanner_version=__version__,
    )


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scanner_version=__version__,
        target="https://example.com/",
        scan_profile="passive",
        started_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
        findings=findings or [],
        stats=ScanStats(
            total_requests=1,
            pages_discovered=1,
            checks_executed=10,
            duration_seconds=5.12345,
        ),
        coverage_limitations=["JS not evaluated."],
    )


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------

class TestReportStructure:
    def test_report_is_valid_json(self) -> None:
        result = _make_result()
        raw = generate_json_report(result)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_required_top_level_keys_present(self) -> None:
        result = _make_result()
        doc = json.loads(generate_json_report(result))
        for key in ["schema_version", "scan_id", "scanner_version", "target",
                    "scan_profile", "started_at", "completed_at", "duration_seconds",
                    "timed_out", "cancelled", "stats", "summary", "findings",
                    "errors", "coverage_limitations"]:
            assert key in doc, f"Missing key: {key}"

    def test_schema_version_correct(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert doc["schema_version"] == REPORT_SCHEMA_VERSION

    def test_scanner_version_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert doc["scanner_version"] == __version__

    def test_target_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert "example.com" in doc["target"]

    def test_timestamps_are_utc_strings(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert doc["started_at"] == "2026-01-01T12:00:00Z"
        assert doc["completed_at"] == "2026-01-01T12:00:05Z"

    def test_duration_rounded(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        # 5.12345 rounded to 2dp = 5.12
        assert doc["duration_seconds"] == pytest.approx(5.12, abs=0.01)

    def test_stats_block_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        stats = doc["stats"]
        assert stats["total_requests"] == 1
        assert stats["checks_executed"] == 10

    def test_summary_counts_match_findings(self) -> None:
        findings = [
            _make_finding("HDR-001", Severity.high),
            _make_finding("HDR-002", Severity.medium),
            _make_finding("HDR-003", Severity.medium),
        ]
        doc = json.loads(generate_json_report(_make_result(findings)))
        assert doc["summary"]["total_findings"] == 3
        assert doc["summary"]["by_severity"]["high"] == 1
        assert doc["summary"]["by_severity"]["medium"] == 2
        assert doc["summary"]["by_severity"]["low"] == 0

    def test_coverage_limitations_included(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert "JS not evaluated." in doc["coverage_limitations"]


# ---------------------------------------------------------------------------
# Empty scan
# ---------------------------------------------------------------------------

class TestEmptyScan:
    def test_empty_findings_list_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        assert doc["findings"] == []

    def test_summary_all_zeros(self) -> None:
        doc = json.loads(generate_json_report(_make_result()))
        counts = doc["summary"]["by_severity"]
        assert all(v == 0 for v in counts.values())


# ---------------------------------------------------------------------------
# Finding serialisation
# ---------------------------------------------------------------------------

class TestFindingSerialisation:
    def test_finding_fields_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        f = doc["findings"][0]
        for key in ["id", "check_id", "title", "description", "severity",
                    "confidence", "status", "detection_method", "owasp",
                    "cwe_ids", "affected_url", "evidence", "remediation",
                    "references", "timestamp", "scanner_version"]:
            assert key in f, f"Missing finding key: {key}"

    def test_owasp_mapping_serialised(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        owasp = doc["findings"][0]["owasp"]
        assert owasp["category_id"] == "A02"
        assert owasp["edition"] == "2025"

    def test_cwe_ids_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        assert 693 in doc["findings"][0]["cwe_ids"]

    def test_evidence_block_present(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        ev = doc["findings"][0]["evidence"]
        assert ev["summary"] == "Header absent."
        assert ev["http"] is not None


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

class TestFindingSorting:
    def test_sorted_most_severe_first(self) -> None:
        findings = [
            _make_finding("HDR-005", Severity.info),
            _make_finding("HDR-001", Severity.high),
            _make_finding("HDR-003", Severity.medium),
            _make_finding("HDR-004", Severity.low),
            _make_finding("HDR-002", Severity.critical),
        ]
        doc = json.loads(generate_json_report(_make_result(findings)))
        severities = [f["severity"] for f in doc["findings"]]
        assert severities[0] == "critical"
        assert severities[1] == "high"
        assert severities[-1] == "info"

    def test_same_severity_sorted_by_check_id(self) -> None:
        findings = [
            _make_finding("HDR-003", Severity.medium),
            _make_finding("HDR-001", Severity.medium),
            _make_finding("HDR-002", Severity.medium),
        ]
        doc = json.loads(generate_json_report(_make_result(findings)))
        ids = [f["check_id"] for f in doc["findings"]]
        assert ids == ["HDR-001", "HDR-002", "HDR-003"]


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_sensitive_query_param_redacted_in_target(self) -> None:
        result = ScanResult(
            scanner_version=__version__,
            target="https://example.com/?token=supersecret",
            scan_profile="passive",
            started_at=datetime.now(tz=timezone.utc),
            stats=ScanStats(),
        )
        doc = json.loads(generate_json_report(result))
        assert "supersecret" not in doc["target"]
        assert "REDACTED" in doc["target"]

    def test_set_cookie_header_redacted_in_evidence(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        http_ev = doc["findings"][0]["evidence"]["http"]
        # set-cookie header value should be redacted
        assert http_ev["response_headers"].get("set-cookie") == "[REDACTED]"

    def test_non_sensitive_headers_preserved(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        http_ev = doc["findings"][0]["evidence"]["http"]
        assert http_ev["response_headers"].get("content-type") == "text/html"

    def test_response_time_rounded(self) -> None:
        doc = json.loads(generate_json_report(_make_result([_make_finding()])))
        rt = doc["findings"][0]["evidence"]["http"]["response_time_ms"]
        # 123.456 → 123.46
        assert rt == pytest.approx(123.46, abs=0.01)

    def test_sensitive_url_in_finding_redacted(self) -> None:
        f = _make_finding(url="https://example.com/?api_key=secret")
        doc = json.loads(generate_json_report(_make_result([f])))
        assert "secret" not in doc["findings"][0]["affected_url"]


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

class TestFileWriting:
    def test_writes_valid_json_to_file(self) -> None:
        result = _make_result()
        with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            generate_json_report_to_file(result, path)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            parsed = json.loads(content)
            assert parsed["schema_version"] == REPORT_SCHEMA_VERSION
        finally:
            os.unlink(path)

    def test_file_content_matches_string_output(self) -> None:
        result = _make_result()
        expected = generate_json_report(result)
        with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            generate_json_report_to_file(result, path)
            with open(path, encoding="utf-8") as fh:
                actual = fh.read()
            assert actual == expected
        finally:
            os.unlink(path)
