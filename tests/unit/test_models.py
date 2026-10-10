"""
Unit tests for Zelythion finding and scan result models.

These tests verify that:
- Finding instances require all mandatory fields.
- check_id format is enforced.
- Severity and confidence values are constrained to their enums.
- ScanResult correctly groups and counts findings.
- Timestamps are UTC-aware.

No network requests are made.
"""

from __future__ import annotations

import pytest
from datetime import timezone

from pydantic import ValidationError

from zelythion import __version__
from zelythion.models import (
    Confidence,
    DetectionMethod,
    Evidence,
    Finding,
    FindingStatus,
    HttpEvidence,
    OWASPMapping,
    ScanResult,
    ScanStats,
    Severity,
)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_minimal_evidence_created(self) -> None:
        ev = Evidence(summary="Test summary.")
        assert ev.summary == "Test summary."
        assert ev.http is None
        assert ev.observed_value is None

    def test_http_evidence_created(self) -> None:
        http_ev = HttpEvidence(
            url="https://example.com/",
            status_code=200,
            response_headers={"x-frame-options": "SAMEORIGIN"},
            response_time_ms=55.5,
        )
        assert http_ev.status_code == 200
        assert http_ev.method == "GET"
        assert http_ev.response_time_ms == pytest.approx(55.5)

    def test_http_method_uppercased(self) -> None:
        ev = HttpEvidence(url="https://example.com/", method="post")
        assert ev.method == "POST"

    def test_evidence_is_immutable(self) -> None:
        ev = Evidence(summary="Immutable.")
        with pytest.raises(Exception):  # Pydantic frozen model
            ev.summary = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def _make_finding(self, **overrides: object) -> Finding:
        defaults: dict[str, object] = {
            "check_id": "HDR-001",
            "title": "Missing CSP",
            "description": "No Content-Security-Policy header was observed.",
            "severity": Severity.medium,
            "confidence": Confidence.confirmed,
            "detection_method": DetectionMethod.passive_header,
            "affected_url": "https://example.com/",
            "evidence": Evidence(summary="Header absent from response."),
            "remediation": "Add a CSP header.",
            "scanner_version": __version__,
        }
        defaults.update(overrides)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_finding_created_with_required_fields(self) -> None:
        f = self._make_finding()
        assert f.check_id == "HDR-001"
        assert f.severity == Severity.medium
        assert f.confidence == Confidence.confirmed
        assert f.status == FindingStatus.open

    def test_finding_id_auto_generated(self) -> None:
        f = self._make_finding()
        assert f.id and len(f.id) == 36  # UUID4 format

    def test_two_findings_have_different_ids(self) -> None:
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.id != f2.id

    def test_timestamp_is_utc(self) -> None:
        f = self._make_finding()
        assert f.timestamp.tzinfo == timezone.utc

    def test_check_id_format_enforced(self) -> None:
        with pytest.raises(ValidationError, match="check_id"):
            self._make_finding(check_id="invalid-format")

    def test_check_id_too_short_prefix_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._make_finding(check_id="H-001")

    def test_check_id_lowercase_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._make_finding(check_id="hdr-001")

    def test_valid_check_id_formats(self) -> None:
        for cid in ["HDR-001", "CKI-002", "TLS-010", "INJCT-001"]:
            f = self._make_finding(check_id=cid)
            assert f.check_id == cid

    def test_owasp_mapping_stored(self) -> None:
        owasp = OWASPMapping(
            edition="2025",
            category_id="A02",
            category_name="Security Misconfiguration",
        )
        f = self._make_finding(owasp=owasp)
        assert f.owasp is not None
        assert f.owasp.category_id == "A02"
        assert f.owasp.edition == "2025"

    def test_cwe_ids_stored(self) -> None:
        f = self._make_finding(cwe_ids=[693, 1021])
        assert 693 in f.cwe_ids
        assert 1021 in f.cwe_ids

    def test_finding_is_immutable(self) -> None:
        f = self._make_finding()
        with pytest.raises(Exception):
            f.title = "mutated"  # type: ignore[misc]

    def test_references_stored(self) -> None:
        refs = ["https://owasp.org/", "https://mdn.io/csp"]
        f = self._make_finding(references=refs)
        assert f.references == refs

    def test_severity_values(self) -> None:
        for sev in Severity:
            f = self._make_finding(severity=sev)
            assert f.severity == sev

    def test_confidence_values(self) -> None:
        for conf in Confidence:
            f = self._make_finding(confidence=conf)
            assert f.confidence == conf


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def _make_finding(self, severity: Severity) -> Finding:
        return Finding(
            check_id="HDR-001",
            title="Test",
            description="Test finding.",
            severity=severity,
            confidence=Confidence.confirmed,
            detection_method=DetectionMethod.passive_header,
            affected_url="https://example.com/",
            evidence=Evidence(summary="Test."),
            remediation="Fix it.",
            scanner_version=__version__,
        )

    def test_scan_result_created(self) -> None:
        from datetime import datetime
        result = ScanResult(
            scanner_version=__version__,
            target="https://example.com",
            scan_profile="passive",
            started_at=datetime.now(tz=timezone.utc),
        )
        assert result.scan_id
        assert result.findings == []

    def test_findings_by_severity(self) -> None:
        from datetime import datetime
        findings = [
            self._make_finding(Severity.high),
            self._make_finding(Severity.high),
            self._make_finding(Severity.medium),
            self._make_finding(Severity.info),
        ]
        result = ScanResult(
            scanner_version=__version__,
            target="https://example.com",
            scan_profile="passive",
            started_at=datetime.now(tz=timezone.utc),
            findings=findings,
        )
        grouped = result.findings_by_severity()
        assert len(grouped["high"]) == 2
        assert len(grouped["medium"]) == 1
        assert len(grouped["info"]) == 1
        assert len(grouped["critical"]) == 0

    def test_summary_counts(self) -> None:
        from datetime import datetime
        findings = [
            self._make_finding(Severity.critical),
            self._make_finding(Severity.high),
            self._make_finding(Severity.high),
        ]
        result = ScanResult(
            scanner_version=__version__,
            target="https://example.com",
            scan_profile="passive",
            started_at=datetime.now(tz=timezone.utc),
            findings=findings,
        )
        counts = result.summary_counts()
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["low"] == 0

    def test_coverage_limitations_stored(self) -> None:
        from datetime import datetime
        result = ScanResult(
            scanner_version=__version__,
            target="https://example.com",
            scan_profile="passive",
            started_at=datetime.now(tz=timezone.utc),
            coverage_limitations=["JavaScript rendering not evaluated."],
        )
        assert "JavaScript rendering not evaluated." in result.coverage_limitations
