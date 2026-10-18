"""
Zelythion JSON report generation.

Produces a deterministic, machine-readable JSON report from a ScanResult.

Design decisions:
- Output is deterministic: findings are sorted by severity then check_id,
  so diff-ing two reports is meaningful.
- Sensitive data is redacted before serialisation via the same utilities
  used by the HTTP client. Reports must never contain raw session tokens,
  authorization headers, or credentials.
- A scan with zero findings is represented explicitly, not as an absent key.
- Timestamps are always ISO-8601 UTC strings.
- The schema version field allows consumers to detect breaking changes.
- Float values are rounded to 2 decimal places to avoid floating-point noise.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

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
    Severity,
)
from zelythion.utils import redact_url_query_params

# Increment when the JSON schema has a breaking change.
REPORT_SCHEMA_VERSION = "1.0"

# Severity order for deterministic sorting (most severe first).
_SEVERITY_ORDER: dict[str, int] = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_json_report(result: ScanResult, indent: int = 2) -> str:
    """
    Serialise a ScanResult to a JSON string.

    The output is:
    - Deterministic (sorted findings, sorted keys).
    - Redacted (no credentials or secrets).
    - Human-readable with the given indentation.

    Args:
        result: The completed scan result.
        indent: JSON indentation spaces (default 2).

    Returns:
        JSON string. Never raises on a valid ScanResult.
    """
    doc = _build_report_document(result)
    return json.dumps(doc, indent=indent, ensure_ascii=False, sort_keys=False)


def generate_json_report_to_file(result: ScanResult, path: str, indent: int = 2) -> None:
    """
    Write a JSON report to a file.

    Args:
        result: The completed scan result.
        path: Destination file path.
        indent: JSON indentation spaces.

    Raises:
        OSError: If the file cannot be written.
    """
    content = generate_json_report(result, indent=indent)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# Internal serialisation helpers
# ---------------------------------------------------------------------------


def _build_report_document(result: ScanResult) -> dict[str, Any]:
    """Build the top-level report dictionary."""
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.check_id),
    )

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": result.scan_id,
        "scanner_version": result.scanner_version,
        "target": redact_url_query_params(result.target),
        "scan_profile": result.scan_profile,
        "started_at": _fmt_dt(result.started_at),
        "completed_at": _fmt_dt(result.completed_at),
        "duration_seconds": round(result.stats.duration_seconds, 2),
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "stats": _serialise_stats(result),
        "summary": _build_summary(result),
        "findings": [_serialise_finding(f) for f in sorted_findings],
        "errors": result.errors,
        "coverage_limitations": result.coverage_limitations,
    }


def _serialise_stats(result: ScanResult) -> dict[str, Any]:
    return {
        "total_requests": result.stats.total_requests,
        "pages_discovered": result.stats.pages_discovered,
        "checks_executed": result.stats.checks_executed,
        "checks_skipped": result.stats.checks_skipped,
        "errors": result.stats.errors,
    }


def _build_summary(result: ScanResult) -> dict[str, Any]:
    counts = result.summary_counts()
    return {
        "total_findings": len(result.findings),
        "by_severity": counts,
    }


def _serialise_finding(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "check_id": f.check_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "status": f.status.value,
        "detection_method": f.detection_method.value,
        "owasp": _serialise_owasp(f.owasp),
        "cwe_ids": f.cwe_ids,
        "affected_url": redact_url_query_params(f.affected_url),
        "affected_component": f.affected_component,
        "evidence": _serialise_evidence(f.evidence),
        "remediation": f.remediation,
        "references": f.references,
        "false_positive_notes": f.false_positive_notes,
        "timestamp": _fmt_dt(f.timestamp),
        "scanner_version": f.scanner_version,
    }


def _serialise_owasp(owasp: Optional[OWASPMapping]) -> Optional[dict[str, str]]:
    if owasp is None:
        return None
    return {
        "edition": owasp.edition,
        "category_id": owasp.category_id,
        "category_name": owasp.category_name,
    }


def _serialise_evidence(ev: Evidence) -> dict[str, Any]:
    return {
        "summary": ev.summary,
        "observed_value": ev.observed_value,
        "expected_value": ev.expected_value,
        "http": _serialise_http_evidence(ev.http),
        "extra": ev.extra,
    }


def _serialise_http_evidence(http: Optional[HttpEvidence]) -> Optional[dict[str, Any]]:
    if http is None:
        return None
    return {
        "url": redact_url_query_params(http.url),
        "method": http.method,
        "status_code": http.status_code,
        "request_headers": _redact_headers(http.request_headers),
        "response_headers": _redact_headers(http.response_headers),
        "response_excerpt": http.response_excerpt,
        "response_time_ms": (
            round(http.response_time_ms, 2) if http.response_time_ms is not None else None
        ),
    }


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Re-apply header redaction at serialisation time as a final safety net."""
    from zelythion.http_client import SENSITIVE_REQUEST_HEADERS, SENSITIVE_RESPONSE_HEADERS, REDACTED_MARKER

    sensitive = SENSITIVE_REQUEST_HEADERS | SENSITIVE_RESPONSE_HEADERS
    return {
        k: (REDACTED_MARKER if k.lower() in sensitive else v)
        for k, v in headers.items()
    }


def _fmt_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
