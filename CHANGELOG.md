# Changelog

All notable changes to Zelythion are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Zelythion uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned

- Bounded HTTP client with scope enforcement and SSRF protection (Phase 1).
- Security header and cookie attribute checks (Phase 2).
- JSON report generation with redaction (Phase 3).
- Passive same-origin crawler (Phase 4).

---

## [0.1.0] — 2026-10-10

### Added

- Initial project structure with `src/`-based layout.
- `pyproject.toml` with Hatchling build backend and pinned dependency ranges.
- MIT License.
- `ScopeValidator` with SSRF protection, private IP blocking (RFC 1918, loopback,
  link-local, multicast, reserved), cloud metadata endpoint blocking, URL normalization,
  and configurable allowlists.
- `ScanConfig` Pydantic model with strict resource limits (depth, pages, requests,
  timeout, concurrency, duration, response size, rate).
- `Finding` model with stable `check_id` format enforcement, severity, confidence,
  OWASP 2025 mapping, CWE identifiers, evidence, remediation guidance, and UTC timestamps.
- `ScanResult` model with grouping and summary-count helpers.
- `Evidence` and `HttpEvidence` models for structured, sanitized scan evidence.
- CLI entry point (`sentinel`) with `scan` and `checks list` subcommands.
- Authorization confirmation gate before any scan begins.
- Unit tests for scope enforcement (41 assertions across 10 test classes).
- Unit tests for finding and scan result models.
- Unit tests for configuration validation.
- `SECURITY.md` vulnerability disclosure policy.
- `CONTRIBUTING.md` development and contribution guide.
- `.gitignore` with Python, IDE, scan output, and secret exclusions.

### Known Limitations

- The HTTP client and scan engine are not yet implemented (Phase 1).
- No security checks produce findings yet (Phase 2+).
- No report generation beyond CLI placeholder output (Phase 3+).
- JavaScript-rendered content is not evaluated.
- No authentication support.
- No web dashboard.

[Unreleased]: https://github.com/Manav-Gupta08/zelythion/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Manav-Gupta08/zelythion/releases/tag/v0.1.0
