# Zelythion Architecture

## Overview

Zelythion uses a layered architecture designed to separate concerns
cleanly: network access, scope enforcement, security checks, and reporting
are each isolated into dedicated modules.

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                            │
│  • Entry point via Typer                                        │
│  • Authorization confirmation gate                              │
│  • Config building (ScanConfig)                                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                      Orchestrator (orchestrator.py)             │
│  • Scan lifecycle management                                    │
│  • Check scheduling                                             │
│  • Resource budget enforcement                                  │
│  • Result aggregation                                           │
└──────┬──────────────────┬───────────────────┬───────────────────┘
       │                  │                   │
┌──────▼──────┐  ┌────────▼──────┐  ┌─────────▼──────────────────┐
│ Scope       │  │ HTTP Client   │  │ Checks (checks/)            │
│ (scope.py)  │  │ (http_client) │  │  • headers.py               │
│             │  │               │  │  • cookies.py               │
│ • URL norm  │  │ • Bounded     │  │  • tls.py                   │
│ • IP checks │  │   requests    │  │  • disclosure.py            │
│ • Allowlist │  │ • Scope check │  │  • injection.py             │
└─────────────┘  │ • Timeouts    │  └─────────────────────────────┘
                 │ • SSRF guard  │
                 └───────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                   Crawler (crawler.py)                          │
│  • Same-origin link discovery                                   │
│  • Form identification (no submission)                          │
│  • Depth/page/request budgets                                   │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│               Reporting (reporting/)                            │
│  • JSON report (json_report.py)                                 │
│  • HTML report (html_report.py)                                 │
│  • Sensitive data redaction                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### cli.py
- Typer CLI entry point
- Authorization confirmation before any scan
- Config building and validation
- Progress display via Rich

### config.py
- Pydantic-validated `ScanConfig` model
- All resource limits (timeout, pages, requests, concurrency, duration)
- Scan profile selection (passive/active)

### scope.py
- URL normalization and validation
- SSRF protection: private IPs, loopback, link-local, cloud metadata
- Scope allowlist enforcement
- Redirect destination validation

### models.py
- `Finding`: structured security finding with evidence and metadata
- `ScanResult`: complete scan output
- `Evidence`: structured, sanitized HTTP evidence
- Severity, Confidence, OWASP, CWE enumerations

### http_client.py (Phase 1)
- httpx-based bounded HTTP client
- Per-request scope re-validation
- TLS verification (mandatory by default)
- Compressed response handling with decompression limits
- Sensitive header redaction

### orchestrator.py (Phase 1)
- Scan lifecycle coordination
- Check scheduling and result collection
- Resource budget tracking
- Graceful cancellation

### checks/ (Phase 2+)
- Independent, modular check implementations
- Each check returns `list[Finding]`
- No side effects outside their return value

### reporting/ (Phase 3+)
- Deterministic serialization
- Sensitive-data redaction before output
- HTML output with escaped untrusted content

## Design Decisions

### Why src/-based layout?
Prevents accidental imports from the project root during testing.
Ensures the installed package is always tested, not the raw source tree.

### Why Pydantic for config and models?
Strict validation at construction time catches misconfiguration before
any network activity. Frozen models prevent mutation after construction.

### Why scope validation before DNS resolution?
DNS results can change between validation and connection time (TOCTOU).
The scope validator rejects obvious static SSRF (literal private IPs, blocked
hostnames). The HTTP client must perform connection-time destination validation
as a second layer of defence.

### Why no TLS verification disable by default?
Disabling TLS verification defeats the purpose of HTTPS entirely and exposes
the scanner's own traffic to interception. A separate lab mode flag is planned
for isolated environments with self-signed certificates.
