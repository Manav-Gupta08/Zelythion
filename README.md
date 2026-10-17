# Zelythion

> An extensible, evidence-driven web application security scanner built in Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-156%20passing-brightgreen.svg)](#testing)

## ⚠️ Authorization Notice

Zelythion is designed **exclusively for authorized security testing**.

You must have explicit written permission from the system owner before scanning any target.
Unauthorized scanning may be illegal and unethical. This tool does **not** authorize you to
test any system.

## What is Zelythion?

Zelythion is a modular, evidence-driven web application security scanner that helps developers
and authorized security engineers identify and remediate security weaknesses through safe,
reproducible, and configurable security testing.

It is grounded in the **OWASP Top 10:2025** taxonomy and produces structured, evidence-backed
findings — not vague alerts. Every finding includes what was observed, why it matters,
how to reproduce it, and how to fix it.

**What it is:** A CLI security scanner with real checks, real evidence, and honest confidence levels.

**What it is not:** A replacement for manual penetration testing, source-code review,
or established commercial security scanners.

## Features

### Currently Implemented

- **Bounded HTTP client** — TLS verification, configurable timeouts, response-size caps,
  request-rate limiting, concurrency limiting, and request-budget enforcement
- **SSRF protection** — Private IP ranges (RFC 1918), loopback, link-local, cloud metadata
  endpoints (AWS/GCP/Azure), and blocked hostnames are all rejected before any socket opens
- **Redirect scope validation** — every redirect hop is validated; out-of-scope destinations
  raise an error before the request is sent
- **Sensitive data redaction** — credentials, session tokens, and secrets are stripped from
  all evidence and logs
- **Security header checks** (passive, OWASP A02):
  - `HDR-001` Missing Content-Security-Policy
  - `HDR-002` Missing X-Content-Type-Options
  - `HDR-003` Missing X-Frame-Options / CSP frame-ancestors
  - `HDR-004` Missing Strict-Transport-Security (HSTS) — HTTPS only
  - `HDR-005` Missing Referrer-Policy
  - `HDR-006` Missing Permissions-Policy
  - `HDR-007` Server version disclosure via Server header
- **Cookie attribute checks** (passive, OWASP A02):
  - `CKI-001` Missing Secure flag — HTTPS responses only
  - `CKI-002` Missing HttpOnly flag
  - `CKI-003` Missing or weak SameSite attribute (SameSite=None escalated to High)
- **Structured findings** — stable check IDs, OWASP 2025 category mapping, CWE identifiers,
  severity, confidence, evidence, remediation guidance, and UTC timestamps
- **Scan orchestrator** — coordinates fetch → checks → result, with deadline enforcement
  and graceful error capture
- **156 unit tests** — no live network required

### Planned (Coming Soon)

- JSON and HTML report generation (Phase 3)
- Passive same-origin crawler (Phase 4)
- TLS certificate checks (Phase 5)
- Expanded OWASP coverage (Phase 6–7)
- Web dashboard with FastAPI + React (Phase 10)

## Installation

**Requirements:** Python 3.11 or later

```bash
git clone https://github.com/Manav-Gupta08/Zelythion.git
cd Zelythion
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify the installation:

```bash
zelythion --version
zelythion --help
```

## Quick Start

```bash
# List all available checks and their status
zelythion checks list

# Run a passive scan against an authorized target
zelythion scan https://your-authorized-target.example

# Run with verbose output
zelythion scan https://your-authorized-target.example --verbose

# Output as JSON
zelythion scan https://your-authorized-target.example --format json
```

## CLI Reference

```
zelythion scan <URL> [OPTIONS]

  URL                           Target URL (must be an authorized target)

  --profile   [passive|active]  Scan profile          (default: passive)
  --format    [text|json|html]  Output format          (default: text)
  --output    PATH              Write report to file
  --depth     INTEGER           Max crawl depth   0–10 (default: 2)
  --timeout   FLOAT             Request timeout, sec   (default: 10.0)
  --max-pages INTEGER           Max pages to crawl     (default: 50)
  --verbose, -v                 Enable verbose output
  --yes, -y                     Skip authorization prompt

zelythion checks list           List all available security checks

zelythion --version             Print scanner version and exit
zelythion --help                Show help
```

## Architecture

```
src/zelythion/
├── __init__.py         Package version and authorization notice
├── cli.py              Typer CLI entry point
├── config.py           Pydantic-validated ScanConfig (all limits enforced here)
├── scope.py            URL validation, SSRF protection, scope allowlist
├── errors.py           Central exception hierarchy
├── http_client.py      Bounded httpx wrapper (rate-limiting, redirects, redaction)
├── orchestrator.py     Scan lifecycle: fetch → checks → ScanResult
├── models.py           Finding, Evidence, ScanResult, enums
├── checks/
│   ├── base.py         BaseCheck abstract interface
│   ├── headers.py      HDR-001 through HDR-007 (security headers)
│   └── cookies.py      CKI-001 through CKI-003 (cookie attributes)
└── utils/
    └── __init__.py     Redaction utilities (URL params, body excerpts, headers)
```

See [docs/architecture.md](docs/architecture.md) for the full module diagram and design decisions.

## Security Model

- **Scope is enforced before every request** — URLs are validated against an allowlist on
  both the initial request and each redirect hop
- **Private destinations are blocked by default** — 10.x, 172.16–31.x, 192.168.x, 127.x,
  169.254.x, ::1, fc00::/7, and cloud metadata endpoints
- **TLS verification is on by default** — it cannot be disabled without an explicit flag
- **Findings require evidence** — checks return an empty list rather than fire without proof
- **Sensitive data never reaches reports** — Authorization, Cookie, Set-Cookie, and token
  query parameters are redacted at the HTTP client layer

## Development

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=zelythion --cov-report=term-missing

# Lint (ruff)
ruff check .

# Format
ruff format .

# Type check
mypy src/
```

## Testing

Tests live in `tests/unit/` and use `httpx.MockTransport` — no live internet connection needed.

```bash
pytest tests/unit/              # All unit tests (156 passing)
pytest tests/unit/test_scope.py # Scope enforcement only
pytest tests/unit/test_checks.py # Check fire/no-fire behaviour
```

Test coverage areas:
- URL validation and scope enforcement (45 tests)
- SSRF protection — private IPs, loopback, cloud metadata, blocked hostnames
- HTTP client — redirects, size limits, budget, header redaction (29 tests)
- Security header checks — fire/no-fire, severity, OWASP mapping (49 tests)
- Cookie attribute checks — Secure, HttpOnly, SameSite edge cases
- Config validation — bounds, immutability, validator logic
- Finding and ScanResult models — IDs, enums, grouping

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, commit conventions,
and pull request process.

## License

[MIT License](LICENSE)

## Author

**Manav Gupta**

CyberSecurity Student | Software Developer | Backend Engineer
