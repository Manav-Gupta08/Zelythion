# SentinelScan

> An extensible, evidence-driven web application security scanner built in Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)

---

## ⚠️ Authorization Notice

SentinelScan is designed **exclusively for authorized security testing**.

You must have explicit written permission from the system owner before scanning any target.
Unauthorized scanning may be illegal and unethical. This tool does **not** authorize you to
test any system.

---

## Overview

SentinelScan is a modular, evidence-driven web application security scanner that helps
developers and authorized security engineers identify and remediate security weaknesses
through safe, reproducible, configurable security testing.

**What it is:** A CLI security scanner grounded in OWASP Top 10 coverage with structured,
evidence-backed findings.

**What it is not:** A replacement for comprehensive penetration testing, source-code review,
or established commercial security scanners.

---

## Features (v0.1)

- Safe, bounded HTTP reconnaissance
- Security header analysis (A02 — Security Misconfiguration)
- Cookie attribute checks
- Structured findings with evidence and confidence levels
- JSON report output
- Strict scope enforcement and SSRF protection
- Conservative passive-only scanning by default

---

## Installation

### Requirements

- Python 3.11 or later
- pip or uv

### Install from source

```bash
git clone https://github.com/Manav-Gupta08/sentinelscan.git
cd sentinelscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Verify installation

```bash
sentinel --version
sentinel --help
```

---

## Quick Start

```bash
# Show available commands
sentinel --help

# List available checks
sentinel checks list

# Run a passive scan (you must own or have permission to test the target)
sentinel scan https://your-authorized-target.example
```

---

## CLI Reference

```
sentinel scan <URL> [OPTIONS]
  --profile   [passive|active]  Scan profile (default: passive)
  --format    [text|json]       Output format (default: text)
  --output    PATH              Write report to file
  --depth     INTEGER           Max crawl depth (default: 2)
  --timeout   FLOAT             Request timeout in seconds (default: 10.0)
  --verbose                     Enable verbose output

sentinel checks list            List all available checks

sentinel --version              Print scanner version
```

---

## Architecture

```
src/sentinelscan/
├── cli.py          — Typer CLI entry point
├── config.py       — Pydantic-validated configuration
├── scope.py        — Target scope and safety enforcement
├── models.py       — Finding, Evidence, and ScanResult models
├── checks/         — Modular security checks
└── reporting/      — JSON and HTML report generation
```

See [docs/architecture.md](docs/architecture.md) for a full diagram and design decisions.

---

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=sentinelscan --cov-report=term-missing

# Lint
ruff check .

# Format
ruff format .

# Type check
mypy src/
```

---

## Testing

Tests live in `tests/`. Unit tests use local mock servers and never require live internet targets.

```bash
pytest tests/unit/       # Unit tests only
pytest tests/integration/ # Integration tests (requires local test server)
```

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT License](LICENSE) — Copyright (c) 2026 Manav Gupta

---

## Known Limitations (v0.1)

- Passive scanning only; no active/injection testing yet
- No authentication support yet
- Single-host scope only
- No persistent scan history
- No web dashboard (planned for a future phase)
- JavaScript-rendered content is not evaluated
- CVSS scoring not yet implemented

A scan with no findings does **not** mean the target is secure.
