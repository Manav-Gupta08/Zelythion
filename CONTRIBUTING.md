# Contributing to Zelythion

Thank you for your interest in contributing to Zelythion!

## Ground Rules

1. **Authorization first**: Never use Zelythion against targets you do not own or have explicit written permission to test.
2. **Security by design**: Every contribution must consider security implications.
3. **Evidence before conclusions**: Do not introduce checks that fire without sufficient evidence.
4. **Tests are mandatory**: Every new feature or check must include tests.
5. **No fabricated results**: Do not fabricate test results, coverage numbers, or scan findings.

## Development Setup

```bash
git clone https://github.com/Manav-Gupta08/zelythion.git
cd zelythion
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Checks

```bash
# All tests
pytest

# With coverage
pytest --cov=zelythion --cov-report=term-missing

# Lint
ruff check .

# Format
ruff format .

# Type check
mypy src/
```

## Submitting a Pull Request

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Make your changes with focused, well-described commits.
4. Add or update tests.
5. Update relevant documentation.
6. Open a Pull Request against `main`.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.
Do **not** open a public issue for security vulnerabilities.

## Code Style

- Follow existing code conventions.
- Use type annotations throughout.
- Document public functions and classes.
- Keep checks modular and focused.

## Commit Message Format

Use short, descriptive imperative-mood titles:
- `Add cookie SameSite attribute check`
- `Fix redirect scope validation`
- `Add TLS certificate expiry test`

Avoid:
- `fix`
- `update`
- `changes`
- `wip`
