"""
Zelythion sensitive-data redaction utilities.

These functions are used by the HTTP client, checks, and reporting modules
to ensure that credentials, session tokens, and other secrets never appear
in scan evidence, log output, or reports.

Redaction is one-way: values are replaced with REDACTED_MARKER and cannot
be recovered. This is intentional — evidence must never contain secrets.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Optional

from zelythion.http_client import (
    REDACTED_MARKER,
    SENSITIVE_REQUEST_HEADERS,
    SENSITIVE_RESPONSE_HEADERS,
    redact_request_headers,
)

__all__ = [
    "REDACTED_MARKER",
    "redact_request_headers",
    "redact_response_headers",
    "redact_url_query_params",
    "redact_body_excerpt",
    "is_sensitive_header",
]

# Query parameter names whose values must be redacted in URLs.
SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "token",
        "access_token",
        "api_key",
        "apikey",
        "api-key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "key",
        "session",
        "sessionid",
        "sid",
        "csrf",
        "csrftoken",
        "_token",
        "nonce",
        "sig",
        "signature",
        "client_secret",
    }
)

# Patterns that match common secret-like values in response bodies.
# Used to redact excerpts before storing them in Evidence.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    # Bearer / JWT tokens
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE),
    # AWS access key patterns
    re.compile(r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b"),
    # Generic "password = something" patterns
    re.compile(r'(?i)(password|passwd|secret|token|api[_\-]?key)\s*[=:]\s*["\']?[^\s"\'&<>]{6,}["\']?'),
    # Basic auth in URLs
    re.compile(r"(https?://)([^:@/\s]+:[^@/\s]+@)"),
]


def redact_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Return a copy of response headers with sensitive values replaced.

    Preserves header names (lowercased) so that their presence/absence
    is still observable in evidence.
    """
    return {
        k.lower(): (REDACTED_MARKER if k.lower() in SENSITIVE_RESPONSE_HEADERS else v)
        for k, v in headers.items()
    }


def redact_url_query_params(url: str) -> str:
    """
    Replace values of sensitive query parameters with REDACTED_MARKER.

    Example:
        Input:  https://example.com/login?token=abc123&page=1
        Output: https://example.com/login?token=[REDACTED]&page=1
    """
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        redacted_params: dict[str, list[str]] = {}
        # Use a URL-safe marker value so urlencode doesn't percent-encode brackets.
        _url_safe_marker = "REDACTED"
        for k, values in params.items():
            if k.lower() in SENSITIVE_QUERY_PARAMS:
                redacted_params[k] = [_url_safe_marker] * len(values)
            else:
                redacted_params[k] = values

        new_query = urllib.parse.urlencode(redacted_params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    except Exception:
        # If URL parsing fails, redact the entire query string to be safe.
        return url.split("?")[0] + "?" + REDACTED_MARKER


def redact_body_excerpt(
    text: str,
    max_length: int = 2048,
    url: Optional[str] = None,
) -> str:
    """
    Produce a safe excerpt from a response body for inclusion in evidence.

    Steps:
    1. Truncate to max_length characters.
    2. Apply secret-pattern redaction.
    3. Strip null bytes and other control characters.

    The url parameter is used only for logging context.
    """
    if not text:
        return ""

    excerpt = text[:max_length]

    for pattern in _SECRET_PATTERNS:
        excerpt = pattern.sub(REDACTED_MARKER, excerpt)

    # Strip null bytes and non-printable control characters (except common whitespace).
    excerpt = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", excerpt)

    return excerpt


def is_sensitive_header(name: str) -> bool:
    """Return True if the header name is in either the request or response sensitive set."""
    lower = name.lower()
    return lower in SENSITIVE_REQUEST_HEADERS or lower in SENSITIVE_RESPONSE_HEADERS
