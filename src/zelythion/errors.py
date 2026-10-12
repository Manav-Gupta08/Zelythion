"""
Zelythion error types.

Centralised exception hierarchy so callers can catch at the right granularity
without importing from scattered modules.
"""

from __future__ import annotations


class ZelythionError(Exception):
    """Base exception for all Zelythion errors."""


# ---------------------------------------------------------------------------
# Scope / destination errors (re-exported from scope.py for convenience)
# ---------------------------------------------------------------------------

from zelythion.scope import ScopeError, PrivateDestinationError, SchemeError  # noqa: E402, F401


# ---------------------------------------------------------------------------
# HTTP / network errors
# ---------------------------------------------------------------------------


class HttpClientError(ZelythionError):
    """Base class for HTTP client errors."""


class RequestTimeoutError(HttpClientError):
    """A network operation exceeded the configured timeout."""


class ConnectionError(HttpClientError):  # noqa: A001  (intentional shadow of builtin)
    """TCP connection could not be established."""


class TlsError(HttpClientError):
    """TLS handshake or certificate verification failed."""


class ResponseSizeError(HttpClientError):
    """Response body exceeded the configured maximum size."""


class TooManyRedirectsError(HttpClientError):
    """Response chain exceeded the configured redirect limit."""


class RedirectOutOfScopeError(HttpClientError, ScopeError):
    """A redirect destination is outside the authorized scan scope."""


class DecompressionError(HttpClientError):
    """Response decompression failed or exceeded limits."""


class ScanCancelledError(ZelythionError):
    """The scan was cancelled by the operator."""
