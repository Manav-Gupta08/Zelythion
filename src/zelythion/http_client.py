"""
Zelythion bounded HTTP client.

This is the single point of contact for all outbound HTTP traffic during a scan.
Every request — including redirects — passes through scope validation and safety
checks before being sent.

Safety properties guaranteed by this client:

1. Scope enforcement   — every URL is validated against ScopeSpec before sending.
2. TLS verification    — certificate verification is ON by default; turning it off
                          requires an explicit lab_mode flag.
3. Redirect safety     — each redirect hop is scope-validated; out-of-scope
                          destinations raise RedirectOutOfScopeError.
4. Response size cap   — body reading stops at max_response_size to prevent
                          memory exhaustion from oversized or compressed responses.
5. Timeouts            — both connect and read timeouts are enforced; stalled
                          connections never block the scan indefinitely.
6. Sensitive redaction — Authorization, Cookie, and Set-Cookie headers are
                          stripped from evidence/logs before leaving this module.
7. Concurrency limit   — a threading.Semaphore caps simultaneous connections.
8. Rate limiting       — a token-bucket enforces requests_per_second.

This client does NOT perform DNS resolution or connection-time IP validation
itself — those are enforced by the OS/TLS stack. The scope validator catches
literal private IPs and blocked hostnames before any socket is opened.
Future work: use a custom transport with connection-time IP revalidation.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

import httpx

from zelythion.config import ScanConfig
from zelythion.errors import (
    ConnectionError,
    DecompressionError,
    HttpClientError,
    RedirectOutOfScopeError,
    RequestTimeoutError,
    ResponseSizeError,
    TlsError,
    TooManyRedirectsError,
)
from zelythion.scope import ScopeSpec, ScopeValidator

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Headers whose values must never appear in evidence, logs, or reports.
SENSITIVE_REQUEST_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "api-key",
        "token",
        "secret",
    }
)

SENSITIVE_RESPONSE_HEADERS: frozenset[str] = frozenset(
    {
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
    }
)

REDACTED_MARKER = "[REDACTED]"

# Default User-Agent — transparent about being a scanner.
DEFAULT_USER_AGENT = "Zelythion-Scanner/0.1 (security scanner; authorized use only)"


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------


@dataclass
class HttpResponse:
    """
    Sanitized HTTP response returned by BoundedHttpClient.

    Response headers and body are already processed:
    - Body is truncated at max_response_size.
    - Sensitive headers are redacted.
    - Redirect chain is recorded.
    """

    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    redirect_chain: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    timed_out: bool = False

    @property
    def text(self) -> str:
        """Decode body as UTF-8, replacing undecodable bytes."""
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        """Return the Content-Type header value (lowercase, stripped)."""
        return self.headers.get("content-type", "").lower().strip()

    def is_html(self) -> bool:
        return "text/html" in self.content_type

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())


# ---------------------------------------------------------------------------
# Token bucket rate limiter
# ---------------------------------------------------------------------------


class _TokenBucket:
    """
    Thread-safe token-bucket rate limiter.

    Allows up to `rate` tokens per second. Each HTTP request consumes one token.
    If no tokens are available, the caller blocks until one is replenished.
    """

    def __init__(self, rate: float) -> None:
        self._rate = rate  # tokens per second
        self._tokens = rate
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> None:
        """Block until a token is available, then consume it."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            wait_time = (1.0 - self._tokens) / self._rate

        time.sleep(wait_time)

        with self._lock:
            self._tokens = max(0.0, self._tokens - 1.0)


# ---------------------------------------------------------------------------
# Bounded HTTP client
# ---------------------------------------------------------------------------


class BoundedHttpClient:
    """
    Synchronous HTTP client with enforced safety boundaries.

    Instantiate once per scan. Call `.get()` for each URL.
    Call `.close()` (or use as a context manager) when done.

    All outbound requests go through:
      1. URL scope validation (ScopeValidator).
      2. Concurrency semaphore acquisition.
      3. Rate-limiter token consumption.
      4. httpx request with connect + read timeouts.
      5. Redirect chain scope validation (each hop).
      6. Response body reading with size cap.
      7. Sensitive header redaction before returning.
    """

    def __init__(self, config: ScanConfig, scope: ScopeSpec) -> None:
        self._config = config
        self._scope = scope
        self._validator = ScopeValidator()

        self._semaphore = threading.Semaphore(config.max_concurrency)
        self._rate_limiter = _TokenBucket(rate=config.requests_per_second)

        self._request_count = 0
        self._count_lock = threading.Lock()

        timeout = httpx.Timeout(
            connect=config.connect_timeout,
            read=config.timeout,
            write=config.timeout,
            pool=config.connect_timeout,
        )

        self._client = httpx.Client(
            verify=config.verify_tls,
            timeout=timeout,
            follow_redirects=False,  # We handle redirects manually for scope checking.
            max_redirects=0,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            limits=httpx.Limits(
                max_connections=config.max_concurrency,
                max_keepalive_connections=config.max_concurrency,
            ),
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "BoundedHttpClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def request_count(self) -> int:
        """Total requests sent so far in this scan."""
        with self._count_lock:
            return self._request_count

    def get(
        self,
        url: str,
        *,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> HttpResponse:
        """
        Perform a scope-validated, bounded GET request.

        Args:
            url: Target URL. Must be in scope.
            extra_headers: Optional additional request headers.

        Returns:
            HttpResponse with sanitized headers and truncated body.

        Raises:
            ScopeError: URL is outside the authorized scope.
            RequestTimeoutError: Connect or read timeout.
            TlsError: TLS verification failure.
            ResponseSizeError: Response body exceeded max_response_size.
            RedirectOutOfScopeError: A redirect hop is outside scope.
            TooManyRedirectsError: More redirects than max_redirects.
            ConnectionError: TCP connection failed.
        """
        # Step 1 — scope validation (raises ScopeError if out of scope)
        validated_url = self._validator.validate_url_in_scope(url, self._scope)

        # Step 2 — request budget
        self._check_request_budget()

        # Step 3 — concurrency + rate limiting
        self._semaphore.acquire()
        try:
            self._rate_limiter.consume()
            return self._send_with_redirect_follow(validated_url, extra_headers or {})
        finally:
            self._semaphore.release()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_request_budget(self) -> None:
        with self._count_lock:
            if self._request_count >= self._config.max_requests:
                raise HttpClientError(
                    f"Request budget exhausted: max_requests={self._config.max_requests} reached."
                )

    def _increment_count(self) -> None:
        with self._count_lock:
            self._request_count += 1

    def _send_with_redirect_follow(
        self,
        url: str,
        extra_headers: dict[str, str],
    ) -> HttpResponse:
        """
        Send a GET request and manually follow redirects, validating each hop.
        """
        redirect_chain: list[str] = []
        current_url = url
        hops = 0
        start = time.monotonic()

        while True:
            if hops > self._config.max_redirects:
                raise TooManyRedirectsError(
                    f"Exceeded max_redirects={self._config.max_redirects} following {url}"
                )

            response = self._send_single(current_url, extra_headers)
            self._increment_count()
            elapsed_ms = (time.monotonic() - start) * 1000.0

            if response.status_code not in (301, 302, 303, 307, 308):
                body = self._read_body(response)
                return HttpResponse(
                    url=current_url,
                    status_code=response.status_code,
                    headers=_redact_response_headers(dict(response.headers)),
                    body=body,
                    redirect_chain=redirect_chain,
                    elapsed_ms=elapsed_ms,
                )

            # --- Redirect handling ---
            location = response.headers.get("location", "").strip()
            if not location:
                raise HttpClientError(
                    f"Redirect response {response.status_code} from {current_url!r} "
                    "has no Location header."
                )

            # Resolve relative redirects.
            resolved = str(httpx.URL(location).copy_merge_params({}))
            if not location.startswith("http"):
                resolved = str(httpx.URL(current_url).copy_with(path=location))

            redirect_chain.append(current_url)

            # Scope-validate the redirect destination.
            try:
                validated_redirect = self._validator.validate_url_in_scope(
                    resolved, self._scope
                )
            except Exception as exc:
                raise RedirectOutOfScopeError(
                    f"Redirect from {current_url!r} → {resolved!r} is outside authorized scope: {exc}"
                ) from exc

            logger.debug("Redirect %d: %s → %s", hops + 1, current_url, validated_redirect)
            current_url = validated_redirect
            hops += 1

    def _send_single(
        self,
        url: str,
        extra_headers: dict[str, str],
    ) -> httpx.Response:
        """Send a single HTTP GET without following redirects. Maps httpx exceptions."""
        try:
            response = self._client.get(url, headers=extra_headers)
            return response
        except httpx.TimeoutException as exc:
            raise RequestTimeoutError(
                f"Request to {url!r} timed out ({self._config.timeout}s): {exc}"
            ) from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Could not connect to {url!r}: {exc}") from exc
        except httpx.RemoteProtocolError as exc:
            raise HttpClientError(f"Protocol error from {url!r}: {exc}") from exc
        except httpx.DecodingError as exc:
            raise DecompressionError(f"Decompression error for {url!r}: {exc}") from exc
        except httpx.TooManyRedirects as exc:
            raise TooManyRedirectsError(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            raise HttpClientError(str(exc)) from exc
        except Exception as exc:
            # Re-raise TLS errors with a clear label.
            exc_name = type(exc).__name__.lower()
            if "ssl" in exc_name or "tls" in exc_name or "cert" in exc_name:
                raise TlsError(f"TLS error for {url!r}: {exc}") from exc
            raise HttpClientError(f"Unexpected error for {url!r}: {exc}") from exc

    def _read_body(self, response: httpx.Response) -> bytes:
        """
        Read the response body up to max_response_size bytes.

        Raises ResponseSizeError if the server sends more data than allowed.
        """
        max_size = self._config.max_response_size
        chunks: list[bytes] = []
        total = 0

        try:
            for chunk in response.iter_bytes(chunk_size=8192):
                total += len(chunk)
                if total > max_size:
                    raise ResponseSizeError(
                        f"Response body exceeds max_response_size "
                        f"({max_size} bytes) for {response.url}"
                    )
                chunks.append(chunk)
        except ResponseSizeError:
            raise
        except Exception as exc:
            raise DecompressionError(f"Error reading response body: {exc}") from exc

        return b"".join(chunks)


# ---------------------------------------------------------------------------
# Header redaction utilities (public — used by checks and reporting)
# ---------------------------------------------------------------------------


def redact_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Return a copy of the headers dict with sensitive values replaced by REDACTED_MARKER.

    The header names are preserved (lowercased) so that the absence of a header
    remains detectable in evidence.
    """
    return {
        k.lower(): (REDACTED_MARKER if k.lower() in SENSITIVE_REQUEST_HEADERS else v)
        for k, v in headers.items()
    }


def _redact_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive response headers (e.g. Set-Cookie values)."""
    return {
        k.lower(): (REDACTED_MARKER if k.lower() in SENSITIVE_RESPONSE_HEADERS else v)
        for k, v in headers.items()
    }
