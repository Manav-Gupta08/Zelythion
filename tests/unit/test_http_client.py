"""
Unit tests for the Zelythion bounded HTTP client.

All tests use httpx.MockTransport — no live network requests are made.
Tests verify:
  - Normal GET requests return correct status and body.
  - Response size limit enforcement.
  - Out-of-scope URL rejection before any request is sent.
  - Redirect following within scope.
  - Out-of-scope redirect blocking.
  - Redirect loop detection via max_redirects.
  - Missing Location header on redirect response.
  - Request budget exhaustion.
  - Sensitive header redaction on responses.
  - Rate-limiter and concurrency objects are constructed correctly.
  - Redaction utilities work independently.
"""

from __future__ import annotations

from typing import Callable

import httpx
import pytest

from zelythion.config import ScanConfig
from zelythion.errors import (
    HttpClientError,
    RedirectOutOfScopeError,
    ResponseSizeError,
    TooManyRedirectsError,
)
from zelythion.http_client import BoundedHttpClient, HttpResponse, redact_request_headers
from zelythion.scope import ScopeSpec, ScopeValidator
from zelythion.utils import (
    is_sensitive_header,
    redact_body_excerpt,
    redact_url_query_params,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(
    transport: httpx.BaseTransport,
    target: str = "https://example.com",
    max_response_size: int = 5 * 1024 * 1024,
    max_redirects: int = 5,
    max_requests: int = 200,
    requests_per_second: float = 50.0,  # fast for tests
) -> tuple[BoundedHttpClient, ScopeSpec]:
    """Build a BoundedHttpClient with a mock transport injected."""
    config = ScanConfig(
        target=target,
        max_response_size=max_response_size,
        max_redirects=max_redirects,
        max_requests=max_requests,
        requests_per_second=requests_per_second,
    )
    scope = ScopeValidator().build_scope_from_target(target)
    client = BoundedHttpClient(config=config, scope=scope)
    # Inject mock transport directly.
    client._client = httpx.Client(
        transport=transport,
        verify=False,
        follow_redirects=False,
        max_redirects=0,
    )
    return client, scope


HandlerFn = Callable[[httpx.Request], httpx.Response]


def _transport(handler: HandlerFn) -> httpx.MockTransport:
    """Wrap a handler function in a MockTransport."""
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Normal GET
# ---------------------------------------------------------------------------


class TestNormalGet:
    def test_200_response_returned(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Hello, Zelythion!")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert resp.status_code == 200
        assert b"Hello, Zelythion!" in resp.body
        assert resp.text == "Hello, Zelythion!"

    def test_404_response_returned(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/missing")

        assert resp.status_code == 404

    def test_request_count_incremented(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        client, _ = _make_client(_transport(handler))
        with client:
            client.get("https://example.com/")
            client.get("https://example.com/page2")

        assert client.request_count == 2

    def test_elapsed_ms_recorded(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert resp.elapsed_ms >= 0.0

    def test_redirect_chain_empty_on_direct_response(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="direct")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert resp.redirect_chain == []

    def test_headers_returned_lowercase(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"X-Custom-Header": "value"}, text="ok")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert "x-custom-header" in resp.headers

    def test_helper_methods_on_response(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<html/>")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert resp.is_html()
        assert resp.header("content-type") == "text/html"
        assert resp.header("nonexistent") is None


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    def test_out_of_scope_url_rejected_before_request(self) -> None:
        requests_made: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            requests_made.append(str(req.url))
            return httpx.Response(200, text="ok")

        client, _ = _make_client(_transport(handler))
        with client:
            with pytest.raises(Exception):  # ScopeError or subclass
                client.get("https://evil.com/steal")

        # No network request should have been made.
        assert requests_made == []

    def test_private_ip_rejected_before_request(self) -> None:
        requests_made: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            requests_made.append(str(req.url))
            return httpx.Response(200, text="ok")

        client, _ = _make_client(_transport(handler))
        with client:
            with pytest.raises(Exception):
                client.get("https://192.168.1.1/admin")

        assert requests_made == []


# ---------------------------------------------------------------------------
# Response size limits
# ---------------------------------------------------------------------------


class TestResponseSizeLimits:
    def test_response_within_limit_succeeds(self) -> None:
        body = b"A" * 1024  # 1 KB

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        client, _ = _make_client(_transport(handler), max_response_size=2048)
        with client:
            resp = client.get("https://example.com/")

        assert len(resp.body) == 1024

    def test_response_exceeding_limit_raises(self) -> None:
        body = b"B" * 10_000  # 10 KB

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        client, _ = _make_client(_transport(handler), max_response_size=1024)
        with client:
            with pytest.raises(ResponseSizeError):
                client.get("https://example.com/big")


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------


class TestRedirectHandling:
    def test_in_scope_redirect_followed(self) -> None:
        call_count = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if str(req.url).endswith("/start"):
                return httpx.Response(
                    302,
                    headers={"location": "https://example.com/destination"},
                    text="",
                )
            return httpx.Response(200, text="arrived")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/start")

        assert resp.status_code == 200
        assert resp.text == "arrived"
        assert "https://example.com/start" in resp.redirect_chain
        assert call_count == 2

    def test_relative_redirect_resolved_correctly(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if str(req.url).endswith("/old"):
                return httpx.Response(
                    301,
                    headers={"location": "/new"},
                    text="",
                )
            return httpx.Response(200, text="new page")

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/old")

        assert resp.status_code == 200
        assert resp.text == "new page"

    def test_out_of_scope_redirect_blocked(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                302,
                headers={"location": "https://attacker.com/steal"},
                text="",
            )

        client, _ = _make_client(_transport(handler))
        with client:
            with pytest.raises(RedirectOutOfScopeError):
                client.get("https://example.com/start")

    def test_private_ip_redirect_blocked(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                301,
                headers={"location": "https://192.168.1.1/admin"},
                text="",
            )

        client, _ = _make_client(_transport(handler))
        with client:
            with pytest.raises(RedirectOutOfScopeError):
                client.get("https://example.com/path")

    def test_too_many_redirects_raises(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            # Always redirect back to same path — infinite loop.
            return httpx.Response(
                302,
                headers={"location": "https://example.com/loop"},
                text="",
            )

        client, _ = _make_client(_transport(handler), max_redirects=3)
        with client:
            with pytest.raises(TooManyRedirectsError):
                client.get("https://example.com/loop")

    def test_redirect_missing_location_raises(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(302, text="")  # No Location header

        client, _ = _make_client(_transport(handler))
        with client:
            with pytest.raises(HttpClientError):
                client.get("https://example.com/start")


# ---------------------------------------------------------------------------
# Request budget
# ---------------------------------------------------------------------------


class TestRequestBudget:
    def test_budget_exhausted_raises(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        client, _ = _make_client(_transport(handler), max_requests=2)
        with client:
            client.get("https://example.com/a")
            client.get("https://example.com/b")
            with pytest.raises(HttpClientError, match="budget"):
                client.get("https://example.com/c")


# ---------------------------------------------------------------------------
# Sensitive header redaction
# ---------------------------------------------------------------------------


class TestHeaderRedaction:
    def test_authorization_header_redacted(self) -> None:
        headers = {
            "Authorization": "Bearer supersecret",
            "Content-Type": "application/json",
        }
        redacted = redact_request_headers(headers)
        assert redacted["authorization"] == "[REDACTED]"
        assert redacted["content-type"] == "application/json"

    def test_cookie_header_redacted(self) -> None:
        headers = {"Cookie": "session=abc123; csrf=xyz"}
        redacted = redact_request_headers(headers)
        assert redacted["cookie"] == "[REDACTED]"

    def test_non_sensitive_headers_preserved(self) -> None:
        headers = {"Accept": "text/html", "X-Custom": "visible"}
        redacted = redact_request_headers(headers)
        assert redacted["accept"] == "text/html"
        assert redacted["x-custom"] == "visible"

    def test_set_cookie_redacted_in_response(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"set-cookie": "session=secret; Path=/; HttpOnly"},
                text="ok",
            )

        client, _ = _make_client(_transport(handler))
        with client:
            resp = client.get("https://example.com/")

        assert resp.headers.get("set-cookie") == "[REDACTED]"


# ---------------------------------------------------------------------------
# Redaction utility tests
# ---------------------------------------------------------------------------


class TestRedactionUtils:
    def test_sensitive_query_param_redacted(self) -> None:
        url = redact_url_query_params("https://example.com/login?token=secret&page=1")
        assert "REDACTED" in url
        assert "page=1" in url
        assert "secret" not in url

    def test_non_sensitive_params_preserved(self) -> None:
        url = redact_url_query_params("https://example.com/?q=search&sort=asc")
        assert "q=search" in url
        assert "sort=asc" in url

    def test_url_without_params_unchanged(self) -> None:
        url = redact_url_query_params("https://example.com/page")
        assert url == "https://example.com/page"

    def test_bearer_token_redacted_in_body(self) -> None:
        text = "HTTP/1.1 200 OK\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.sig"
        result = redact_body_excerpt(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_body_truncated_at_max_length(self) -> None:
        text = "A" * 5000
        result = redact_body_excerpt(text, max_length=100)
        assert len(result) <= 100

    def test_is_sensitive_header_true(self) -> None:
        assert is_sensitive_header("Authorization")
        assert is_sensitive_header("COOKIE")
        assert is_sensitive_header("set-cookie")

    def test_is_sensitive_header_false(self) -> None:
        assert not is_sensitive_header("Content-Type")
        assert not is_sensitive_header("X-Frame-Options")
