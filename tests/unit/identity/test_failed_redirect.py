"""Tests for the real `ExternalAuth.failed_redirect` (FEAT-104, TASK-116).

Deliberately calls the real method. `test_link_flow.py:TestFinishIdentityLink`
replaces it with a MagicMock, so those tests pass today while the method is
still unsafe.
"""
from urllib.parse import parse_qs, urlparse

from aiohttp.test_utils import make_mocked_request

from navigator_auth.libs.sanitize import HEADER_FORBIDDEN
from .conftest import make_backend

FAILED_URL = "https://app.example.com/login/failed"


def _backend():
    from navigator_auth.backends.github import GithubAuth

    backend = make_backend(GithubAuth)
    backend.get_failed_redirect_url = lambda request: FAILED_URL
    return backend


def _redirect(**kwargs):
    request = make_mocked_request("GET", "/auth/github/callback/")
    return _backend().failed_redirect(request, **kwargs)


class TestFailedRedirectHeaderSafety:
    def test_multiline_message_yields_single_line_header(self):
        """The FEAT-104 crash: a ValidationError's text has newlines."""
        resp = _redirect(message="UserIdentity: errors\nHint: check payload")
        value = resp.headers["x-message"]
        assert "\n" not in value and "\r" not in value
        assert HEADER_FORBIDDEN.search(value) is None

    def test_crlf_payload_injects_no_header(self):
        """A CRLF payload must not become a second header."""
        resp = _redirect(message="boom\r\nSet-Cookie: evil=1")
        assert "Set-Cookie" not in resp.headers

    def test_error_code_is_sanitized_too(self):
        """`error` is a public parameter with no enforcement behind it."""
        resp = _redirect(error="E\r\nX-Injected: 1")
        assert "X-Injected" not in resp.headers
        assert HEADER_FORBIDDEN.search(resp.headers["x-error"]) is None

    def test_headers_and_query_agree(self):
        """The sanitized value appears in both the header and the URL."""
        resp = _redirect(error="E\nX", message="line one\nline two")
        query = parse_qs(urlparse(str(resp.location)).query)
        assert query["message"] == [resp.headers["x-message"]]
        assert query["error"] == [resp.headers["x-error"]]

    def test_clean_message_passes_through(self):
        """No regression: an ordinary message is unchanged."""
        resp = _redirect(error="ERROR_X", message="Access denied")
        assert resp.headers["x-message"] == "Access denied"
        assert resp.headers["x-error"] == "ERROR_X"
