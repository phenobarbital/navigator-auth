"""Tests for the CSRF double-submit-cookie protection (navigator_auth/middlewares/csrf.py).

Covers:
- token generation/verification (navigator_auth/libs/csrf.py)
- the cookie-only-session detection used to scope the check
- the middleware's request-side rejection and response-side cookie issuance
"""
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.libs.csrf import generate_csrf_token, verify_csrf_token
from navigator_auth.middlewares import csrf as csrf_module
from navigator_auth.middlewares.csrf import (
    csrf_middleware,
    _is_cookie_only_session,
    _valid_csrf_request,
)

SECRET = b"unit-test-secret-key-0123456789"
SESSION_ID = "session-abc-123"


# ---------------------------------------------------------------------------
# Token generation / verification
# ---------------------------------------------------------------------------

def test_generate_and_verify_roundtrip():
    token = generate_csrf_token(SECRET, SESSION_ID)
    assert verify_csrf_token(SECRET, SESSION_ID, token) is True


def test_verify_rejects_wrong_session():
    token = generate_csrf_token(SECRET, SESSION_ID)
    assert verify_csrf_token(SECRET, "other-session", token) is False


def test_verify_rejects_tampered_signature():
    token = generate_csrf_token(SECRET, SESSION_ID)
    nonce, signature = token.split(".", 1)
    tampered = f"{nonce}.{signature[:-1]}{'A' if signature[-1] != 'A' else 'B'}"
    assert verify_csrf_token(SECRET, SESSION_ID, tampered) is False


def test_verify_rejects_malformed_token():
    assert verify_csrf_token(SECRET, SESSION_ID, "not-a-valid-token") is False
    assert verify_csrf_token(SECRET, SESSION_ID, "") is False
    assert verify_csrf_token(SECRET, "", "whatever.sig") is False


# ---------------------------------------------------------------------------
# Cookie-only-session detection
# ---------------------------------------------------------------------------

def test_cookie_only_session_true_when_authenticated_without_auth_header():
    request = make_mocked_request("POST", "/")
    request["authenticated"] = True
    assert _is_cookie_only_session(request) is True


def test_cookie_only_session_false_with_authorization_header():
    request = make_mocked_request(
        "POST", "/", headers={"Authorization": "Bearer sometoken"}
    )
    request["authenticated"] = True
    assert _is_cookie_only_session(request) is False


def test_cookie_only_session_false_when_not_authenticated():
    request = make_mocked_request("POST", "/")
    assert _is_cookie_only_session(request) is False


# ---------------------------------------------------------------------------
# _valid_csrf_request
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _patch_secret(monkeypatch):
    monkeypatch.setattr(csrf_module, "SECRET_KEY", SECRET)


def test_valid_csrf_request_accepts_matching_signed_token():
    token = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "POST",
        "/",
        headers={csrf_module.CSRF_HEADER_NAME: token, "Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={token}"},
    )
    assert _valid_csrf_request(request, SESSION_ID) is True


def test_valid_csrf_request_rejects_cookie_header_mismatch():
    token = generate_csrf_token(SECRET, SESSION_ID)
    other = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "POST",
        "/",
        headers={csrf_module.CSRF_HEADER_NAME: token, "Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={other}"},
    )
    assert _valid_csrf_request(request, SESSION_ID) is False


def test_valid_csrf_request_rejects_missing_header():
    token = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "POST", "/", headers={"Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={token}"}
    )
    assert _valid_csrf_request(request, SESSION_ID) is False


def test_valid_csrf_request_rejects_missing_session_id():
    token = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "POST",
        "/",
        headers={csrf_module.CSRF_HEADER_NAME: token, "Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={token}"},
    )
    assert _valid_csrf_request(request, None) is False


# ---------------------------------------------------------------------------
# Full middleware behaviour
# ---------------------------------------------------------------------------

async def _ok_handler(_request):
    return web.Response(text="ok")


@pytest.mark.asyncio
async def test_middleware_rejects_unsafe_cookie_only_request_without_token():
    request = make_mocked_request("POST", "/")
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    with pytest.raises(web.HTTPForbidden):
        await csrf_middleware(request, _ok_handler)


@pytest.mark.asyncio
async def test_middleware_allows_unsafe_request_with_valid_token():
    token = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "POST",
        "/",
        headers={csrf_module.CSRF_HEADER_NAME: token, "Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={token}"},
    )
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    response = await csrf_middleware(request, _ok_handler)
    assert response.status == 200


@pytest.mark.asyncio
async def test_middleware_exempts_bearer_authenticated_requests():
    request = make_mocked_request(
        "POST", "/", headers={"Authorization": "Bearer sometoken"}
    )
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    # No CSRF cookie/header at all -- must NOT be rejected, since this
    # request cannot be forged cross-site.
    response = await csrf_middleware(request, _ok_handler)
    assert response.status == 200


@pytest.mark.asyncio
async def test_middleware_issues_cookie_when_missing_on_authenticated_response():
    request = make_mocked_request("GET", "/")
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    response = await csrf_middleware(request, _ok_handler)
    set_cookie = response.cookies.get(csrf_module.CSRF_COOKIE_NAME)
    assert set_cookie is not None
    assert verify_csrf_token(SECRET, SESSION_ID, set_cookie.value) is True


@pytest.mark.asyncio
async def test_middleware_does_not_reissue_a_still_valid_cookie():
    token = generate_csrf_token(SECRET, SESSION_ID)
    request = make_mocked_request(
        "GET", "/", headers={"Cookie": f"{csrf_module.CSRF_COOKIE_NAME}={token}"}
    )
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    response = await csrf_middleware(request, _ok_handler)
    assert csrf_module.CSRF_COOKIE_NAME not in response.cookies


@pytest.mark.asyncio
async def test_middleware_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(csrf_module, "ENABLE_CSRF_PROTECTION", False)
    request = make_mocked_request("POST", "/")
    request["authenticated"] = True
    request[csrf_module.SESSION_ID] = SESSION_ID

    response = await csrf_middleware(request, _ok_handler)
    assert response.status == 200
