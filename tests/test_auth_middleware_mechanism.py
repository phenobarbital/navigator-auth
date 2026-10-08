"""Integration tests for ``AuthHandler._auth_middleware`` recording the
authentication mechanism (``request[AUTH_MECHANISM_KEY]``) and for the CSRF
middleware acting on it (``navigator_auth/middlewares/csrf.py``).

A real aiohttp server is started with ``AuthHandler(secure_cookies=True,
enable_authdb=False, backends=("...NoAuth",))``, so the only authentication
paths are the two in ``_auth_middleware`` itself: the bearer-token path and the
``elif self.secure_cookies`` session-cookie fallback (``NoAuth`` registers no
middleware of its own). The session lives in the
real Redis-backed storage; a test-only route (excluded from authentication)
creates it, and the tests then present it either as a JWT (``Authorization:
Bearer``) or as the session cookie.

Requirements:
  - Redis running (``navigator_session.conf.SESSION_URL``).
"""

from http.cookies import SimpleCookie
import warnings

import pytest
import pytest_asyncio
from aiohttp import DummyCookieJar, web
from aiohttp.test_utils import TestClient, TestServer
from navigator_session import SESSION_ID, SESSION_KEY

from navigator_auth.conf import (
    AUTH_MECHANISM_BEARER,
    AUTH_MECHANISM_COOKIE,
    AUTH_MECHANISM_KEY,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SECRET_KEY,
)
from navigator_auth.libs.csrf import generate_csrf_token, verify_csrf_token

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]

TEST_IDENTITY = "test_auth_mechanism_user"
TEST_EMAIL = "test_auth_mechanism@example.com"


@pytest_asyncio.fixture(scope="module")
async def mechanism_app():
    """A real ``AuthHandler`` app plus two test-only routes.

    ``POST /_test/session`` (excluded from auth) creates a Redis session holding
    a user and returns its id. ``* /_test/whoami`` (protected) echoes what the
    middlewares left on the request.
    """
    from navigator_auth import AuthHandler
    from navigator_auth.identities import AuthUser

    app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=True, enable_authdb=False, backends=("navigator_auth.backends.NoAuth",))
        auth.setup(app)

    storage = auth.session.storage

    async def _create_session(request: web.Request):
        request[SESSION_KEY] = TEST_IDENTITY
        session = await storage.new_session(request, {SESSION_KEY: TEST_IDENTITY})
        user = AuthUser(id=TEST_IDENTITY, username=TEST_IDENTITY, email=TEST_EMAIL)
        await session.save_encoded_data(request, "user", user)
        return web.json_response({"session_id": request[SESSION_ID]})

    async def _whoami(request: web.Request):
        user = getattr(request, "user", None)
        return web.json_response(
            {
                "authenticated": request.get("authenticated", False),
                "mechanism": request.get(AUTH_MECHANISM_KEY),
                "session_id": request.get(SESSION_ID),
                "user": getattr(user, "username", None),
            }
        )

    app.router.add_post("/_test/session", _create_session)
    app.router.add_route("*", "/_test/whoami", _whoami)
    auth.add_exclude_list("/_test/session")

    server = TestServer(app)
    # No cookie jar: every test states its credentials explicitly.
    client = TestClient(server, cookie_jar=DummyCookieJar())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.start_server()

    yield client, auth

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()


@pytest_asyncio.fixture(scope="module")
async def session_id(mechanism_app):
    client, _ = mechanism_app
    resp = await client.post("/_test/session")
    assert resp.status == 200, await resp.text()
    return (await resp.json())["session_id"]


def _session_cookie(auth, sid: str) -> str:
    """The ``Cookie`` header value the browser would send for this session."""
    storage = auth.session.storage
    cookie = SimpleCookie()
    cookie[storage.cookie_name] = storage._encoder({"session_id": sid})
    return cookie.output(header="", sep="").strip()


def _bearer(auth, sid: str) -> str:
    token, _, _, scheme = auth._idp.create_token(
        data={SESSION_ID: sid, SESSION_KEY: TEST_IDENTITY, "username": TEST_IDENTITY}
    )
    return f"{scheme} {token}"


def _csrf_headers(sid: str) -> dict:
    token = generate_csrf_token(SECRET_KEY, sid)
    cookie = SimpleCookie()
    cookie[CSRF_COOKIE_NAME] = token
    return {CSRF_HEADER_NAME: token, "Cookie": cookie.output(header="", sep="").strip()}


# ---------------------------------------------------------------------------
# No credential
# ---------------------------------------------------------------------------


async def test_no_credential_is_unauthorized(mechanism_app):
    client, _ = mechanism_app
    resp = await client.get("/_test/whoami")
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Bearer path
# ---------------------------------------------------------------------------


async def test_bearer_records_bearer_mechanism(mechanism_app, session_id):
    client, auth = mechanism_app
    resp = await client.get("/_test/whoami", headers={"Authorization": _bearer(auth, session_id)})
    assert resp.status == 200, await resp.text()
    body = await resp.json()
    assert body["authenticated"] is True
    assert body["mechanism"] == AUTH_MECHANISM_BEARER
    assert body["session_id"] == session_id
    assert body["user"] == TEST_IDENTITY
    # not a cookie session: no CSRF cookie is issued
    assert CSRF_COOKIE_NAME not in resp.cookies


async def test_bearer_unsafe_request_is_exempt_from_csrf(mechanism_app, session_id):
    client, auth = mechanism_app
    resp = await client.post("/_test/whoami", headers={"Authorization": _bearer(auth, session_id)})
    assert resp.status == 200, await resp.text()
    assert (await resp.json())["mechanism"] == AUTH_MECHANISM_BEARER


# ---------------------------------------------------------------------------
# Cookie path (``elif self.secure_cookies``)
# ---------------------------------------------------------------------------


async def test_cookie_records_cookie_mechanism_and_issues_csrf_cookie(mechanism_app, session_id):
    client, auth = mechanism_app
    resp = await client.get("/_test/whoami", headers={"Cookie": _session_cookie(auth, session_id)})
    assert resp.status == 200, await resp.text()
    body = await resp.json()
    assert body["authenticated"] is True
    assert body["mechanism"] == AUTH_MECHANISM_COOKIE
    assert body["session_id"] == session_id
    assert body["user"] == TEST_IDENTITY
    csrf_cookie = resp.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_cookie is not None
    assert verify_csrf_token(SECRET_KEY, session_id, csrf_cookie.value) is True


async def test_cookie_unsafe_request_without_csrf_is_forbidden(mechanism_app, session_id):
    client, auth = mechanism_app
    resp = await client.post("/_test/whoami", headers={"Cookie": _session_cookie(auth, session_id)})
    assert resp.status == 403
    assert "CSRF" in (resp.reason or "")


async def test_cookie_unsafe_request_with_csrf_is_allowed(mechanism_app, session_id):
    client, auth = mechanism_app
    csrf = _csrf_headers(session_id)
    headers = {
        CSRF_HEADER_NAME: csrf[CSRF_HEADER_NAME],
        "Cookie": f"{_session_cookie(auth, session_id)}; {csrf['Cookie']}",
    }
    resp = await client.post("/_test/whoami", headers=headers)
    assert resp.status == 200, await resp.text()
    assert (await resp.json())["mechanism"] == AUTH_MECHANISM_COOKIE


async def test_cookie_session_cannot_opt_out_with_junk_apikey(mechanism_app, session_id):
    """A cookie session must not skip the CSRF check by appending ``?apikey=``.

    With ``APIKeyAuth`` registered the junk key is rejected even earlier (401);
    here no API-key backend is loaded, so the request reaches the CSRF
    middleware as a cookie session and is refused there.
    """
    client, auth = mechanism_app
    resp = await client.post("/_test/whoami?apikey=junk", headers={"Cookie": _session_cookie(auth, session_id)})
    assert resp.status == 403
