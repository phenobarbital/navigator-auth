"""
Live integration tests for BasicAuth.open_session() (FEAT-096 TASK-046).

Mirrors the `live_app` pattern used in tests/test_basic_auth.py: starts a
real aiohttp server with AuthHandler (BasicAuth only) so `open_session`
exercises the real session middleware (Redis-backed) and the real
IdentityProvider.create_token(). A small test-only route drives
`open_session` directly (bypassing password validation) with a synthetic
user dict, since this module tests the factored-out method itself, not the
password-authentication tail that already covers the "no extras" path in
test_basic_auth.py.

Requirements:
  - PostgreSQL running with the `navigator` database and `auth` schema.
  - Redis running for session storage.
"""

import asyncio
import warnings
import jwt
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient
from navigator_session import SESSION_OBJECT, AUTH_SESSION_OBJECT

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    # Pre-existing environment limitation: the dev/test SECRET_KEY is shorter
    # than PyJWT's recommended HMAC key length. Not in scope for FEAT-096.
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
    pytest.mark.asyncio(loop_scope="module"),
]

TEST_USER_ID = 999001
TEST_USERNAME = "test_open_session_user"
TEST_EMAIL = "test_open_session@example.com"


def _fake_user() -> dict:
    """A user dict shaped like a DEFAULT_MAPPING row (no DB round-trip)."""
    return {
        "user_id": TEST_USER_ID,
        "username": TEST_USERNAME,
        "password": "unused",
        "first_name": "Open",
        "last_name": "Session",
        "email": TEST_EMAIL,
        "enabled": True,
        "superuser": False,
        "last_login": None,
        "title": None,
        "display_name": "Open Session Display",
    }


@pytest_asyncio.fixture(scope="module")
async def open_session_app():
    """
    Build a real AuthHandler(BasicAuth) app and expose a test-only route
    that calls `BasicAuth.open_session` directly with the payload's
    `extra`/`expiration`, returning the resulting dict and the session's
    `max_age` for assertions.
    """
    import navigator_auth.conf as conf

    original_backends = conf.AUTHENTICATION_BACKENDS
    conf.AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",)

    from navigator_auth import AuthHandler
    from navigator_auth.conf import SECRET_KEY, AUTH_JWT_ALGORITHM
    from navigator_auth.responses import JSONResponse

    app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=False)
        auth.setup(app)

    backend = auth.backends["BasicAuth"]
    app["open_session_backend"] = backend

    async def _open_session_view(request: web.Request):
        payload = await request.json()
        extra = payload.get("extra")
        expiration = payload.get("expiration")
        user = _fake_user()
        result = await backend.open_session(
            request, user, extra=extra, expiration=expiration
        )
        session = request.get(SESSION_OBJECT)
        out = {
            "result": {k: v for k, v in result.items() if k != AUTH_SESSION_OBJECT},
            "session_data": result.get(AUTH_SESSION_OBJECT, {}),
            "max_age": session.max_age if session is not None else None,
        }
        return JSONResponse(out, status=200)

    app.router.add_post("/_test/open_session", _open_session_view)

    server = TestServer(app)
    client = TestClient(server)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.start_server()

    # The default AUTH_SUCCESSFUL_CALLBACKS (e.g. resources.auth.saving_troc_user)
    # are production callbacks that expect a real DB-backed user; with the
    # synthetic user used here they are not representative and can block the
    # shared event loop. Disabled here (must be after on_startup, which
    # re-populates `_callbacks` from AUTH_SUCCESSFUL_CALLBACKS);
    # test_open_session_callbacks_invoked below installs a lightweight fake
    # callback to verify the invocation path itself (unchanged by this task).
    backend._callbacks = None

    yield client, SECRET_KEY, AUTH_JWT_ALGORITHM

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()
    conf.AUTHENTICATION_BACKENDS = original_backends


def _decode(token: str, secret, algorithm: str) -> dict:
    return jwt.decode(token, secret, algorithms=[algorithm])


async def test_open_session_default_matches_authenticate(open_session_app):
    """No extras/expiration -> same response/JWT shape as authenticate()."""
    client, secret, algorithm = open_session_app
    resp = await client.post("/_test/open_session", json={})
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    result = data["result"]
    for key in ("token", "username", "user_id", "auth_method", "refresh_token", "expires_in", "token_type"):
        assert key in result, f"Missing {key}: {result}"
    assert result["auth_method"] == "basic"
    claims = _decode(result["token"], secret, algorithm)
    assert "auth_origin" not in claims
    assert "external_expires_at" not in claims
    # No `expiration` override -> untouched, storage-default max_age
    # (unchanged pre-task behaviour); not the 120s cap used elsewhere below.
    assert data["max_age"] != 120


async def test_open_session_extra_merged_both_levels(open_session_app):
    """`extra` lands in userdata top level and in AUTH_SESSION_OBJECT."""
    client, _secret, _alg = open_session_app
    extra = {"auth_origin": "azure", "provider_user_id": "abc-123"}
    resp = await client.post("/_test/open_session", json={"extra": extra})
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    result = data["result"]
    session_data = data["session_data"]
    assert result.get("auth_origin") == "azure"
    assert result.get("provider_user_id") == "abc-123"
    assert session_data.get("auth_origin") == "azure"
    assert session_data.get("provider_user_id") == "abc-123"


async def test_open_session_extra_in_jwt(open_session_app):
    """auth_origin appears in the decoded JWT; unrelated extras don't."""
    client, secret, algorithm = open_session_app
    extra = {"auth_origin": "azure", "provider_user_id": "abc-123"}
    resp = await client.post("/_test/open_session", json={"extra": extra})
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    claims = _decode(data["result"]["token"], secret, algorithm)
    assert claims.get("auth_origin") == "azure"
    # provider_user_id is not one of the mirrored JWT keys per spec.
    assert "provider_user_id" not in claims


async def test_open_session_expiration_caps_jwt_and_session_max_age(open_session_app):
    """expiration=N -> JWT exp-iat ~= N; returned session.max_age == N."""
    client, secret, algorithm = open_session_app
    n = 120
    resp = await client.post("/_test/open_session", json={"expiration": n})
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    claims = _decode(data["result"]["token"], secret, algorithm)
    delta = claims["exp"] - claims["iat"]
    assert abs(delta - n) <= 2
    assert data["max_age"] == n


async def test_open_session_callbacks_invoked(open_session_app):
    """`open_session` invokes configured success callbacks (fire-and-forget)."""
    client, _secret, _alg = open_session_app
    backend = client.app["open_session_backend"]
    calls = []

    async def _fake_callback(request, user, model, **kwargs):
        calls.append((user, kwargs.get("userdata")))

    backend._callbacks = [_fake_callback]
    try:
        resp = await client.post("/_test/open_session", json={})
        assert resp.status == 200, await resp.text()
        data = await resp.json()
        assert data["result"]["username"] == TEST_USERNAME
        # give the fire-and-forget background task a chance to run
        await asyncio.sleep(0.05)
        assert len(calls) == 1
        _called_user, called_userdata = calls[0]
        assert called_userdata is not None
    finally:
        backend._callbacks = None
