"""FEAT-108 M4 — ``@is_authenticated`` backend loop (D1, D2, FEAT-106 MFA)."""

from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, MagicMock, patch
import warnings

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp import DummyCookieJar
from aiohttp.test_utils import TestClient, TestServer
from navigator_session import SESSION_ID, SESSION_KEY

from navigator_auth import AuthHandler
from navigator_auth.backends.abstract import BaseAuthBackend
from navigator_auth.backends.noauth import AnonymousUser, NoAuth
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.decorators import allow_anonymous, is_authenticated
from navigator_auth.exceptions import MfaSignal


def _backend(*, result=None, raises=None, anonymous=False) -> MagicMock:
    """Build a backend double with an explicit anonymous marker."""
    backend = MagicMock()
    backend._anonymous_auth = anonymous
    backend.authenticate = AsyncMock(return_value=result, side_effect=raises)
    return backend


def _request(backends: dict) -> MagicMock:
    """Build a request double with the configured authentication backends."""
    request = MagicMock(spec=web.Request)
    request.method = "GET"
    request.path = "/api/v1/me"
    request.app = {AUTH_EXCLUDE_LIST_KEY: [], "auth": MagicMock(backends=backends)}
    request.get = lambda key, default=None: default
    request.allow_anonymous = False
    return request


def test_noauth_class_flag():
    """NoAuth is explicitly identified as a guest backend."""
    assert NoAuth._anonymous_auth is True
    assert BaseAuthBackend._anonymous_auth is False


@pytest.mark.asyncio
async def test_anonymous_backend_is_never_called():
    """Anonymous backends cannot authenticate a protected function handler."""
    guest = _backend(result={"user": "guest"}, anonymous=True)
    handler = AsyncMock(return_value=web.Response(status=200))

    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(handler)(_request({"NoAuth": guest}))

    guest.authenticate.assert_not_awaited()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_unexpected_error_is_logged_and_skipped():
    """Unexpected backend errors are logged and do not prevent later success."""
    first = _backend(raises=TypeError("token-secret-value"))
    second = _backend(result={"user": "demo"})
    handler = AsyncMock(return_value=web.Response(status=200))

    with patch("navigator_auth.decorators.logger") as log:
        response = await is_authenticated()(handler)(_request({"A": first, "B": second}))

    assert response.status == 200
    handler.assert_awaited_once()
    log.exception.assert_called_once()
    log_args = log.exception.call_args.args
    assert log_args[0] == "is_authenticated: backend %s failed; trying the next one"
    assert log_args[1] == "A"
    assert "token-secret-value" not in str(log.exception.call_args)


@pytest.mark.asyncio
async def test_unexpected_error_only_backend_gives_401():
    """An unexpected error from the only backend fails closed with 401."""
    only = _backend(raises=TypeError("boom"))

    with patch("navigator_auth.decorators.logger"):
        with pytest.raises(web.HTTPUnauthorized):
            await is_authenticated()(AsyncMock())(_request({"A": only}))


@pytest.mark.asyncio
async def test_mfa_signal_still_stops_the_loop():
    """MFA remains terminal and prevents a later backend from authenticating."""
    first = _backend(raises=MfaSignal("second factor required"))
    second = _backend(result={"user": "demo"})

    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(AsyncMock())(_request({"A": first, "B": second}))

    second.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_method_wrapper_same_semantics():
    """Class-based views share anonymous, error, and MFA backend semantics."""

    class ProtectedView:
        def __init__(self, request):
            self.request = request

        async def get(self):
            return web.Response(status=200)

    guest = _backend(result={"user": "guest"}, anonymous=True)
    error = _backend(raises=TypeError("boom"))
    success = _backend(result={"user": "demo"})
    decorated = is_authenticated()(ProtectedView)

    with patch("navigator_auth.decorators.logger") as log:
        response = await decorated(_request({"guest": guest, "error": error, "success": success})).get()

    assert response.status == 200
    guest.authenticate.assert_not_awaited()
    error.authenticate.assert_awaited_once()
    success.authenticate.assert_awaited_once()
    log.exception.assert_called_once()

    mfa = _backend(raises=MfaSignal("second factor required"))
    later = _backend(result={"user": "demo"})
    with pytest.raises(web.HTTPUnauthorized):
        await decorated(_request({"mfa": mfa, "later": later})).get()
    later.authenticate.assert_not_awaited()


# --- FEAT-108 AC6a: restored guest sessions (real Redis sessions) -----------------------------

@pytest_asyncio.fixture(scope="module")
async def restored_guest_app():
    """Provide protected and explicitly anonymous routes over real sessions."""
    app = web.Application()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(
            secure_cookies=True,
            enable_authdb=False,
            backends=("navigator_auth.backends.NoAuth",),
            authz_backends=[],
        )
        auth.setup(app)

    storage = auth.session.storage

    async def create_session(request: web.Request) -> web.Response:
        """Create a pre-change encoded guest or normal user session."""
        try:
            payload = await request.json()
            kind = payload["kind"]
            identity = f"restored-{kind}"
            request[SESSION_KEY] = identity
            session = await storage.new_session(request, {SESSION_KEY: identity})
            if kind == "guest":
                user = AnonymousUser(id=identity, username=identity, email=f"{identity}@example.com")
            else:
                from navigator_auth.identities import AuthUser

                user = AuthUser(id=identity, username=identity, email=f"{identity}@example.com")
            await session.save_encoded_data(request, "user", user)
            return web.json_response({"session_id": request[SESSION_ID]})
        except Exception as exc:
            pytest.skip(f"Redis session storage unavailable: {exc}")

    @is_authenticated()
    async def protected_function(request: web.Request) -> web.Response:
        """Return success from a protected function handler."""
        return web.Response(status=200)

    @is_authenticated()
    class ProtectedView(web.View):
        """Return success from a protected class-based handler."""

        async def get(self) -> web.Response:
            return web.Response(status=200)

    @is_authenticated()
    async def excluded_handler(request: web.Request) -> web.Response:
        """Return success when the path is explicitly excluded."""
        return web.Response(status=200)

    @allow_anonymous()
    @is_authenticated()
    async def anonymous_handler(request: web.Request) -> web.Response:
        """Return success when the handler explicitly allows anonymous access."""
        return web.Response(status=200)

    app.router.add_post("/_test/session", create_session)
    app.router.add_get("/_test/protected-function", protected_function)
    app.router.add_get("/_test/protected-view", ProtectedView)
    app.router.add_get("/_test/excluded", excluded_handler)
    app.router.add_get("/_test/anonymous", anonymous_handler)
    auth.add_exclude_list("/_test/session")
    auth.add_exclude_list("/_test/excluded")

    server = TestServer(app)
    client = TestClient(server, cookie_jar=DummyCookieJar())
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            await client.start_server()
    except Exception as exc:
        await client.close()
        pytest.skip(f"Redis session storage unavailable: {exc}")

    yield client, auth

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        await client.close()


def _session_cookie(auth, session_id: str) -> str:
    """Build the explicit session cookie for a stored session id."""
    cookie = SimpleCookie()
    cookie[auth.session.storage.cookie_name] = auth.session.storage._encoder({"session_id": session_id})
    return cookie.output(header="", sep="").strip()


def _session_bearer(auth, session_id: str, identity: str) -> str:
    """Build a bearer token carrying the stored session id."""
    token, _, _, scheme = auth._idp.create_token(
        data={SESSION_ID: session_id, SESSION_KEY: identity, "username": identity}
    )
    return f"{scheme} {token}"


async def _create_session(client: TestClient, kind: str) -> str:
    """Create a real serialized session and return its id."""
    response = await client.post("/_test/session", json={"kind": kind})
    assert response.status == 200, await response.text()
    return (await response.json())["session_id"]


@pytest.mark.asyncio(loop_scope="module")
async def test_existing_guest_sessions_rejected(restored_guest_app):
    """Reject restored guests before shortcuts while preserving explicit exemptions."""
    client, auth = restored_guest_app
    guest_session = await _create_session(client, "guest")
    normal_session = await _create_session(client, "normal")

    for session_id, identity, expected_status in (
        (guest_session, "restored-guest", 401),
        (normal_session, "restored-normal", 200),
    ):
        credentials = (
            {"Cookie": _session_cookie(auth, session_id)},
            {"Authorization": _session_bearer(auth, session_id, identity)},
        )
        for headers in credentials:
            for path in ("/_test/protected-function", "/_test/protected-view"):
                response = await client.get(path, headers=headers)
                assert response.status == expected_status, (path, headers, await response.text())

    for path in ("/_test/excluded", "/_test/anonymous"):
        for headers in (
            {"Cookie": _session_cookie(auth, guest_session)},
            {"Authorization": _session_bearer(auth, guest_session, "restored-guest")},
        ):
            response = await client.get(path, headers=headers)
            assert response.status == 200, (path, headers, await response.text())
