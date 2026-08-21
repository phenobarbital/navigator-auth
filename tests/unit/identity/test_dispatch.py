"""Unit tests for ExternalAuth callback dispatch and token_request."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import AuthException


def _make_backend():
    """A concrete ExternalAuth without running __init__ machinery."""
    from navigator_auth.backends.external import ExternalAuth

    class _Concrete(ExternalAuth):
        async def authenticate(self, request):  # pragma: no cover
            raise NotImplementedError

        async def auth_callback(self, request):  # pragma: no cover
            raise NotImplementedError

        async def logout(self, request):  # pragma: no cover
            pass

        async def finish_logout(self, request):  # pragma: no cover
            pass

        async def check_credentials(self, request):  # pragma: no cover
            return True

    backend = object.__new__(_Concrete)
    backend._service_name = "testsvc"
    backend.logger = MagicMock()
    backend._flow_store = MagicMock()
    return backend


class TestAuthCallbackDispatch:
    @pytest.mark.asyncio
    async def test_link_state_routes_to_finish_identity_link(self):
        backend = _make_backend()
        flow = {"user_id": 7, "flow": "identity_link"}
        backend._flow_store.consume_link = AsyncMock(return_value=flow)
        backend.finish_identity_link = AsyncMock(
            return_value=web.Response(text="linked")
        )
        backend.auth_callback = AsyncMock()
        request = make_mocked_request(
            "GET", "/auth/testsvc/callback/?state=abc123&code=xyz"
        )
        response = await backend._auth_callback_dispatch(request)
        backend.finish_identity_link.assert_awaited_once()
        args = backend.finish_identity_link.await_args.args
        assert args[1] == flow
        backend.auth_callback.assert_not_awaited()
        assert response.text == "linked"

    @pytest.mark.asyncio
    async def test_unknown_state_falls_through_to_login(self):
        backend = _make_backend()
        backend._flow_store.consume_link = AsyncMock(return_value=None)
        backend.finish_identity_link = AsyncMock()
        backend.auth_callback = AsyncMock(
            return_value=web.Response(text="login")
        )
        request = make_mocked_request(
            "GET", "/auth/testsvc/callback/?state=abc123&code=xyz"
        )
        response = await backend._auth_callback_dispatch(request)
        backend.auth_callback.assert_awaited_once_with(request)
        backend.finish_identity_link.assert_not_awaited()
        assert response.text == "login"

    @pytest.mark.asyncio
    async def test_no_state_goes_to_login_without_redis_lookup(self):
        backend = _make_backend()
        backend._flow_store.consume_link = AsyncMock()
        backend.auth_callback = AsyncMock(
            return_value=web.Response(text="login")
        )
        request = make_mocked_request("GET", "/auth/testsvc/callback/?code=x")
        await backend._auth_callback_dispatch(request)
        backend._flow_store.consume_link.assert_not_awaited()
        backend.auth_callback.assert_awaited_once()


class _FakeResponse:
    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._body = body

    async def read(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch_client_session(response: _FakeResponse):
    session = MagicMock()
    session.post = MagicMock(return_value=response)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return patch(
        "navigator_auth.backends.external.ClientSession",
        return_value=session,
    ), session


class TestTokenRequest:
    @pytest.mark.asyncio
    async def test_json_response(self):
        backend = _make_backend()
        resp = _FakeResponse(body=b'{"access_token": "at", "token_type": "bearer"}')
        patcher, session = _patch_client_session(resp)
        with patcher:
            result = await backend.token_request(
                "https://x/token", data={"code": "c"}
            )
        assert result == {"access_token": "at", "token_type": "bearer"}
        # form-encoded body + JSON accept header
        kwargs = session.post.call_args.kwargs
        assert kwargs["headers"]["Accept"] == "application/json"
        assert kwargs["headers"]["Content-Type"] == (
            "application/x-www-form-urlencoded"
        )
        assert kwargs["data"] == {"code": "c"}

    @pytest.mark.asyncio
    async def test_form_encoded_fallback_flattened(self):
        """GitHub-style form-encoded reply becomes a flat dict, not lists."""
        backend = _make_backend()
        resp = _FakeResponse(
            body=b"access_token=gho_abc&scope=user%3Aemail&token_type=bearer"
        )
        patcher, _ = _patch_client_session(resp)
        with patcher:
            result = await backend.token_request("https://x/token", data={})
        assert result["access_token"] == "gho_abc"
        assert result["token_type"] == "bearer"
        assert not isinstance(result["access_token"], list)

    @pytest.mark.asyncio
    async def test_error_key_raises(self):
        backend = _make_backend()
        resp = _FakeResponse(body=b'{"error": "bad_verification_code"}')
        patcher, _ = _patch_client_session(resp)
        with patcher, pytest.raises(AuthException):
            await backend.token_request("https://x/token", data={})

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        backend = _make_backend()
        resp = _FakeResponse(status=401, body=b'{"message": "denied"}')
        patcher, _ = _patch_client_session(resp)
        with patcher, pytest.raises(AuthException):
            await backend.token_request("https://x/token", data={})


class TestGetRedirectUri:
    def test_pure_no_instance_mutation(self):
        backend = _make_backend()
        request = make_mocked_request(
            "GET", "/auth/testsvc/login", headers={"Host": "example.com"}
        )
        uri = backend.get_redirect_uri(request)
        assert uri.endswith("://example.com/auth/testsvc/callback/")
        assert not hasattr(backend, "redirect_uri") or "{domain}" in str(
            getattr(backend, "redirect_uri", "{domain}")
        )
