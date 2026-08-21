"""Unit tests for the fixed GitHub login flow."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.github import GithubAuth, GITHUB_LOGIN_FLOW
from .conftest import make_backend


def _github(flow_store=None):
    backend = make_backend(GithubAuth, flow_store=flow_store)
    backend._token_uri = "https://github.com/login/oauth/access_token"
    backend.userinfo_uri = "https://api.github.com/user"
    backend.user_mapping = {"email": "email"}
    backend.login_failed_uri = "/login-failed"
    return backend


class TestGithubAuthorize:
    @pytest.mark.asyncio
    async def test_get_credentials_no_client_secret_and_state_stored(
        self, flow_store
    ):
        backend = _github(flow_store)
        request = make_mocked_request("GET", "/api/v1/auth/github/")
        params = await backend.get_credentials(
            request, "https://app/auth/github/callback/"
        )
        assert "client_secret" not in params
        assert params["redirect_uri"] == "https://app/auth/github/callback/"
        state = params["state"]
        assert len(state) > 20
        key = GITHUB_LOGIN_FLOW.format(state=state)
        assert flow_store.storage[key]["redirect_uri"] == (
            "https://app/auth/github/callback/"
        )
        assert flow_store.ttls[key] == 600


class TestGithubCallback:
    @pytest.mark.asyncio
    async def test_unknown_state_rejected(self, flow_store):
        backend = _github(flow_store)
        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=x&state=bogus"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_missing_state_rejected(self, flow_store):
        backend = _github(flow_store)
        request = make_mocked_request("GET", "/auth/github/callback/?code=x")
        response = await backend.auth_callback(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_exchange_uses_token_request_with_redirect_uri(
        self, flow_store
    ):
        backend = _github(flow_store)
        await flow_store.set(
            GITHUB_LOGIN_FLOW.format(state="st"),
            {"redirect_uri": "https://app/auth/github/callback/"},
            ttl=600,
        )
        backend.token_request = AsyncMock(
            return_value={"access_token": "gho_at", "token_type": "bearer"}
        )
        backend.get = AsyncMock(
            return_value={"login": "octo", "email": "o@x.com", "name": "Octo"}
        )
        backend.build_user_info = MagicMock(
            return_value=({"email": "o@x.com"}, "octo")
        )
        backend.validate_user_info = AsyncMock(return_value={"token": "jwt"})
        backend.home_redirect = MagicMock(return_value="REDIRECT")

        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=c0de&state=st"
        )
        result = await backend.auth_callback(request)
        assert result == "REDIRECT"
        data = backend.token_request.await_args.kwargs["data"]
        assert data["code"] == "c0de"
        assert data["redirect_uri"] == "https://app/auth/github/callback/"
        # single-use: state consumed
        assert flow_store.storage == {}

    @pytest.mark.asyncio
    async def test_null_email_falls_back_to_user_emails(self, flow_store):
        backend = _github(flow_store)
        await flow_store.set(
            GITHUB_LOGIN_FLOW.format(state="st"), {"redirect_uri": "r"}, ttl=600
        )
        backend.token_request = AsyncMock(
            return_value={"access_token": "gho_at", "token_type": "bearer"}
        )

        async def _get(url, **kwargs):
            if url.endswith("/user"):
                return {"login": "octo", "email": None}
            return [
                {"email": "other@x.com", "primary": False, "verified": True},
                {"email": "main@x.com", "primary": True, "verified": True},
            ]

        backend.get = AsyncMock(side_effect=_get)
        captured = {}

        def _build(data, token, mapping=None):
            captured.update(data)
            return ({"email": data["email"]}, "octo")

        backend.build_user_info = MagicMock(side_effect=_build)
        backend.validate_user_info = AsyncMock(return_value={"token": "jwt"})
        backend.home_redirect = MagicMock(return_value="REDIRECT")

        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=c&state=st"
        )
        await backend.auth_callback(request)
        assert captured["email"] == "main@x.com"

    @pytest.mark.asyncio
    async def test_exchange_failure_returns_403(self, flow_store):
        from navigator_auth.exceptions import AuthException

        backend = _github(flow_store)
        await flow_store.set(
            GITHUB_LOGIN_FLOW.format(state="st"), {"redirect_uri": "r"}, ttl=600
        )
        backend.token_request = AsyncMock(
            side_effect=AuthException("github: Token request failed")
        )
        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=c&state=st"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403
