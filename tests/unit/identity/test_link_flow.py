"""Unit tests for the identity-link flow (generic + Azure override)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import AuthException
from navigator_auth.identity.types import TokenResponse
from .conftest import make_backend


def _generic_backend(flow_store=None):
    from navigator_auth.backends.github import GithubAuth

    backend = make_backend(GithubAuth, flow_store=flow_store)
    backend.authorize_uri = "https://github.com/login/oauth/authorize"
    backend._token_uri = "https://github.com/login/oauth/access_token"
    backend.userinfo_uri = "https://api.github.com/user"
    return backend


class TestAuthorizeIdentity:
    @pytest.mark.asyncio
    async def test_redirect_url_and_stored_flow(self, flow_store):
        backend = _generic_backend(flow_store)
        backend.get_redirect_uri = MagicMock(
            return_value="https://app/auth/github/callback/"
        )
        with patch(
            "navigator_auth.backends.github.GITHUB_CLIENT_ID", "cid"
        ), patch("navigator_auth.backends.github.GITHUB_CLIENT_SECRET", "cs"):
            request = make_mocked_request(
                "GET", "/api/v1/user/identities/link/github"
            )
            response = await backend.authorize_identity(
                request, user_id=42, finish_redirect="/manage"
            )
        url = response.location
        assert url.startswith("https://github.com/login/oauth/authorize")
        assert "client_id=cid" in url
        assert "cs" not in url.replace("scope", "")  # no client_secret
        assert "state=" in url
        # link flow stored under idlink:{state} with the session user bound
        key = next(iter(flow_store.storage))
        assert key.startswith("idlink:")
        payload = flow_store.storage[key]
        assert payload["user_id"] == 42
        assert payload["provider"] == "github"
        assert payload["flow"] == "identity_link"
        assert payload["finish_redirect"] == "/manage"

    @pytest.mark.asyncio
    async def test_unconfigured_backend_raises(self, flow_store):
        from navigator_auth.backends.external import ExternalAuth

        backend = _generic_backend(flow_store)
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        backend.get_identity_client = MagicMock(
            side_effect=AuthException("nope")
        )
        request = make_mocked_request("GET", "/x")
        with pytest.raises(AuthException):
            await backend.authorize_identity(request, 1, "/")


class TestExchangeAndRefresh:
    @pytest.mark.asyncio
    async def test_generic_exchange_builds_token_response(self, flow_store):
        backend = _generic_backend(flow_store)
        backend.token_request = AsyncMock(
            return_value={
                "access_token": "at",
                "refresh_token": "rt",
                "token_type": "bearer",
                "expires_in": 28800,
            }
        )
        with patch(
            "navigator_auth.backends.github.GITHUB_CLIENT_ID", "cid"
        ), patch("navigator_auth.backends.github.GITHUB_CLIENT_SECRET", "cs"):
            request = make_mocked_request("GET", "/cb?code=c0de&state=s")
            token = await backend.exchange_code_for_tokens(
                request, {"redirect_uri": "https://app/cb"}
            )
        assert isinstance(token, TokenResponse)
        assert token.access_token == "at"
        assert token.refresh_token == "rt"
        assert token.expires_at is not None
        data = backend.token_request.await_args.kwargs["data"]
        assert data["grant_type"] == "authorization_code"
        assert data["redirect_uri"] == "https://app/cb"

    @pytest.mark.asyncio
    async def test_generic_refresh_keeps_unrotated_token(self, flow_store):
        backend = _generic_backend(flow_store)
        backend.token_request = AsyncMock(
            return_value={"access_token": "new_at", "expires_in": 3600}
        )
        with patch(
            "navigator_auth.backends.github.GITHUB_CLIENT_ID", "cid"
        ), patch("navigator_auth.backends.github.GITHUB_CLIENT_SECRET", "cs"):
            token = await backend.refresh_identity_tokens("old_rt")
        assert token.access_token == "new_at"
        assert token.refresh_token == "old_rt"
        data = backend.token_request.await_args.kwargs["data"]
        assert data["grant_type"] == "refresh_token"


class TestFinishIdentityLink:
    def _flow(self):
        return {
            "user_id": 42,
            "provider": "github",
            "flow": "identity_link",
            "finish_redirect": "/manage",
            "redirect_uri": "https://app/cb",
            "extra": {},
        }

    @pytest.mark.asyncio
    async def test_happy_path_persists_and_redirects(self, flow_store):
        backend = _generic_backend(flow_store)
        token = TokenResponse(access_token="at", refresh_token="rt")
        backend.exchange_code_for_tokens = AsyncMock(return_value=token)
        backend.get_identity_userinfo = AsyncMock(
            return_value={"id": 99, "login": "octo"}
        )
        store = MagicMock()
        store.save_linked_identity = AsyncMock()
        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=c&state=s",
            headers={"Host": "app"},
        )
        request.app["authdb"] = MagicMock()
        with patch(
            "navigator_auth.identity.store.IdentityStore", return_value=store
        ), patch(
            "navigator_session.get_session",
            new=AsyncMock(return_value=None),
        ):
            response = await backend.finish_identity_link(request, self._flow())
        assert response.status == 302
        assert response.location.endswith("/manage")
        args = store.save_linked_identity.await_args.args
        assert args[0] == 42
        assert args[1] == "github"
        assert args[2] is token
        # provider_user_id resolved from userinfo
        assert token.provider_user_id == "99"

    @pytest.mark.asyncio
    async def test_provider_error_redirects_to_failure(self, flow_store):
        backend = _generic_backend(flow_store)
        backend.failed_redirect = MagicMock(return_value="FAILED")
        request = make_mocked_request(
            "GET", "/auth/github/callback/?error=access_denied&state=s"
        )
        result = await backend.finish_identity_link(request, self._flow())
        assert result == "FAILED"
        assert (
            backend.failed_redirect.call_args.kwargs["error"]
            == "IDENTITY_LINK_DENIED"
        )

    @pytest.mark.asyncio
    async def test_exchange_failure_redirects_to_failure(self, flow_store):
        backend = _generic_backend(flow_store)
        backend.exchange_code_for_tokens = AsyncMock(
            side_effect=AuthException("bad code")
        )
        backend.failed_redirect = MagicMock(return_value="FAILED")
        request = make_mocked_request(
            "GET", "/auth/github/callback/?code=c&state=s"
        )
        request.app["authdb"] = MagicMock()
        result = await backend.finish_identity_link(request, self._flow())
        assert result == "FAILED"


class TestAzureIdentityLink:
    def _azure(self, flow_store=None):
        from navigator_auth.backends.azure import AzureAuth

        backend = make_backend(AzureAuth, flow_store=flow_store)
        return backend

    @pytest.mark.asyncio
    async def test_authorize_uses_msal_flow_state(self, flow_store):
        backend = self._azure(flow_store)
        backend.get_redirect_uri = MagicMock(return_value="https://app/cb")
        msal_app = MagicMock()
        msal_app.initiate_auth_code_flow = MagicMock(
            return_value={
                "state": "msal-state",
                "auth_uri": "https://login.microsoftonline.com/authorize?x=1",
            }
        )
        backend.get_msal_app = MagicMock(return_value=msal_app)
        request = make_mocked_request("GET", "/link/azure")
        response = await backend.authorize_identity(request, 7, "/manage")
        assert response.location.startswith("https://login.microsoftonline.com")
        payload = flow_store.storage["idlink:msal-state"]
        assert payload["user_id"] == 7
        assert payload["extra"]["msal_flow"]["state"] == "msal-state"

    @pytest.mark.asyncio
    async def test_exchange_pulls_refresh_token_from_cache(self, flow_store):
        import msal as msal_mod

        backend = self._azure(flow_store)
        msal_app = MagicMock()
        msal_app.acquire_token_by_auth_code_flow = MagicMock(
            return_value={
                "access_token": "az_at",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "User.Read",
            }
        )
        backend.get_msal_app = MagicMock(return_value=msal_app)
        with patch.object(
            msal_mod, "SerializableTokenCache"
        ) as cache_cls:
            cache = MagicMock()
            cache.find = MagicMock(
                return_value=[{"secret": "az_rt", "home_account_id": "h"}]
            )
            cache_cls.return_value = cache
            request = make_mocked_request("GET", "/cb?code=c&state=s")
            token = await backend.exchange_code_for_tokens(
                request, {"extra": {"msal_flow": {"state": "s"}}}
            )
        assert token.access_token == "az_at"
        assert token.refresh_token == "az_rt"
        assert token.scopes == ["User.Read"]
        # raw payload never carries the refresh token
        assert "refresh_token" not in token.raw

    @pytest.mark.asyncio
    async def test_msal_error_raises(self, flow_store):
        backend = self._azure(flow_store)
        msal_app = MagicMock()
        msal_app.acquire_token_by_auth_code_flow = MagicMock(
            return_value={"error": "invalid_grant", "error_description": "x"}
        )
        backend.get_msal_app = MagicMock(return_value=msal_app)
        request = make_mocked_request("GET", "/cb?code=c&state=s")
        with pytest.raises(AuthException):
            await backend.exchange_code_for_tokens(
                request, {"extra": {"msal_flow": {}}}
            )

    @pytest.mark.asyncio
    async def test_refresh_keeps_unrotated_token(self, flow_store):
        backend = self._azure(flow_store)
        msal_app = MagicMock()
        msal_app.acquire_token_by_refresh_token = MagicMock(
            return_value={
                "access_token": "new_at",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )
        backend.get_msal_app = MagicMock(return_value=msal_app)
        with patch("navigator_auth.backends.azure.AzureAuth._refresh_token_from_cache", return_value=None):
            token = await backend.refresh_identity_tokens("old_rt")
        assert token.refresh_token == "old_rt"
