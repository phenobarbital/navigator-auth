"""Unit tests for the fixed Okta login flow."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.backends.okta import OktaAuth, OKTA_LOGIN_FLOW
from .conftest import make_backend


def _okta(flow_store=None):
    backend = make_backend(OktaAuth, flow_store=flow_store)
    backend._token_uri = "https://okta.example/oauth2/default/v1/token"
    backend.userinfo_uri = "https://okta.example/oauth2/default/v1/userinfo"
    backend._issuer = "https://okta.example/oauth2/default"
    backend.user_mapping = {"email": "email"}
    backend.login_failed_uri = "/login-failed"
    return backend


class TestOktaAuthorize:
    @pytest.mark.asyncio
    async def test_random_state_and_nonce_stored(self, flow_store):
        backend = _okta(flow_store)
        request = make_mocked_request("GET", "/api/v1/auth/okta/")
        params = await backend.get_credentials(
            request, "https://app/auth/okta/callback/"
        )
        state, nonce = params["state"], params["nonce"]
        # no more hardcoded sentinel values
        assert state != "ApplicationState" and len(state) > 20
        assert nonce != "SampleNonce" and len(nonce) > 20
        stored = flow_store.storage[OKTA_LOGIN_FLOW.format(state=state)]
        assert stored["nonce"] == nonce
        assert stored["redirect_uri"] == "https://app/auth/okta/callback/"

    @pytest.mark.asyncio
    async def test_two_flows_get_distinct_state(self, flow_store):
        backend = _okta(flow_store)
        request = make_mocked_request("GET", "/api/v1/auth/okta/")
        p1 = await backend.get_credentials(request, "https://app/cb")
        p2 = await backend.get_credentials(request, "https://app/cb")
        assert p1["state"] != p2["state"]
        assert p1["nonce"] != p2["nonce"]


class TestOktaCallback:
    @pytest.mark.asyncio
    async def test_unknown_state_rejected(self, flow_store):
        backend = _okta(flow_store)
        request = make_mocked_request(
            "GET", "/auth/okta/callback/?code=c&state=bogus"
        )
        response = await backend.auth_callback(request)
        assert response.status == 403

    @pytest.mark.asyncio
    async def test_nonce_from_flow_used_for_id_token_validation(
        self, flow_store
    ):
        backend = _okta(flow_store)
        await flow_store.set(
            OKTA_LOGIN_FLOW.format(state="st"),
            {"nonce": "the-nonce", "redirect_uri": "https://app/cb"},
            ttl=600,
        )
        backend.token_request = AsyncMock(
            return_value={
                "token_type": "Bearer",
                "access_token": "at",
                "id_token": "idt",
            }
        )
        backend.get = AsyncMock(return_value={"sub": "u1", "email": "e@x"})
        backend.build_user_info = MagicMock(return_value=({"email": "e@x"}, "u1"))
        backend.validate_user_info = AsyncMock(return_value={"token": "jwt"})
        backend.home_redirect = MagicMock(return_value="REDIRECT")

        with patch(
            "navigator_auth.backends.okta.OKTA_CLIENT_ID", "cid"
        ), patch(
            "navigator_auth.backends.okta.OKTA_CLIENT_SECRET", "cs"
        ), patch(
            "navigator_auth.backends.okta.is_token_valid",
            new=AsyncMock(return_value=True),
        ), patch(
            "navigator_auth.backends.okta.is_id_token_valid",
            new=AsyncMock(return_value=True),
        ) as id_check:
            request = make_mocked_request(
                "GET", "/auth/okta/callback/?code=c&state=st"
            )
            result = await backend.auth_callback(request)
        assert result == "REDIRECT", getattr(result, "text", result)
        assert id_check.await_args.args[3] == "the-nonce"
        # exchange used the stored redirect_uri
        data = backend.token_request.await_args.kwargs["data"]
        assert data["redirect_uri"] == "https://app/cb"

    @pytest.mark.asyncio
    async def test_invalid_access_token_rejected(self, flow_store):
        backend = _okta(flow_store)
        await flow_store.set(
            OKTA_LOGIN_FLOW.format(state="st"),
            {"nonce": "n", "redirect_uri": "r"},
            ttl=600,
        )
        backend.token_request = AsyncMock(
            return_value={
                "token_type": "Bearer",
                "access_token": "at",
                "id_token": "idt",
            }
        )
        with patch(
            "navigator_auth.backends.okta.OKTA_CLIENT_ID", "cid"
        ), patch(
            "navigator_auth.backends.okta.OKTA_CLIENT_SECRET", "cs"
        ), patch(
            "navigator_auth.backends.okta.is_token_valid",
            new=AsyncMock(return_value=False),
        ):
            request = make_mocked_request(
                "GET", "/auth/okta/callback/?code=c&state=st"
            )
            response = await backend.auth_callback(request)
        assert response.status == 403
